#!/usr/bin/env python3
"""Provider-free durable store ports for the v3 Orch Dork run kernel.

The engine in 'orch_dork_run_engine' never touches storage directly; every
durable state change goes through the small port implemented by the two
adapters below.

* 'InMemoryRunStore' - process-local reference adapter; proves the port's
  compare-and-swap and idempotency discipline in isolation.

* 'SQLiteRunStore' - durable single-file adapter with schema initialization
  via 'PRAGMA user_version' and transactional insert-or-reject appends.

Shared discipline: a writer reserves the next per-run sequence, and only
that writer's commit can land the row. A concurrent writer sees
'StaleSeqError' instead of duplicating the transition. SQLite keeps its
reserved row uncommitted in the same transaction as the final fact, so a
connection or process crash rolls it back. Startup also removes legacy
committed sentinels from earlier generations. Readers never treat either
form as canonical state.
Tampered event rows are rejected by the engine's hash-chain verification;
this module only persists raw rows.
"""

from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
import threading
from pathlib import Path
from urllib.parse import quote
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Hash of the empty chain; every run's first event points at it.
GENESIS_PREV_HASH = "0" * 64
SCHEMA_VERSION = 2
_AUTHORIZATION_TIMEOUT_SECONDS = 5.0
_AUTHORIZATION_LOCAL = threading.local()
_AUTHORIZATION_RECOVERY_NEEDED = object()
_AUTHORIZATION_LEGACY_RECOVERY_NEEDED = object()

_MAX_PAYLOAD_BYTES = 262144
_MAX_RUN_ID = 128
_MAX_NAME = 256
_MAX_ACTOR = 128
_MAX_KIND = 64
_MAX_NOTE = 1024

# The store is the single source for the terminal event vocabulary:
# 'completed' for the completion fact and 'terminated' for cancellation
# (the "cancelled" string is the cancel payload's reason, not a kind).
# The engine and both adapters import this tuple; durable reopen
# invariants depend on it.
TERMINAL_KINDS = ("completed", "terminated")


def event_hash(
    run_seq: int,
    prev_hash: str,
    kind: str,
    actor_key: str,
    payload: str,
    note: Optional[str],
) -> str:
    """Deterministic SHA-256 row hash, chained through the prior row hash.

    Canonical encoding: sorted keys, compact separators, ensure_ascii=False.
    This is the single hash implementation; the engine re-exports it so
    'verify_event_chain' and the append path stay byte-identical.
    """
    return hashlib.sha256(
        json.dumps(
            {"seq": run_seq, "prev_hash": prev_hash, "kind": kind,
             "actor_key": actor_key, "payload": payload, "note": note},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def runtime_origin(kind: str) -> Dict[str, str]:
    """Explicit runtime origin for a kernel-appended (non-lane) event.

    The digest covers the runtime marker and the event kind, so two
    different kinds never share an origin and the origin is recomputable
    from the record, never lifted from a transcript.
    """
    return {
        "kind": "runtime",
        "source": "orch-dork/run-engine",
        "sha256": hashlib.sha256(
            ("orch-dork/v3/runtime-fact:" + kind).encode("utf-8")
        ).hexdigest(),
    }


def _default_commit_facts(
    run_seq: int,
    prev_hash: str,
    kind: str,
    actor_key: str,
    payload: str,
    note: Optional[str],
    provided_hash: Optional[str],
    provided_origin: Optional[Mapping[str, str]],
) -> Tuple[str, Dict[str, str]]:
    """Single default-resolution path shared by both adapters' commits.

    Each provided fact is trusted verbatim; each omitted fact is resolved
    deterministically from the row's canonical fields, independently.
    """
    if provided_hash is None:
        provided_hash = event_hash(run_seq, prev_hash, kind, actor_key,
                                   payload, note)
    if provided_origin is None:
        provided_origin = runtime_origin(kind)
    return str(provided_hash), dict(provided_origin)


class StoreError(RuntimeError):
    """The store is missing, corrupt, or otherwise unusable."""


class StaleSeqError(StoreError):
    """A reserve or commit raced a newer chain tip or claimed seq."""


class _Validation:
    def __init__(self, *, max_payload_bytes: int = _MAX_PAYLOAD_BYTES) -> None:
        if type(max_payload_bytes) is not int or max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be a positive integer")
        self._max_payload_bytes = max_payload_bytes

    @property
    def max_payload_bytes(self) -> int:
        """Host-configured UTF-8 write ceiling; ordinary stores retain 256 KiB."""
        return self._max_payload_bytes

    def _payload(self, value: Any) -> None:
        if not isinstance(value, str):
            raise ValueError("payload must be a string")
        if len(value.encode("utf-8")) > self.max_payload_bytes:
            raise ValueError("payload exceeds " + str(self.max_payload_bytes) + " bytes")

    def run_id(self, value: Any) -> str:
        return self._text(value, "run_id", _MAX_RUN_ID)

    def name(self, value: Any) -> str:
        return self._text(value, "name", _MAX_NAME)

    def actor(self, value: Any) -> str:
        return self._text(value, "actor_key", _MAX_ACTOR)

    def kind(self, value: Any) -> str:
        return self._text(value, "kind", _MAX_KIND)

    def hash(self, value: Any, field: str) -> str:
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError(field + " must be a 64-character hex digest")
        if any(c not in "0123456789abcdef" for c in value):
            raise ValueError(field + " must be lowercase hex")
        return value

    def origin(self, value: Any) -> Dict[str, str]:
        if not isinstance(value, Mapping) or set(value) != {"kind", "source", "sha256"}:
            raise ValueError("origin must be a mapping with keys kind, source, sha256")
        kind_val = self._text(value["kind"], "origin.kind", _MAX_KIND)
        source = self._text(value["source"], "origin.source", 256)
        self.hash(value["sha256"], "origin.sha256")
        return {"kind": kind_val, "source": source, "sha256": str(value["sha256"])}

    def seq(self, value: Any, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(field + " must be a non-negative integer")
        return value

    def note(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            raise ValueError("note must be a non-empty string or None")
        if len(value.encode("utf-8")) > _MAX_NOTE:
            raise ValueError("note exceeds " + str(_MAX_NOTE) + " bytes")
        return value

    def _text(self, value: Any, field: str, limit: int) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError(field + " must be a non-empty string")
        if len(value.encode("utf-8")) > limit:
            raise ValueError(field + " exceeds " + str(limit) + " bytes")
        return value


class _Record:
    def __init__(self, run_id: str, name: str, deliverable: bool) -> None:
        self.run_id = run_id
        self.name = name
        self.deliverable = deliverable
        self.last_seq = 0
        self.terminal_seq: Optional[int] = None
        self.events: Dict[int, Dict[str, Any]] = {}

    def tip_hash(self) -> str:
        if self.last_seq in self.events:
            return self.events[self.last_seq]["event_hash"]
        return GENESIS_PREV_HASH


class InMemoryRunStore(_Validation):
    """Thread-safe in-memory adapter for the v3 run store port."""

    durable = False

    def __init__(self, *, max_payload_bytes: int = _MAX_PAYLOAD_BYTES) -> None:
        super().__init__(max_payload_bytes=max_payload_bytes)
        self._lock = threading.Lock()
        self._runs: Dict[str, _Record] = {}
        self._claimed: Dict[str, int] = {}

    def init(self) -> None:
        """Idempotent process-local initialization without reaping live CAS."""
        with self._lock:
            return None

    def exists(self, run_id: str) -> bool:
        self.run_id(run_id)
        with self._lock:
            return run_id in self._runs

    def create_run(self, run_id: str, name: str, deliverable: bool) -> None:
        self.run_id(run_id)
        self.name(name)
        with self._lock:
            existing = self._runs.get(run_id)
            if existing is not None:
                if existing.name != name or existing.deliverable != bool(deliverable):
                    raise StaleSeqError("run " + run_id + " already exists with different meta")
                return
            self._runs[run_id] = _Record(run_id, name, bool(deliverable))
            self._claimed[run_id] = 0

    def create_started_run(
        self,
        run_id: str,
        name: str,
        deliverable: bool,
        payload: str,
        event_hash_value: str,
        origin: Mapping[str, str],
    ) -> None:
        """Atomically create one run together with its canonical seq-1 fact."""

        self.run_id(run_id)
        self.name(name)
        self.hash(event_hash_value, "event_hash")
        normalized_origin = self.origin(origin)
        self._payload(payload)
        with self._lock:
            if run_id in self._runs:
                raise StaleSeqError("run " + run_id + " already exists")
            record = _Record(run_id, name, bool(deliverable))
            record.events[1] = {
                "run_id": run_id,
                "seq": 1,
                "kind": "started",
                "actor_key": "kernel",
                "payload": payload,
                "note": None,
                "prev_hash": GENESIS_PREV_HASH,
                "event_hash": event_hash_value,
                "origin": normalized_origin,
            }
            record.last_seq = 1
            self._runs[run_id] = record
            self._claimed[run_id] = 0

    def meta(self, run_id: str) -> Optional[Dict[str, Any]]:
        self.run_id(run_id)
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                return None
            terminal = None
            if record.terminal_seq in record.events:
                terminal = dict(record.events[record.terminal_seq])
            return {
                "run_id": run_id,
                "name": record.name,
                "deliverable": record.deliverable,
                "last_seq": record.last_seq,
                "terminal": terminal,
            }

    def seq(self, run_id: str) -> int:
        self.run_id(run_id)
        with self._lock:
            record = self._runs.get(run_id)
            return record.last_seq if record is not None else 0

    def run_ids(self) -> List[str]:
        """Return a sorted read-only projection of canonical run identities."""

        with self._lock:
            return sorted(self._runs)

    def reserve(self, run_id: str, run_seq: int) -> Tuple[int, str]:
        """Claim the next seq for a run; a racer claiming the same seq fails."""
        self.run_id(run_id)
        super().seq(run_seq, "run_seq")
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                raise StaleSeqError("unknown run " + run_id)
            if run_seq != record.last_seq + 1:
                raise StaleSeqError(
                    "stale seq request " + str(run_seq) + " (tip " + str(record.last_seq) + ")"
                )
            claimed = self._claimed.get(run_id, 0)
            if claimed >= run_seq:
                raise StaleSeqError("seq " + str(run_seq) + " already claimed")
            self._claimed[run_id] = run_seq
            return (run_seq, record.tip_hash())

    def release(self, run_id: str, run_seq: int) -> bool:
        """Release one uncommitted claim after its owning append fails."""

        self.run_id(run_id)
        super().seq(run_seq, "run_seq")
        with self._lock:
            if self._claimed.get(run_id, 0) != run_seq:
                return False
            self._claimed[run_id] = 0
            return True

    def commit(
        self,
        run_id: str,
        run_seq: int,
        kind: str,
        actor_key: str,
        payload: str,
        prev_hash: str,
        event_hash: Optional[str] = None,
        origin: Optional[Mapping[str, str]] = None,
        note: Optional[str] = None,
    ) -> int:
        """Land the reserved event; only the claiming writer may succeed.

        Reserved (reserved = 1) rows are discarded; committed rows are the
        self-contained durable facts.
        """
        self.run_id(run_id)
        super().seq(run_seq, "run_seq")
        kind = self.kind(kind)
        actor_key = self.actor(actor_key)
        prev_hash = self.hash(prev_hash, "prev_hash")
        note = self.note(note)
        if event_hash is None or origin is None:
            event_hash, origin = _default_commit_facts(
                run_seq, prev_hash, kind, actor_key, payload,
                note, event_hash, origin)
        self.hash(event_hash, "event_hash")
        origin = self.origin(origin)
        self._payload(payload)
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                raise StaleSeqError("unknown run " + run_id)
            claimed = self._claimed.get(run_id, 0)
            if claimed != run_seq:
                raise StaleSeqError(
                    "commit seq " + str(run_seq) + " does not match claim " + str(claimed)
                )
            expected_prev = (
                record.events[run_seq - 1]["event_hash"]
                if run_seq - 1 in record.events
                else GENESIS_PREV_HASH
            )
            if prev_hash != expected_prev:
                raise StaleSeqError("broken chain: prev does not match tip")
            if run_seq in record.events:
                raise StaleSeqError("seq " + str(run_seq) + " already committed")
            record.events[run_seq] = {
                "run_id": run_id,
                "seq": run_seq,
                "kind": kind,
                "actor_key": actor_key,
                "payload": payload,
                "note": note,
                "prev_hash": prev_hash,
                "event_hash": event_hash,
                "origin": origin,
            }
            record.last_seq = max(record.last_seq, run_seq)
            if kind in TERMINAL_KINDS and record.terminal_seq is None:
                record.terminal_seq = run_seq
            self._claimed[run_id] = 0
            return run_seq

    def events(self, run_id: str, after_seq: int = 0) -> List[Dict[str, Any]]:
        self.run_id(run_id)
        super().seq(after_seq, "after_seq")
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                return []
            out = []
            for seq in sorted(record.events):
                if seq <= after_seq or seq > record.last_seq:
                    continue
                out.append(dict(record.events[seq]))
            return out

    def close(self) -> None:
        with self._lock:
            self._runs = {}
            self._claimed = {}


class SQLiteRunStore(_Validation):
    """Durable single-file SQLite adapter for the v3 run store port."""

    durable = True

    def __init__(self, path: os.PathLike | str, *, max_payload_bytes: int = _MAX_PAYLOAD_BYTES) -> None:
        super().__init__(max_payload_bytes=max_payload_bytes)
        self._path = Path(path).resolve()
        before = self._path.stat() if self._path.exists() else None
        self._database_identity = (before.st_dev,before.st_ino) if before else None
        self._claim_authorization = None
        self._lock = threading.Lock()
        self._claim_lock = threading.RLock()
        self._runs: Dict[str, _Record] = {}
        self._claimed: Dict[str, int] = {}
        self._conn: Optional[sqlite3.Connection] = None
        self._active_claim: Optional[Tuple[str, int]] = None
        self._active_claim_owner: Optional[int] = None
        self._init()

    def _has_legacy_schema_header(self, expected_info):
        """Recognize the predecessor schema without triggering SQLite rollback.

        SQLite's fixed header records user_version at bytes60:64. Only version1
        predates lock enrollment; version2 must retain its existing lock even
        when a hot journal prevents querying the recorded binding. This read
        grants no migration: the acquired lock and recovered SQL schema are
        checked again before initialization writes anything.
        """
        descriptor = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            observed = os.fstat(descriptor)
            if (observed.st_dev, observed.st_ino) != (expected_info.st_dev, expected_info.st_ino):
                raise StoreError("canonical store identity changed while reading its header")
            header = os.read(descriptor, 100)
            return (len(header) == 100 and header[:16] == b"SQLite format 3\x00"
                    and int.from_bytes(header[60:64], "big") == 1)
        finally:
            os.close(descriptor)

    def _authorization_pin(self, *, deadline=None, recover=False):
        """Read immutable lock identity; defer SQLite crash rollback to the guard.

        Version1 is enrolled once under the protective lock at initialization.
        Version2 never adopts a missing/replaced lock. These bytes pin a kernel
        exclusion primitive, not a competing mission owner/lease database.
        """
        if not self._path.exists():
            if self._database_identity is not None:
                raise StoreError("canonical store disappeared")
            return None
        info = self._path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise StoreError("canonical store must be one regular file")
        if self._database_identity is not None and (info.st_dev, info.st_ino) != self._database_identity:
            raise StoreError("canonical store identity changed")
        reader = None
        try:
            reader = sqlite3.connect("file:"+quote(str(self._path), safe="/")+("?mode=rw" if recover else "?mode=ro"),
                                     uri=True, timeout=max(0,deadline-time.monotonic())
                                     if deadline is not None else 5)
            version = reader.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise StoreError("unsupported schema user_version "+str(version))
            if version < 2:
                return None
            rows = reader.execute("SELECT singleton,lock_device,lock_inode FROM store_authorization").fetchall()
            if len(rows) != 1 or rows[0][0] != 1:
                raise StoreError("canonical authorization binding is unavailable")
            return tuple(rows[0][1:])
        except sqlite3.DatabaseError as error:
            if not recover and getattr(error,'sqlite_errorcode',0) & 255 == sqlite3.SQLITE_READONLY:
                # A real hot journal needs SQLite's rollback before any query.
                # Do that only after holding the existing kernel lock; missing
                # custody never permits creating/replacing a recovery lock.
                if self._has_legacy_schema_header(info):
                    return _AUTHORIZATION_LEGACY_RECOVERY_NEEDED
                return _AUTHORIZATION_RECOVERY_NEEDED
            raise StoreError("canonical authorization binding is unreadable") from error
        finally:
            if reader is not None:
                reader.close()

    def _authorization_lock_identity(self, descriptor, path, pin):
        """Check the held file and its name before trusting a stored binding."""
        info, observed = os.fstat(descriptor), path.lstat()
        identity = (info.st_dev, info.st_ino)
        if not stat.S_ISREG(info.st_mode) or not stat.S_ISREG(observed.st_mode):
            raise StoreError("canonical authorization lock is not regular")
        if info.st_uid != os.getuid():
            raise StoreError("canonical authorization lock owner differs")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise StoreError("canonical authorization lock mode is not private")
        if info.st_nlink != 1:
            raise StoreError("canonical authorization lock has multiple names")
        if (observed.st_dev, observed.st_ino) != identity or (
                pin not in (None, _AUTHORIZATION_RECOVERY_NEEDED,
                            _AUTHORIZATION_LEGACY_RECOVERY_NEEDED) and pin != identity):
            raise StoreError("canonical authorization lock identity changed")
        return identity

    @staticmethod
    def _acquire_authorization_lock(descriptor, deadline):
        """Acquire one bounded kernel lock without changing its ownership."""
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StoreError("canonical authorization lock is busy")
                time.sleep(.01)

    @contextmanager
    def authorization_guard(self):
        """Exclude every durable writer and yield already-held protective fds.

        Reentrant on the same thread, including canonical pathname aliases and
        different store connections. External effect children may inherit the
        descriptor: contexts CLOSE only, never LOCK_UN, so a surviving child
        keeps authority unchanged after parent loss. All writers use this gate
        before their existing connection/claim locks. Read methods stay reads.
        Advisory locks do not protect against a same-UID actor bypassing the
        store; worker containment must deny this DB and its metadata.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        key = str(self._path)
        deadline = time.monotonic()+_AUTHORIZATION_TIMEOUT_SECONDS
        pin = self._authorization_pin(deadline=deadline)
        path = self._path.with_name(self._path.name+".authorization.lock")
        entries = getattr(_AUTHORIZATION_LOCAL, 'entries', None)
        if entries is None:
            entries = _AUTHORIZATION_LOCAL.entries = {}
        entry = entries.get(key)
        descriptor = None
        protecting = False
        try:
            if entry is None:
                flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
                if pin in (None, _AUTHORIZATION_LEGACY_RECOVERY_NEEDED):
                    flags |= os.O_CREAT
                descriptor = os.open(path, flags, 0o600)
            else:
                descriptor = entry['fd']
            identity = self._authorization_lock_identity(descriptor, path, pin)
            if entry is None:
                self._acquire_authorization_lock(descriptor, deadline)
                # Re-observe the name after acquisition; no replacement adoption.
                settled_pin = self._authorization_pin(deadline=deadline,
                    recover=pin in (_AUTHORIZATION_RECOVERY_NEEDED,
                                    _AUTHORIZATION_LEGACY_RECOVERY_NEEDED))
                if self._authorization_lock_identity(descriptor, path, settled_pin) != identity:
                    raise StoreError("canonical authorization binding changed while acquiring")
                entry = entries[key] = {'fd':descriptor, 'depth':0}
            entry['depth'] += 1
            protecting = True
            try:
                yield (descriptor,)
            finally:
                entry['depth'] -= 1
                if entry['depth'] == 0:
                    del entries[key]
                    os.close(descriptor)
                descriptor = None
        except OSError as error:
            if protecting:
                raise
            if error.errno == errno.ENOENT:
                raise StoreError("canonical authorization lock is missing") from error
            if error.errno == errno.ELOOP:
                raise StoreError("canonical authorization lock is a symlink") from error
            raise StoreError("canonical authorization lock is unavailable") from error
        finally:
            if descriptor is not None and key not in entries:
                os.close(descriptor)

    def _finish_claim_authorization(self):
        context, self._claim_authorization = self._claim_authorization, None
        if context is not None:
            context.__exit__(None,None,None)

    def _require_no_active_claim_locked(self):
        """Reject nested writes before touching the reserved transaction."""
        if self._active_claim is not None:
            raise StoreError("run creation is forbidden during an active reservation")

    @contextmanager
    def _creation_guard(self):
        """One ordering/refusal boundary for both public creation operations."""
        with self.authorization_guard(), self._claim_lock, self._lock:
            self._require_no_active_claim_locked()
            yield

    def _abort_claim_locked(self):
        """Discard a partial claim without releasing its outer protective fd."""
        if self._conn.in_transaction:
            self._conn.rollback()
        self._active_claim = None
        self._active_claim_owner = None
        self._rebuild()

    # ------------------------------------------------------------- internals
    def _init(self) -> None:
        with self.authorization_guard() as fds:
            try:
                self._initialize(fds[0])
                info = self._path.stat()
                self._database_identity = (info.st_dev,info.st_ino)
            except BaseException:
                if self._conn is not None:
                    self._conn.close()
                    self._conn = None
                raise

    def _initialize(self, authorization_fd) -> None:
        if not self._path.parent.exists():
            self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            # The port is shared across threads: its state and claim locks
            # serialize connection use, so the sqlite3 object must be usable
            # from any thread holding them.
            conn = sqlite3.connect(str(self._path), timeout=5.0,
                                   check_same_thread=False)
            self._conn = conn
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute("PRAGMA foreign_keys = ON")
            with conn:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                if version > SCHEMA_VERSION:
                    raise StoreError(
                        "unsupported schema user_version " + str(version)
                    )
                if version == 0:
                    conn.executescript(
                        """
                        CREATE TABLE runs (
                            run_id TEXT PRIMARY KEY,
                            name TEXT NOT NULL,
                            deliverable INTEGER NOT NULL CHECK (deliverable IN (0, 1))
                        );
                        CREATE TABLE claims (
                            run_id TEXT PRIMARY KEY REFERENCES runs (run_id)
                                ON DELETE CASCADE,
                            run_seq INTEGER NOT NULL CHECK (run_seq >= 0)
                        );
                        CREATE TABLE events (
                            run_id TEXT NOT NULL REFERENCES runs (run_id)
                                ON DELETE CASCADE,
                            run_seq INTEGER NOT NULL,
                            kind TEXT NOT NULL,
                            actor_key TEXT NOT NULL,
                            payload TEXT NOT NULL,
                            note TEXT,
                            prev_hash TEXT NOT NULL,
                            event_hash TEXT NOT NULL,
                            origin TEXT NOT NULL,
                            reserved INTEGER NOT NULL DEFAULT 0
                                CHECK (reserved IN (0, 1)),
                            PRIMARY KEY (run_id, run_seq)
                        );
                        CREATE INDEX idx_events_run_seq
                            ON events (run_id, run_seq);
                        """
                    )
                if version < 2:
                    conn.execute("CREATE TABLE store_authorization (singleton INTEGER PRIMARY KEY CHECK(singleton=1), lock_device INTEGER NOT NULL, lock_inode INTEGER NOT NULL)")
                    pinned = os.fstat(authorization_fd)
                    conn.execute("INSERT INTO store_authorization VALUES (1,?,?)",(pinned.st_dev,pinned.st_ino))
                    conn.execute("PRAGMA user_version = "+str(SCHEMA_VERSION))
            self._rebuild(release_stale=True)

    def _rebuild(self, *, release_stale: bool = False) -> None:
        """Refresh the in-memory projection; discard reserved sentinel rows.

        A reserved row is CAS bookkeeping; after a crash it names a seq that
        was never fully landed, so it is dropped and the claims row reset.
        """
        conn = self._conn
        if release_stale:
            with conn:
                conn.execute("DELETE FROM events WHERE reserved = 1")
                conn.execute("UPDATE claims SET run_seq = 0 WHERE run_seq != 0")
        self._runs = {}
        self._claimed = {}
        for row in conn.execute("SELECT run_id, name, deliverable FROM runs"):
            record = _Record(row["run_id"], row["name"], bool(row["deliverable"]))
            self._runs[record.run_id] = record
            self._claimed[record.run_id] = 0
        for row in conn.execute("SELECT run_id, run_seq FROM claims"):
            claimed = int(row["run_seq"])
            if release_stale and claimed != 0:
                raise StoreError("claim cleanup failed for run " + row["run_id"])
            self._claimed[str(row["run_id"])] = claimed
        for row in conn.execute(
            "SELECT run_id, run_seq, kind, actor_key, payload, note, prev_hash, event_hash, origin "
            "FROM events WHERE reserved = 0 ORDER BY run_id, run_seq"
        ):
            record = self._runs.get(row["run_id"])
            if record is None:
                continue
            seq = int(row["run_seq"])
            origin = json.loads(row["origin"])
            if not isinstance(origin, dict) or set(origin) != {"kind", "source", "sha256"}:
                raise StoreError(
                    "corrupt origin for run " + record.run_id + " seq " + str(seq)
                )
            record.events[seq] = {
                "run_id": record.run_id,
                "seq": seq,
                "kind": row["kind"],
                "actor_key": row["actor_key"],
                "payload": row["payload"],
                "note": row["note"],
                "prev_hash": row["prev_hash"],
                "event_hash": row["event_hash"],
                "origin": origin,
            }
            record.last_seq = max(record.last_seq, seq)
            if row["kind"] in TERMINAL_KINDS and record.terminal_seq is None:
                record.terminal_seq = seq

    def _record_for_read_locked(self, run_id: str) -> Optional[_Record]:
        """Refresh committed cross-connection writes under the owned lock."""

        self._rebuild()
        return self._runs.get(run_id)

    # ------------------------------------------------------------------ port
    def init(self) -> None:
        """Refresh committed state without reaping another live CAS claim."""
        with self._lock:
            self._rebuild()

    def exists(self, run_id: str) -> bool:
        self.run_id(run_id)
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            return row is not None

    def create_run(self, run_id: str, name: str, deliverable: bool) -> None:
        self.run_id(run_id)
        self.name(name)
        with self._creation_guard():
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO runs (run_id, name, deliverable) VALUES (?, ?, ?)",
                        (run_id, name, int(bool(deliverable))),
                    )
                    self._conn.execute(
                        "INSERT INTO claims (run_id, run_seq) VALUES (?, 0)",
                        (run_id,),
                    )
            except sqlite3.IntegrityError as exc:
                raise StaleSeqError("run " + run_id + " already exists") from exc
            self._runs[run_id] = _Record(run_id, name, bool(deliverable))
            self._claimed[run_id] = 0

    def create_started_run(
        self,
        run_id: str,
        name: str,
        deliverable: bool,
        payload: str,
        event_hash_value: str,
        origin: Mapping[str, str],
    ) -> None:
        """Atomically create one run together with its canonical seq-1 fact."""

        self.run_id(run_id)
        self.name(name)
        self.hash(event_hash_value, "event_hash")
        normalized_origin = self.origin(origin)
        self._payload(payload)
        with self._creation_guard():
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    "INSERT INTO runs (run_id, name, deliverable) VALUES (?, ?, ?)",
                    (run_id, name, int(bool(deliverable))),
                )
                self._conn.execute(
                    "INSERT INTO claims (run_id, run_seq) VALUES (?, 0)",
                    (run_id,),
                )
                self._conn.execute(
                    "INSERT INTO events "
                    "(run_id, run_seq, kind, actor_key, payload, note, prev_hash, event_hash, origin, reserved) "
                    "VALUES (?, 1, 'started', 'kernel', ?, NULL, ?, ?, ?, 0)",
                    (
                        run_id,
                        payload,
                        GENESIS_PREV_HASH,
                        event_hash_value,
                        json.dumps(
                            normalized_origin,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    ),
                )
                self._conn.commit()
            except BaseException as error:
                self._abort_claim_locked()
                if isinstance(error, sqlite3.IntegrityError):
                    raise StaleSeqError("run " + run_id + " already exists") from error
                raise
            self._rebuild()

    def meta(self, run_id: str) -> Optional[Dict[str, Any]]:
        self.run_id(run_id)
        with self._lock:
            record = self._record_for_read_locked(run_id)
            if record is None:
                return None
            terminal = None
            if record.terminal_seq in record.events:
                terminal = dict(record.events[record.terminal_seq])
            return {
                "run_id": run_id,
                "name": record.name,
                "deliverable": record.deliverable,
                "last_seq": record.last_seq,
                "terminal": terminal,
            }

    def seq(self, run_id: str) -> int:
        self.run_id(run_id)
        with self._lock:
            record = self._record_for_read_locked(run_id)
            if record is None:
                return 0
            return record.last_seq

    def run_ids(self) -> List[str]:
        """Return sorted canonical run identities without creating state."""

        with self._lock:
            return [
                str(row["run_id"])
                for row in self._conn.execute(
                    "SELECT run_id FROM runs ORDER BY run_id"
                )
            ]

    def reserve(self, run_id: str, run_seq: int) -> Tuple[int, str]:
        context = self.authorization_guard()
        context.__enter__()
        try:
            result = self._reserve(run_id,run_seq)
            self._claim_authorization = context
            return result
        except BaseException:
            context.__exit__(*sys.exc_info())
            raise

    def _reserve(self, run_id: str, run_seq: int) -> Tuple[int, str]:
        self.run_id(run_id)
        super().seq(run_seq, "run_seq")
        self._claim_lock.acquire()
        transaction_started = False
        try:
            with self._lock:
                if self._active_claim is not None:
                    raise StaleSeqError("another seq is already claimed by this store")
                # Keep the CAS sentinel uncommitted until the canonical fact
                # lands. SQLite rolls the whole claim back if this process or
                # connection dies, and another live controller cannot reap it
                # as stale crash debris while the write is in flight.
                self._conn.execute("BEGIN IMMEDIATE")
                transaction_started = True
                self._rebuild()
                record = self._runs.get(run_id)
                if record is None:
                    raise StaleSeqError("unknown run " + run_id)
                if run_seq != record.last_seq + 1:
                    raise StaleSeqError(
                        "stale seq request "
                        + str(run_seq)
                        + " (tip "
                        + str(record.last_seq)
                        + ")"
                    )
                claimed = self._claimed.get(run_id, 0)
                if claimed >= run_seq:
                    raise StaleSeqError("seq " + str(run_seq) + " already claimed")
                prev_hash = record.tip_hash()
                sentinel = {
                    "kind": "occupied",
                    "source": "orch-dork/run-engine",
                    "sha256": GENESIS_PREV_HASH,
                }
                cur = self._conn.execute(
                    "UPDATE claims SET run_seq = ? WHERE run_id = ? AND run_seq = ?",
                    (run_seq, run_id, claimed),
                )
                if cur.rowcount != 1:
                    raise StaleSeqError("seq " + str(run_seq) + " already claimed")
                self._conn.execute(
                    "INSERT INTO events "
                    "(run_id, run_seq, kind, actor_key, payload, note, prev_hash, event_hash, origin, reserved) "
                    "VALUES (?, ?, 'occupied', '-', '{}', NULL, ?, ?, ?, 1)",
                    (
                        run_id,
                        run_seq,
                        prev_hash,
                        GENESIS_PREV_HASH,
                        json.dumps(sentinel, sort_keys=True, separators=(",", ":")),
                    ),
                )
                self._claimed[run_id] = run_seq
                self._active_claim = (run_id, run_seq)
                self._active_claim_owner = threading.get_ident()
                return (run_seq, prev_hash)
        except BaseException as error:
            try:
                if transaction_started:
                    with self._lock:
                        self._abort_claim_locked()
            finally:
                self._claim_lock.release()
            if isinstance(error, (sqlite3.IntegrityError, sqlite3.OperationalError)):
                raise StaleSeqError("seq " + str(run_seq) + " already claimed") from error
            raise

    def release(self, run_id: str, run_seq: int) -> bool:
        released = self._release(run_id,run_seq)
        if released:
            self._finish_claim_authorization()
        return released

    def _release(self, run_id: str, run_seq: int) -> bool:
        """Rollback one uncommitted transactional claim after append failure."""

        self.run_id(run_id)
        super().seq(run_seq, "run_seq")
        if self._active_claim_owner != threading.get_ident():
            return False
        with self._lock:
            if self._active_claim != (run_id, run_seq):
                return False
            self._abort_claim_locked()
        self._claim_lock.release()
        return True

    def commit(self, run_id, run_seq, kind, actor_key, payload, prev_hash,
               event_hash=None, origin=None, note=None):
        try:
            return self._commit(run_id,run_seq,kind,actor_key,payload,prev_hash,
                                event_hash,origin,note)
        finally:
            if self._active_claim is None:
                self._finish_claim_authorization()

    def _commit(
        self,
        run_id: str,
        run_seq: int,
        kind: str,
        actor_key: str,
        payload: str,
        prev_hash: str,
        event_hash: Optional[str] = None,
        origin: Optional[Mapping[str, str]] = None,
        note: Optional[str] = None,
    ) -> int:
        self.run_id(run_id)
        super().seq(run_seq, "run_seq")
        kind = self.kind(kind)
        actor_key = self.actor(actor_key)
        prev_hash = self.hash(prev_hash, "prev_hash")
        note = self.note(note)
        if event_hash is None or origin is None:
            event_hash, origin = _default_commit_facts(
                run_seq, prev_hash, kind, actor_key, payload,
                note, event_hash, origin)
        self.hash(event_hash, "event_hash")
        origin = self.origin(origin)
        self._payload(payload)
        if self._active_claim_owner != threading.get_ident():
            raise StaleSeqError(
                "commit seq " + str(run_seq) + " is not owned by this thread"
            )
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                raise StaleSeqError("unknown run " + run_id)
            claimed = self._claimed.get(run_id, 0)
            if claimed != run_seq or self._active_claim != (run_id, run_seq):
                raise StaleSeqError(
                    "commit seq " + str(run_seq) + " does not match claim " + str(claimed)
                )
            expected_prev = (
                record.events[run_seq - 1]["event_hash"]
                if run_seq - 1 in record.events
                else GENESIS_PREV_HASH
            )
            if prev_hash != expected_prev:
                raise StaleSeqError("broken chain: prev does not match tip")
            if run_seq in record.events:
                raise StaleSeqError("seq " + str(run_seq) + " already committed")
            try:
                self._conn.execute(
                    "DELETE FROM events WHERE run_id = ? AND run_seq = ? AND reserved = 1",
                    (run_id, run_seq),
                )
                self._conn.execute(
                    "INSERT INTO events "
                    "(run_id, run_seq, kind, actor_key, payload, note, prev_hash, event_hash, origin, reserved) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                    (
                        run_id,
                        run_seq,
                        kind,
                        actor_key,
                        payload,
                        note,
                        prev_hash,
                        event_hash,
                        json.dumps(origin, sort_keys=True, separators=(",", ":")),
                    ),
                )
                cur = self._conn.execute(
                    "UPDATE claims SET run_seq = 0 WHERE run_id = ? AND run_seq = ?",
                    (run_id, run_seq),
                )
                if cur.rowcount != 1:
                    raise StaleSeqError("claim lost for seq " + str(run_seq))
                self._conn.commit()
            except BaseException as error:
                try:
                    self._abort_claim_locked()
                finally:
                    self._claim_lock.release()
                if isinstance(error, sqlite3.IntegrityError):
                    raise StaleSeqError("seq " + str(run_seq) + " already committed") from error
                raise
            record.events[run_seq] = {
                "run_id": run_id,
                "seq": run_seq,
                "kind": kind,
                "actor_key": actor_key,
                "payload": payload,
                "note": note,
                "prev_hash": prev_hash,
                "event_hash": event_hash,
                "origin": origin,
            }
            record.last_seq = max(record.last_seq, run_seq)
            if kind in TERMINAL_KINDS and record.terminal_seq is None:
                record.terminal_seq = run_seq
            self._claimed[run_id] = 0
            self._active_claim = None
            self._active_claim_owner = None
            self._claim_lock.release()
            return run_seq

    def events(self, run_id: str, after_seq: int = 0) -> List[Dict[str, Any]]:
        self.run_id(run_id)
        super().seq(after_seq, "after_seq")
        with self._lock:
            record = self._record_for_read_locked(run_id)
            if record is None:
                return []
            out = []
            for seq in sorted(record.events):
                if seq <= after_seq or seq > record.last_seq:
                    continue
                out.append(dict(record.events[seq]))
            return out

    def close(self) -> None:
        # No DB mutation when there is no live transaction. An owned rollback
        # already carries its retained reserve guard until the connection closes.
        try:
            self._close()
        finally:
            if self._active_claim is None:
                self._finish_claim_authorization()

    def _close(self) -> None:
        with self._claim_lock:
            with self._lock:
                if self._conn is not None:
                    if self._active_claim is not None and self._conn.in_transaction:
                        self._conn.rollback()
                    self._conn.close()
                    self._conn = None
                if self._active_claim is not None:
                    self._active_claim = None
                    self._active_claim_owner = None
                    self._claim_lock.release()
                else:
                    self._active_claim_owner = None
                self._runs = {}
                self._claimed = {}
