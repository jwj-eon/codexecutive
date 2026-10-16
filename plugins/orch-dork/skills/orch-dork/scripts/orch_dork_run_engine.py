#!/usr/bin/env python3
"""Provider-free deterministic core for Orch Dork v3 durable runs."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


from orch_dork_run_store import (
    GENESIS_PREV_HASH,
    InMemoryRunStore,
    SQLiteRunStore,
    StaleSeqError,
    TERMINAL_KINDS,
    event_hash,
    runtime_origin,
)

ACTOR_KINDS = frozenset({"executor", "integrator", "observer", "reviewer", "tester"})
# The engine's four-part run result. Release adjudication (telemetry)
# uses a different four-axis set: RELEASE_ADJUDICATION_AXES.
RUN_RESULT_DIMENSIONS = ("execution", "deliverable", "conformance", "evidence")


class RunKernelError(RuntimeError):
    """Broken hash chain or other stream invariant violated."""


class MalformedInputError(ValueError):
    """A plan, transition, or query argument violates the data contract."""


class NotFoundError(LookupError):
    """The run (or acting actor) does not exist in the store."""


class ProtocolError(RuntimeError):
    """A transition the run protocol forbids was attempted."""


class TerminalRequiredError(RuntimeError):
    """Terminal result requested before the terminal fact landed."""


class RunEngine:
    """v3 kernel seam: start, apply, complete, cancel, events, result, run, reduce.

    All durable state lives in the store port; the event stream is the
    authoritative, append-only, hash-chained history that every read-time
    view (including terminal outcomes) is reduced from.
    """

    def __init__(self, store):
        self.store = store
        store.init()

    def start(self, plan):
        """Validate the plan, durably create the run, and land seq 1."""
        try:
            plan = plan_core(plan)
        except MalformedInputError:
            raise
        if self.store.exists(plan["run_id"]):
            raise ProtocolError("run " + plan["run_id"] + " is already started")
        assignments = _canonical_assignments(plan)
        sha = _digest(plan)
        plan["plan_sha256"] = sha
        facts = {
            "plan": plan,
            "plan_sha256": sha,
            "assignments": {role: dict(rec) for role, rec in assignments.items()},
        }
        payload = json.dumps(
            facts,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        digest = event_hash(
            1,
            GENESIS_PREV_HASH,
            KIND_STARTED,
            "kernel",
            payload,
            None,
        )
        try:
            self.store.create_started_run(
                plan["run_id"],
                plan["name"],
                plan["deliverable"],
                payload,
                digest,
                runtime_origin(KIND_STARTED),
            )
        except StaleSeqError as exc:
            raise ProtocolError("run " + plan["run_id"] + " already exists") from exc
        return self.run(plan["run_id"])

    def apply(self, run_id, actor_key, roles, status="SUCCESS",
              deliverables=None, evidence=None, note=None,
              expected_seq=None, expected_prev_hash=None):
        """Record one verified stage fact for the roles the actor staffs."""
        self._check_running(run_id)
        if any(r["kind"] in TERMINAL_KINDS
               for r in self.store.events(run_id, 0)):
            raise ProtocolError("run " + str(run_id) + " is terminal")
        if not isinstance(actor_key, str) or not actor_key:
            raise MalformedInputError("actor_key is required")
        run = self.run(run_id)
        bound = {rec.actor_key for rec in run.assignments.values()}
        if actor_key not in bound:
            raise MalformedInputError("actor " + actor_key + " is unbound")
        role_list = _as_role_list(roles)
        for role in role_list:
            if role not in run.assignments:
                raise MalformedInputError("role " + role + " is not expected")
            if run.assignments[role].actor_key != actor_key:
                raise MalformedInputError(
                    "actor " + actor_key + " does not staff role " + role)
        if status not in STATUS_CHOICES:
            raise MalformedInputError("status must be one of " + str(STATUS_CHOICES))
        deliverables = _validate_text_map(deliverables, "deliverables")
        if evidence is None:
            evidence = {}
        _validate_evidence(evidence)
        facts = {
            "roles": sorted(role_list),
            "status": status,
            "deliverables": deliverables,
            "evidence": dict(evidence),
        }
        self.append_event(
            run_id,
            KIND_APPLIED,
            actor_key,
            facts,
            note,
            expected_seq=expected_seq,
            expected_prev_hash=expected_prev_hash,
        )

    def complete(self, run_id, actor_key, status, note=None,
                 expected_seq=None, expected_prev_hash=None):
        """Land the terminal completion fact once every role demonstrated."""
        self._check_running(run_id)
        if any(r["kind"] in TERMINAL_KINDS
               for r in self.store.events(run_id, 0)):
            raise ProtocolError("run " + str(run_id) + " is terminal")
        if status not in STATUS_CHOICES:
            raise MalformedInputError("status must be one of " + str(STATUS_CHOICES))
        if not isinstance(actor_key, str) or not actor_key:
            raise MalformedInputError("actor_key is required")
        run = self.run(run_id)
        if "integrator" in run.assignments:
            if actor_key != run.assignments["integrator"].actor_key:
                raise MalformedInputError(
                    "only the integrator actor may complete the run")
        if status == "SUCCESS":
            applied_roles = set()
            for row in self.store.events(run_id, 0):
                if row["kind"] == KIND_APPLIED:
                    applied_roles.update(json.loads(row["payload"])["roles"])
            missing = [role for role in run["expected_roles"]
                       if role not in applied_roles]
            if missing:
                raise ProtocolError(
                    "complete requires applied facts for every role; missing: "
                    + ", ".join(missing))
        self.append_event(
            run_id,
            KIND_COMPLETED,
            actor_key,
            {"status": status},
            note,
            expected_seq=expected_seq,
            expected_prev_hash=expected_prev_hash,
        )

    def cancel(self, run_id, note=None, expected_seq=None,
               expected_prev_hash=None):
        """Cancel the run; idempotent only against its own terminal fact."""
        self._check_running(run_id)
        rows = self.store.events(run_id, 0)
        terminal = next((r for r in rows if r["kind"] in TERMINAL_KINDS), None)
        if terminal is not None:
            if terminal["kind"] == KIND_TERMINATED:
                return self._event(terminal)
            raise ProtocolError("run " + str(run_id) + " is terminal")
        self.append_event(
            run_id,
            KIND_TERMINATED,
            "kernel",
            {"reason": "cancelled"},
            note,
            expected_seq=expected_seq,
            expected_prev_hash=expected_prev_hash,
        )
        terminal = next(r for r in self.store.events(run_id, 0)
                        if r["kind"] == KIND_TERMINATED)
        return self._event(terminal)

    def result(self, run_id):
        """Reduce the verified stream to the terminal Outcome (four axes)."""
        self._check_running(run_id)
        rows = self.store.events(run_id, 0)
        verify_event_chain(rows)
        if not any(r["kind"] in TERMINAL_KINDS for r in rows):
            raise TerminalRequiredError("run " + str(run_id) + " is not terminal")
        terminal = next(r for r in rows if r["kind"] in TERMINAL_KINDS)
        _validate_terminal_row(terminal)
        return Outcome(_outcome_axes(terminal, rows))

    def close(self):
        """Close the underlying store port."""
        self.store.close()

    # -- lifecycle ----------------------------------------------------------
    def append_event(self, run_id, kind, actor_key, facts, note=None,
                     expected_seq=None, expected_prev_hash=None):
        """Reserve the next seq, hash-chain the fact row, and commit it.

        Reserved-but-uncommitted rows are claim bookkeeping only; reserve is
        compare-and-swapped so a racer cannot duplicate a transition.
        """
        payload = _canon(facts).decode('utf-8')
        return self._append_prepared_event(
            run_id, kind, actor_key, lambda: payload, note,
            expected_seq, expected_prev_hash,
        )

    def append_event_checked(self, run_id, kind, actor_key, facts_builder,
                             note=None, expected_seq=None,
                             expected_prev_hash=None):
        """Build one host fact while the canonical reservation is held.

        SQLite's reservation holds its write transaction through the commit.
        A trusted host builder can therefore re-read another authoritative
        stream on this engine before deciding the fact. It must perform no
        external effects or nested writes. This primitive supplies no mission
        admission authority; Control Tower validates that closed transition.
        In-memory stores retain their ordinary single-host adapter semantics.
        """
        if not callable(facts_builder):
            raise MalformedInputError("facts_builder must be callable")

        def prepare_payload():
            facts = facts_builder()
            if not isinstance(facts, Mapping):
                raise MalformedInputError("checked facts must be a mapping")
            return _canon(facts).decode('utf-8')

        return self._append_prepared_event(
            run_id, kind, actor_key, prepare_payload, note,
            expected_seq, expected_prev_hash,
        )

    def _append_prepared_event(self, run_id, kind, actor_key, prepare_payload,
                               note, expected_seq, expected_prev_hash):
        if not isinstance(kind, str) or kind not in CANONICAL_KINDS:
            raise MalformedInputError(
                "event kind must be one of " + ", ".join(sorted(CANONICAL_KINDS)))
        if expected_seq is not None and (
            isinstance(expected_seq, bool)
            or not isinstance(expected_seq, int)
            or expected_seq < 0
        ):
            raise MalformedInputError("expected_seq must be a non-negative integer")
        if expected_prev_hash is not None and (
            not isinstance(expected_prev_hash, str)
            or len(expected_prev_hash) != 64
            or any(char not in "0123456789abcdef" for char in expected_prev_hash)
        ):
            raise MalformedInputError("expected_prev_hash must be lowercase sha256")
        last = self.store.seq(run_id)
        if expected_seq is not None and last != expected_seq:
            raise StaleSeqError(
                "expected seq " + str(expected_seq) + " but tip is " + str(last)
            )
        if expected_prev_hash is not None:
            rows = self.store.events(run_id, 0)
            actual_prev = rows[-1]["event_hash"] if rows else GENESIS_PREV_HASH
            if actual_prev != expected_prev_hash:
                raise StaleSeqError("expected prev hash does not match tip")
        seq, prev = self.store.reserve(run_id, last + 1)
        try:
            payload = prepare_payload()
            digest = event_hash(seq, prev, kind, actor_key, payload, note)
            self.store.commit(
                run_id,
                seq,
                kind,
                actor_key,
                payload,
                prev,
                digest,
                runtime_origin(kind),
                note,
            )
        except BaseException:
            self.store.release(run_id, seq)
            raise
        return seq

    def _check_running(self, run_id):
        if not isinstance(run_id, str) or not run_id:
            raise NotFoundError("unknown run")
        meta = self.store.meta(run_id)
        if meta is None:
            raise NotFoundError("unknown run " + str(run_id))
        return meta

    @staticmethod
    def _event(row):
        """A typed native runtime fact row (payload stays a JSON string)."""
        return RunEvent({
            "run_id": row["run_id"],
            "seq": row["seq"],
            "kind": row["kind"],
            "actor_key": row["actor_key"],
            "payload": _Payload(row["payload"]),
            "note": row.get("note"),
            "prev_hash": row["prev_hash"],
            "event_hash": row["event_hash"],
            "origin": dict(row["origin"]),
        })

    def events(self, run_id, after_seq=0):
        """Verifiable, hash-chained events with seq greater than after_seq."""
        if isinstance(after_seq, bool) or not isinstance(after_seq, int) or after_seq < 0:
            raise MalformedInputError("after_seq must be a non-negative integer")
        if isinstance(run_id, str) and not run_id:
            raise NotFoundError("unknown run")
        rows = self.store.events(run_id, 0)
        if not rows:
            if not self.store.exists(run_id):
                raise NotFoundError("unknown run " + str(run_id))
            return []
        verify_event_chain(rows)
        return [self._event(row) for row in rows if row["seq"] > after_seq]

    def run(self, run_id):
        """The started run's typed view: plan digest plus canonical bindings."""
        meta = self._check_running(run_id)
        started = next((r for r in self.store.events(run_id, 0)
                        if r["kind"] == KIND_STARTED), None)
        if started is None:
            raise RunKernelError("run " + run_id + " has no started fact")
        facts = json.loads(started["payload"])
        plan = facts["plan"]
        return Run({
            "run_id": run_id,
            "name": meta["name"],
            "deliverable": bool(meta["deliverable"]),
            "plan_sha256": facts["plan_sha256"],
            "expected_roles": tuple(plan["expected_roles"]),
            "assignments": {role: Assignment(rec)
                            for role, rec in facts["assignments"].items()},
        })

    def reduce(self, plan, events):
        """Deterministically reduce an event history to its canonical state.

        Equal histories yield equal states: the view is a pure function of
        the verified chain (everything below, the store, is untouched).
        """
        if not isinstance(plan, Mapping):
            raise MalformedInputError("reduce requires a plan mapping")
        rows = _event_rows(events)
        verify_event_chain(rows)
        rows = sorted(rows, key=lambda row: row["seq"])
        started = next((r for r in rows if r["kind"] == KIND_STARTED), None)
        if started is None:
            raise MalformedInputError("history lacks a started fact")
        terminal = next((r for r in rows if r["kind"] in TERMINAL_KINDS), None)
        if terminal is not None:
            _validate_terminal_row(terminal)
        applied = [r for r in rows if r["kind"] == KIND_APPLIED]
        prepared = any(json.loads(r["payload"]).get("deliverables")
                       for r in applied)
        evidence_roles = set()
        deliverables = {}
        for row in applied:
            facts = json.loads(row["payload"])
            deliverables.update(facts.get("deliverables") or {})
            evidence_roles.update(facts.get("evidence") or {})
        if terminal is not None:
            axes = _outcome_axes(terminal, rows)
        else:
            axes = {
                "execution": "pending",
                "deliverable": (DELIVERABLE_PREPARED if prepared
                                else DELIVERABLE_ABSENT),
                "conformance": "pending",
                "evidence": _evidence_scalar(_expected_roles(rows), evidence_roles),
            }
        state = {
            "run_id": rows[0]["run_id"],
            "seq": rows[-1]["seq"],
            "last_hash": rows[-1]["event_hash"],
            "terminal": terminal is not None,
            "terminal_kind": (terminal["kind"] if terminal is not None
                              else None),
            "plan_sha256": json.loads(started["payload"])["plan_sha256"],
            "applied_by": sorted(r["actor_key"] for r in applied),
            "deliverables": deliverables,
            "axes": axes,
            # Digest over the verified canonical chain: provenance of the
            # whole stream, binding every row's fields and hash chain.
            "stream_sha256": stream_digest(rows),
        }
        return _freeze(state)


def _digest(value: Any) -> str:
    """SHA-256 hex of the canonical encoding of ``value``."""
    return hashlib.sha256(_canon(value)).hexdigest()


def _canon(value: Any) -> bytes:
    """Canonical encoding: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
def verify_event_chain(rows: Sequence[Mapping[str, Any]]) -> List[int]:
    """Verify the canonical event chain; fail closed with RunKernelError.

    Every row must be a mapping carrying a strictly integer seq, a kind
    from exactly CANONICAL_KINDS, a non-empty actor_key, a JSON string
    payload, 64-hex prev_hash and event_hash, and a string-or-null note
    with no duplicate seq.  Harmless physical row reordering is
    normalized by sorting the rows on their strictly integer seq before the
    protocol is enforced: the chain must start at seq 1 and be contiguous,
    the started fact is first and appears exactly once, applied facts land
    only while the run is open, exactly one terminal (completed or
    terminated) may appear, and no fact may follow the terminal.  Every
    prev_hash/event_hash must recompute from the GENESIS root.  An empty
    input verifies to an empty list; on success returns the verified
    sequence numbers in canonical order.
    """
    if not isinstance(rows, (list, tuple)):
        raise TypeError("rows requires a sequence of event rows")
    seen: set = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise RunKernelError("event row requires a mapping")
        seq = row.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
            raise RunKernelError("chain seq must be a positive integer")
        kind = row.get("kind")
        if not isinstance(kind, str) or kind not in CANONICAL_KINDS:
            raise RunKernelError("event kind is not canonical: " + str(kind))
        if not isinstance(row.get("actor_key"), str) or not row["actor_key"]:
            raise RunKernelError("chain row actor_key must be non-empty")
        if not isinstance(row.get("payload"), str):
            raise RunKernelError("chain row payload must be a JSON string")
        ph = row.get("prev_hash")
        if not isinstance(ph, str) or len(ph) != 64:
            raise RunKernelError("chain row prev_hash must be 64-char hex")
        eh = row.get("event_hash")
        if not isinstance(eh, str) or len(eh) != 64:
            raise RunKernelError("chain row event_hash must be 64-char hex")
        note = row.get("note")
        if note is not None and (not isinstance(note, str) or not note):
            raise RunKernelError("chain row note must be a string or null")
        if seq in seen:
            raise RunKernelError("duplicate seq " + str(seq) + " in chain")
        seen.add(seq)
    # Harmless physical reordering of the fact rows is not part of the
    # stream's meaning: normalize to strictly ascending integer seq, then
    # enforce the canonical protocol on the ordered chain -- seq 1 first
    # and contiguous, started first and exactly once, applied only while
    # the run is open, exactly one terminal of completed/terminated, and
    # no fact after the terminal -- while every prev_hash/event_hash still
    # recomputes from the GENESIS root.
    pairs = [(row["seq"], row) for row in rows]
    pairs.sort(key=lambda pair: pair[0])
    prev = GENESIS_PREV_HASH
    verified: List[int] = []
    started_seen = False
    terminal_seen = False
    for seq, row in pairs:
        if not verified:
            if seq != 1:
                raise RunKernelError("chain must start at seq 1")
        elif seq != verified[-1] + 1:
            raise RunKernelError("chain gap after seq " + str(verified[-1]))
        if terminal_seen:
            raise RunKernelError("fact after terminal at seq " + str(seq))
        kind = row["kind"]
        if kind == KIND_STARTED:
            if started_seen or verified:
                raise RunKernelError(
                    "started fact must be the first row of the chain"
                    " and may appear only once")
            started_seen = True
        elif kind in TERMINAL_KINDS:
            terminal_seen = True
        if row["prev_hash"] != prev:
            raise RunKernelError("prev_hash broken at seq " + str(seq))
        expected = event_hash(seq, prev, kind, row["actor_key"],
                              row["payload"], row.get("note"))
        if row["event_hash"] != expected:
            raise RunKernelError("event hash mismatch at seq " + str(seq))
        verified.append(seq)
        prev = row["event_hash"]
    return verified
# Preserve legacy run names and admit the existing Watcher's exact closed run
# identity. Mission/intake joins must retain that real identity without a rename.
RUN_ID_RE = re.compile(r"^(?:[a-z][a-z0-9]*(-[a-z0-9]+)?|gr-[0-9]{8}-[0-9a-f]{8})$")
EXECUTION_SUCCESS = "succeeded"
EXECUTION_FAILED = "failed"
EXECUTION_CANCELLED = "cancelled"
DELIVERABLE_PREPARED = "prepared"
DELIVERABLE_DELIVERED = "delivered"
DELIVERABLE_ABSENT = "absent"
CONFORMANCE_CONFORMS = "conforms"
CONFORMANCE_CONFLICTS = "conflicts"
CONFORMANCE_MISSING = "missing"
KIND_STARTED = "started"
KIND_APPLIED = "applied"
KIND_COMPLETED = "completed"
KIND_TERMINATED = "terminated"
# The canonical fact vocabulary of the durable stream.  verify_event_chain
# fails closed on anything outside this exact set, and the public append
# seam admits only these kinds.
CANONICAL_KINDS = (KIND_STARTED, KIND_APPLIED, KIND_COMPLETED, KIND_TERMINATED)

# Applied fact rows carry an open, bounded evidence vocabulary: an
# evidence key is a bounded descriptive string, never a fixed code.
# Terminal outcomes reduce it to a single scalar decision.
EVIDENCE_COMPLETE = "complete"
EVIDENCE_PARTIAL = "partial"
EVIDENCE_MISSING = "missing"
_MAX_EVIDENCE_KEY_BYTES = 64
_MAX_EVIDENCE_VALUE_BYTES = 1024
_MAX_EVIDENCE_KEYS = 64


def _evidence_key_ok(axis):
    """A descriptive evidence key: nonempty, whitespace-free string in bound."""
    return (
        isinstance(axis, str)
        and axis and not any(ch.isspace() for ch in axis)
        and len(axis.encode("utf-8")) <= _MAX_EVIDENCE_KEY_BYTES
    )


class _Payload(str):
    """A stored JSON payload that also supports ['key'] fact access."""

    def __getitem__(self, key):
        return json.loads(self)[key]

class _Frozen(dict):
    """Immutable mapping snapshot: attribute reads, TypeError on any write."""
    __slots__ = ()

    _MISSING = object()

    __hash__ = dict.__hash__

    def __ne__(self, other):
        return not self.__eq__(other)

    def __missing__(self, key):
        return KeyError(key)

    def __getattr__(self, name):
        if name in self:
            return self[name]
        raise AttributeError(name)

    def __setattr__(self, name, value):
        raise TypeError(type(self).__name__ + " snapshots are immutable")

    def __setitem__(self, key, value):
        raise TypeError(type(self).__name__ + " snapshots are immutable")

    def __delitem__(self, key):
        raise TypeError(type(self).__name__ + " snapshots are immutable")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


class Actor(_Frozen):
    """A closed actor identity; kind is from ACTOR_KINDS."""
    canonical_key = ("intent", "kind", "model")


class Assignment(_Frozen):
    """One role->actor binding; the role is independent of the actor kind."""
    canonical_key = ("intent", "kind", "model")


class RunEvent(_Frozen):
    """A verified, chained, native runtime fact."""


class Run(_Frozen):
    """A started-run snapshot with canonical role assignments."""


class Outcome(_Frozen):
    """A terminal result: four independent axes, never one boolean."""


def actor(kind="executor", model=None, actor_key=None, intent="code:default"):
    if kind not in ACTOR_KINDS:
        raise MalformedInputError("actor kind is invalid")
    if not isinstance(model, str) or not model:
        raise MalformedInputError("actor model is required")
    if not isinstance(intent, str) or not intent:
        raise MalformedInputError("actor intent is required")
    if actor_key is None:
        actor_key = "worker" if kind == "executor" else kind
    if not isinstance(actor_key, str) or not actor_key:
        raise MalformedInputError("actor_key is required")
    return {"actor_key": actor_key, "kind": kind, "model": model, "intent": intent}


def make_plan(run_id, name, expected_roles, deliverable=True, actors=(), origin=None):
    """Build and validate a canonical v3 run plan."""
    if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
        raise MalformedInputError("plan run_id is malformed: " + repr(run_id))
    if not isinstance(name, str) or not name.strip():
        raise MalformedInputError("plan name is malformed")
    roles = _as_role_list(expected_roles)
    deliverable = _as_bool(deliverable, "deliverable")
    if isinstance(actors, (str, Mapping)) or not isinstance(actors, (list, tuple)):
        raise MalformedInputError("plan actors must be a list or tuple")
    actor_list = []
    seen_keys = set()
    for record in actors:
        if not isinstance(record, dict):
            raise MalformedInputError("plan actors must be mappings from actor()")
        key = record.get("actor_key")
        kind = record.get("kind")
        model = record.get("model")
        intent = record.get("intent")
        if not isinstance(key, str) or not key:
            raise MalformedInputError("plan actor actor_key is malformed")
        if not isinstance(kind, str) or kind not in ACTOR_KINDS:
            raise MalformedInputError("plan actor kind is malformed")
        if not isinstance(model, str) or not model:
            raise MalformedInputError("plan actor model is malformed")
        if not isinstance(intent, str) or not intent:
            raise MalformedInputError("plan actor intent is malformed")
        if key in seen_keys:
            raise MalformedInputError("duplicate plan actor key: " + key)
        seen_keys.add(key)
        actor_list.append({"actor_key": key, "kind": kind, "model": model, "intent": intent})
    if len(actor_list) != len(roles):
        raise MalformedInputError("plan actors must staff every expected role")
    if origin is None:
        origin = {}
    if not isinstance(origin, Mapping) or any(not isinstance(k, str) or not k for k in origin):
        raise MalformedInputError("plan origin must be a string-keyed mapping")
    return {
        "run_id": run_id,
        "name": name,
        "expected_roles": tuple(roles),
        "deliverable": deliverable,
        "actors": actor_list,
        "origin": dict(origin),
    }


def _as_role_list(value):
    if isinstance(value, (str, Mapping)) or not isinstance(value, (list, tuple)):
        raise MalformedInputError("plan expected_roles must be a list or tuple")
    roles = []
    for role in value:
        if not isinstance(role, str) or not role:
            raise MalformedInputError("plan roles must be non-empty strings")
        if role in roles:
            raise MalformedInputError("plan roles must be unique")
        roles.append(role)
    if not roles:
        raise MalformedInputError("plan expected_roles must not be empty")
    return roles


def _as_bool(value, field):
    if not isinstance(value, bool):
        raise MalformedInputError(field + " must be a bool")
    return value


def reducer_probe(state_a, state_b):
    """Deterministic equality probe over canonical state views."""
    if not isinstance(state_a, Mapping) or not isinstance(state_b, Mapping):
        raise MalformedInputError("reducer_probe requires state mappings")
    digest_a = _digest(dict(state_a))
    digest_b = _digest(dict(state_b))
    return {"equal": digest_a == digest_b, "digest_a": digest_a, "digest_b": digest_b}


def _role_set(plan):
    """Ordered expected roles of a validated plan."""
    return list(plan.get("expected_roles") or ())


STATUS_CHOICES = ("SUCCESS", "ERROR")


def _validate_text_map(value, field):
    """Require a string->non-empty-string mapping (None allowed at call sites)."""
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise MalformedInputError(field + " must be a mapping")
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise MalformedInputError(field + " keys must be non-empty strings")
        if not isinstance(item, str) or not item:
            raise MalformedInputError(field + " values must be non-empty strings")
    return dict(value)


def _validate_evidence(evidence):
    """Applied evidence: bounded descriptive nonempty-string keys/values."""
    if not isinstance(evidence, Mapping):
        raise MalformedInputError("evidence must be a mapping")
    if len(evidence) > _MAX_EVIDENCE_KEYS:
        raise MalformedInputError(
            "evidence accepts at most " + str(_MAX_EVIDENCE_KEYS) + " keys")
    for key, value in evidence.items():
        if not _evidence_key_ok(key):
            raise MalformedInputError(
                "evidence keys must be nonempty whitespace-free strings of at most "
                + str(_MAX_EVIDENCE_KEY_BYTES) + " bytes")
        if (not isinstance(value, str) or not value
                or len(value.encode("utf-8")) > _MAX_EVIDENCE_VALUE_BYTES):
            raise MalformedInputError(
                "evidence values must be non-empty strings of at most "
                + str(_MAX_EVIDENCE_VALUE_BYTES) + " bytes")


def _expected_roles(rows):
    """Expected roles from the history's started fact (validated up front)."""
    started = next(r for r in rows if r["kind"] == KIND_STARTED)
    return tuple(json.loads(started["payload"])["plan"]["expected_roles"])


def _evidence_scalar(expected_roles, evidence_roles):
    """Scalar evidence decision: complete iff every expected role is covered.

    The decision is reduced from the nonempty descriptive evidence keys of
    the verified applied rows; the underlying semantics are not exposed.
    """
    if set(expected_roles) <= evidence_roles:
        return EVIDENCE_COMPLETE
    if evidence_roles:
        return EVIDENCE_PARTIAL
    return EVIDENCE_MISSING


def stream_digest(rows):
    """Canonical SHA-256 over verified chain rows, ranked by chain position.

    Every row field (including the chained hashes that bind the position)
    participates, so equal histories reduce to equal digests and no proper
    prefix of a chain shares the digest of the full chain.

    Public API: the verified chain is the sole authority for run state
    and this digest binds projections to that authority; the telemetry
    lifecycle bridge consumes it via lazy import.
    """
    return _digest(
        {
            "stream": [
                {
                    "rank": index,
                    "run_id": row["run_id"],
                    "seq": row["seq"],
                    "kind": row["kind"],
                    "actor_key": row["actor_key"],
                    "payload": row["payload"],
                    "note": row["note"],
                    "prev_hash": row["prev_hash"],
                    "event_hash": row["event_hash"],
                    "origin": row["origin"],
                }
                for index, row in enumerate(rows, start=1)
            ]
        }
    )


def _canonical_assignments(plan):
    """Bind roles to actors: explicit key==role first, then order of mention."""
    roles = _role_set(plan)
    actors = list(plan.get("actors") or ())
    unused = list(actors)
    assignments = {}
    for role in roles:
        record = next((item for item in unused if item["actor_key"] == role), None)
        if record is None:
            if not unused:
                raise MalformedInputError("plan actors must staff every expected role")
            record = unused[0]
        unused.remove(record)
        assignments[role] = Assignment({"role": role, **record})
    return assignments

def _freeze(value):
    """Re-freeze nested native structures into value-equal snapshots."""
    if isinstance(value, Mapping):
        return _Frozen({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return [_freeze(v) for v in value]
    return value


def _event_rows(events):
    """Normalize event objects/rows into canonical chain row dicts."""
    rows = []
    for event in events:
        if isinstance(event, Mapping):
            row = event
        else:
            row = {}
            for field in ("run_id", "seq", "kind", "actor_key", "payload",
                         "note", "prev_hash", "event_hash", "origin"):
                payload_str = getattr(event, "payload_str", None)
                row[field] = (payload_str if field == "payload" else getattr(event, field))
        rows.append(row)
    return rows


def _validate_terminal_row(row):
    """Reject a malformed terminal fact row (chain verification already passed)."""
    if row["kind"] == KIND_TERMINATED:
        payload = row.get("payload")
        if not isinstance(payload, str) or not payload:
            raise RunKernelError("terminal row payload must be a JSON string")
        facts = json.loads(payload)
        if not isinstance(facts, Mapping) or facts.get("reason") != "cancelled":
            raise RunKernelError("terminal row payload is malformed")
        return
    if row["kind"] == KIND_COMPLETED:
        payload = row.get("payload")
        if not isinstance(payload, str) or not payload:
            raise RunKernelError("terminal row payload must be a JSON string")
        facts = json.loads(payload)
        if not isinstance(facts, Mapping) or facts.get("status") not in STATUS_CHOICES:
            raise RunKernelError("terminal row status is malformed")


def _outcome_axes(terminal, rows):
    """The four independent terminal outcome axes, from verified facts only."""
    applied = [r for r in rows if r["kind"] == KIND_APPLIED]
    prepared = any(json.loads(r["payload"]).get("deliverables")
                   for r in applied)
    evidence_roles = set()
    for row in applied:
        for axis, value in ((json.loads(row["payload"]).get("evidence")) or {}).items():
            if value:
                evidence_roles.add(axis)
    if terminal["kind"] == KIND_TERMINATED:
        execution, conformance = EXECUTION_CANCELLED, CONFORMANCE_CONFLICTS
    else:
        status = json.loads(terminal["payload"]).get("status")
        if status == "SUCCESS":
            execution, conformance = EXECUTION_SUCCESS, CONFORMANCE_CONFORMS
        else:
            execution, conformance = EXECUTION_FAILED, CONFORMANCE_MISSING
    if prepared and terminal["kind"] == KIND_COMPLETED:
        deliverable = DELIVERABLE_DELIVERED
    elif prepared:
        deliverable = DELIVERABLE_PREPARED
    else:
        deliverable = DELIVERABLE_ABSENT
    return {
        "execution": execution,
        "deliverable": deliverable,
        "conformance": conformance,
        "evidence": _evidence_scalar(_expected_roles(rows), evidence_roles),
    }


def plan_core(plan):
    """Validate ``plan`` and return its canonical reduced core."""
    if not isinstance(plan, Mapping):
        raise MalformedInputError("plan_core requires a plan mapping")
    allowed = {"run_id", "name", "expected_roles", "deliverable", "actors", "origin"}
    unexpected = set(plan) - allowed
    if unexpected:
        raise MalformedInputError("plan has unexpected keys: " + ", ".join(sorted(unexpected)))
    return make_plan(
        run_id=plan.get("run_id"),
        name=plan.get("name"),
        expected_roles=plan.get("expected_roles"),
        deliverable=plan.get("deliverable"),
        actors=plan.get("actors"),
        origin=plan.get("origin"),
    )
