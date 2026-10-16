#!/usr/bin/env python3
"""Issue 77 recovery: make a run's outcome survive a root that never reports.

The dogfood corpus depends on a verdict written by the root orchestrator at the
end of the run, as its last act. That is precisely the moment a long
orchestration root is most likely to be dead, out of context, or poisoned, so
the most informative runs are the ones most likely to lose their record. Two
consecutive real runs proved it: one recorded only because its root happened to
survive, and one recorded only because a human later reconstructed the verdict
by hand from the session record.

This module removes the dependency on that last turn by splitting a record into
the two halves that have completely different failure modes:

* The mechanical spine -- lane count, frozen plan digest, gate results,
  spawn-wave membership, declared deliverables, and how the root itself ended.
  These are facts the runtime already wrote durably to the session record, and
  they stay derivable long after every agent in the run is gone.
* The judgement -- the three closed-set verdicts. Those are worth something
  precisely because a human who saw the outcome supplied them, so nothing here
  produces them.

A spine is therefore not a label and can never become one. It carries no
verdict field, append_spine refuses any entry that has one, and no function
here writes an orch-dork/dogfood-record/v1. What a spine buys is that the
perishable half of a record is captured mechanically, sealed into the same
append-only chain, and counted as an unlabeled run, so a later labeler supplies
judgement only, against frozen facts rather than memory.

Honest absence governs every derivation. Where the session record does not
determine a fact, the spine reports it undetermined and leaves the field null.
derived_class in particular stays null unless the mechanical evidence settles
it, because that field gates plan_verdict applicability in the corpus, and a
guess there would manufacture an applicability decision rather than merely add
noise.

Provider-free: zero model calls, zero credentials, zero network.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterator, Mapping, Sequence


def _load_corpus_module():
    """Import the corpus module by path, the way every sibling module does."""

    # Reuse an already-imported copy when there is one. Loading a second,
    # independent copy would give it its own DogfoodCorpusError class, so a
    # caller that imported the corpus normally could not catch what this
    # module raises: the failure would surface as a crash rather than as the
    # refusal it is.
    existing = sys.modules.get("orch_dork_dogfood_corpus")
    if existing is not None:
        return existing
    path = Path(__file__).resolve().with_name("orch_dork_dogfood_corpus.py")
    spec = importlib.util.spec_from_file_location("orch_dork_dogfood_corpus", path)
    if spec is None or spec.loader is None:  # pragma: no cover - install damage.
        raise ImportError("orch_dork_dogfood_corpus.py is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules["orch_dork_dogfood_corpus"] = module
    spec.loader.exec_module(module)
    return module


corpus = _load_corpus_module()

DogfoodCorpusError = corpus.DogfoodCorpusError

SPINE_SCHEMA = corpus.SPINE_SCHEMA
SPINE_VERSION = "dogfood-run-spine/1.0"
SEGMENT_SPINE_VERSION = "dogfood-run-spine/1.1"
SEGMENT_SCHEMA = "orch-dork/dogfood-session-segment/v1"
PROBE_SCHEMA = "orch-dork/dogfood-deliverable-probe/v1"

# How the root's own final turn ended. This is the failure mode under study, so
# it is recorded as a first-class fact rather than left to be inferred later.
#
#   reported -- the final turn produced a terminal agent report.
#   silent   -- the final turn closed without one; the root died mid-flight.
#   absent   -- no terminal turn record at all; it never got that far.
ROOT_COMPLETIONS = ("reported", "silent", "absent")

PLAN_TOOL = "validate_orchestration_plan"
WAVE_TOOL = "validate_orchestration_spawn_wave"
ADMISSION_TOOL = "evaluate_ticket_admission"
TRACE_QUALIFICATION_TOOL = "qualify_orchestration_trace"

# There are two plan schemas with two validators, and a run freezes its plan
# through exactly one of them: orch-dork/plan/v1 via validate_orchestration_plan,
# and orch-dork/logical-plan/v1 via validate_logical_worker_program. Knowing
# only one path would leave every run that used the other looking as though it
# had never frozen a plan, which is the difference between an honest
# undetermined class and a silently wrong one.
LOGICAL_PLAN_TOOL = "validate_logical_worker_program"
PLAN_TOOLS = (PLAN_TOOL, LOGICAL_PLAN_TOOL)

# The two schemas name their lane list differently. Everything else this
# module reads -- ids, deliverables, integration strategy, protected
# resources -- is shaped the same in both.
LANE_KEYS = ("lanes", "workers")

# A session record is append-only and can grow large. Bound every read so a
# damaged or hostile path fails closed instead of exhausting the host.
MAX_SESSION_BYTES = 64 * 1024 * 1024
MAX_LANES = 256
MAX_GATES = 64
MAX_CODE_MODE_INPUT_BYTES = 262_144
MAX_CODE_MODE_OUTPUT_BYTES = 262_144

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_RELATIVE_PATH = re.compile(r"\A[A-Za-z0-9._][A-Za-z0-9._/@+-]{0,1023}\Z")
_SHORT_COMMIT = re.compile(r"\A[0-9a-f]{7,64}\Z")
_CODE_MODE_SPAWN = re.compile(
    r"\btools\.multi_agent_v1__spawn_agent\s*\("
)


class DogfoodRecoveryError(DogfoodCorpusError):
    """Raised when a session record cannot support an honest derivation."""


# Compatibility name retained for existing callers; all canonicalization now
# comes from the corpus module's public content-addressing seam.
_digest = corpus.content_digest


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.match(value):
        raise DogfoodRecoveryError(f"{field} must be a bounded identifier")
    return value


def _payload(row: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = row.get("payload")
    return payload if isinstance(payload, Mapping) else {}


def _payload_type(row: Mapping[str, Any]) -> str | None:
    value = _payload(row).get("type")
    return value if isinstance(value, str) else None


def _bounded_path(value: Any) -> str | None:
    """Accept a declared workspace-relative resource path, or nothing.

    Absolute paths, parent escapes, and semantic: pseudo-resources are not
    files on disk, so they are dropped rather than recorded as if they were
    artifacts anyone could check for.
    """

    if not isinstance(value, str) or not value or not _RELATIVE_PATH.match(value):
        return None
    if ".." in Path(value).parts:
        return None
    return value


def _result_body(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Parse one MCP tool result body. No text from it is ever copied out."""

    result = payload.get("result")
    if not isinstance(result, Mapping):
        return None
    structured = result.get("structuredContent")
    if isinstance(structured, Mapping):
        return structured
    inner = result.get("Ok")
    container = inner if isinstance(inner, Mapping) else result
    content = container.get("content")
    if not isinstance(content, list):
        return None
    for block in content:
        if not isinstance(block, Mapping) or block.get("type") != "text":
            continue
        text = block.get("text")
        if not isinstance(text, str):
            continue
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, Mapping):
            return parsed
    return None


def iter_gate_calls(
    rows: Sequence[Mapping[str, Any]],
) -> Iterator[tuple[str, Mapping[str, Any]]]:
    """Yield parsed provider-free gate result bodies from session rows."""

    for row in rows:
        payload = _payload(row)
        if payload.get("type") == "mcp_tool_call_end":
            invocation = payload.get("invocation")
            if not isinstance(invocation, Mapping):
                continue
            tool = invocation.get("tool")
            result_owner = payload
        elif payload.get("type") == "item_completed":
            item = payload.get("item")
            if not isinstance(item, Mapping) or item.get("type") != "McpToolCall":
                continue
            tool = item.get("tool")
            result_owner = item
        else:
            continue
        if not isinstance(tool, str) or not _IDENTIFIER.match(tool):
            continue
        body = _result_body(result_owner)
        if body is None:
            continue
        yield tool, body


def read_session(path: str | Path) -> tuple[list[dict[str, Any]], str, int]:
    """Read a session record, returning its rows, file digest, and row count."""

    target = Path(path)
    try:
        if target.is_symlink() or not target.is_file():
            raise DogfoodRecoveryError("session record must be a regular file")
        raw = target.read_bytes()
    except DogfoodRecoveryError:
        raise
    except OSError as exc:
        raise DogfoodRecoveryError("session record is unreadable") from exc
    if len(raw) > MAX_SESSION_BYTES:
        raise DogfoodRecoveryError("session record is too large to derive from")
    digest = hashlib.sha256(raw).hexdigest()
    rows: list[dict[str, Any]] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            # A half-written trailing line is normal for an append-only record
            # whose writer died -- exactly the case this module exists for.
            # Skip it; the sealed file digest still pins what was read.
            continue
        if isinstance(value, Mapping):
            rows.append(dict(value))
    if not rows:
        raise DogfoodRecoveryError("session record holds no readable rows")
    return rows, digest, len(rows)


def read_session_segment(
    path: str | Path,
    *,
    line_start: int,
    line_end: int,
) -> tuple[list[dict[str, Any]], str, int, list[dict[str, Any]]]:
    """Read one immutable physical-line segment plus the session identity rows.

    A Codex task can host several separately admitted runs. Hashing the whole
    ever-growing JSONL file makes an earlier spine stale and mixes unrelated
    lanes. A segment pins the exact inclusive line range that belongs to one
    completed run; later appends do not change its identity.
    """

    if type(line_start) is not int or type(line_end) is not int:
        raise DogfoodRecoveryError("segment line bounds must be integers")
    if line_start < 1 or line_end < line_start:
        raise DogfoodRecoveryError("segment line bounds are invalid")
    target = Path(path)
    try:
        if target.is_symlink() or not target.is_file():
            raise DogfoodRecoveryError("session record must be a regular file")
        raw = target.read_bytes()
    except DogfoodRecoveryError:
        raise
    except OSError as exc:
        raise DogfoodRecoveryError("session record is unreadable") from exc
    if len(raw) > MAX_SESSION_BYTES:
        raise DogfoodRecoveryError("session record is too large to derive from")
    physical = raw.splitlines(keepends=True)
    if line_end > len(physical):
        raise DogfoodRecoveryError("segment line bounds exceed the session record")
    selected = b"".join(physical[line_start - 1 : line_end])
    rows: list[dict[str, Any]] = []
    for line in selected.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, Mapping):
            rows.append(dict(value))
    if not rows:
        raise DogfoodRecoveryError("session segment holds no readable rows")
    all_rows, _, _ = read_session(path)
    return rows, hashlib.sha256(selected).hexdigest(), len(rows), all_rows


def _session_identity(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    for row in rows:
        if row.get("type") != "session_meta":
            continue
        payload = _payload(row)
        git = payload.get("git") if isinstance(payload.get("git"), Mapping) else {}
        commit = git.get("commit_hash")
        session_id = payload.get("id")
        cwd = payload.get("cwd")
        return {
            "session_id": session_id if isinstance(session_id, str) and _IDENTIFIER.match(session_id) else None,
            "cwd": cwd if isinstance(cwd, str) and 0 < len(cwd) <= 1024 else None,
            "base_commit": commit if isinstance(commit, str) and _SHORT_COMMIT.match(commit) else None,
        }
    raise DogfoodRecoveryError("session record has no session_meta row")


def _root_completion(rows: Sequence[Mapping[str, Any]]) -> tuple[str, int]:
    """Classify how the root's final turn ended, and count its turns.

    A terminal turn that closes with no final agent report is the signature of
    the failure this module exists for: the run finished, the root did not.
    Only the presence of that report is recorded, never its text.
    """

    turns = 0
    reported: bool | None = None
    for row in rows:
        if _payload_type(row) != "task_complete":
            continue
        turns += 1
        reported = _payload(row).get("last_agent_message") is not None
    if reported is None:
        return "absent", turns
    return ("reported" if reported else "silent"), turns


def _code_mode_spawn_lanes(
    rows: Sequence[Mapping[str, Any]],
    *,
    root_thread_id: str | None = None,
) -> list[dict[str, str | None]]:
    """Recover structural spawn receipts from bounded code-mode envelopes.

    Program text is inspected only for the exact native spawn symbol and is
    never retained. Lane keys and worker IDs come from matching bounded JSON
    output; prompts, nicknames, and other output fields are discarded.
    """

    spawn_calls: set[str] = set()
    for row in rows:
        payload = _payload(row)
        program = payload.get("input")
        call_id = payload.get("call_id")
        if (
            payload.get("type") == "custom_tool_call"
            and payload.get("name") == "exec"
            and payload.get("status") == "completed"
            and isinstance(call_id, str)
            and _IDENTIFIER.match(call_id)
            and isinstance(program, str)
            and len(program.encode("utf-8")) <= MAX_CODE_MODE_INPUT_BYTES
            and _CODE_MODE_SPAWN.search(program)
        ):
            spawn_calls.add(call_id)

    by_lane: dict[str, str] = {}
    by_thread: dict[str, str | None] = {}

    def add(lane_id: Any, value: Any) -> None:
        if not isinstance(value, Mapping):
            return
        agent_id = value.get("agent_id")
        worker_id = value.get("worker_id")
        if (
            isinstance(agent_id, str)
            and isinstance(worker_id, str)
            and agent_id != worker_id
        ):
            raise DogfoodRecoveryError("contradictory code-mode spawn evidence")
        thread_id = worker_id if isinstance(worker_id, str) else agent_id
        if not isinstance(thread_id, str) or not _IDENTIFIER.match(thread_id):
            return
        if isinstance(worker_id, str):
            if value.get("status") != "created" or value.get("fresh") is not True:
                return
            parent_thread_id = value.get("parent_thread_id")
            if (
                root_thread_id is not None
                and parent_thread_id != root_thread_id
            ):
                raise DogfoodRecoveryError("contradictory code-mode spawn evidence")
        lane_candidates = [
            candidate
            for candidate in (
                lane_id,
                value.get("lane_id"),
                value.get("logical_worker_id"),
            )
            if isinstance(candidate, str) and _IDENTIFIER.match(candidate)
        ]
        if len(set(lane_candidates)) > 1:
            raise DogfoodRecoveryError("contradictory code-mode spawn evidence")
        lane = lane_candidates[0] if lane_candidates else None
        if lane is not None and lane in by_lane and by_lane[lane] != thread_id:
            raise DogfoodRecoveryError("contradictory code-mode spawn evidence")
        if thread_id in by_thread and by_thread[thread_id] != lane:
            raise DogfoodRecoveryError("contradictory code-mode spawn evidence")
        if lane is not None:
            by_lane[lane] = thread_id
        by_thread[thread_id] = lane

    for row in rows:
        payload = _payload(row)
        if (
            payload.get("type") != "custom_tool_call_output"
            or payload.get("call_id") not in spawn_calls
        ):
            continue
        output = payload.get("output")
        if not isinstance(output, list):
            continue
        for block in output[:64]:
            if not isinstance(block, Mapping) or block.get("type") not in {
                "input_text",
                "text",
            }:
                continue
            encoded = block.get("text")
            if (
                not isinstance(encoded, str)
                or len(encoded.encode("utf-8")) > MAX_CODE_MODE_OUTPUT_BYTES
            ):
                continue
            try:
                parsed = json.loads(encoded)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(parsed, Mapping) and (
                "agent_id" in parsed or "worker_id" in parsed
            ):
                add(None, parsed)
            elif isinstance(parsed, Mapping):
                for lane_id, value in list(parsed.items())[:MAX_LANES]:
                    add(lane_id, value)
            elif isinstance(parsed, list):
                for value in parsed[:MAX_LANES]:
                    add(None, value)

    return [
        {"agent_path": lane, "thread_id": thread_id}
        for thread_id, lane in sorted(
            by_thread.items(), key=lambda item: (item[1] or "", item[0])
        )
    ]


def _lane_threads(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    lanes: list[dict[str, Any]] = []
    seen_threads: set[str] = set()
    for row in rows:
        payload = _payload(row)
        if payload.get("type") == "sub_agent_activity" and payload.get("kind") == "started":
            agent_path = payload.get("agent_path")
            thread_id = payload.get("agent_thread_id")
            if not isinstance(agent_path, str) or not _IDENTIFIER.match(agent_path.lstrip("/") or "-"):
                continue
            normalized_thread = (
                thread_id
                if isinstance(thread_id, str) and _IDENTIFIER.match(thread_id)
                else None
            )
            lanes.append({"agent_path": agent_path, "thread_id": normalized_thread})
            if normalized_thread is not None:
                seen_threads.add(normalized_thread)
        elif payload.get("type") == "item_completed":
            item = payload.get("item")
            if (
                not isinstance(item, Mapping)
                or item.get("type") != "CollabAgentToolCall"
                or item.get("tool") != "spawn_agent"
                or item.get("status") != "completed"
            ):
                continue
            thread_ids = item.get("receiver_thread_ids")
            if not isinstance(thread_ids, list):
                continue
            for thread_id in thread_ids:
                if (
                    not isinstance(thread_id, str)
                    or not _IDENTIFIER.match(thread_id)
                    or thread_id in seen_threads
                ):
                    continue
                # The current native envelope exposes the durable thread ID,
                # but no agent_path. Preserve that absence instead of deriving
                # one from the private spawn prompt or nickname.
                lanes.append({"agent_path": None, "thread_id": thread_id})
                seen_threads.add(thread_id)
                if len(lanes) >= MAX_LANES:
                    break
        if len(lanes) >= MAX_LANES:
            break
    root_thread_id = next(
        (
            _payload(row).get("id")
            for row in rows
            if row.get("type") == "session_meta"
            and isinstance(_payload(row).get("id"), str)
        ),
        None,
    )
    for lane in _code_mode_spawn_lanes(rows, root_thread_id=root_thread_id):
        thread_id = lane.get("thread_id")
        if thread_id in seen_threads:
            continue
        lanes.append(dict(lane))
        if isinstance(thread_id, str):
            seen_threads.add(thread_id)
        if len(lanes) >= MAX_LANES:
            break
    return lanes


def _plan_facts(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Take the last frozen plan that passed, and only its structural fields."""

    facts: dict[str, Any] = {
        "plan_frozen": False,
        "plan_schema": None,
        "plan_sha256": None,
        "lane_ids": [],
        "planned_lane_count": None,
        "declared_deliverables": [],
        "declared_deliverable_count": 0,
        "redacted_deliverable_count": 0,
        "protected_resource_count": None,
        "integration_strategy": None,
        "integration_owner": None,
        "planned_worker_model": None,
        "planned_worker_effort": None,
        "planned_retries_allowed": None,
        "planned_fallbacks_allowed": None,
        "root_coordination_only_after_freeze": None,
    }
    for tool, body in iter_gate_calls(rows):
        if tool not in PLAN_TOOLS or body.get("status") != "PASS":
            continue
        plan = body.get("canonical_plan")
        if not isinstance(plan, Mapping):
            continue
        lanes = next(
            (plan[key] for key in LANE_KEYS if isinstance(plan.get(key), list)),
            None,
        )
        if lanes is None:
            continue
        lane_ids: list[str] = []
        deliverables: list[dict[str, str]] = []
        declared_deliverable_count = 0
        redacted_deliverable_count = 0
        for lane in lanes[:MAX_LANES]:
            if not isinstance(lane, Mapping):
                continue
            lane_id = lane.get("id")
            if not isinstance(lane_id, str) or not _IDENTIFIER.match(lane_id):
                continue
            lane_ids.append(lane_id)
            declared = lane.get("deliverables")
            if not isinstance(declared, list):
                continue
            for item in declared:
                if not isinstance(item, str):
                    continue
                declared_deliverable_count += 1
                path = _bounded_path(item)
                if path is not None:
                    deliverables.append({"lane_id": lane_id, "path": path})
                else:
                    redacted_deliverable_count += 1
        integration = plan.get("integration") if isinstance(plan.get("integration"), Mapping) else {}
        children = plan.get("children") if isinstance(plan.get("children"), Mapping) else {}
        root = plan.get("root") if isinstance(plan.get("root"), Mapping) else {}
        protected = plan.get("protected_resources")
        strategy = integration.get("strategy")
        integration_owner = integration.get("owner")
        worker_model = children.get("model")
        worker_effort = children.get("effort")
        retries_allowed = children.get("retries_allowed")
        fallbacks_allowed = children.get("fallbacks_allowed")
        root_coordination_only = root.get("coordination_only_after_freeze")
        plan_sha = body.get("plan_sha256")
        facts = {
            "plan_frozen": True,
            "plan_schema": plan.get("schema") if isinstance(plan.get("schema"), str) else None,
            "plan_sha256": plan_sha if isinstance(plan_sha, str) and _SHA256.match(plan_sha) else None,
            "lane_ids": lane_ids,
            "planned_lane_count": len(lane_ids),
            "declared_deliverables": deliverables,
            "declared_deliverable_count": declared_deliverable_count,
            "redacted_deliverable_count": redacted_deliverable_count,
            "protected_resource_count": len(protected) if isinstance(protected, list) else None,
            "integration_strategy": strategy if isinstance(strategy, str) and _IDENTIFIER.match(strategy) else None,
            "integration_owner": integration_owner
            if isinstance(integration_owner, str) and _IDENTIFIER.match(integration_owner)
            else None,
            "planned_worker_model": worker_model
            if isinstance(worker_model, str) and _IDENTIFIER.match(worker_model)
            else None,
            "planned_worker_effort": worker_effort
            if isinstance(worker_effort, str) and _IDENTIFIER.match(worker_effort)
            else None,
            "planned_retries_allowed": retries_allowed
            if type(retries_allowed) is int and retries_allowed >= 0
            else None,
            "planned_fallbacks_allowed": fallbacks_allowed
            if type(fallbacks_allowed) is int and fallbacks_allowed >= 0
            else None,
            "root_coordination_only_after_freeze": root_coordination_only
            if isinstance(root_coordination_only, bool)
            else None,
        }
    return facts


def _gate_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Per-gate call counts and terminal status.

    Call count carries as much signal as final status: a gate called twice,
    FAIL then PASS, means the run caught a real defect before spawning. That is
    a different run from one that passed everything first time, and collapsing
    the two would erase the evidence that the gates did any work.
    """

    order: list[str] = []
    summaries: dict[str, dict[str, Any]] = {}
    previous_by_stage: dict[tuple[str, str], str | None] = {}
    plan_frozen = False

    def status_of(body: Mapping[str, Any]) -> str | None:
        for field in ("status", "decision", "outcome", "disposition"):
            value = body.get(field)
            if isinstance(value, str) and _IDENTIFIER.match(value):
                return value
        return None

    def stage_of(tool: str, body: Mapping[str, Any]) -> str:
        operation = body.get("operation")
        if isinstance(operation, str) and _IDENTIFIER.match(operation):
            return operation
        if tool in PLAN_TOOLS:
            return "plan_validation"
        if tool in {
            "observe_current_orchestration_route",
            "evaluate_worker_lifecycle",
        }:
            return "pre_spawn" if plan_frozen else "pre_freeze"
        if tool == "validate_orchestration_admission":
            return "pre_freeze"
        if tool in {WAVE_TOOL, "run_logical_worker_waves"}:
            return "spawn_wave"
        return "default"

    def failed(status: str | None) -> bool:
        if status is None:
            return False
        upper = status.upper()
        return (
            upper.startswith(("FAIL", "REFUS", "BLOCK", "ERROR", "STOP"))
            or upper
            in {"RESTART_REQUIRED", "ROUTE_CHANGED", "ROUTING_UNKNOWN"}
        )

    for call_index, (tool, body) in enumerate(iter_gate_calls(rows), 1):
        if tool not in summaries:
            if len(order) >= MAX_GATES:
                continue
            order.append(tool)
            summaries[tool] = {
                "gate": tool,
                "calls": 0,
                "final_status": None,
                "retry_count": 0,
                "history": [],
            }
        status = status_of(body)
        stage = stage_of(tool, body)
        key = (tool, stage)
        retry = key in previous_by_stage and failed(previous_by_stage[key])
        summary = summaries[tool]
        summary["calls"] += 1
        summary["final_status"] = status
        summary["retry_count"] += int(retry)
        summary["history"].append(
            {
                "call": call_index,
                "stage": stage,
                "status": status,
                "retry": retry,
            }
        )
        previous_by_stage[key] = status
        if tool in PLAN_TOOLS and status == "PASS":
            plan_frozen = True
    gates = [summaries[tool] for tool in sorted(order)]
    return {
        "gates": gates,
        "gate_count": len(gates),
        "gate_call_count": sum(item["calls"] for item in gates),
        "gate_retry_count": sum(item["retry_count"] for item in gates),
    }


def _admission(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ticket_id: str | None = None
    decision: str | None = None
    for tool, body in iter_gate_calls(rows):
        if tool != ADMISSION_TOOL:
            continue
        candidate = body.get("ticket_id")
        if isinstance(candidate, str) and _IDENTIFIER.match(candidate):
            ticket_id = candidate
        value = body.get("decision")
        if isinstance(value, str) and _IDENTIFIER.match(value):
            decision = value
    return {"ticket_id": ticket_id, "admission_decision": decision}


def _wave(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    status: str | None = None
    for tool, body in iter_gate_calls(rows):
        if tool != WAVE_TOOL:
            continue
        value = body.get("status")
        status = value if isinstance(value, str) and _IDENTIFIER.match(value) else None
        found = body.get("members")
        members = []
        if isinstance(found, list):
            for member in found[:MAX_LANES]:
                if not isinstance(member, Mapping):
                    continue
                lane_id = member.get("lane_id")
                worker_id = member.get("worker_id")
                if isinstance(lane_id, str) and _IDENTIFIER.match(lane_id):
                    members.append(
                        {
                            "lane_id": lane_id,
                            "worker_id": worker_id if isinstance(worker_id, str) else None,
                        }
                    )
    return {"wave_status": status, "wave_members": members}


def _trace_qualification(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Keep the final submitted trace result separate from spawn-wave state."""

    result: dict[str, Any] = {
        "trace_qualification_status": None,
        "trace_qualified": None,
        "trace_claim_permitted": None,
        "trace_qualification_issues": [],
    }
    for tool, body in iter_gate_calls(rows):
        if tool != TRACE_QUALIFICATION_TOOL:
            continue
        status = body.get("status")
        qualified = body.get("qualified")
        claim_permitted = body.get("claim_permitted")
        raw_issues = body.get("issues")
        issues = []
        if isinstance(raw_issues, list):
            issues = [
                item
                for item in raw_issues[:MAX_GATES]
                if isinstance(item, str) and 0 < len(item) <= 256 and "\n" not in item
            ]
        result = {
            "trace_qualification_status": status
            if isinstance(status, str) and _IDENTIFIER.match(status)
            else None,
            "trace_qualified": qualified if isinstance(qualified, bool) else None,
            "trace_claim_permitted": claim_permitted
            if isinstance(claim_permitted, bool)
            else None,
            "trace_qualification_issues": issues,
        }
    return result


def _spawn_count(rows: Sequence[Mapping[str, Any]]) -> int:
    anonymous = 0
    thread_ids: set[str] = set()
    for row in rows:
        payload = _payload(row)
        if payload.get("type") == "function_call" and payload.get("name") == "spawn_agent":
            anonymous += 1
        elif payload.get("type") == "item_completed":
            item = payload.get("item")
            if (
                isinstance(item, Mapping)
                and item.get("type") == "CollabAgentToolCall"
                and item.get("tool") == "spawn_agent"
                and item.get("status") == "completed"
                and isinstance(item.get("receiver_thread_ids"), list)
                and item["receiver_thread_ids"]
            ):
                thread_ids.update(
                    value
                    for value in item["receiver_thread_ids"]
                    if isinstance(value, str) and _IDENTIFIER.match(value)
                )
    thread_ids.update(
        lane["thread_id"]
        for lane in _code_mode_spawn_lanes(rows)
        if isinstance(lane.get("thread_id"), str)
    )
    return anonymous + len(thread_ids)


def _reconcile_spawn_evidence(
    rows: Sequence[Mapping[str, Any]], facts: dict[str, Any]
) -> None:
    """Make passing-wave disagreement visible instead of deriving zeros."""

    members = facts.get("wave_members")
    members = members if isinstance(members, list) else []
    if facts.get("wave_status") != "PASS" or not members:
        facts["spawn_evidence_status"] = "unverified"
        facts["spawn_evidence_issues"] = []
        return
    code_lanes = _code_mode_spawn_lanes(rows)
    if code_lanes:
        observed = {
            (lane.get("agent_path"), lane.get("thread_id")) for lane in code_lanes
        }
        wave = {
            (member.get("lane_id"), member.get("worker_id"))
            for member in members
            if isinstance(member, Mapping)
        }
        if observed != wave:
            raise DogfoodRecoveryError("contradictory spawn evidence")
        facts["spawn_evidence_status"] = "consistent"
        facts["spawn_evidence_issues"] = []
        return
    if facts.get("spawn_count") == 0 or facts.get("lane_count") == 0:
        facts["spawn_evidence_status"] = "contradictory"
        facts["spawn_evidence_issues"] = [
            "spawn:passing_wave_without_direct_spawn_or_lane_evidence"
        ]
        return
    facts["spawn_evidence_status"] = "consistent-unbound"
    facts["spawn_evidence_issues"] = []


def _classify(facts: Mapping[str, Any]) -> tuple[str | None, list[str], list[str]]:
    """Settle the run's class from mechanical evidence, or decline to.

    actual_class gates plan_verdict applicability in the corpus, so a wrong
    value here corrupts a rule rather than merely adding noise. It is derived
    only from evidence that admits a single reading, and is left null with a
    stated reason otherwise.
    """

    undetermined: list[str] = []
    spawns = int(facts.get("spawn_count") or 0)
    lanes = facts.get("lane_threads") or []
    members = facts.get("wave_members") or []
    decision = facts.get("admission_decision")

    if facts.get("spawn_evidence_status") == "contradictory":
        undetermined.extend(facts.get("spawn_evidence_issues") or [])
        return None, [], sorted(set(undetermined))

    # What settles "orchestrated" is that decomposition actually executed:
    # a plan was frozen, workers were spawned, and lanes were observed to
    # start. The wave gate is deliberately not part of this test. It judges
    # custody and admission conformance, which is a different question from
    # what the run was, and a run whose conformance gate failed while eight
    # lanes demonstrably ran is still an orchestrated run. Its status is kept
    # as a separate recorded fact so nothing is hidden by that choice.
    if spawns > 0 and facts.get("plan_frozen") and lanes:
        basis = [
            "plan:frozen_pass",
            f"spawn:agents:{spawns}",
            f"lane:started:{len(lanes)}",
        ]
        if facts.get("wave_status") is not None:
            basis.append(f"wave:{str(facts['wave_status']).lower()}:{len(members)}")
        return "orchestrated", basis, undetermined

    if spawns == 0 and decision == "REFUSED":
        return "refused", ["admission:refused", "spawn:none"], undetermined

    if spawns == 0 and decision == "ATOMIC_ADMITTED":
        return "atomic", ["admission:atomic_admitted", "spawn:none"], undetermined

    if spawns > 0:
        if not facts.get("plan_frozen"):
            undetermined.append("class:spawned_without_frozen_plan")
        if not lanes:
            undetermined.append("class:spawned_without_observed_lane_start")
    elif decision is None:
        undetermined.append("class:no_spawn_and_no_admission_decision")
    else:
        undetermined.append(f"class:no_spawn_under_decision:{decision}")
    return None, [], sorted(set(undetermined))


def derive_run_spine(
    session_path: str | Path,
    *,
    run_key: str,
    derived_at: str,
    derived_by: str,
    host: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    expected_ticket_id: str | None = None,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Derive the mechanical spine of one run from its session record alone.

    Deterministic: the same session bytes always yield the same facts and the
    same spine_sha256. Nothing here reads the corpus, an aggregate summary, or
    any live agent, so a spine can be derived at any later time by anyone, with
    no surviving root.
    """

    selectors = (line_start, line_end, expected_ticket_id, expected_plan_sha256)
    bounded = any(value is not None for value in selectors)
    if bounded and any(value is None for value in selectors):
        raise DogfoodRecoveryError(
            "bounded recovery requires line_start, line_end, expected_ticket_id, and expected_plan_sha256"
        )
    if bounded:
        rows, session_sha256, line_count, identity_rows = read_session_segment(
            session_path,
            line_start=int(line_start),
            line_end=int(line_end),
        )
        identity = _session_identity(identity_rows)
    else:
        rows, session_sha256, line_count = read_session(session_path)
        identity = _session_identity(rows)
    completion, turn_count = _root_completion(rows)
    lane_threads = _lane_threads(rows)
    worker_attempt_count = len(lane_threads)

    facts: dict[str, Any] = {
        "spine_version": SEGMENT_SPINE_VERSION if bounded else SPINE_VERSION,
        "root_completion": completion,
        "turn_count": turn_count,
        "spawn_count": _spawn_count(rows),
        "lane_count": worker_attempt_count,
        "worker_attempt_count": worker_attempt_count,
        "lane_threads": lane_threads,
        "base_commit": identity["base_commit"],
        "cwd": identity["cwd"],
    }
    facts.update(_plan_facts(rows))
    planned_lane_count = facts.get("planned_lane_count")
    if type(planned_lane_count) is int and planned_lane_count > 0:
        facts["lane_count"] = planned_lane_count
        facts["extra_worker_attempt_count"] = max(
            0, worker_attempt_count - planned_lane_count
        )
    else:
        facts["extra_worker_attempt_count"] = None
    facts.update(_gate_summary(rows))
    facts.update(_admission(rows))
    facts.update(_wave(rows))
    facts.update(_trace_qualification(rows))
    _reconcile_spawn_evidence(rows, facts)

    if bounded:
        if facts.get("ticket_id") != expected_ticket_id:
            raise DogfoodRecoveryError("segment ticket identity does not match the selector")
        if facts.get("plan_sha256") != expected_plan_sha256:
            raise DogfoodRecoveryError("segment plan identity does not match the selector")

    derived_class, basis, undetermined = _classify(facts)
    facts["derived_class"] = derived_class
    facts["class_basis"] = basis
    facts["undetermined"] = undetermined

    source = {
        "session_sha256": session_sha256,
        "session_id": identity["session_id"],
        "line_count": line_count,
    }
    if bounded:
        source["selection"] = {
            "schema": SEGMENT_SCHEMA,
            "line_start": line_start,
            "line_end": line_end,
            "expected_ticket_id": expected_ticket_id,
            "expected_plan_sha256": expected_plan_sha256,
        }
    spine: dict[str, Any] = {
        "schema": SPINE_SCHEMA,
        "kind": "run_spine",
        "run_key": _identifier(run_key, "run_key"),
        "derived_at": corpus.validate_timestamp(derived_at, "derived_at"),
        "derived_by": _identifier(derived_by, "derived_by"),
        "host": _identifier(host, "host") if host is not None else None,
        "source": source,
        "facts": facts,
        # Covers the re-derivable evidence only, so any later reader can re-run
        # the derivation against the same session bytes and prove the spine was
        # not hand-edited. A timestamped probe stays outside it deliberately.
        "spine_sha256": _digest({"source": source, "facts": facts}),
    }
    corpus.reject_secret_fields(spine, "spine")
    return spine


def probe_deliverables(
    spine: Mapping[str, Any], workspace_root: str | Path, *, observed_at: str
) -> dict[str, Any]:
    """Observe whether the plan's declared deliverables exist right now.

    Held outside spine_sha256 on purpose. A spine is a fact about immutable
    session bytes; this is a fact about a mutable filesystem at one instant, and
    sealing them together would make an honest re-derivation look tampered
    with. A present file is not a shipped outcome, and nothing here says it is.
    """

    if not isinstance(spine, Mapping) or spine.get("schema") != SPINE_SCHEMA:
        raise DogfoodRecoveryError(f"spine schema must be {SPINE_SCHEMA}")
    root = Path(workspace_root)
    facts = spine.get("facts") if isinstance(spine.get("facts"), Mapping) else {}
    declared = facts.get("declared_deliverables")
    declared = declared if isinstance(declared, list) else []
    items: list[dict[str, Any]] = []
    for entry in declared[:MAX_LANES]:
        if not isinstance(entry, Mapping):
            continue
        path = _bounded_path(entry.get("path"))
        if path is None:
            continue
        target = root / path
        try:
            if target.is_symlink() or not target.is_file():
                status, size = "absent", None
            else:
                size = target.stat().st_size
                status = "present" if size > 0 else "empty"
        except OSError:
            status, size = "unreadable", None
        items.append(
            {
                "lane_id": entry.get("lane_id"),
                "path": path,
                "status": status,
                "size_bytes": size,
            }
        )
    return {
        "schema": PROBE_SCHEMA,
        "observed_at": corpus.validate_timestamp(observed_at, "observed_at"),
        "declared_count": len(items),
        "present_count": sum(1 for item in items if item["status"] == "present"),
        "items": items,
    }


def attach_probe(spine: Mapping[str, Any], probe: Mapping[str, Any]) -> dict[str, Any]:
    """Attach a deliverable probe without disturbing spine_sha256."""

    if not isinstance(spine, Mapping) or spine.get("schema") != SPINE_SCHEMA:
        raise DogfoodRecoveryError(f"spine schema must be {SPINE_SCHEMA}")
    if not isinstance(probe, Mapping) or probe.get("schema") != PROBE_SCHEMA:
        raise DogfoodRecoveryError(f"probe schema must be {PROBE_SCHEMA}")
    result = dict(spine)
    result["probe"] = dict(probe)
    corpus.reject_secret_fields(result, "spine")
    return result


def append_spine(path: str | Path, spine: Mapping[str, Any]) -> dict[str, Any]:
    """Append one spine to the corpus chain. A run may have exactly one.

    The verdict-field refusal is the structural guarantee that this recovery
    path can never become an automatic labeler: a spine that grew a verdict
    would be a fabricated label, so it fails closed instead of being written.
    """

    if not isinstance(spine, Mapping) or spine.get("schema") != SPINE_SCHEMA:
        raise DogfoodRecoveryError(f"spine schema must be {SPINE_SCHEMA}")
    if spine.get("kind") != "run_spine":
        raise DogfoodRecoveryError("spine kind must be run_spine")
    if spine.get("host") is None:
        raise DogfoodRecoveryError("host is required when appending a run spine")
    for field in ("classification_verdict", "plan_verdict", "outcome", "blind", "analysis_digest_seen"):
        if field in spine:
            raise DogfoodRecoveryError(f"a spine must not carry {field}; it records facts, not judgement")
    run_key = _identifier(spine.get("run_key"), "run_key")
    entries = corpus.read_corpus(path)
    if any(entry.get("kind") == "run_spine" and entry.get("run_key") == run_key for entry in entries):
        raise DogfoodRecoveryError(f"run_key {run_key} already has a spine")
    return corpus.append_entry(path, spine)


def append_spine_correction(
    path: str | Path,
    spine: Mapping[str, Any],
    *,
    expected_spine_sha256: str,
    corrected_at: str,
    corrected_by: str,
    correction_reason: str,
) -> dict[str, Any]:
    """Append one exact additive correction to the currently effective spine."""

    if not isinstance(spine, Mapping) or spine.get("schema") != SPINE_SCHEMA:
        raise DogfoodRecoveryError(f"spine schema must be {SPINE_SCHEMA}")
    if spine.get("kind") != "run_spine":
        raise DogfoodRecoveryError("spine kind must be run_spine")
    if spine.get("host") is None:
        raise DogfoodRecoveryError("host is required when correcting a run spine")
    for field in (
        "classification_verdict",
        "plan_verdict",
        "outcome",
        "blind",
        "analysis_digest_seen",
    ):
        if field in spine:
            raise DogfoodRecoveryError(
                f"a spine must not carry {field}; it records facts, not judgement"
            )
    if not isinstance(expected_spine_sha256, str) or not _SHA256.match(
        expected_spine_sha256
    ):
        raise DogfoodRecoveryError("expected_spine_sha256 must be a sha256 digest")
    if not isinstance(correction_reason, str) or not correction_reason.strip():
        raise DogfoodRecoveryError("correction_reason is required")
    if len(correction_reason) > corpus.MAX_NOTE_CHARS:
        raise DogfoodRecoveryError(
            f"correction_reason must be at most {corpus.MAX_NOTE_CHARS} characters"
        )
    if any(
        field in spine
        for field in ("sequence", "prev_sha256", "corpus_version", "entry_sha256")
    ):
        raise DogfoodRecoveryError("replacement spine must be an unsealed spine body")

    run_key = _identifier(spine.get("run_key"), "run_key")
    entries = corpus.read_corpus(path)
    state = next(
        (
            item
            for item in corpus.resolve_effective_spines(entries)
            if item["run_key"] == run_key
        ),
        None,
    )
    if state is None:
        raise DogfoodRecoveryError(f"run_key {run_key} has no spine to correct")
    current_spine = state["spine"]
    current_entry = state["entry"]
    if current_spine.get("spine_sha256") != expected_spine_sha256:
        raise DogfoodRecoveryError("expected spine digest does not match current evidence")
    if current_spine.get("host") != spine.get("host"):
        raise DogfoodRecoveryError("replacement spine host does not match current evidence")
    source = spine.get("source")
    facts = spine.get("facts")
    if not isinstance(source, Mapping) or not isinstance(facts, Mapping):
        raise DogfoodRecoveryError("replacement spine evidence body is invalid")
    if spine.get("spine_sha256") != _digest(
        {"source": dict(source), "facts": dict(facts)}
    ):
        raise DogfoodRecoveryError("replacement spine digest is invalid")
    if spine.get("spine_sha256") == expected_spine_sha256:
        raise DogfoodRecoveryError("replacement spine does not change the evidence")

    correction = {
        "schema": corpus.SPINE_CORRECTION_SCHEMA,
        "kind": "run_spine_correction",
        "run_key": run_key,
        "corrected_at": corpus.validate_timestamp(corrected_at, "corrected_at"),
        "corrected_by": _identifier(corrected_by, "corrected_by"),
        "host": spine.get("host"),
        "correction_reason": correction_reason,
        "corrects": {
            "sequence": current_entry.get("sequence"),
            "entry_sha256": current_entry.get("entry_sha256"),
            "spine_sha256": current_spine.get("spine_sha256"),
        },
        "replacement_spine": dict(spine),
    }
    corpus.reject_secret_fields(correction, "spine_correction")
    return corpus.append_entry(path, correction)


def verify_spine(spine: Mapping[str, Any], session_path: str | Path) -> dict[str, Any]:
    """Re-derive a stored spine from its session record and compare.

    This is what makes a spine evidence rather than an assertion: anyone can
    replay it against the same bytes and see whether it still holds.
    """

    if not isinstance(spine, Mapping) or spine.get("schema") != SPINE_SCHEMA:
        raise DogfoodRecoveryError(f"spine schema must be {SPINE_SCHEMA}")
    source = spine.get("source") if isinstance(spine.get("source"), Mapping) else {}
    stored_facts = spine.get("facts") if isinstance(spine.get("facts"), Mapping) else {}
    selection = source.get("selection") if isinstance(source.get("selection"), Mapping) else {}
    replay = derive_run_spine(
        session_path,
        run_key=str(spine.get("run_key")),
        derived_at=str(spine.get("derived_at")),
        derived_by=str(spine.get("derived_by")),
        host=spine.get("host") if isinstance(spine.get("host"), str) else None,
        line_start=selection.get("line_start"),
        line_end=selection.get("line_end"),
        expected_ticket_id=selection.get("expected_ticket_id"),
        expected_plan_sha256=selection.get("expected_plan_sha256"),
    )
    mismatches: list[str] = []
    # Self-consistency first: does the spine's own digest still cover its own
    # body? This catches a hand-edited spine directly, without needing the
    # session record, so tampering is visible even to a reader who only has
    # the corpus line in front of them.
    if spine.get("spine_sha256") != _digest({"source": dict(source), "facts": dict(stored_facts)}):
        mismatches.append("spine:self_digest")
    if source.get("session_sha256") != replay["source"]["session_sha256"]:
        mismatches.append("source:session_sha256")
    if spine.get("spine_sha256") != replay["spine_sha256"]:
        mismatches.append("spine:spine_sha256")
    for key in sorted(set(stored_facts) | set(replay["facts"])):
        if stored_facts.get(key) != replay["facts"].get(key):
            mismatches.append(f"facts:{key}")
    return {
        "schema": SPINE_SCHEMA,
        "verified": not mismatches,
        "mismatches": sorted(set(mismatches)),
        "session_sha256": replay["source"]["session_sha256"],
        "spine_sha256": replay["spine_sha256"],
    }


def _read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Derive a dogfood run spine from a session record")
    parser.add_argument("session", help="Path to the run's session record JSONL")
    parser.add_argument("--run-key", help="Corpus run_key this spine belongs to")
    parser.add_argument("--derived-by", help="Who derived the spine")
    parser.add_argument("--derived-at", help="ISO 8601 UTC timestamp ending in Z")
    parser.add_argument("--host", default=None)
    parser.add_argument("--line-start", type=int, default=None)
    parser.add_argument("--line-end", type=int, default=None)
    parser.add_argument("--expected-ticket-id", default=None)
    parser.add_argument("--expected-plan-sha256", default=None)
    parser.add_argument("--probe-root", default=None, help="Workspace root to probe declared deliverables in")
    parser.add_argument("--append", default=None, help="Corpus path to append the sealed spine to")
    parser.add_argument(
        "--corrects-spine-sha256",
        default=None,
        help="Exact currently effective spine digest to supersede additively",
    )
    parser.add_argument(
        "--correction-reason",
        default=None,
        help="Required bounded reason when appending a spine correction",
    )
    parser.add_argument("--verify", default=None, help="Stored spine JSON to re-derive and compare")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.verify:
            result: Mapping[str, Any] = verify_spine(_read_json(args.verify), args.session)
        else:
            missing = [
                name
                for name, value in (
                    ("--run-key", args.run_key),
                    ("--derived-by", args.derived_by),
                    ("--derived-at", args.derived_at),
                )
                if not value
            ]
            if missing:
                raise DogfoodRecoveryError("missing required options: " + ", ".join(missing))
            spine = derive_run_spine(
                args.session,
                run_key=args.run_key,
                derived_at=args.derived_at,
                derived_by=args.derived_by,
                host=args.host,
                line_start=args.line_start,
                line_end=args.line_end,
                expected_ticket_id=args.expected_ticket_id,
                expected_plan_sha256=args.expected_plan_sha256,
            )
            if args.probe_root:
                spine = attach_probe(
                    spine, probe_deliverables(spine, args.probe_root, observed_at=args.derived_at)
                )
            if args.append and not args.host:
                raise DogfoodRecoveryError(
                    "--host is required when appending a run spine"
                )
            correction_requested = any(
                value is not None
                for value in (
                    args.corrects_spine_sha256,
                    args.correction_reason,
                )
            )
            if correction_requested and (
                not args.append
                or not args.corrects_spine_sha256
                or not args.correction_reason
            ):
                raise DogfoodRecoveryError(
                    "a spine correction requires --append, "
                    "--corrects-spine-sha256, and --correction-reason"
                )
            if correction_requested:
                result = append_spine_correction(
                    args.append,
                    spine,
                    expected_spine_sha256=args.corrects_spine_sha256,
                    corrected_at=args.derived_at,
                    corrected_by=args.derived_by,
                    correction_reason=args.correction_reason,
                )
            else:
                result = append_spine(args.append, spine) if args.append else spine
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
