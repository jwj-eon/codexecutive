#!/usr/bin/env python3
"""Issues 131-132: let any model serve as a blind dogfood labeler.

This module is a provider-free boundary.  It exports a sealed packet from
already-recorded public evidence, derives a packet-specific structured request,
and later imports a provenance-typed answer; it never calls a model, reads
credentials, or treats a model identity or schema-conforming output as proof of
quality.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_dogfood_corpus as corpus  # noqa: E402
import orch_dork_dogfood_recovery as recovery  # noqa: E402


PACKET_SCHEMA = "orch-dork/dogfood-blind-labeler-packet/v1"
RUBRIC_SCHEMA = "orch-dork/dogfood-blind-labeler-rubric/v1"
MODEL_ANSWER_SCHEMA = "orch-dork/dogfood-model-answer/v1"
MODEL_REQUEST_SCHEMA = "orch-dork/dogfood-model-request/v1"
MODEL_VERDICT_SCHEMA = "orch-dork/dogfood-model-verdict/v1"
MODEL_CHAIN_VERSION = "dogfood-model-verdict-chain/1.0"
COMBINED_SUMMARY_SCHEMA = "orch-dork/dogfood-combined-summary/v1"

MAX_TEXT_CHARS = 2000
MAX_EVIDENCE_ITEMS = 2048
MAX_JSON_FILE_BYTES = 1024 * 1024
MAX_STRUCTURED_OUTPUT_ENUM_VALUES = 900

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(
    r"(?:\A|[\s'\"])(?:/(?:home|Users|private|tmp|var|etc)/|[A-Za-z]:[\\/])"
)
_SENSITIVE_KEY = re.compile(
    r"(?:credential|password|secret|api[_-]?key|private[_-]?key|cookie|"
    r"raw[_-]?(?:prompt|message|session|trace)|chain[_-]?of[_-]?thought|"
    r"reasoning[_-]?(?:content|body))",
    re.IGNORECASE,
)
_CREDENTIAL_VALUE = re.compile(
    r"(?:\b(?:api[_-]?key|access[_-]?token|password|passwd|client[_-]?secret)"
    r"\s*[:=]\s*\S+|\bauthorization\s*:\s*(?:bearer|basic)\s+\S+|"
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{16,})",
    re.IGNORECASE,
)

_PACKET_FIELDS = frozenset(
    {
        "schema",
        "binding",
        "rubric",
        "rubric_sha256",
        "evidence",
        "context_policy",
        "packet_sha256",
    }
)
_ANSWER_FIELDS = frozenset(
    {
        "schema",
        "packet_sha256",
        "rubric_sha256",
        "decision",
        "actual_class",
        "classification_verdict",
        "plan_verdict",
        "outcome",
        "evidence_refs",
        "justifications",
        "abstention_reason",
    }
)
_VERDICT_FIELDS = (
    "actual_class",
    "classification_verdict",
    "plan_verdict",
    "outcome",
)
_PROVENANCE_FIELDS = frozenset(
    {
        "source_kind",
        "model_id",
        "model_version",
        "transport",
        "invocation_id",
        "inference_config",
        "prompt_template_sha256",
        "fresh_context",
        "packet_only",
        "peer_verdicts_seen",
        "analysis_digest_seen",
    }
)
_MODEL_ENTRY_FIELDS = frozenset(
    {
        "schema",
        "kind",
        "run_key",
        "recorded_at",
        "host",
        "packet_sha256",
        "rubric_sha256",
        "spine_sha256",
        "ticket_key",
        "observation",
        "answer",
        "answer_sha256",
        "provenance",
        "provenance_sha256",
        "blind",
    }
)
_MODEL_CORRECTION_FIELDS = _MODEL_ENTRY_FIELDS | frozenset(
    {"corrects", "correction_reason"}
)
_MODEL_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "packet_sha256",
        "rubric_sha256",
        "instruction_template_sha256",
        "instruction",
        "answer_schema",
        "answer_schema_sha256",
        "context_policy",
        "request_sha256",
    }
)
_CHAIN_FIELDS = frozenset(
    {"sequence", "prev_sha256", "corpus_version", "entry_sha256"}
)
_ABSTENTION_REASONS = frozenset(
    {"insufficient_evidence", "ambiguous_rubric", "cannot_determine", "other"}
)

_MODEL_PROMPT_TEMPLATE = """You are a blind dogfood run labeler. Use only the sealed packet below. Do not call tools, inspect files, search, or use outside knowledge. You have not seen aggregate analysis or peer verdicts.

Return exactly one JSON object matching the supplied output schema. Provide no Markdown fence and no text before or after the object. Copy packet_sha256 and rubric_sha256 exactly from the packet. Cite packet-local evidence IDs for every verdict field. If the packet cannot honestly support every required verdict field, abstain. Never guess, repair, retry, or provide private reasoning.

SEALED_PACKET_JSON:
{{PACKET_JSON}}
"""


RUBRIC: dict[str, Any] = {
    "schema": RUBRIC_SCHEMA,
    "questions": {
        "actual_class": {
            "question": "What was this run actually?",
            "values": list(corpus.CLASSES),
        },
        "classification_verdict": {
            "question": "Was that the right orchestration decision?",
            "values": list(corpus.CLASSIFICATION_VERDICTS),
        },
        "plan_verdict": {
            "question": "If a multi-lane plan ran, was that plan good?",
            "values": list(corpus.PLAN_VERDICTS),
            "applicability": (
                "Use not_applicable only for atomic or refused runs; an "
                "orchestrated run must use another value."
            ),
        },
        "outcome": {
            "question": "How did the real run end up?",
            "values": list(corpus.OUTCOMES),
        },
    },
    "answer_rules": {
        "evidence_refs_required": True,
        "unclear_is_allowed": True,
        "abstention_is_allowed": True,
        "private_chain_of_thought_forbidden": True,
        "bounded_justification_only": True,
    },
}


class BlindLabelerError(corpus.DogfoodCorpusError):
    """Raised when packet or verdict evidence cannot be accepted honestly."""


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise BlindLabelerError(f"{field} must be a bounded identifier")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise BlindLabelerError(f"{field} must be a sha256 digest")
    return value


def _public_text(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > MAX_TEXT_CHARS
        or "\x00" in value
    ):
        raise BlindLabelerError(f"{field} must be bounded public text")
    if _ABSOLUTE_PATH.search(value):
        raise BlindLabelerError(f"{field} contains an absolute host path")
    if _CREDENTIAL_VALUE.search(value):
        raise BlindLabelerError(f"{field} contains credential-shaped material")
    return value


def _resource(value: Any, field: str) -> str:
    value = _public_text(value, field)
    if value.startswith(("/", "~")) or ".." in Path(value).parts:
        raise BlindLabelerError(f"{field} must be workspace-relative or semantic")
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > recovery.MAX_LANES:
        raise BlindLabelerError(f"{field} must be a bounded array")
    return [
        _public_text(item, f"{field}[{index}]")
        for index, item in enumerate(value)
    ]


def _evidence_ref_schema(
    *, min_items: int | None = None, max_items: int = 32
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "array",
        "items": {"$ref": "#/$defs/evidence_id"},
        "maxItems": max_items,
    }
    if min_items is not None:
        schema["minItems"] = min_items
    return schema


def _answer_branch_schema(
    packet: Mapping[str, Any], *, decision: str
) -> dict[str, Any]:
    common = {
        "schema": {"enum": [MODEL_ANSWER_SCHEMA]},
        "packet_sha256": {"enum": [packet["packet_sha256"]]},
        "rubric_sha256": {"enum": [packet["rubric_sha256"]]},
        "decision": {"enum": [decision]},
    }
    if decision == "verdict":
        derived = packet["evidence"].get("execution.derived_class")
        verdict_fields = {
            "actual_class": {
                "enum": [derived] if derived in corpus.CLASSES else list(corpus.CLASSES)
            },
            "classification_verdict": {
                "enum": list(corpus.CLASSIFICATION_VERDICTS)
            },
            "plan_verdict": {"enum": list(corpus.PLAN_VERDICTS)},
            "outcome": {"enum": list(corpus.OUTCOMES)},
        }
        refs = {
            field: _evidence_ref_schema(min_items=1)
            for field in _VERDICT_FIELDS
        }
        justifications = {
            field: {
                "type": ["string", "null"],
                "minLength": 1,
                "maxLength": MAX_TEXT_CHARS,
            }
            for field in _VERDICT_FIELDS
        }
        abstention_reason = {"type": "null"}
    else:
        verdict_fields = {field: {"type": "null"} for field in _VERDICT_FIELDS}
        refs = {
            field: _evidence_ref_schema(max_items=0)
            for field in _VERDICT_FIELDS
        }
        justifications = {field: {"type": "null"} for field in _VERDICT_FIELDS}
        abstention_reason = {"enum": sorted(_ABSTENTION_REASONS)}

    properties = {
        **common,
        **verdict_fields,
        "evidence_refs": {
            "type": "object",
            "additionalProperties": False,
            "required": list(_VERDICT_FIELDS),
            "properties": refs,
        },
        "justifications": {
            "type": "object",
            "additionalProperties": False,
            "required": list(_VERDICT_FIELDS),
            "properties": justifications,
        },
        "abstention_reason": abstention_reason,
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(properties),
        "properties": properties,
    }


def _resource_list(value: Any, field: str) -> tuple[list[str], int]:
    if not isinstance(value, list) or len(value) > recovery.MAX_LANES:
        raise BlindLabelerError(f"{field} must be a bounded array")
    accepted: list[str] = []
    redacted = 0
    for index, item in enumerate(value):
        try:
            accepted.append(_resource(item, f"{field}[{index}]"))
        except BlindLabelerError:
            redacted += 1
    return accepted, redacted


def _effective_spine_state(
    entries: Sequence[Mapping[str, Any]], run_key: str
) -> Mapping[str, Any]:
    states = [
        state
        for state in corpus.resolve_effective_spines(entries)
        if state["run_key"] == run_key
    ]
    if len(states) != 1:
        raise BlindLabelerError("packet:run_unknown")
    return states[0]


def _bound_rows(
    spine: Mapping[str, Any], session_path: str | Path
) -> tuple[list[dict[str, Any]], Mapping[str, Any]]:
    """Replay exact source identity while tolerating additive extractor fields.

    A spine sealed by an older extractor can legitimately omit facts added in
    a later release.  The packet still requires the stored spine's own seal,
    exact source bytes/segment, ticket, and frozen plan identity.  Current
    replay facts become packet evidence and their own digest is exposed beside
    (never substituted for) the effective stored spine digest.
    """

    source = spine.get("source") if isinstance(spine.get("source"), Mapping) else {}
    stored_facts = (
        spine.get("facts") if isinstance(spine.get("facts"), Mapping) else {}
    )
    if spine.get("spine_sha256") != corpus.content_digest(
        {"source": dict(source), "facts": dict(stored_facts)}
    ):
        raise BlindLabelerError("packet:spine_replay_failed:self_digest")
    selection = (
        source.get("selection")
        if isinstance(source.get("selection"), Mapping)
        else None
    )
    replay = recovery.derive_run_spine(
        session_path,
        run_key=str(spine.get("run_key")),
        derived_at=str(spine.get("derived_at")),
        derived_by=str(spine.get("derived_by")),
        host=spine.get("host") if isinstance(spine.get("host"), str) else None,
        line_start=selection.get("line_start") if selection else None,
        line_end=selection.get("line_end") if selection else None,
        expected_ticket_id=selection.get("expected_ticket_id") if selection else None,
        expected_plan_sha256=selection.get("expected_plan_sha256")
        if selection
        else None,
    )
    replay_source = replay.get("source")
    replay_facts = replay.get("facts")
    if not isinstance(replay_source, Mapping) or not isinstance(
        replay_facts, Mapping
    ):
        raise BlindLabelerError("packet:spine_replay_failed:shape")
    for field in ("session_sha256", "session_id", "line_count"):
        if source.get(field) != replay_source.get(field):
            raise BlindLabelerError(
                "packet:spine_replay_failed:source:" + field
            )
    for field in ("ticket_id", "plan_sha256", "plan_schema"):
        stored = stored_facts.get(field)
        if stored is not None and stored != replay_facts.get(field):
            raise BlindLabelerError(
                "packet:spine_replay_failed:facts:" + field
            )
    stored_class = stored_facts.get("derived_class")
    replay_class = replay_facts.get("derived_class")
    if (
        stored_class in corpus.CLASSES
        and replay_class in corpus.CLASSES
        and stored_class != replay_class
    ):
        raise BlindLabelerError("packet:spine_replay_failed:facts:derived_class")
    if stored_facts.get("plan_frozen") is True and replay_facts.get(
        "plan_frozen"
    ) is not True:
        raise BlindLabelerError("packet:spine_replay_failed:facts:plan_frozen")
    if selection is None:
        rows, _, _ = recovery.read_session(session_path)
    else:
        rows, _, _, _ = recovery.read_session_segment(
            session_path,
            line_start=selection.get("line_start"),
            line_end=selection.get("line_end"),
        )
    return rows, replay


def _frozen_plan(
    rows: Sequence[Mapping[str, Any]], expected_sha256: str
) -> Mapping[str, Any]:
    plans: list[Mapping[str, Any]] = []
    for tool, body in recovery.iter_gate_calls(rows):
        plan = body.get("canonical_plan")
        if (
            tool in recovery.PLAN_TOOLS
            and body.get("status") == "PASS"
            and body.get("plan_sha256") == expected_sha256
            and isinstance(plan, Mapping)
            and corpus.content_digest(plan) == expected_sha256
        ):
            plans.append(plan)
    if not plans:
        raise BlindLabelerError("packet:frozen_plan_unavailable")
    canonical = {corpus.canonical_json(plan) for plan in plans}
    if len(canonical) != 1:
        raise BlindLabelerError("packet:frozen_plan_contradictory")
    return plans[-1]


def _add(evidence: dict[str, Any], evidence_id: str, value: Any) -> None:
    if evidence_id in evidence:
        raise BlindLabelerError("packet:evidence_id_duplicate:" + evidence_id)
    if len(evidence) >= MAX_EVIDENCE_ITEMS:
        raise BlindLabelerError("packet:evidence_limit_exceeded")
    evidence[evidence_id] = value


def _plan_evidence(plan: Mapping[str, Any], evidence: dict[str, Any]) -> None:
    decision = plan.get("decision") if isinstance(plan.get("decision"), Mapping) else {}
    mode = decision.get("mode")
    if isinstance(mode, str):
        _add(evidence, "task.decision_mode", _identifier(mode, "decision.mode"))

    acceptance = plan.get("acceptance_criteria")
    if acceptance is not None:
        for index, criterion in enumerate(
            _string_list(acceptance, "acceptance_criteria")
        ):
            _add(evidence, f"task.acceptance.{index}", criterion)

    lane_key = next(
        (key for key in recovery.LANE_KEYS if isinstance(plan.get(key), list)),
        None,
    )
    if lane_key is None:
        raise BlindLabelerError("packet:plan_lanes_missing")
    lanes = plan[lane_key]
    if not lanes or len(lanes) > recovery.MAX_LANES:
        raise BlindLabelerError("packet:plan_lanes_invalid")
    seen: set[str] = set()
    for index, raw in enumerate(lanes):
        if not isinstance(raw, Mapping):
            raise BlindLabelerError(f"packet:lane_invalid:{index}")
        lane_id = _identifier(raw.get("id"), f"lanes[{index}].id")
        if lane_id in seen:
            raise BlindLabelerError("packet:lane_duplicate:" + lane_id)
        seen.add(lane_id)
        prefix = "plan.lane." + lane_id
        if raw.get("objective") is not None:
            _add(
                evidence,
                prefix + ".objective",
                _public_text(raw.get("objective"), prefix + ".objective"),
            )
        for name in ("dependencies", "verification"):
            if raw.get(name) is not None:
                _add(
                    evidence,
                    prefix + "." + name,
                    _string_list(raw.get(name), prefix + "." + name),
                )
        for name in ("deliverables", "owned_resources"):
            if raw.get(name) is not None:
                values, redacted = _resource_list(
                    raw.get(name), prefix + "." + name
                )
                _add(evidence, prefix + "." + name, values)
                if redacted:
                    _add(
                        evidence,
                        prefix + "." + name + ".redacted_count",
                        redacted,
                    )

    integration = (
        plan.get("integration")
        if isinstance(plan.get("integration"), Mapping)
        else {}
    )
    strategy = integration.get("strategy")
    if isinstance(strategy, str):
        _add(
            evidence,
            "plan.integration.strategy",
            _identifier(strategy, "integration.strategy"),
        )
    if isinstance(integration.get("release_required"), bool):
        _add(
            evidence,
            "plan.integration.release_required",
            integration["release_required"],
        )
    if integration.get("final_verification") is not None:
        _add(
            evidence,
            "plan.integration.final_verification",
            _string_list(
                integration["final_verification"], "integration.final_verification"
            ),
        )
    if plan.get("protected_resources") is not None:
        protected, redacted = _resource_list(
            plan["protected_resources"], "protected_resources"
        )
        _add(
            evidence,
            "plan.protected_resources",
            protected,
        )
        if redacted:
            _add(evidence, "plan.protected_resources.redacted_count", redacted)
    children = plan.get("children") if isinstance(plan.get("children"), Mapping) else {}
    for name in ("expected_count", "retries_allowed", "fallbacks_allowed"):
        value = children.get(name)
        if type(value) is int and value >= 0:
            _add(evidence, "plan.children." + name, value)
    root = plan.get("root") if isinstance(plan.get("root"), Mapping) else {}
    if isinstance(root.get("coordination_only_after_freeze"), bool):
        _add(
            evidence,
            "plan.root.coordination_only_after_freeze",
            root["coordination_only_after_freeze"],
        )


def _execution_evidence(
    facts: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    evidence: dict[str, Any],
) -> None:
    for name in (
        "derived_class",
        "class_basis",
        "undetermined",
        "lane_count",
        "planned_lane_count",
        "worker_attempt_count",
        "extra_worker_attempt_count",
        "gate_count",
        "gate_retry_count",
        "root_completion",
        "wave_status",
        "plan_frozen",
        "integration_strategy",
        "integration_owner",
        "trace_qualification_status",
        "trace_qualified",
        "trace_claim_permitted",
        "trace_qualification_issues",
        "root_coordination_only_after_freeze",
        "planned_retries_allowed",
        "planned_fallbacks_allowed",
        "declared_deliverable_count",
        "redacted_deliverable_count",
    ):
        if name in facts:
            _add(evidence, "execution." + name, facts[name])
    if isinstance(facts.get("gates"), list):
        for gate in facts["gates"]:
            if not isinstance(gate, Mapping):
                continue
            name = gate.get("gate")
            if isinstance(name, str) and _IDENTIFIER.fullmatch(name):
                _add(evidence, "execution.gate." + name, dict(gate))

    trace_bodies = [
        body
        for tool, body in recovery.iter_gate_calls(rows)
        if tool == recovery.TRACE_QUALIFICATION_TOOL
    ]
    if trace_bodies:
        body = trace_bodies[-1]
        summary = body.get("summary")
        terminal = body.get("terminal_evidence")
        if isinstance(summary, Mapping):
            allowed = {
                key: summary[key]
                for key in (
                    "children",
                    "events",
                    "releases",
                    "root_implementation_tools",
                )
                if type(summary.get(key)) is int and summary[key] >= 0
            }
            if allowed:
                _add(evidence, "execution.trace.summary", allowed)
        if isinstance(terminal, Mapping):
            allowed_terminal = {
                key: _identifier(terminal[key], "terminal_evidence." + key)
                for key in ("status", "required_next_step", "run_completed_event")
                if isinstance(terminal.get(key), str)
            }
            if allowed_terminal:
                _add(evidence, "execution.trace.terminal_evidence", allowed_terminal)


def build_blind_packet(
    corpus_path: str | Path,
    *,
    run_key: str,
    session_path: str | Path,
) -> dict[str, Any]:
    """Export one deterministic packet with no model call or raw transcript."""

    run_key = _identifier(run_key, "run_key")
    entries = corpus.read_corpus(corpus_path)
    if any(
        record.get("run_key") == run_key
        for record in corpus.effective_records(entries)
    ):
        raise BlindLabelerError("packet:run_already_human_labeled")
    state = _effective_spine_state(entries, run_key)
    spine = state["spine"]
    readiness = corpus.spine_label_readiness(spine)
    if readiness.get("ready") is not True:
        raise BlindLabelerError(
            "packet:spine_unresolved:" + ",".join(readiness.get("issues", []))
        )
    rows, replay = _bound_rows(spine, session_path)
    facts = replay.get("facts") if isinstance(replay.get("facts"), Mapping) else {}
    plan_sha256 = facts.get("plan_sha256")
    if not isinstance(plan_sha256, str) or not _SHA256.fullmatch(plan_sha256):
        raise BlindLabelerError("packet:frozen_plan_digest_missing")
    plan = _frozen_plan(rows, plan_sha256)

    evidence: dict[str, Any] = {}
    ticket_id = facts.get("ticket_id")
    if isinstance(ticket_id, str):
        _add(evidence, "task.ticket_id", _identifier(ticket_id, "ticket_id"))
    _plan_evidence(plan, evidence)
    _execution_evidence(facts, rows, evidence)

    source = spine.get("source") if isinstance(spine.get("source"), Mapping) else {}
    binding = {
        "run_key": run_key,
        "host": spine.get("host"),
        "effective_spine_sequence": state["entry"].get("sequence"),
        "effective_spine_entry_sha256": state["entry"].get("entry_sha256"),
        "spine_sha256": spine.get("spine_sha256"),
        "replay_spine_sha256": replay.get("spine_sha256"),
        "source_identity_verified": True,
        "session_sha256": source.get("session_sha256"),
        "selection": dict(source["selection"])
        if isinstance(source.get("selection"), Mapping)
        else None,
        "plan_sha256": plan_sha256,
    }
    rubric_sha256 = corpus.content_digest(RUBRIC)
    core = {
        "schema": PACKET_SCHEMA,
        "binding": binding,
        "rubric": RUBRIC,
        "rubric_sha256": rubric_sha256,
        "evidence": dict(sorted(evidence.items())),
        "context_policy": {
            "fresh_context_required_for_blind": True,
            "packet_only_required_for_blind": True,
            "aggregate_analysis_forbidden_for_blind": True,
            "peer_verdicts_forbidden_for_blind": True,
        },
    }
    corpus.reject_secret_fields(core, "packet")
    packet = {**core, "packet_sha256": corpus.content_digest(core)}
    if len(corpus.canonical_json(packet).encode("utf-8")) > MAX_JSON_FILE_BYTES:
        raise BlindLabelerError("packet:too_large")
    return packet


def verify_blind_packet(packet: Any) -> dict[str, Any]:
    """Verify a packet's closed shape and both content-addressed seals."""

    if not isinstance(packet, Mapping) or set(packet) != _PACKET_FIELDS:
        raise BlindLabelerError("packet:shape_invalid")
    if packet.get("schema") != PACKET_SCHEMA:
        raise BlindLabelerError("packet:schema_invalid")
    if packet.get("rubric") != RUBRIC:
        raise BlindLabelerError("packet:rubric_changed")
    if packet.get("rubric_sha256") != corpus.content_digest(RUBRIC):
        raise BlindLabelerError("packet:rubric_digest_invalid")
    core = dict(packet)
    recorded = core.pop("packet_sha256", None)
    if not isinstance(recorded, str) or recorded != corpus.content_digest(core):
        raise BlindLabelerError("packet:digest_invalid")
    binding = packet.get("binding")
    evidence = packet.get("evidence")
    if not isinstance(binding, Mapping) or not isinstance(evidence, Mapping):
        raise BlindLabelerError("packet:evidence_shape_invalid")
    if len(evidence) > MAX_EVIDENCE_ITEMS or any(
        not isinstance(key, str) or not key for key in evidence
    ):
        raise BlindLabelerError("packet:evidence_invalid")
    for field in (
        "effective_spine_entry_sha256",
        "spine_sha256",
        "replay_spine_sha256",
        "session_sha256",
        "plan_sha256",
    ):
        _sha256(binding.get(field), "binding." + field)
    if binding.get("source_identity_verified") is not True:
        raise BlindLabelerError("packet:source_identity_unverified")
    _identifier(binding.get("run_key"), "binding.run_key")
    _identifier(binding.get("host"), "binding.host")
    corpus.reject_secret_fields(packet, "packet")
    return dict(packet)


def build_model_request(packet: Any) -> dict[str, Any]:
    """Build one deterministic packet-bound structured-output request."""

    packet = verify_blind_packet(packet)
    evidence_ids = sorted(packet["evidence"])
    if len(evidence_ids) > MAX_STRUCTURED_OUTPUT_ENUM_VALUES:
        raise BlindLabelerError("model_request:evidence_enum_too_large")
    answer_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Orch Dork blind dogfood answer",
        "type": "object",
        "additionalProperties": False,
        "required": ["answer"],
        "properties": {
            "answer": {
                "anyOf": [
                    _answer_branch_schema(packet, decision="verdict"),
                    _answer_branch_schema(packet, decision="abstain"),
                ]
            }
        },
        "$defs": {
            "evidence_id": {"type": "string", "enum": evidence_ids},
        },
    }
    prompt = _MODEL_PROMPT_TEMPLATE.replace(
        "{{PACKET_JSON}}", corpus.canonical_json(packet)
    )
    core = {
        "schema": MODEL_REQUEST_SCHEMA,
        "packet_sha256": packet["packet_sha256"],
        "rubric_sha256": packet["rubric_sha256"],
        "instruction_template_sha256": corpus.content_digest(
            _MODEL_PROMPT_TEMPLATE
        ),
        "instruction": prompt,
        "answer_schema": answer_schema,
        "answer_schema_sha256": corpus.content_digest(answer_schema),
        "context_policy": dict(packet["context_policy"]),
    }
    corpus.reject_secret_fields(core, "model_request")
    request = {**core, "request_sha256": corpus.content_digest(core)}
    if len(corpus.canonical_json(request).encode("utf-8")) > MAX_JSON_FILE_BYTES:
        raise BlindLabelerError("model_request:too_large")
    return request


def verify_model_request(packet: Any, request: Any) -> dict[str, Any]:
    """Re-derive one structured request and refuse any changed surface."""

    packet = verify_blind_packet(packet)
    if not isinstance(request, Mapping) or set(request) != _MODEL_REQUEST_FIELDS:
        raise BlindLabelerError("model_request:shape_invalid")
    if request.get("schema") != MODEL_REQUEST_SCHEMA:
        raise BlindLabelerError("model_request:schema_invalid")
    core = dict(request)
    recorded = core.pop("request_sha256", None)
    if not isinstance(recorded, str) or recorded != corpus.content_digest(core):
        raise BlindLabelerError("model_request:digest_invalid")
    if request.get("answer_schema_sha256") != corpus.content_digest(
        request.get("answer_schema")
    ):
        raise BlindLabelerError("model_request:answer_schema_digest_invalid")
    corpus.reject_secret_fields(request, "model_request")

    expected = build_model_request(packet)
    for field, reason in (
        ("packet_sha256", "packet_digest_changed"),
        ("rubric_sha256", "rubric_digest_changed"),
        ("instruction_template_sha256", "instruction_template_changed"),
        ("instruction", "instruction_changed"),
        ("answer_schema", "answer_schema_changed"),
        ("answer_schema_sha256", "answer_schema_digest_changed"),
        ("context_policy", "context_policy_changed"),
    ):
        if request.get(field) != expected[field]:
            raise BlindLabelerError("model_request:" + reason)
    return dict(request)


def _current_packet_binding(
    corpus_path: str | Path, packet: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], Mapping[str, Any]]:
    entries = corpus.read_corpus(corpus_path)
    binding = packet["binding"]
    run_key = binding["run_key"]
    state = _effective_spine_state(entries, run_key)
    spine = state["spine"]
    expected = {
        "effective_spine_sequence": state["entry"].get("sequence"),
        "effective_spine_entry_sha256": state["entry"].get("entry_sha256"),
        "spine_sha256": spine.get("spine_sha256"),
    }
    if any(binding.get(key) != value for key, value in expected.items()):
        raise BlindLabelerError("verdict:packet_spine_stale")
    if any(
        record.get("run_key") == run_key
        for record in corpus.effective_records(entries)
    ):
        raise BlindLabelerError("verdict:run_already_human_labeled")
    return entries, state


def _normalize_answer(
    packet: Mapping[str, Any], answer: Any
) -> dict[str, Any]:
    if isinstance(answer, Mapping) and set(answer) == {"answer"}:
        answer = answer["answer"]
    if not isinstance(answer, Mapping) or set(answer) != _ANSWER_FIELDS:
        raise BlindLabelerError("answer:shape_invalid")
    if answer.get("schema") != MODEL_ANSWER_SCHEMA:
        raise BlindLabelerError("answer:schema_invalid")
    if answer.get("packet_sha256") != packet["packet_sha256"]:
        raise BlindLabelerError("answer:packet_digest_mismatch")
    if answer.get("rubric_sha256") != packet["rubric_sha256"]:
        raise BlindLabelerError("answer:rubric_digest_mismatch")

    decision = answer.get("decision")
    if decision not in {"verdict", "abstain"}:
        raise BlindLabelerError("answer:decision_invalid")
    refs = answer.get("evidence_refs")
    if not isinstance(refs, Mapping) or set(refs) != set(_VERDICT_FIELDS):
        raise BlindLabelerError("answer:evidence_refs_shape_invalid")
    known_refs = set(packet["evidence"])
    normalized_refs: dict[str, list[str]] = {}
    for field in _VERDICT_FIELDS:
        values = refs.get(field)
        if (
            not isinstance(values, list)
            or len(values) > 32
            or len(values) != len(set(values))
            or any(not isinstance(item, str) or item not in known_refs for item in values)
        ):
            raise BlindLabelerError("answer:evidence_refs_invalid:" + field)
        normalized_refs[field] = list(values)

    justifications = answer.get("justifications")
    if not isinstance(justifications, Mapping) or any(
        key not in _VERDICT_FIELDS for key in justifications
    ):
        raise BlindLabelerError("answer:justifications_shape_invalid")
    normalized_justifications = {
        key: _public_text(value, "justifications." + key)
        for key, value in justifications.items()
        if value is not None
    }

    if decision == "abstain":
        if any(answer.get(field) is not None for field in _VERDICT_FIELDS):
            raise BlindLabelerError("answer:abstention_carries_verdict")
        if any(normalized_refs.values()) or normalized_justifications:
            raise BlindLabelerError("answer:abstention_carries_judgement")
        if answer.get("abstention_reason") not in _ABSTENTION_REASONS:
            raise BlindLabelerError("answer:abstention_reason_invalid")
    else:
        if answer.get("abstention_reason") is not None:
            raise BlindLabelerError("answer:verdict_carries_abstention")
        if any(not normalized_refs[field] for field in _VERDICT_FIELDS):
            raise BlindLabelerError("answer:evidence_refs_required")
        corpus.validate_verdict_values(
            actual_class=answer.get("actual_class"),
            classification_verdict=answer.get("classification_verdict"),
            plan_verdict=answer.get("plan_verdict"),
            outcome=answer.get("outcome"),
        )
        derived = packet["evidence"].get("execution.derived_class")
        if derived in corpus.CLASSES and answer.get("actual_class") != derived:
            raise BlindLabelerError("answer:actual_class_contradicts_spine")
        if (
            derived in corpus.CLASSES
            and "execution.derived_class" not in normalized_refs["actual_class"]
        ):
            raise BlindLabelerError("answer:actual_class_missing_decisive_ref")

    return {
        "schema": MODEL_ANSWER_SCHEMA,
        "packet_sha256": packet["packet_sha256"],
        "rubric_sha256": packet["rubric_sha256"],
        "decision": decision,
        **{field: answer.get(field) for field in _VERDICT_FIELDS},
        "evidence_refs": normalized_refs,
        "justifications": dict(sorted(normalized_justifications.items())),
        "abstention_reason": answer.get("abstention_reason"),
    }


def _config_value(value: Any, field: str) -> Any:
    if value is None or isinstance(value, bool) or type(value) is int:
        return value
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise BlindLabelerError(field + " must be finite")
        return value
    if isinstance(value, str):
        return _public_text(value, field)
    raise BlindLabelerError(field + " must be a bounded scalar")


def _normalize_provenance(value: Any) -> tuple[dict[str, Any], bool]:
    if not isinstance(value, Mapping) or set(value) != _PROVENANCE_FIELDS:
        raise BlindLabelerError("provenance:shape_invalid")
    if value.get("source_kind") != "model":
        raise BlindLabelerError("provenance:source_kind_invalid")
    model_id = _identifier(value.get("model_id"), "provenance.model_id")
    model_version = value.get("model_version")
    if model_version is not None:
        model_version = _identifier(model_version, "provenance.model_version")
    transport = _identifier(value.get("transport"), "provenance.transport")
    invocation_id = value.get("invocation_id")
    if invocation_id is not None:
        invocation_id = _identifier(invocation_id, "provenance.invocation_id")
    config = value.get("inference_config")
    if not isinstance(config, Mapping) or len(config) > 32:
        raise BlindLabelerError("provenance:inference_config_invalid")
    normalized_config: dict[str, Any] = {}
    for key, item in config.items():
        normalized_key = _identifier(key, "provenance.inference_config.key")
        if _SENSITIVE_KEY.search(normalized_key):
            raise BlindLabelerError(
                "provenance:inference_config_sensitive:" + normalized_key
            )
        normalized_config[normalized_key] = _config_value(
            item, "provenance.inference_config." + normalized_key
        )
    prompt_digest = _sha256(
        value.get("prompt_template_sha256"),
        "provenance.prompt_template_sha256",
    )
    for field in ("fresh_context", "packet_only", "peer_verdicts_seen"):
        if not isinstance(value.get(field), bool):
            raise BlindLabelerError("provenance:" + field + "_invalid")
    analysis = value.get("analysis_digest_seen")
    if analysis is not None:
        analysis = _sha256(analysis, "provenance.analysis_digest_seen")
    blind = (
        value["fresh_context"]
        and value["packet_only"]
        and not value["peer_verdicts_seen"]
        and analysis is None
    )
    normalized = {
        "source_kind": "model",
        "model_id": model_id,
        "model_version": model_version,
        "transport": transport,
        "invocation_id": invocation_id,
        "inference_config": dict(sorted(normalized_config.items())),
        "prompt_template_sha256": prompt_digest,
        "fresh_context": value["fresh_context"],
        "packet_only": value["packet_only"],
        "peer_verdicts_seen": value["peer_verdicts_seen"],
        "analysis_digest_seen": analysis,
    }
    return normalized, blind


def _validate_model_entry(entry: Mapping[str, Any]) -> None:
    body = {key: value for key, value in entry.items() if key not in _CHAIN_FIELDS}
    expected_fields = (
        _MODEL_CORRECTION_FIELDS
        if body.get("kind") == "model_correction"
        else _MODEL_ENTRY_FIELDS
    )
    if set(body) != expected_fields:
        raise BlindLabelerError("model_chain:entry_shape_invalid")
    if body.get("schema") != MODEL_VERDICT_SCHEMA:
        raise BlindLabelerError("model_chain:entry_schema_invalid")
    if body.get("kind") not in {
        "model_verdict",
        "model_abstention",
        "model_correction",
    }:
        raise BlindLabelerError("model_chain:entry_kind_invalid")
    run_key = _identifier(body.get("run_key"), "model_chain.run_key")
    host = _identifier(body.get("host"), "model_chain.host")
    corpus.validate_timestamp(body.get("recorded_at"), "model_chain.recorded_at")
    for field in (
        "packet_sha256",
        "rubric_sha256",
        "spine_sha256",
        "answer_sha256",
        "provenance_sha256",
    ):
        _sha256(body.get(field), "model_chain." + field)

    answer = body.get("answer")
    if not isinstance(answer, Mapping) or body.get(
        "answer_sha256"
    ) != corpus.content_digest(answer):
        raise BlindLabelerError("model_chain:answer_digest_invalid")
    refs = answer.get("evidence_refs")
    if not isinstance(refs, Mapping):
        raise BlindLabelerError("model_chain:answer_invalid")
    evidence_ids: set[str] = set()
    for values in refs.values():
        if not isinstance(values, list):
            raise BlindLabelerError("model_chain:answer_invalid")
        for value in values:
            evidence_ids.add(_identifier(value, "model_chain.answer.evidence_ref"))
    synthetic_packet = {
        "packet_sha256": body["packet_sha256"],
        "rubric_sha256": body["rubric_sha256"],
        "binding": {"run_key": run_key, "host": host},
        "evidence": {evidence_id: None for evidence_id in evidence_ids},
    }
    if _normalize_answer(synthetic_packet, answer) != dict(answer):
        raise BlindLabelerError("model_chain:answer_not_canonical")
    if (
        body.get("kind") == "model_verdict"
        and answer.get("decision") != "verdict"
    ) or (
        body.get("kind") == "model_abstention"
        and answer.get("decision") != "abstain"
    ):
        raise BlindLabelerError("model_chain:kind_answer_mismatch")

    provenance = body.get("provenance")
    if not isinstance(provenance, Mapping) or body.get(
        "provenance_sha256"
    ) != corpus.content_digest(provenance):
        raise BlindLabelerError("model_chain:provenance_digest_invalid")
    normalized_provenance, derived_blind = _normalize_provenance(provenance)
    if normalized_provenance != dict(provenance):
        raise BlindLabelerError("model_chain:provenance_not_canonical")
    if body.get("blind") is not derived_blind:
        raise BlindLabelerError("model_chain:blind_mismatch")
    _identifier(body.get("ticket_key"), "model_chain.ticket_key")
    observation = body.get("observation")
    if not isinstance(observation, Mapping) or set(observation) != {
        "lane_count",
        "checks_count",
        "checks_passed",
    }:
        raise BlindLabelerError("model_chain:observation_invalid")
    for field in ("lane_count", "checks_count", "checks_passed"):
        if type(observation.get(field)) is not int or observation[field] < 0:
            raise BlindLabelerError("model_chain:observation_invalid:" + field)
    if observation["checks_passed"] > observation["checks_count"]:
        raise BlindLabelerError("model_chain:observation_checks_contradictory")
    if body.get("kind") == "model_correction":
        corrects = body.get("corrects")
        if (
            not isinstance(corrects, Mapping)
            or set(corrects) != {"sequence", "entry_sha256"}
            or type(corrects.get("sequence")) is not int
            or corrects["sequence"] < 0
        ):
            raise BlindLabelerError("model_chain:correction_target_invalid")
        _sha256(corrects.get("entry_sha256"), "model_chain.corrects.entry_sha256")
        _public_text(body.get("correction_reason"), "correction_reason")


def effective_model_verdicts(
    entries: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return one effective model result per run with exact corrections."""

    states: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for entry in entries:
        kind = entry.get("kind")
        run_key = _identifier(entry.get("run_key"), "model_chain.run_key")
        if kind in {"model_verdict", "model_abstention"}:
            if run_key in states:
                raise BlindLabelerError("model_chain:duplicate_initial_run:" + run_key)
            order.append(run_key)
            states[run_key] = dict(entry)
            continue
        if kind != "model_correction":
            raise BlindLabelerError("model_chain:entry_kind_invalid")
        prior = states.get(run_key)
        if prior is None:
            raise BlindLabelerError("model_chain:orphaned_correction:" + run_key)
        expected = {
            "sequence": prior.get("sequence"),
            "entry_sha256": prior.get("entry_sha256"),
        }
        if entry.get("corrects") != expected:
            raise BlindLabelerError("model_chain:stale_or_forked_correction:" + run_key)
        replacement = dict(entry)
        replacement["supersedes_sequence"] = prior.get("sequence")
        states[run_key] = replacement
    return [states[run_key] for run_key in order]


def read_model_chain(
    path: str | Path, *, expected_host: str | None = None
) -> list[dict[str, Any]]:
    """Read and validate one host-local model-verdict chain."""

    entries = corpus.read_corpus(path)
    for entry in entries:
        if entry.get("corpus_version") != MODEL_CHAIN_VERSION:
            raise BlindLabelerError("model_chain:version_invalid")
        if expected_host is not None and entry.get("host") != expected_host:
            raise BlindLabelerError("model_chain:host_mismatch")
        _validate_model_entry(entry)
    effective_model_verdicts(entries)
    return entries


def record_model_verdict(
    corpus_path: str | Path,
    model_chain_path: str | Path,
    *,
    packet: Mapping[str, Any],
    answer: Mapping[str, Any],
    provenance: Mapping[str, Any],
    recorded_at: str,
    host: str,
    corrects_entry_sha256: str | None = None,
    correction_reason: str | None = None,
) -> dict[str, Any]:
    """Validate and append one model verdict without touching human evidence."""

    packet = verify_blind_packet(packet)
    _, state = _current_packet_binding(corpus_path, packet)
    host = _identifier(host, "host")
    if packet["binding"].get("host") != host:
        raise BlindLabelerError("verdict:host_mismatch")
    chain = read_model_chain(model_chain_path, expected_host=host)
    run_key = packet["binding"]["run_key"]
    current = next(
        (
            entry
            for entry in effective_model_verdicts(chain)
            if entry.get("run_key") == run_key
        ),
        None,
    )
    correction_requested = (
        corrects_entry_sha256 is not None or correction_reason is not None
    )
    if correction_requested:
        if current is None or corrects_entry_sha256 is None or correction_reason is None:
            raise BlindLabelerError("verdict:correction_incomplete")
        _sha256(corrects_entry_sha256, "corrects_entry_sha256")
        if current.get("entry_sha256") != corrects_entry_sha256:
            raise BlindLabelerError("verdict:correction_target_stale")
        correction_reason = _public_text(correction_reason, "correction_reason")
    elif current is not None:
        raise BlindLabelerError("verdict:run_already_model_labeled")
    normalized_answer = _normalize_answer(packet, answer)
    normalized_provenance, blind = _normalize_provenance(provenance)
    evidence = packet["evidence"]
    ticket_key = evidence.get("task.ticket_id")
    if not isinstance(ticket_key, str) or not _IDENTIFIER.fullmatch(ticket_key):
        ticket_key = run_key
    lane_count = evidence.get("execution.planned_lane_count")
    if type(lane_count) is not int:
        lane_count = evidence.get("execution.lane_count")
    lane_count = lane_count if type(lane_count) is int and lane_count >= 0 else 0
    gates = [
        value
        for key, value in evidence.items()
        if key.startswith("execution.gate.") and isinstance(value, Mapping)
    ]
    checks_passed = sum(1 for gate in gates if gate.get("final_status") == "PASS")
    entry = {
        "schema": MODEL_VERDICT_SCHEMA,
        "kind": (
            "model_correction"
            if correction_requested
            else (
                "model_verdict"
                if normalized_answer["decision"] == "verdict"
                else "model_abstention"
            )
        ),
        "run_key": run_key,
        "recorded_at": corpus.validate_timestamp(recorded_at, "recorded_at"),
        "host": host,
        "packet_sha256": packet["packet_sha256"],
        "rubric_sha256": packet["rubric_sha256"],
        "spine_sha256": state["spine"]["spine_sha256"],
        "ticket_key": ticket_key,
        "observation": {
            "lane_count": lane_count,
            "checks_count": len(gates),
            "checks_passed": checks_passed,
        },
        "answer": normalized_answer,
        "answer_sha256": corpus.content_digest(normalized_answer),
        "provenance": normalized_provenance,
        "provenance_sha256": corpus.content_digest(normalized_provenance),
        "blind": blind,
    }
    if correction_requested and current is not None:
        entry["corrects"] = {
            "sequence": current["sequence"],
            "entry_sha256": current["entry_sha256"],
        }
        entry["correction_reason"] = correction_reason
    _validate_model_entry(entry)
    return corpus.append_entry(
        model_chain_path, entry, corpus_version=MODEL_CHAIN_VERSION
    )


def _common_human_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "run_key": record.get("run_key"),
        "source_kind": "human",
        "blind": record.get("blind") is True,
        "actual_class": record.get("actual_class"),
        "classification_verdict": record.get("classification_verdict"),
        "plan_verdict": record.get("plan_verdict"),
        "outcome": record.get("outcome"),
        "ticket_key": record.get("ticket_key"),
        "observation": record.get("observation"),
        "record_sha256": record.get("entry_sha256"),
    }


def _common_model_record(entry: Mapping[str, Any]) -> dict[str, Any]:
    answer = entry["answer"]
    return {
        "run_key": entry.get("run_key"),
        "source_kind": "model",
        "blind": entry.get("blind") is True,
        "actual_class": answer.get("actual_class"),
        "classification_verdict": answer.get("classification_verdict"),
        "plan_verdict": answer.get("plan_verdict"),
        "outcome": answer.get("outcome"),
        "ticket_key": entry.get("ticket_key"),
        "observation": entry.get("observation"),
        "record_sha256": entry.get("entry_sha256"),
    }


def summarize_combined(
    corpus_path: str | Path,
    model_chain_path: str | Path,
    *,
    min_records: int = corpus.DEFAULT_MIN_RECORDS,
) -> dict[str, Any]:
    """Project human and model verdicts without merging their raw chains."""

    if type(min_records) is not int or min_records < 1:
        raise BlindLabelerError("summary:min_records_invalid")
    human_entries = corpus.read_corpus(corpus_path)
    effective_human_entries = corpus.effective_records(human_entries)
    human_hosts = {
        entry.get("host")
        for entry in effective_human_entries
        if isinstance(entry.get("host"), str)
    }
    if len(human_hosts) > 1:
        raise BlindLabelerError("summary:human_host_mixed")
    expected_host = next(iter(human_hosts), None)
    model_entries = read_model_chain(
        model_chain_path, expected_host=expected_host
    )
    model_hosts = {
        entry.get("host")
        for entry in model_entries
        if isinstance(entry.get("host"), str)
    }
    if len(model_hosts) > 1 or (
        human_hosts and model_hosts and human_hosts != model_hosts
    ):
        raise BlindLabelerError("summary:cross_host_chain_refused")

    human_records = [
        _common_human_record(record)
        for record in effective_human_entries
    ]
    effective_models = effective_model_verdicts(model_entries)
    model_records = [
        _common_model_record(entry)
        for entry in effective_models
        if entry.get("answer", {}).get("decision") == "verdict"
    ]
    human_keys = {record["run_key"] for record in human_records}
    model_keys = {record["run_key"] for record in model_records}
    overlap = sorted(human_keys & model_keys)
    if overlap:
        raise BlindLabelerError("summary:cross_source_duplicate:" + ",".join(overlap))
    if len(model_keys) != len(model_records):
        raise BlindLabelerError("summary:model_run_duplicate")

    records = human_records + model_records
    blind = sum(record["blind"] for record in records)
    total = len(records)
    reasons: list[str] = []
    if total < min_records:
        reasons.append(f"combined:below_min_records:{total}<{min_records}")
    if blind < min_records:
        reasons.append(f"combined:below_min_blind_records:{blind}<{min_records}")

    spine_states = corpus.resolve_effective_spines(human_entries)
    labeled_or_attempted = human_keys | {
        entry.get("run_key") for entry in model_entries
    }
    awaiting = sorted(
        state["run_key"]
        for state in spine_states
        if state["run_key"] not in labeled_or_attempted
    )
    ready = sorted(
        state["run_key"]
        for state in spine_states
        if state["run_key"] in awaiting
        and corpus.spine_label_readiness(state["spine"])["ready"]
    )
    unresolved = sorted(set(awaiting) - set(ready))
    blind_needed = max(0, min_records - blind)
    return {
        "schema": COMBINED_SUMMARY_SCHEMA,
        "record_count": total,
        "blind_record_count": blind,
        "source_counts": {
            "human": len(human_records),
            "model": len(model_records),
        },
        "by_source": {
            "human": corpus.summarize_verdict_records(human_records),
            "model": corpus.summarize_verdict_records(model_records),
        },
        "model_chain_entry_count": len(model_entries),
        "model_abstention_count": sum(
            entry.get("answer", {}).get("decision") == "abstain"
            for entry in effective_models
        ),
        "model_correction_count": sum(
            entry.get("kind") == "model_correction" for entry in model_entries
        ),
        "unlabeled_run_keys": awaiting,
        "unlabeled_run_count": len(awaiting),
        "label_ready_unlabeled_run_keys": ready,
        "label_ready_unlabeled_run_count": len(ready),
        "unresolved_unlabeled_run_keys": unresolved,
        "unresolved_unlabeled_run_count": len(unresolved),
        "blind_records_needed": blind_needed,
        "further_real_runs_required": max(0, blind_needed - len(ready)),
        "aggregate_reportable": not reasons,
        "insufficient_reasons": reasons,
        "min_records": min_records,
        "provider_free_projection": True,
        "projection_model_calls": 0,
        # Import provenance can establish how many results entered the chain,
        # but not how many model calls a transport made to produce them.
        "imported_model_result_count": len(model_entries),
        "label_model_calls": None,
        "raw_chains_merged": False,
    }


def _read_json_file(path: str | Path, label: str) -> Mapping[str, Any]:
    target = Path(path)
    try:
        if target.is_symlink() or not target.is_file():
            raise BlindLabelerError(label + ":regular_file_required")
        if target.stat().st_size > MAX_JSON_FILE_BYTES:
            raise BlindLabelerError(label + ":too_large")
        value = json.loads(target.read_text(encoding="utf-8"))
    except BlindLabelerError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BlindLabelerError(label + ":unreadable") from exc
    if not isinstance(value, Mapping):
        raise BlindLabelerError(label + ":object_required")
    return value


def _emit(value: Mapping[str, Any], *, compact: bool) -> None:
    print(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":") if compact else None,
            indent=None if compact else 2,
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    packet_parser = commands.add_parser("packet", help="Export one blind packet")
    packet_parser.add_argument("--corpus", required=True)
    packet_parser.add_argument("--run-key", required=True)
    packet_parser.add_argument("--session", required=True)
    packet_parser.add_argument("--compact", action="store_true")

    request_parser = commands.add_parser(
        "request", help="Build one packet-specific structured model request"
    )
    request_parser.add_argument("--packet", required=True)
    request_parser.add_argument(
        "--component",
        choices=("envelope", "answer-schema", "instruction"),
        default="envelope",
    )
    request_parser.add_argument("--compact", action="store_true")

    record_parser = commands.add_parser("record", help="Validate and append a model answer")
    record_parser.add_argument("--corpus", required=True)
    record_parser.add_argument("--model-chain", required=True)
    record_parser.add_argument("--packet", required=True)
    record_parser.add_argument("--answer", required=True)
    record_parser.add_argument("--provenance", required=True)
    record_parser.add_argument("--recorded-at", required=True)
    record_parser.add_argument("--host", required=True)
    record_parser.add_argument("--corrects-entry-sha256")
    record_parser.add_argument("--correction-reason")
    record_parser.add_argument("--compact", action="store_true")

    summary_parser = commands.add_parser("summary", help="Project both verdict sources")
    summary_parser.add_argument("--corpus", required=True)
    summary_parser.add_argument("--model-chain", required=True)
    summary_parser.add_argument(
        "--min-records", type=int, default=corpus.DEFAULT_MIN_RECORDS
    )
    summary_parser.add_argument("--compact", action="store_true")

    args = parser.parse_args(argv)
    plain_output: str | None = None
    try:
        if args.command == "packet":
            result = build_blind_packet(
                args.corpus, run_key=args.run_key, session_path=args.session
            )
        elif args.command == "request":
            request = build_model_request(
                _read_json_file(args.packet, "packet_file")
            )
            if args.component == "instruction":
                result = {}
                plain_output = request["instruction"]
            elif args.component == "answer-schema":
                result = request["answer_schema"]
            else:
                result = request
        elif args.command == "record":
            result = record_model_verdict(
                args.corpus,
                args.model_chain,
                packet=_read_json_file(args.packet, "packet_file"),
                answer=_read_json_file(args.answer, "answer_file"),
                provenance=_read_json_file(args.provenance, "provenance_file"),
                recorded_at=args.recorded_at,
                host=args.host,
                corrects_entry_sha256=args.corrects_entry_sha256,
                correction_reason=args.correction_reason,
            )
        else:
            result = summarize_combined(
                args.corpus,
                args.model_chain,
                min_records=args.min_records,
            )
    except (BlindLabelerError, corpus.DogfoodCorpusError) as exc:
        _emit({"status": "REFUSE", "reason": str(exc)}, compact=True)
        return 1
    if plain_output is not None:
        sys.stdout.write(plain_output)
    else:
        _emit(result, compact=args.compact)
    return 0


__all__ = [
    "PACKET_SCHEMA",
    "RUBRIC_SCHEMA",
    "MODEL_ANSWER_SCHEMA",
    "MODEL_REQUEST_SCHEMA",
    "MODEL_VERDICT_SCHEMA",
    "MODEL_CHAIN_VERSION",
    "COMBINED_SUMMARY_SCHEMA",
    "RUBRIC",
    "BlindLabelerError",
    "build_blind_packet",
    "build_model_request",
    "verify_model_request",
    "verify_blind_packet",
    "read_model_chain",
    "record_model_verdict",
    "effective_model_verdicts",
    "summarize_combined",
    "main",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
