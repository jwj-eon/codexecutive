#!/usr/bin/env python3
"""Provider-free result-relevant Topology Closure for Control Tower plans."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault(name, module)
        spec.loader.exec_module(module)
        return module


contracts = _load_sibling("orch_dork_adaptive_contracts")
relay = _load_sibling("orch_dork_relay")


PROGRAM_SCHEMA = "orch-dork/topology-closure-program/v1"
SUBMISSION_SCHEMA = "orch-dork/parallel-join-submission/v1"
REPORT_SCHEMA = "orch-dork/topology-closure/v1"
MAX_PROGRAM_BYTES = 16 * 1024 * 1024

RELATION_KINDS = frozenset(
    {
        "data_reference",
        "semantic_reference",
        "ordering",
        "shared_state",
        "authority_prerequisite",
        "verification_prerequisite",
    }
)
RESOLUTION_KINDS = frozenset(
    {"co_located", "serial_relay", "join", "irrelevant", "unresolved"}
)
JOIN_KINDS = frozenset({"mechanical", "semantic", "mixed"})
UNKNOWN_RISKS = frozenset({"low", "medium", "high", "critical"})
UNKNOWN_DISPOSITIONS = frozenset({"atomic", "review", "refuse"})

_PROGRAM_FIELDS = frozenset(
    {
        "schema",
        "task_brief_sha256",
        "acceptance_checks",
        "project_ground_sha256",
        "privacy_class",
        "profile_id",
        "semantic_plan_sha256",
        "compiler_input_sha256",
        "logical_plan",
        "admitted_input_refs",
        "submission",
    }
)
_SUBMISSION_FIELDS = frozenset(
    {
        "schema",
        "topology_id",
        "information_units",
        "producers",
        "relations",
        "relays",
        "join",
        "criteria",
        "artifacts",
        "unknowns",
        "submission_sha256",
    }
)
_UNIT_FIELDS = frozenset({"unit_id", "source_ref", "source_evidence_sha256"})
_PRODUCER_FIELDS = frozenset({"node_id", "unit_ids", "output_artifact_id"})
_RELATION_FIELDS = frozenset(
    {
        "relation_id",
        "from_unit_id",
        "to_unit_id",
        "kind",
        "consumer_node_id",
        "criterion_id",
        "resolution_kind",
        "relay_id",
        "join_id",
        "irrelevance_evidence_sha256",
    }
)
_RELAY_FIELDS = frozenset({"relay_id", "manifest", "delivery"})
_JOIN_FIELDS = frozenset(
    {
        "node_id",
        "kind",
        "input_producer_ids",
        "owned_criterion_ids",
        "output_artifact_id",
    }
)
_CRITERION_FIELDS = frozenset(
    {"criterion_id", "producer_node_ids", "verifier_node_ids"}
)
_ARTIFACT_FIELDS = frozenset(
    {"artifact_id", "producer_node_id", "consumer_node_ids", "retention_reason"}
)
_UNKNOWN_FIELDS = frozenset(
    {"unknown_id", "risk", "disposition", "evidence_sha256"}
)
_ACCEPTANCE_FIELDS = frozenset({"id", "description", "required"})
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], code: str) -> None:
    if code not in issues:
        issues.append(code)


def _closed(value: Any, fields: frozenset[str], path: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, path + ":not_object")
        return {}
    if set(value) != fields:
        if fields - set(value):
            _issue(issues, path + ":missing_fields")
        if set(value) - fields:
            _issue(issues, path + ":unknown_fields")
    return value


def _identifier(value: Any, path: str, issues: list[str]) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _issue(issues, path + ":invalid")
        return ""
    return value


def _digest(value: Any, path: str, issues: list[str], *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _issue(issues, path + ":invalid")
        return None
    return value


def _identifier_list(
    value: Any,
    path: str,
    issues: list[str],
    *,
    allow_empty: bool = False,
    maximum: int = 256,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        _issue(issues, path + ":invalid")
        return []
    result = [_identifier(item, f"{path}[{index}]", issues) for index, item in enumerate(value)]
    result = [item for item in result if item]
    if not allow_empty and not result:
        _issue(issues, path + ":empty")
    if len(result) != len(set(result)):
        _issue(issues, path + ":duplicates")
    return result


def _seal_valid(value: Any, field: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    digest = value.get(field)
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        return False
    core = dict(value)
    core.pop(field, None)
    return digest == _sha256(core)


def _plan_dependencies(logical_plan: Mapping[str, Any]) -> tuple[set[str], set[tuple[str, str]]]:
    workers = logical_plan.get("workers") if isinstance(logical_plan.get("workers"), list) else []
    nodes = {
        str(worker.get("id"))
        for worker in workers
        if isinstance(worker, Mapping) and isinstance(worker.get("id"), str)
    }
    edges = {
        (str(dependency), str(worker.get("id")))
        for worker in workers
        if isinstance(worker, Mapping) and isinstance(worker.get("dependencies"), list)
        for dependency in worker["dependencies"]
        if isinstance(dependency, str)
    }
    return nodes, edges


def evaluate_topology_closure(program: Any) -> dict[str, Any]:
    """Evaluate one exact parallel topology without dispatch or mutable state."""

    issues: list[str] = []
    try:
        encoded_program = json.dumps(
            program,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        encoded_program = b""
        _issue(issues, "program:encoding_invalid")
    if len(encoded_program) > MAX_PROGRAM_BYTES:
        _issue(issues, "program:bytes_exceeded")
        value = {}
    else:
        value = _closed(program, _PROGRAM_FIELDS, "program", issues)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    for field in (
        "task_brief_sha256",
        "project_ground_sha256",
        "semantic_plan_sha256",
        "compiler_input_sha256",
    ):
        _digest(value.get(field), "program:" + field, issues)
    if value.get("profile_id") not in {
        "parallel_join/v1",
        "finite_dag/v1",
    }:
        _issue(issues, "program:profile_invalid")
    if value.get("privacy_class") != "local_only":
        _issue(issues, "program:privacy_invalid")

    acceptance_ids: list[str] = []
    acceptance = value.get("acceptance_checks")
    if not isinstance(acceptance, list) or not acceptance or len(acceptance) > 64:
        _issue(issues, "program:acceptance_invalid")
    else:
        for index, raw in enumerate(acceptance):
            row = _closed(raw, _ACCEPTANCE_FIELDS, f"acceptance[{index}]", issues)
            criterion_id = _identifier(row.get("id"), f"acceptance[{index}].id", issues)
            if criterion_id:
                acceptance_ids.append(criterion_id)
            if type(row.get("required")) is not bool:
                _issue(issues, f"acceptance[{index}].required_invalid")
    if len(acceptance_ids) != len(set(acceptance_ids)):
        _issue(issues, "program:acceptance_duplicate")

    admitted_refs: dict[str, dict[str, Any]] = {}
    raw_admitted = value.get("admitted_input_refs")
    if not isinstance(raw_admitted, list) or len(raw_admitted) > 256:
        _issue(issues, "program:admitted_refs_invalid")
    else:
        for raw in raw_admitted:
            report = contracts.validate_artifact_ref(raw)
            if report.get("status") != "PASS":
                _issue(issues, "program:admitted_ref_invalid")
                continue
            ref = report["normalized"]
            admitted_refs[ref["uri"]] = ref

    logical_plan = value.get("logical_plan") if isinstance(value.get("logical_plan"), Mapping) else {}
    plan_nodes, plan_edges = _plan_dependencies(logical_plan)
    if _sha256(logical_plan) != value.get("compiler_input_sha256"):
        _issue(issues, "program:compiler_input_mismatch")

    submission = _closed(value.get("submission"), _SUBMISSION_FIELDS, "submission", issues)
    if submission.get("schema") != SUBMISSION_SCHEMA:
        _issue(issues, "submission:schema_invalid")
    if not _seal_valid(submission, "submission_sha256"):
        _issue(issues, "submission:seal_invalid")
    topology_id = _identifier(submission.get("topology_id"), "submission:topology_id", issues)

    units: dict[str, dict[str, Any]] = {}
    raw_units = submission.get("information_units")
    if not isinstance(raw_units, list) or not raw_units or len(raw_units) > 256:
        _issue(issues, "topology:information_units_invalid")
    else:
        for index, raw in enumerate(raw_units):
            row = _closed(raw, _UNIT_FIELDS, f"units[{index}]", issues)
            unit_id = _identifier(row.get("unit_id"), f"units[{index}].unit_id", issues)
            if unit_id in units:
                _issue(issues, "topology:information_unit_duplicate:" + unit_id)
                continue
            ref_report = contracts.validate_artifact_ref(row.get("source_ref"))
            if ref_report.get("status") != "PASS":
                _issue(issues, "topology:source_ref_invalid:" + unit_id)
                continue
            ref = ref_report["normalized"]
            evidence = _digest(
                row.get("source_evidence_sha256"),
                f"units[{index}].source_evidence_sha256",
                issues,
            )
            if evidence != ref["sha256"]:
                _issue(issues, "topology:source_evidence_mismatch:" + unit_id)
            if admitted_refs.get(ref["uri"]) != ref:
                _issue(issues, "topology:source_not_admitted:" + unit_id)
            units[unit_id] = {"source_ref": ref, "source_evidence_sha256": evidence}

    producers: dict[str, dict[str, Any]] = {}
    unit_owner: dict[str, str] = {}
    raw_producers = submission.get("producers")
    if not isinstance(raw_producers, list) or len(raw_producers) < 2:
        _issue(issues, "topology:producer_count_invalid")
    else:
        for index, raw in enumerate(raw_producers):
            row = _closed(raw, _PRODUCER_FIELDS, f"producers[{index}]", issues)
            node_id = _identifier(row.get("node_id"), f"producers[{index}].node_id", issues)
            unit_ids = _identifier_list(row.get("unit_ids"), f"producers[{index}].unit_ids", issues)
            output_id = _identifier(
                row.get("output_artifact_id"),
                f"producers[{index}].output_artifact_id",
                issues,
            )
            if node_id in producers:
                _issue(issues, "topology:producer_duplicate:" + node_id)
            producers[node_id] = {"unit_ids": unit_ids, "output_artifact_id": output_id}
            if node_id not in plan_nodes:
                _issue(issues, "topology:producer_missing_from_plan:" + node_id)
            for unit_id in unit_ids:
                if unit_id not in units:
                    _issue(issues, "topology:partition_unknown_unit:" + unit_id)
                if unit_id in unit_owner:
                    _issue(issues, "topology:partition_duplicate_unit:" + unit_id)
                unit_owner[unit_id] = node_id
    for unit_id in sorted(set(units) - set(unit_owner)):
        _issue(issues, "topology:partition_missing_unit:" + unit_id)

    join = _closed(submission.get("join"), _JOIN_FIELDS, "join", issues)
    join_id = _identifier(join.get("node_id"), "join:node_id", issues)
    if join.get("kind") not in JOIN_KINDS:
        _issue(issues, "join:kind_invalid")
    join_inputs = _identifier_list(join.get("input_producer_ids"), "join:input_producer_ids", issues)
    join_criteria = _identifier_list(join.get("owned_criterion_ids"), "join:owned_criterion_ids", issues)
    join_output = _identifier(join.get("output_artifact_id"), "join:output_artifact_id", issues)
    if set(join_inputs) != set(producers):
        _issue(issues, "join:producer_inputs_incomplete")
    if join_id not in plan_nodes:
        _issue(issues, "join:missing_from_plan")
    for producer_id in producers:
        if (producer_id, join_id) not in plan_edges:
            _issue(issues, "join:plan_dependency_missing:" + producer_id)

    relay_records: dict[str, dict[str, Any]] = {}
    raw_relays = submission.get("relays")
    if not isinstance(raw_relays, list) or len(raw_relays) > 256:
        _issue(issues, "topology:relays_invalid")
    else:
        for index, raw in enumerate(raw_relays):
            row = _closed(raw, _RELAY_FIELDS, f"relays[{index}]", issues)
            relay_id = _identifier(row.get("relay_id"), f"relays[{index}].relay_id", issues)
            if relay_id in relay_records:
                _issue(issues, "topology:relay_duplicate:" + relay_id)
            manifest_report = relay.validate_relay_manifest(row.get("manifest"))
            delivery_report = relay.evaluate_relay_delivery(row.get("delivery"))
            if manifest_report.get("status") != "PASS":
                _issue(issues, "topology:relay_manifest_invalid:" + relay_id)
            if delivery_report.get("status") != "PASS":
                _issue(issues, "topology:relay_delivery_invalid:" + relay_id)
            manifest = row.get("manifest")
            required_facts = (
                manifest.get("required_facts", [])
                if isinstance(manifest, Mapping)
                else []
            )
            if any(
                not isinstance(fact, Mapping)
                or fact.get("freshness")
                != {
                    "kind": "plan_revision",
                    "revision": logical_plan.get("revision"),
                }
                for fact in required_facts
            ):
                _issue(issues, "topology:relay_freshness_mismatch:" + relay_id)
            relay_records[relay_id] = {
                "manifest": row.get("manifest"),
                "manifest_report": manifest_report,
                "delivery_report": delivery_report,
            }

    criteria: dict[str, dict[str, Any]] = {}
    raw_criteria = submission.get("criteria")
    known_nodes = set(producers) | {join_id, "reviewer"}
    if not isinstance(raw_criteria, list) or not raw_criteria or len(raw_criteria) > 64:
        _issue(issues, "topology:criteria_invalid")
    else:
        for index, raw in enumerate(raw_criteria):
            row = _closed(raw, _CRITERION_FIELDS, f"criteria[{index}]", issues)
            criterion_id = _identifier(
                row.get("criterion_id"), f"criteria[{index}].criterion_id", issues
            )
            producer_ids = _identifier_list(
                row.get("producer_node_ids"), f"criteria[{index}].producer_node_ids", issues
            )
            verifier_ids = _identifier_list(
                row.get("verifier_node_ids"), f"criteria[{index}].verifier_node_ids", issues
            )
            if criterion_id in criteria:
                _issue(issues, "topology:criterion_duplicate:" + criterion_id)
            if set(producer_ids + verifier_ids) - known_nodes:
                _issue(issues, "topology:criterion_unknown_node:" + criterion_id)
            criteria[criterion_id] = {
                "producer_node_ids": producer_ids,
                "verifier_node_ids": verifier_ids,
            }
    for criterion_id in sorted(set(acceptance_ids) - set(criteria)):
        _issue(issues, "topology:criterion_uncovered:" + criterion_id)
    for criterion_id in sorted(set(criteria) - set(acceptance_ids)):
        _issue(issues, "topology:criterion_not_admitted:" + criterion_id)
    for criterion_id in join_criteria:
        if criterion_id not in acceptance_ids:
            _issue(issues, "join:criterion_not_admitted:" + criterion_id)
        criterion = criteria.get(criterion_id)
        if (
            criterion is not None
            and join_id not in criterion["producer_node_ids"]
        ):
            _issue(
                issues,
                "topology:join_criterion_producer_missing:" + criterion_id,
            )

    artifact_records: dict[str, dict[str, Any]] = {}
    raw_artifacts = submission.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts or len(raw_artifacts) > 128:
        _issue(issues, "topology:artifacts_invalid")
    else:
        for index, raw in enumerate(raw_artifacts):
            row = _closed(raw, _ARTIFACT_FIELDS, f"artifacts[{index}]", issues)
            artifact_id = _identifier(row.get("artifact_id"), f"artifacts[{index}].artifact_id", issues)
            producer_id = _identifier(
                row.get("producer_node_id"), f"artifacts[{index}].producer_node_id", issues
            )
            consumer_ids = _identifier_list(
                row.get("consumer_node_ids"),
                f"artifacts[{index}].consumer_node_ids",
                issues,
                allow_empty=True,
            )
            retention = row.get("retention_reason")
            if retention is not None:
                _identifier(retention, f"artifacts[{index}].retention_reason", issues)
            if artifact_id in artifact_records:
                _issue(issues, "topology:artifact_duplicate:" + artifact_id)
            if producer_id not in known_nodes:
                _issue(issues, "topology:artifact_producer_unknown:" + artifact_id)
            if set(consumer_ids) - known_nodes:
                _issue(issues, "topology:artifact_consumer_unknown:" + artifact_id)
            if not consumer_ids and retention is None:
                _issue(issues, "topology:artifact_unconsumed:" + artifact_id)
            artifact_records[artifact_id] = {
                "producer_node_id": producer_id,
                "consumer_node_ids": consumer_ids,
                "retention_reason": retention,
            }
    for producer_id, producer in producers.items():
        artifact = artifact_records.get(producer["output_artifact_id"])
        if artifact is None or artifact["producer_node_id"] != producer_id:
            _issue(issues, "topology:producer_artifact_missing:" + producer_id)
        elif join_id not in artifact["consumer_node_ids"]:
            _issue(
                issues,
                "topology:producer_artifact_join_missing:" + producer_id,
            )
    joined_artifact = artifact_records.get(join_output)
    if joined_artifact is None or joined_artifact["producer_node_id"] != join_id:
        _issue(issues, "topology:join_artifact_missing")
    elif "reviewer" not in joined_artifact["consumer_node_ids"]:
        _issue(issues, "topology:join_artifact_verifier_missing")

    context_manifests: list[dict[str, Any]] = []
    plan_revision = logical_plan.get("revision")
    for artifact_id, artifact in sorted(artifact_records.items()):
        for consumer_id in artifact["consumer_node_ids"]:
            manifest_core = {
                "schema": "orch-dork/context-manifest/v1",
                "edge_id": artifact["producer_node_id"] + "->" + consumer_id,
                "producer_node_id": artifact["producer_node_id"],
                "consumer_node_id": consumer_id,
                "required_artifact_ids": [artifact_id],
                "optional_refs": [],
                "forbidden_refs": ["conversation_history", "private_reasoning"],
                "freshness": {"kind": "plan_revision", "revision": plan_revision},
                "purpose": "Deliver only the declared artifact to its consumer.",
                "consumer_ack": {
                    "required": True,
                    "status": "pending_runtime_delivery",
                },
            }
            context_manifests.append(
                {**manifest_core, "manifest_sha256": _sha256(manifest_core)}
            )

    relation_closures: list[dict[str, Any]] = []
    raw_relations = submission.get("relations")
    seen_relations: set[str] = set()
    if not isinstance(raw_relations, list) or not raw_relations or len(raw_relations) > 512:
        _issue(issues, "topology:relations_invalid")
    else:
        for index, raw in enumerate(raw_relations):
            row = _closed(raw, _RELATION_FIELDS, f"relations[{index}]", issues)
            relation_id = _identifier(
                row.get("relation_id"), f"relations[{index}].relation_id", issues
            )
            if relation_id in seen_relations:
                _issue(issues, "topology:relation_duplicate:" + relation_id)
            seen_relations.add(relation_id)
            from_unit = _identifier(
                row.get("from_unit_id"), f"relations[{index}].from_unit_id", issues
            )
            to_unit = _identifier(
                row.get("to_unit_id"), f"relations[{index}].to_unit_id", issues
            )
            criterion_id = _identifier(
                row.get("criterion_id"), f"relations[{index}].criterion_id", issues
            )
            consumer_id = _identifier(
                row.get("consumer_node_id"), f"relations[{index}].consumer_node_id", issues
            )
            kind = row.get("kind")
            resolution = row.get("resolution_kind")
            if kind not in RELATION_KINDS:
                _issue(issues, "topology:relation_kind_invalid:" + relation_id)
            if resolution not in RESOLUTION_KINDS:
                _issue(issues, "topology:resolution_kind_invalid:" + relation_id)
            if from_unit not in units or to_unit not in units:
                _issue(issues, "topology:relation_unit_unknown:" + relation_id)
                continue
            if criterion_id not in criteria:
                _issue(issues, "topology:relation_criterion_unknown:" + relation_id)
            from_owner = unit_owner.get(from_unit)
            to_owner = unit_owner.get(to_unit)
            crossing = from_owner != to_owner
            closed = False
            if crossing and kind == "shared_state":
                _issue(
                    issues,
                    "topology:cross_lane_mutable_state:" + relation_id,
                )
            if not crossing and resolution == "co_located" and consumer_id == from_owner:
                closed = True
            elif resolution == "serial_relay" and crossing:
                relay_id = row.get("relay_id")
                relay_record = relay_records.get(relay_id)
                source = units[from_unit]["source_ref"]
                manifest = relay_record.get("manifest", {}) if relay_record else {}
                required = manifest.get("required_inputs", []) if isinstance(manifest, Mapping) else []
                required_facts = (
                    manifest.get("required_facts", [])
                    if isinstance(manifest, Mapping)
                    else []
                )
                pins_source = any(
                    isinstance(entry, Mapping)
                    and entry.get("artifact_ref") == source["uri"]
                    and entry.get("sha256") == source["sha256"]
                    for entry in required
                )
                pins_relation = any(
                    isinstance(fact, Mapping)
                    and fact.get("value_ref")
                    == "relation:" + from_unit + ":" + to_unit
                    for fact in required_facts
                )
                if (
                    kind != "shared_state"
                    and relay_record
                    and manifest.get("producer_node") == from_owner
                    and manifest.get("consumer_node") == consumer_id == to_owner
                    and pins_source
                    and pins_relation
                    and (from_owner, to_owner) in plan_edges
                ):
                    closed = True
            elif resolution == "join" and crossing:
                if (
                    row.get("join_id") == join_id == consumer_id
                    and criterion_id in join_criteria
                    and {from_owner, to_owner} <= set(join_inputs)
                ):
                    closed = True
            elif resolution == "irrelevant":
                if _digest(
                    row.get("irrelevance_evidence_sha256"),
                    f"relations[{index}].irrelevance_evidence_sha256",
                    issues,
                ) is not None:
                    closed = True
            if not closed:
                if resolution == "unresolved":
                    _issue(issues, "topology:cross_relation_unresolved:" + relation_id)
                else:
                    _issue(issues, "topology:relation_not_closed:" + relation_id)
            relation_closures.append(
                {
                    "relation_id": relation_id,
                    "from_node_id": from_owner,
                    "to_node_id": to_owner,
                    "consumer_node_id": consumer_id,
                    "resolution_kind": resolution,
                    "closed": closed,
                }
            )

    unknown_records: list[dict[str, Any]] = []
    review_required = False
    raw_unknowns = submission.get("unknowns")
    if not isinstance(raw_unknowns, list) or len(raw_unknowns) > 64:
        _issue(issues, "topology:unknowns_invalid")
    else:
        for index, raw in enumerate(raw_unknowns):
            row = _closed(raw, _UNKNOWN_FIELDS, f"unknowns[{index}]", issues)
            unknown_id = _identifier(row.get("unknown_id"), f"unknowns[{index}].unknown_id", issues)
            risk = row.get("risk")
            disposition = row.get("disposition")
            if risk not in UNKNOWN_RISKS:
                _issue(issues, "topology:unknown_risk_invalid:" + unknown_id)
            if disposition not in UNKNOWN_DISPOSITIONS:
                _issue(issues, "topology:unknown_disposition_invalid:" + unknown_id)
            _digest(row.get("evidence_sha256"), f"unknowns[{index}].evidence_sha256", issues)
            if risk in {"high", "critical"} or disposition == "refuse":
                _issue(issues, "topology:unknown_refuses:" + unknown_id)
            elif disposition in {"atomic", "review"}:
                review_required = True
            unknown_records.append(dict(row))

    if issues:
        status = "REFUSED"
    elif review_required:
        status = "REVIEW_REQUIRED"
    else:
        status = "PASS"
    core = {
        "schema": REPORT_SCHEMA,
        "status": status,
        "topology_id": topology_id or None,
        "task_brief_sha256": value.get("task_brief_sha256"),
        "acceptance_sha256": _sha256(acceptance if isinstance(acceptance, list) else []),
        "semantic_plan_sha256": value.get("semantic_plan_sha256"),
        "logical_plan_sha256": _sha256(logical_plan),
        "compiler_input_sha256": value.get("compiler_input_sha256"),
        "project_ground_sha256": value.get("project_ground_sha256"),
        "profile_id": value.get("profile_id"),
        "submission_sha256": submission.get("submission_sha256"),
        "information_unit_count": len(units),
        "producer_count": len(producers),
        "relation_closures": sorted(relation_closures, key=lambda row: row["relation_id"]),
        "criterion_coverage": {
            criterion_id: criteria[criterion_id] for criterion_id in sorted(criteria)
        },
        "artifact_consumption": {
            artifact_id: artifact_records[artifact_id]
            for artifact_id in sorted(artifact_records)
        },
        "context_manifests": context_manifests,
        "unknowns": sorted(unknown_records, key=lambda row: str(row.get("unknown_id"))),
        "issues": sorted(issues),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "closure_sha256": _sha256(core)}


__all__ = [
    "PROGRAM_SCHEMA",
    "SUBMISSION_SCHEMA",
    "REPORT_SCHEMA",
    "evaluate_topology_closure",
]
