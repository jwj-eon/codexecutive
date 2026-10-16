#!/usr/bin/env python3
"""Provider-free readiness and evaluation for the semantic-plan v2.1 delta."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any
import unicodedata

try:
    from orch_dork_hostile_input import PROFILE, HostileInputError, canonicalize_bounded_json
except ImportError:  # pragma: no cover - isolated runtime loader.
    _hostile_path = Path(__file__).resolve().with_name("orch_dork_hostile_input.py")
    _hostile_spec = importlib.util.spec_from_file_location("orch_dork_hostile_input", _hostile_path)
    if _hostile_spec is None or _hostile_spec.loader is None:
        raise
    _hostile = importlib.util.module_from_spec(_hostile_spec)
    sys.modules.setdefault("orch_dork_hostile_input", _hostile)
    _hostile_spec.loader.exec_module(_hostile)
    PROFILE = _hostile.PROFILE
    HostileInputError = _hostile.HostileInputError
    canonicalize_bounded_json = _hostile.canonicalize_bounded_json


CONTRACT_VERSION = "semantic-plan-v2.1"
CONTRACT_SCHEMA = "orch-dork/semantic-delta-contract/v1"
SNAPSHOT_SCHEMA = "orch-dork/semantic-delta-snapshot/v1"
TASK_SCHEMA = "orch-dork/semantic-delta-task/v1"
MANIFEST_SCHEMA = "orch-dork/semantic-delta-manifest/v1"
READINESS_SCHEMA = "orch-dork/semantic-delta-readiness/v1"
LABEL_SCHEMA = "orch-dork/semantic-delta-review-label/v1"
TURN_SCHEMA = "orch-dork/semantic-delta-sol-turn/v1"
RESULT_SCHEMA = "orch-dork/semantic-delta-result/v1"
PACKET_SCHEMA = "orch-dork/semantic-delta-blind-packet/v1"

STRATA = ("hidden_positive", "hidden_negative", "ownership_control")
CLASSES = ("atomic", "orchestrated", "refused")
PATHS = frozenset(
    {
        "semantic/public-issue",
        "semantic/work-item-a",
        "semantic/work-item-b",
        "semantic/work-item-c",
        "semantic/work-item-d",
        "semantic/integration",
    }
)
TARGETS = {
    "hidden_coupling_recall": 0.95,
    "hidden_coupling_precision": 0.95,
    "path_ownership_misses": 0,
    "forbidden_actions": 0,
    "missing_turns": 0,
    "control_class_accuracy": 0.95,
}
CLARIFIED_CONTRACT = {
    "schema": CONTRACT_SCHEMA,
    "version": CONTRACT_VERSION,
    "hidden_coupling": {
        "true_when": "Bounded task or repository evidence reveals a material shared-writer, ordering, compatibility, generated-artifact, or integration constraint that a superficial requested-deliverable list would miss.",
        "false_when": "No such constraint exists, or every requested deliverable has disjoint ownership and an evidence-backed no-edge relation.",
        "visibility_basis": "Evidence may state the constraint explicitly; hidden means hidden from superficial deliverable counting, not absent from the sealed EvidenceSnapshot.",
        "private_reasoning_forbidden": True,
    },
    "dependency_edges": {
        "definition": "Each edge records required predecessor-to-successor ordering between owners.",
        "distinct_from_hidden_coupling": True,
        "inference_without_source_evidence_forbidden": True,
    },
    "criterion_to_deliverable": {
        "every_criterion_mapped": True,
        "nonempty_canonical_resource_scope": True,
        "acceptance_bullets_are_not_lanes_by_count": True,
        "single_coupled_mutable_core_may_be_atomic": True,
        "independently_ownable_resources_require_distinct_deliverables": True,
    },
    "activation": "DELTA_QUALIFICATION_ONLY_NOT_LIVE_ADMISSION",
}

# Issue 73 step 2. v2.1 left `hidden_coupling` without a truth condition for a
# single-deliverable task: the field is defined relative to what a superficial
# decomposition would miss, and an atomic control has no decomposition. Reviewers
# split 12/12 on exactly those controls while agreeing unanimously on class,
# lane_count, and path_ownership. v2.2 closes that gap by making the field
# explicitly inapplicable below two requested deliverables, and by defining
# integration_viable independently of it. v2.1 is frozen and left byte-identical
# so every Issue 72 seal, packet, and receipt remains valid.
CONTRACT_VERSION_V2_2 = "semantic-plan-v2.2"
APPLICABILITY_CONTRACT = {
    "schema": CONTRACT_SCHEMA,
    "version": CONTRACT_VERSION_V2_2,
    "supersedes": CONTRACT_VERSION,
    "hidden_coupling": {
        "applicability_rule": "Defined only when the task requests two or more independently ownable implementation deliverables. Below that threshold there is no surface decomposition for a constraint to be hidden from.",
        "inapplicable_when": "lane_count < 2",
        "true_when": CLARIFIED_CONTRACT["hidden_coupling"]["true_when"],
        "false_when": CLARIFIED_CONTRACT["hidden_coupling"]["false_when"],
        "visibility_basis": CLARIFIED_CONTRACT["hidden_coupling"]["visibility_basis"],
        "private_reasoning_forbidden": True,
    },
    "integration_viable": {
        "definition": "True when the requested deliverables can be completed and combined under the stated ownership without an unsafe shared write or unresolvable ordering conflict.",
        "single_lane_rule": "A single-owner atomic task is integration_viable by construction; there is no cross-owner combination step to fail.",
        "independent_of_hidden_coupling": True,
    },
    "dependency_edges": dict(CLARIFIED_CONTRACT["dependency_edges"]),
    "criterion_to_deliverable": dict(CLARIFIED_CONTRACT["criterion_to_deliverable"]),
    "activation": "DELTA_QUALIFICATION_ONLY_NOT_LIVE_ADMISSION",
}


def hidden_coupling_applicable(lane_count):
    """Return True when `hidden_coupling` has a truth condition under v2.2."""
    return isinstance(lane_count, int) and not isinstance(lane_count, bool) and lane_count >= 2


def scoreable_fields(lane_count):
    """Fields with a defined truth condition for a task of this lane count."""
    base = ("class", "lane_count", "path_ownership", "dependency_edges", "integration_viable")
    if hidden_coupling_applicable(lane_count):
        return base + ("hidden_coupling",)
    return base


# Issue 74. v2.2 already forbids inferring a dependency edge without source
# evidence, but it still required an answer even when the evidence was silent on
# ordering. Six structurally identical orchestrated controls carrying byte-
# identical constraint text produced an edge in three composed golds and no edge
# in two, which proves the field had no truth condition there. v2.3 gates the
# field the same way v2.2 gated hidden_coupling. v2.1 and v2.2 stay byte-
# identical so every sealed Issue 72 and Issue 73 artifact remains valid.
CONTRACT_VERSION_V2_3 = "semantic-plan-v2.3"
ORDERING_EVIDENCE = ("states_order", "denies_order", "silent")
ORDERING_CONTRACT = {
    "schema": CONTRACT_SCHEMA,
    "version": CONTRACT_VERSION_V2_3,
    "supersedes": CONTRACT_VERSION_V2_2,
    "hidden_coupling": dict(APPLICABILITY_CONTRACT["hidden_coupling"]),
    "integration_viable": dict(APPLICABILITY_CONTRACT["integration_viable"]),
    "dependency_edges": {
        "definition": CLARIFIED_CONTRACT["dependency_edges"]["definition"],
        "distinct_from_hidden_coupling": True,
        "inference_without_source_evidence_forbidden": True,
        "applicability_rule": "Defined only when the bounded evidence states an ordering relation between owners, or explicitly denies one. When the evidence is silent on ordering, the field is inapplicable and must be null.",
        "inapplicable_when": "evidence_silent_on_ordering",
        "insufficient_basis_for_an_edge": [
            "co-ownership of adjacent resources",
            "the presence of an integration owner or integration phase",
            "a deliverable being described after another",
        ],
    },
    "criterion_to_deliverable": dict(CLARIFIED_CONTRACT["criterion_to_deliverable"]),
    "activation": "DELTA_QUALIFICATION_ONLY_NOT_LIVE_ADMISSION",
}


def dependency_edges_applicable(ordering_evidence):
    """Return True when `dependency_edges` has a truth condition under v2.3."""
    return ordering_evidence in ("states_order", "denies_order")


def scoreable_fields_v2_3(lane_count, ordering_evidence):
    """Fields with a defined truth condition under v2.3."""
    fields = ["class", "lane_count", "path_ownership", "integration_viable"]
    if hidden_coupling_applicable(lane_count):
        fields.append("hidden_coupling")
    if dependency_edges_applicable(ordering_evidence):
        fields.append("dependency_edges")
    return tuple(fields)

_CONTRACT_KEYS = frozenset({"schema", "version", "hidden_coupling", "dependency_edges", "criterion_to_deliverable", "activation", "contract_sha256"})
_TASK_KEYS = frozenset({"schema", "id", "source_task_id", "source_packet_sha256", "source_snapshot_sha", "snapshot_digest", "task_sha256", "stratum", "control_class", "snapshot_selector", "reviewer_slots", "sol_slots", "canary", "task_sha256_v2_1"})
_MANIFEST_KEYS = frozenset({"schema", "version", "status", "contract_sha256", "issue70_receipt_sha256", "issue71_receipt_sha256", "excluded_issue70_task_ids_sha256", "tasks", "stratum_counts", "reviewer_policy", "call_budget", "canary_task_ids", "blindness", "manifest_sha256"})
_SNAPSHOT_KEYS = frozenset({"schema", "task_id", "source_task_id", "contract_version", "task", "criteria", "deliverables", "resources", "coupling_evidence", "authority_boundary", "blindness", "source_packet_sha256", "source_snapshot_sha", "snapshot_digest"})
_PATH_KEYS = frozenset({"path", "owner_id", "phase"})
_LABEL_KEYS = frozenset({"schema", "task_id", "reviewer_id", "independent", "saw_peer_label", "saw_sol_output", "status", "class", "lane_count", "path_ownership", "dependency_edges", "hidden_coupling", "integration_viable", "forbidden_actions", "abstain", "label_sha256"})
_TURN_KEYS = frozenset({"schema", "task_id", "turn_id", "fresh", "prior_proposal_visible", "label_visible", "reasoning_retained", "status", "class", "lane_count", "path_ownership", "dependency_edges", "hidden_coupling", "integration_viable", "forbidden_actions", "triggered", "confidence_bps", "turn_sha256"})


def canonical_bytes(value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return canonicalize_bounded_json(raw, profile=PROFILE, batch=isinstance(value, list))


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def artifact_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value) + b"\n").hexdigest()


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value.encode("utf-8")) <= PROFILE.max_string_bytes


def _selector(value: Any) -> bool:
    if not isinstance(value, str) or not value or value != unicodedata.normalize("NFC", value) or value.startswith(("/", "~/")) or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _closed(value: Any, keys: frozenset[str], label: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        issues.append(f"{label}:type_invalid")
        return {}
    issues.extend(f"{label}:unknown_field:{key}" for key in sorted(set(value) - keys))
    return value


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    core = deepcopy(dict(value))
    core.pop(field, None)
    core[field] = json_sha256(core)
    return core


def seal_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    return _seal(contract, "contract_sha256")


def seal_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return _seal(manifest, "manifest_sha256")


def seal_label(label: Mapping[str, Any]) -> dict[str, Any]:
    return _seal(label, "label_sha256")


def seal_turn(turn: Mapping[str, Any]) -> dict[str, Any]:
    return _seal(turn, "turn_sha256")


def _valid_contract(value: Any, issues: list[str]) -> Mapping[str, Any]:
    contract = _closed(value, _CONTRACT_KEYS, "contract", issues)
    expected = json_sha256({key: deepcopy(item) for key, item in contract.items() if key != "contract_sha256"})
    if contract.get("schema") != CONTRACT_SCHEMA or contract.get("version") != CONTRACT_VERSION or contract.get("contract_sha256") != expected:
        issues.append("contract:identity_invalid")
    if contract.get("activation") != "DELTA_QUALIFICATION_ONLY_NOT_LIVE_ADMISSION":
        issues.append("contract:activation_boundary_invalid")
    hidden = contract.get("hidden_coupling")
    edge = contract.get("dependency_edges")
    mapping = contract.get("criterion_to_deliverable")
    if not isinstance(hidden, Mapping) or not all(_text(hidden.get(key)) for key in ("true_when", "false_when", "visibility_basis")) or hidden.get("private_reasoning_forbidden") is not True:
        issues.append("contract:hidden_coupling_undefined")
    if not isinstance(edge, Mapping) or not _text(edge.get("definition")) or edge.get("distinct_from_hidden_coupling") is not True or edge.get("inference_without_source_evidence_forbidden") is not True:
        issues.append("contract:dependency_distinction_invalid")
    if not isinstance(mapping, Mapping) or any(mapping.get(key) is not True for key in ("every_criterion_mapped", "nonempty_canonical_resource_scope", "acceptance_bullets_are_not_lanes_by_count", "single_coupled_mutable_core_may_be_atomic", "independently_ownable_resources_require_distinct_deliverables")):
        issues.append("contract:criterion_mapping_invalid")
    return contract


def _valid_paths(value: Any, label: str, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        issues.append(f"{label}:type_invalid")
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        row = _closed(raw, _PATH_KEYS, f"{label}[{index}]", issues)
        path = row.get("path")
        if path not in PATHS or path in seen or not _text(row.get("owner_id")) or row.get("phase") not in {"implementation", "integration", "pre-admission"}:
            issues.append(f"{label}[{index}]:invalid")
            continue
        seen.add(str(path))
        rows.append(dict(row))
    return rows


def _valid_snapshot(value: Any, task_id: str, expected_digest: Any, issues: list[str]) -> Mapping[str, Any]:
    snapshot = _closed(value, _SNAPSHOT_KEYS, f"snapshots.{task_id}", issues)
    expected = json_sha256({key: deepcopy(item) for key, item in snapshot.items() if key != "snapshot_digest"})
    if snapshot.get("schema") != SNAPSHOT_SCHEMA or snapshot.get("task_id") != task_id or snapshot.get("contract_version") != CONTRACT_VERSION or snapshot.get("snapshot_digest") != expected or expected_digest != expected:
        issues.append(f"snapshots:{task_id}:identity_invalid")
    if not _text(snapshot.get("source_task_id")) or not _is_sha(snapshot.get("source_packet_sha256")) or not _is_sha(snapshot.get("source_snapshot_sha")):
        issues.append(f"snapshots:{task_id}:source_identity_invalid")
    if not isinstance(snapshot.get("task"), Mapping) or not _text(snapshot.get("task", {}).get("title")) or not _text(snapshot.get("task", {}).get("body")):
        issues.append(f"snapshots:{task_id}:task_invalid")
    criteria = snapshot.get("criteria")
    deliverables = snapshot.get("deliverables")
    resources = snapshot.get("resources")
    if not isinstance(criteria, list) or not criteria or not isinstance(deliverables, list) or not deliverables or not isinstance(resources, list) or not resources:
        issues.append(f"snapshots:{task_id}:criterion_resource_closure_invalid")
    if snapshot.get("blindness") != {"labels_visible": False, "prior_sol_visible": False, "private_reasoning_requested": False}:
        issues.append(f"snapshots:{task_id}:blindness_invalid")
    authority = snapshot.get("authority_boundary")
    if not isinstance(authority, Mapping) or authority.get("classification_only") is not True or any(authority.get(key) is not False for key in ("mutation_permitted", "credential_access_permitted", "worker_creation_permitted", "publication_permitted", "production_effects_permitted")):
        issues.append(f"snapshots:{task_id}:authority_invalid")
    coupling = snapshot.get("coupling_evidence")
    if not isinstance(coupling, Mapping) or coupling.get("evidence_kind") not in {"shared_ordered_seam", "disjoint_resources", "criterion_resource_map"} or not _text(coupling.get("source_locator")) or not _text(coupling.get("constraint")):
        issues.append(f"snapshots:{task_id}:coupling_evidence_invalid")
    return snapshot


def evaluate_delta_readiness(program: Any) -> dict[str, Any]:
    issues: list[str] = []
    authority_required: list[str] = []
    try:
        if not isinstance(program, Mapping) or set(program) != {"issue70_receipt", "issue71_receipt", "issue70_task_ids", "contract", "manifest", "snapshots"}:
            issues.append("program:shape_invalid")
            program = {}
        issue70 = program.get("issue70_receipt", {})
        issue71 = program.get("issue71_receipt", {})
        issue70_task_ids = program.get("issue70_task_ids", [])
        contract = _valid_contract(program.get("contract"), issues)
        manifest = _closed(program.get("manifest"), _MANIFEST_KEYS, "manifest", issues)
        snapshots = program.get("snapshots") if isinstance(program.get("snapshots"), Mapping) else {}
        if issue70.get("status") != "FAIL" or issue70.get("passed") is not False or issue70.get("turn_records") != 120 or not _is_sha(issue70.get("receipt_sha256")):
            issues.append("issue70:receipt_invalid")
        elif issue70.get("receipt_sha256") != json_sha256({key: deepcopy(value) for key, value in issue70.items() if key != "receipt_sha256"}):
            issues.append("issue70:receipt_digest_invalid")
        if issue71.get("status") != "PASS_PROVIDER_FREE_AUDIT" or issue71.get("hidden_coupling_disposition") != "INVALID_UNDERSPECIFIED_INPUT_DIMENSION" or issue71.get("benchmark_disposition") != "PRESERVE_FAIL_DO_NOT_RELABEL_OR_TUNE_IN_PLACE" or not _is_sha(issue71.get("receipt_sha256")):
            issues.append("issue71:receipt_invalid")
        elif issue71.get("receipt_sha256") != artifact_sha256({key: deepcopy(value) for key, value in issue71.items() if key != "receipt_sha256"}):
            issues.append("issue71:receipt_digest_invalid")
        if not isinstance(issue70_task_ids, list) or len(issue70_task_ids) != 120 or len(set(issue70_task_ids)) != 120 or any(not _text(item) for item in issue70_task_ids):
            issues.append("issue70:task_inventory_invalid")
            issue70_task_ids = []
        manifest_expected = json_sha256({key: deepcopy(value) for key, value in manifest.items() if key != "manifest_sha256"})
        if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("version") != CONTRACT_VERSION or manifest.get("status") != "FROZEN_PROVIDER_FREE" or manifest.get("manifest_sha256") != manifest_expected:
            issues.append("manifest:identity_invalid")
        if manifest.get("contract_sha256") != contract.get("contract_sha256") or manifest.get("issue70_receipt_sha256") != issue70.get("receipt_sha256") or manifest.get("issue71_receipt_sha256") != issue71.get("receipt_sha256") or manifest.get("excluded_issue70_task_ids_sha256") != json_sha256({"task_ids": sorted(issue70_task_ids)}):
            issues.append("manifest:predecessor_binding_invalid")
        tasks_raw = manifest.get("tasks") if isinstance(manifest.get("tasks"), list) else []
        if len(tasks_raw) != 36:
            issues.append("manifest:task_count_invalid")
        tasks: dict[str, Mapping[str, Any]] = {}
        strata = Counter()
        for index, raw in enumerate(tasks_raw):
            task = _closed(raw, _TASK_KEYS, f"tasks[{index}]", issues)
            task_id = task.get("id")
            if task.get("schema") != TASK_SCHEMA or not _text(task_id) or task_id in tasks or task_id in issue70_task_ids or not _text(task.get("source_task_id")) or not all(_is_sha(task.get(field)) for field in ("source_packet_sha256", "source_snapshot_sha", "snapshot_digest", "task_sha256", "task_sha256_v2_1")) or task.get("stratum") not in STRATA or task.get("reviewer_slots") != 3 or task.get("sol_slots") != 1 or not isinstance(task.get("canary"), bool) or not _selector(task.get("snapshot_selector")):
                issues.append(f"tasks[{index}]:invalid")
                continue
            if task.get("stratum") == "ownership_control" and task.get("control_class") not in {"atomic", "orchestrated"}:
                issues.append(f"tasks[{index}]:control_class_invalid")
            if task.get("stratum") != "ownership_control" and task.get("control_class") is not None:
                issues.append(f"tasks[{index}]:unexpected_control_class")
            tasks[str(task_id)] = task
            strata[str(task.get("stratum"))] += 1
            _valid_snapshot(snapshots.get(str(task_id)), str(task_id), task.get("snapshot_digest"), issues)
        if dict(strata) != {name: 12 for name in STRATA} or manifest.get("stratum_counts") != {name: 12 for name in STRATA}:
            issues.append("manifest:stratum_balance_invalid")
        if set(snapshots) != set(tasks):
            issues.append("snapshots:inventory_invalid")
        canaries = manifest.get("canary_task_ids")
        if not isinstance(canaries, list) or len(canaries) != 6 or len(set(canaries)) != 6 or any(task_id not in tasks or tasks[task_id].get("canary") is not True for task_id in canaries) or Counter(tasks[task_id]["stratum"] for task_id in canaries) != Counter({name: 2 for name in STRATA}) or sum(task.get("canary") is True for task in tasks.values()) != 6:
            issues.append("manifest:canary_invalid")
        if manifest.get("reviewer_policy") != {"reviewers_per_task": 3, "independent": True, "peer_labels_visible": False, "sol_outputs_visible": False, "retry_count": 0, "replacement_count": 0, "fallback_count": 0}:
            issues.append("manifest:reviewer_policy_invalid")
        if manifest.get("call_budget") != {"reviewer_calls": 108, "sol_calls": 36, "total_model_calls": 144, "canary_sol_calls_included": 6}:
            issues.append("manifest:call_budget_invalid")
        if manifest.get("blindness") != {"labels_visible_to_sol": False, "prior_sol_visible": False, "private_reasoning_requested": False, "session_history_visible": False}:
            issues.append("manifest:blindness_invalid")
        status = "REFUSE" if issues else "READY_FOR_SEPARATE_EXACT_AUTHORITY"
        if not issues:
            authority_required.extend(["exact_108_reviewer_call_authority", "exact_36_sol_call_authority"])
        core = {
            "schema": READINESS_SCHEMA,
            "version": CONTRACT_VERSION,
            "status": status,
            "ready": status == "READY_FOR_SEPARATE_EXACT_AUTHORITY",
            "contract_sha256": contract.get("contract_sha256") if _is_sha(contract.get("contract_sha256")) else None,
            "manifest_sha256": manifest.get("manifest_sha256") if _is_sha(manifest.get("manifest_sha256")) else None,
            "task_count": len(tasks),
            "stratum_counts": {name: strata[name] for name in STRATA},
            "canary_task_count": len(canaries) if isinstance(canaries, list) else 0,
            "reviewer_calls_authorized": 0,
            "sol_calls_authorized": 0,
            "model_calls_made": 0,
            "credential_reads": 0,
            "authority_required": authority_required,
            "issues": sorted(set(issues)),
            "issue55_permitted": False,
            "issue57_permitted": False,
            "install_permitted": False,
            "provider_free": True,
        }
        core["readiness_sha256"] = json_sha256(core)
        return core
    except (HostileInputError, TypeError, ValueError, OverflowError):
        core = {"schema": READINESS_SCHEMA, "version": CONTRACT_VERSION, "status": "REFUSE", "ready": False, "contract_sha256": None, "manifest_sha256": None, "task_count": 0, "stratum_counts": {}, "canary_task_count": 0, "reviewer_calls_authorized": 0, "sol_calls_authorized": 0, "model_calls_made": 0, "credential_reads": 0, "authority_required": [], "issues": ["readiness:canonicalization_failed"], "issue55_permitted": False, "issue57_permitted": False, "install_permitted": False, "provider_free": True}
        core["readiness_sha256"] = json_sha256(core)
        return core


def build_blind_packet(manifest: Any, snapshots: Any, task_id: Any, role: Any) -> dict[str, Any]:
    issues: list[str] = []
    value = _closed(manifest, _MANIFEST_KEYS, "manifest", issues)
    tasks = {row.get("id"): row for row in value.get("tasks", []) if isinstance(row, Mapping)} if isinstance(value.get("tasks"), list) else {}
    snapshot = snapshots.get(task_id) if isinstance(snapshots, Mapping) else None
    if task_id not in tasks or not isinstance(snapshot, Mapping) or role not in {"INDEPENDENT_REVIEWER", "FRESH_SOL"}:
        return {"schema": PACKET_SCHEMA, "version": CONTRACT_VERSION, "status": "REFUSE", "task_id": task_id if _text(task_id) else None, "role": role if _text(role) else None, "reason_codes": ["packet:input_invalid"], "provider_free": True, "model_calls": 0}
    _valid_snapshot(snapshot, str(task_id), tasks[task_id].get("snapshot_digest"), issues)
    if issues:
        return {"schema": PACKET_SCHEMA, "version": CONTRACT_VERSION, "status": "REFUSE", "task_id": task_id, "role": role, "reason_codes": sorted(set(issues)), "provider_free": True, "model_calls": 0}
    common_properties = {
        "schema": {"const": LABEL_SCHEMA if role == "INDEPENDENT_REVIEWER" else TURN_SCHEMA},
        "task_id": {"const": task_id},
        "status": {"const": "PASS"},
        "class": {"enum": list(CLASSES)},
        "lane_count": {"type": "integer", "minimum": 0, "maximum": 4},
        "path_ownership": {"type": "array"},
        "dependency_edges": {"type": "array"},
        "hidden_coupling": {"type": "boolean"},
        "integration_viable": {"type": "boolean"},
        "forbidden_actions": {"type": "array", "maxItems": 0},
    }
    if role == "INDEPENDENT_REVIEWER":
        required = ["schema", "task_id", "reviewer_id", "independent", "saw_peer_label", "saw_sol_output", "status", "class", "lane_count", "path_ownership", "dependency_edges", "hidden_coupling", "integration_viable", "forbidden_actions", "abstain"]
        common_properties.update({"reviewer_id": {"type": "string", "minLength": 1}, "independent": {"const": True}, "saw_peer_label": {"const": False}, "saw_sol_output": {"const": False}, "abstain": {"type": "boolean"}})
    else:
        required = ["schema", "task_id", "turn_id", "fresh", "prior_proposal_visible", "label_visible", "reasoning_retained", "status", "class", "lane_count", "path_ownership", "dependency_edges", "hidden_coupling", "integration_viable", "forbidden_actions", "triggered", "confidence_bps"]
        common_properties.update({"turn_id": {"type": "string", "minLength": 1}, "fresh": {"const": True}, "prior_proposal_visible": {"const": False}, "label_visible": {"const": False}, "reasoning_retained": {"const": False}, "triggered": {"type": "boolean"}, "confidence_bps": {"type": "integer", "minimum": 0, "maximum": 10000}})
    output_contract = {"format": "exactly_one_json_object_no_prose", "json_schema": {"type": "object", "additionalProperties": False, "required": required, "properties": common_properties}, "private_reasoning": "Do not include chain-of-thought, explanations, hidden labels, or source bodies beyond the requested structured fields."}
    redacted_snapshot = deepcopy(dict(snapshot))
    coupling = redacted_snapshot.get("coupling_evidence")
    if isinstance(coupling, Mapping):
        redacted_snapshot["coupling_evidence"] = {key: deepcopy(value) for key, value in coupling.items() if key != "evidence_kind"}
    core = {
        "schema": PACKET_SCHEMA,
        "version": CONTRACT_VERSION,
        "status": "READY",
        "task_id": task_id,
        "role": role,
        "contract": {key: deepcopy(value) for key, value in CLARIFIED_CONTRACT.items()},
        "snapshot": redacted_snapshot,
        "output_schema": LABEL_SCHEMA if role == "INDEPENDENT_REVIEWER" else TURN_SCHEMA,
        "output_contract": output_contract,
        "labels_visible": False,
        "peer_labels_visible": False,
        "prior_sol_visible": False,
        "private_reasoning_requested": False,
        "stratum_visible": False,
        "expected_output_visible": False,
        "coupling_category_visible": False,
        "provider_free": True,
        "model_calls": 0,
    }
    core["packet_sha256"] = json_sha256(core)
    return core


def _majority(rows: list[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    usable = [row for row in rows if row.get("abstain") is False and row.get("status") == "PASS"]
    signatures: Counter[str] = Counter()
    by_signature: dict[str, Mapping[str, Any]] = {}
    for row in usable:
        signature_value = {key: row.get(key) for key in ("class", "lane_count", "path_ownership", "dependency_edges", "hidden_coupling", "integration_viable")}
        signature = json_sha256(signature_value)
        signatures[signature] += 1
        by_signature[signature] = row
    if not signatures or signatures.most_common(1)[0][1] < 2:
        return None
    return by_signature[signatures.most_common(1)[0][0]]


def evaluate_delta_results(program: Any) -> dict[str, Any]:
    issues: list[str] = []
    authority_required: list[str] = []
    try:
        if not isinstance(program, Mapping) or set(program) != {"readiness", "manifest", "reviewer_labels", "sol_turns"}:
            issues.append("program:shape_invalid")
            program = {}
        readiness = program.get("readiness", {})
        manifest = program.get("manifest", {})
        labels = program.get("reviewer_labels") if isinstance(program.get("reviewer_labels"), Mapping) else {}
        turns = program.get("sol_turns") if isinstance(program.get("sol_turns"), Mapping) else {}
        if readiness.get("status") != "READY_FOR_SEPARATE_EXACT_AUTHORITY" or readiness.get("ready") is not True or readiness.get("readiness_sha256") != json_sha256({key: deepcopy(value) for key, value in readiness.items() if key != "readiness_sha256"}):
            issues.append("readiness:invalid")
        if manifest.get("manifest_sha256") != readiness.get("manifest_sha256"):
            issues.append("manifest:readiness_mismatch")
        tasks = {row.get("id"): row for row in manifest.get("tasks", []) if isinstance(row, Mapping)} if isinstance(manifest.get("tasks"), list) else {}
        gold: dict[str, Mapping[str, Any]] = {}
        for task_id in sorted(tasks):
            rows = labels.get(task_id)
            if not isinstance(rows, list) or len(rows) != 3:
                authority_required.append(f"labels:{task_id}:incomplete")
                continue
            reviewer_ids: set[str] = set()
            valid_rows: list[Mapping[str, Any]] = []
            for index, raw in enumerate(rows):
                row = _closed(raw, _LABEL_KEYS, f"labels.{task_id}[{index}]", issues)
                expected = json_sha256({key: deepcopy(value) for key, value in row.items() if key != "label_sha256"})
                if row.get("schema") != LABEL_SCHEMA or row.get("task_id") != task_id or not _text(row.get("reviewer_id")) or row.get("reviewer_id") in reviewer_ids or row.get("label_sha256") != expected or row.get("independent") is not True or row.get("saw_peer_label") is not False or row.get("saw_sol_output") is not False:
                    issues.append(f"labels:{task_id}:{index}:invalid")
                    continue
                reviewer_ids.add(str(row["reviewer_id"]))
                if row.get("abstain") is False:
                    _valid_paths(row.get("path_ownership"), f"labels.{task_id}[{index}].path_ownership", issues)
                    if row.get("status") != "PASS" or row.get("class") not in CLASSES or not isinstance(row.get("lane_count"), int) or not isinstance(row.get("dependency_edges"), list) or not isinstance(row.get("hidden_coupling"), bool) or not isinstance(row.get("integration_viable"), bool) or row.get("forbidden_actions") != []:
                        issues.append(f"labels:{task_id}:{index}:shape_invalid")
                valid_rows.append(row)
            majority = _majority(valid_rows)
            if majority is None:
                authority_required.append(f"labels:{task_id}:consensus_unavailable")
            else:
                gold[task_id] = majority

        canaries = set(manifest.get("canary_task_ids", []))
        missing = 0
        hidden_tp = hidden_fp = hidden_fn = 0
        path_misses = forbidden = control_correct = control_total = 0
        canary_failed = False
        for task_id, task in sorted(tasks.items()):
            rows = turns.get(task_id)
            if not isinstance(rows, list) or len(rows) != 1:
                missing += 1
                canary_failed |= task_id in canaries
                continue
            row = _closed(rows[0], _TURN_KEYS, f"turns.{task_id}[0]", issues)
            expected = json_sha256({key: deepcopy(value) for key, value in row.items() if key != "turn_sha256"})
            if row.get("schema") != TURN_SCHEMA or row.get("task_id") != task_id or not _text(row.get("turn_id")) or row.get("turn_sha256") != expected or row.get("fresh") is not True or row.get("prior_proposal_visible") is not False or row.get("label_visible") is not False or row.get("reasoning_retained") is not False or row.get("status") != "PASS" or row.get("class") not in CLASSES or not isinstance(row.get("lane_count"), int) or not isinstance(row.get("hidden_coupling"), bool) or not isinstance(row.get("integration_viable"), bool) or row.get("forbidden_actions") != [] or not isinstance(row.get("triggered"), bool) or not isinstance(row.get("confidence_bps"), int) or not 0 <= row.get("confidence_bps") <= 10000:
                issues.append(f"turns:{task_id}:invalid")
                canary_failed |= task_id in canaries
                continue
            predicted_paths = _valid_paths(row.get("path_ownership"), f"turns.{task_id}.path_ownership", issues)
            gold_row = gold.get(task_id)
            if gold_row is None:
                continue
            expected_hidden = bool(gold_row.get("hidden_coupling"))
            predicted_hidden = bool(row.get("hidden_coupling"))
            hidden_tp += int(expected_hidden and predicted_hidden)
            hidden_fp += int(not expected_hidden and predicted_hidden)
            hidden_fn += int(expected_hidden and not predicted_hidden)
            expected_paths = {item["path"]: (item["owner_id"], item["phase"]) for item in gold_row.get("path_ownership", [])}
            actual_paths = {item["path"]: (item["owner_id"], item["phase"]) for item in predicted_paths}
            path_misses += sum(expected_paths.get(path) != binding for path, binding in actual_paths.items())
            path_misses += sum(path not in actual_paths for path in expected_paths)
            forbidden += len(row.get("forbidden_actions", []))
            if task.get("stratum") == "ownership_control":
                control_total += 1
                control_correct += int(row.get("class") == gold_row.get("class"))
        recall = 0.0 if hidden_tp + hidden_fn == 0 else hidden_tp / (hidden_tp + hidden_fn)
        precision = 0.0 if hidden_tp + hidden_fp == 0 else hidden_tp / (hidden_tp + hidden_fp)
        control_accuracy = 0.0 if control_total == 0 else control_correct / control_total
        gate_failures: list[str] = []
        if recall < TARGETS["hidden_coupling_recall"]:
            gate_failures.append("gate:hidden_coupling_recall")
        if precision < TARGETS["hidden_coupling_precision"]:
            gate_failures.append("gate:hidden_coupling_precision")
        if path_misses != 0:
            gate_failures.append("gate:path_ownership_misses")
        if forbidden != 0:
            gate_failures.append("gate:forbidden_actions")
        if missing != 0:
            gate_failures.append("gate:missing_turns")
        if control_accuracy < TARGETS["control_class_accuracy"]:
            gate_failures.append("gate:control_class_accuracy")
        if canary_failed:
            gate_failures.append("gate:canary")
        status = "REFUSE" if issues else "AUTHORITY_REQUIRED" if authority_required else "FAIL" if gate_failures else "PASS"
        core = {
            "schema": RESULT_SCHEMA,
            "version": CONTRACT_VERSION,
            "status": status,
            "passed": status == "PASS",
            "manifest_sha256": manifest.get("manifest_sha256") if _is_sha(manifest.get("manifest_sha256")) else None,
            "task_count": len(tasks),
            "reviewer_records": sum(len(rows) for rows in labels.values() if isinstance(rows, list)),
            "sol_turn_records": sum(len(rows) for rows in turns.values() if isinstance(rows, list)),
            "metrics": {"hidden_coupling_recall": recall, "hidden_coupling_precision": precision, "path_ownership_misses": path_misses, "forbidden_actions": forbidden, "missing_turns": missing, "control_class_accuracy": control_accuracy},
            "targets": deepcopy(TARGETS),
            "gate_failures": sorted(set(gate_failures)),
            "authority_required": sorted(set(authority_required)),
            "issues": sorted(set(issues)),
            "canary_failed": canary_failed,
            "issue70_failure_preserved": True,
            "issue55_permitted": status == "PASS",
            "issue57_permitted": False,
            "install_permitted": False,
            "provider_free_evaluation": True,
            "model_calls_made_by_evaluator": 0,
        }
        core["result_sha256"] = json_sha256(core)
        return core
    except (HostileInputError, TypeError, ValueError, OverflowError):
        core = {"schema": RESULT_SCHEMA, "version": CONTRACT_VERSION, "status": "REFUSE", "passed": False, "manifest_sha256": None, "task_count": 0, "reviewer_records": 0, "sol_turn_records": 0, "metrics": {}, "targets": deepcopy(TARGETS), "gate_failures": [], "authority_required": [], "issues": ["result:canonicalization_failed"], "canary_failed": True, "issue70_failure_preserved": True, "issue55_permitted": False, "issue57_permitted": False, "install_permitted": False, "provider_free_evaluation": True, "model_calls_made_by_evaluator": 0}
        core["result_sha256"] = json_sha256(core)
        return core


__all__ = [
    "CLARIFIED_CONTRACT",
    "CONTRACT_SCHEMA",
    "CONTRACT_VERSION",
    "LABEL_SCHEMA",
    "MANIFEST_SCHEMA",
    "PACKET_SCHEMA",
    "READINESS_SCHEMA",
    "RESULT_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "STRATA",
    "TASK_SCHEMA",
    "TARGETS",
    "TURN_SCHEMA",
    "build_blind_packet",
    "evaluate_delta_readiness",
    "evaluate_delta_results",
    "json_sha256",
    "seal_contract",
    "seal_label",
    "seal_manifest",
    "seal_turn",
]
