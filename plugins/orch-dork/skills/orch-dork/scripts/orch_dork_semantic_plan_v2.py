#!/usr/bin/env python3
"""Provider-free semantic acceptance/resource/dependency closure contract."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import fnmatch
import hashlib
import importlib.util
import json
from pathlib import PurePosixPath, Path
import re
import sys
import unicodedata
from typing import Any

try:
    from orch_dork_hostile_input import PROFILE, HostileInputError, canonicalize_bounded_json
except ImportError:  # pragma: no cover - isolated policy loader.
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


CONTRACT_VERSION = "semantic-plan-v2"
TICKET_SCHEMA = "orch-dork/semantic-ticket/v2"
CRITERION_SCHEMA = "orch-dork/acceptance-criterion/v2"
CANDIDATE_SCHEMA = "orch-dork/semantic-candidate-plan/v2"
ADAPTER_SCHEMA = "orch-dork/semantic-project-adapter/v2"
DECISION_SCHEMA = "orch-dork/semantic-plan-decision/v2"
RECEIPT_SCHEMA = "orch-dork/semantic-plan-receipt/v2"

ADMIT = "ADMIT"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
REFUSE = "REFUSE"

PHASES = frozenset({"implementation", "integration", "generated", "install", "publication", "final_verification", "read_only"})
UNKNOWN_REASONS = frozenset(
    {
        "missing_source",
        "ambiguous_resource",
        "owner_unavailable",
        "dependency_unproven",
        "snapshot_stale",
        "adapter_unavailable",
        "verification_unknown",
    }
)
RISK_KINDS = frozenset(
    {
        "hidden_coupling",
        "irreversible_action",
        "high_consequence",
        "generated_drift",
        "publication_boundary",
        "ownership_ambiguity",
        "legacy_cycle",
        "natural_lane_overflow",
        "authority_mismatch",
    }
)
REVIEW_RISKS = frozenset({"hidden_coupling", "irreversible_action", "high_consequence", "generated_drift", "publication_boundary", "ownership_ambiguity", "natural_lane_overflow"})

_TICKET_KEYS = frozenset({"schema", "id", "spec_sha256", "authority_scope_sha256", "writable_scope_sha256"})
_CRITERION_KEYS = frozenset({"schema", "id", "description", "evidence_locator"})
_PLAN_KEYS = frozenset(
    {
        "schema",
        "ticket_id",
        "ticket_spec_sha256",
        "acceptance_sha256",
        "authority_scope_sha256",
        "writable_scope_sha256",
        "snapshot_digest",
        "adapter_generation",
        "lanes",
        "deliverables",
        "resources",
        "mappings",
        "dependencies",
        "integration",
        "unknowns",
        "risks",
        "protected_resources",
    }
)
_LANE_KEYS = frozenset({"id", "objective", "aliases", "retired", "owner_kind"})
_DELIVERABLE_KEYS = frozenset({"id", "description", "criterion_ids"})
_MAPPING_KEYS = frozenset({"criterion_id", "deliverable_id", "resource_id", "owner_id", "phase", "evidence_locator"})
_DEPENDENCY_KEYS = frozenset({"source", "target", "relation", "deliverable_ids", "resource_ids", "rationale", "evidence_locator"})
_INTEGRATION_KEYS = frozenset({"owner_kind", "owner_id", "resource_ids", "predecessor_evidence", "release_conditions"})
_RELEASE_KEYS = frozenset({"id", "kind", "evidence_locator", "expected_sha256", "status"})
_UNKNOWN_KEYS = frozenset({"reason", "source_locator", "detail"})
_RISK_KEYS = frozenset({"kind", "source_locator", "severity"})
_ADAPTER_KEYS = frozenset({"schema", "generation", "snapshot_digest", "status", "required_phases", "resource_bindings", "authority_scope_sha256", "writable_scope_sha256", "issues"})
_FRESHNESS_KEYS = frozenset(
    {
        "schema",
        "status",
        "fresh",
        "snapshot_digest",
        "static_digest",
        "volatile_digest",
        "deltas",
        "issues",
        "evidence_tier",
        "cache_hit",
        "mutation_permitted",
        "authority_granted",
        "admission_snapshot",
        "static_identities",
        "volatile_expiries",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "freshness_digest",
    }
)
_BINDING_KEYS = frozenset({"resource_id", "canonical_identity", "evidence_locator", "status"})
_CONCRETE_KEYS = frozenset({"id", "kind", "store", "path_kind", "selector", "content_sha256", "baseline_sha256", "adapter", "evidence_locator"})
_SEMANTIC_KEYS = frozenset({"id", "kind", "namespace", "key", "operation", "content_sha256", "adapter", "evidence_locator"})
_PLACEHOLDER = re.compile(r"(?i)(?:\btrust\s+me\b|\b(?:todo|tbd|placeholder)\b|\?\?\?)")


def canonical_bytes(value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return canonicalize_bounded_json(raw, profile=PROFILE, batch=isinstance(value, list))


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _text(value: Any, *, allow_placeholder: bool = False) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= PROFILE.max_string_bytes
        and (allow_placeholder or _PLACEHOLDER.search(value) is None)
    )


def _closed(value: Any, keys: frozenset[str], label: str, refuse: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        refuse.append(f"{label}:type_invalid")
        return {}
    refuse.extend(f"{label}:unknown_field:{field}" for field in sorted(set(value) - keys))
    return value


def _canonical_selector(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > PROFILE.max_path_bytes:
        return None
    if value.startswith(("/", "~", "\\")) or ":\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    if value.count("**") > 1 or any(char in value for char in "\x00\r\n"):
        return None
    return unicodedata.normalize("NFC", value)


def _canonical_resource(raw: Any, index: int, refuse: list[str]) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        refuse.append(f"resources[{index}]:type_invalid")
        return None
    kind = raw.get("kind")
    keys = _CONCRETE_KEYS if kind == "concrete" else _SEMANTIC_KEYS if kind == "semantic" else frozenset()
    value = _closed(raw, keys, f"resources[{index}]", refuse)
    if kind not in {"concrete", "semantic"}:
        refuse.append(f"resources[{index}]:kind_invalid")
        return None
    if not _text(value.get("id")) or not _text(value.get("adapter")) or not _text(value.get("evidence_locator")):
        refuse.append(f"resources[{index}]:identity_invalid")
        return None
    if not _is_sha(value.get("content_sha256")):
        refuse.append(f"resources[{index}]:content_identity_invalid")
    result = dict(value)
    if kind == "concrete":
        selector = _canonical_selector(value.get("selector"))
        if selector is None or value.get("path_kind") not in {"file", "directory", "glob", "generated", "install", "publication", "verification"} or not _text(value.get("store")):
            refuse.append(f"resources[{index}]:concrete_identity_invalid")
        else:
            result["selector"] = selector
        if not _is_sha(value.get("baseline_sha256")):
            refuse.append(f"resources[{index}]:baseline_identity_invalid")
    else:
        if not all(_text(value.get(field)) for field in ("namespace", "key", "operation")):
            refuse.append(f"resources[{index}]:semantic_identity_invalid")
    return result


def _resource_identity(value: Mapping[str, Any]) -> str:
    if value.get("kind") == "concrete":
        return "concrete:" + str(value.get("store")) + ":" + str(value.get("path_kind")) + ":" + str(value.get("selector")).casefold()
    return "semantic:" + str(value.get("namespace")) + ":" + str(value.get("key")) + ":" + str(value.get("operation"))


def _concrete_overlap(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    if first.get("kind") != "concrete" or second.get("kind") != "concrete" or first.get("store") != second.get("store"):
        return False
    left = str(first.get("selector"))
    right = str(second.get("selector"))
    if left == right or fnmatch.fnmatchcase(left, right) or fnmatch.fnmatchcase(right, left):
        return True
    left_prefix = left.split("*", 1)[0].rstrip("/")
    right_prefix = right.split("*", 1)[0].rstrip("/")
    return bool(left_prefix and right_prefix) and (
        left_prefix.startswith(right_prefix + "/") or right_prefix.startswith(left_prefix + "/")
    )


def _has_cycle(edges: Mapping[str, set[str]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for target in sorted(edges.get(node, set())):
            if visit(target):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in sorted(edges))


def validate_semantic_plan_v2(
    ticket: Any,
    acceptance_criteria: Any,
    candidate_plan: Any,
    evidence_snapshot: Any,
    project_adapter: Any,
) -> dict[str, Any]:
    """Validate one complete semantic plan without performing work."""

    refuse: list[str] = []
    review: list[str] = []
    try:
        ticket_value = _closed(ticket, _TICKET_KEYS, "ticket", refuse)
        if ticket_value.get("schema") != TICKET_SCHEMA or not _text(ticket_value.get("id")):
            refuse.append("ticket:identity_invalid")
        for field in ("spec_sha256", "authority_scope_sha256", "writable_scope_sha256"):
            if not _is_sha(ticket_value.get(field)):
                refuse.append(f"ticket:{field}_invalid")

        criteria = acceptance_criteria if isinstance(acceptance_criteria, list) else []
        if not isinstance(acceptance_criteria, list) or not criteria or len(criteria) > PROFILE.max_operations:
            refuse.append("acceptance_criteria:invalid")
        criterion_rows: list[dict[str, Any]] = []
        criterion_ids: set[str] = set()
        for index, raw in enumerate(criteria):
            row = _closed(raw, _CRITERION_KEYS, f"criteria[{index}]", refuse)
            criterion_id = row.get("id")
            if row.get("schema") != CRITERION_SCHEMA or not _text(criterion_id) or criterion_id in criterion_ids or not _text(row.get("description")) or not _text(row.get("evidence_locator")):
                refuse.append(f"criteria[{index}]:invalid")
                continue
            criterion_ids.add(str(criterion_id))
            criterion_rows.append(dict(row))
        criterion_rows = sorted(criterion_rows, key=lambda row: row["id"])
        acceptance_sha = json_sha256(criterion_rows)

        freshness = _closed(evidence_snapshot, _FRESHNESS_KEYS, "evidence_snapshot", refuse)
        snapshot_digest = freshness.get("snapshot_digest")
        if freshness.get("schema") != "orch-dork/snapshot-freshness/v1" or freshness.get("status") != "FRESH" or freshness.get("fresh") is not True:
            review.append("snapshot:not_fresh")
        if not _is_sha(snapshot_digest) or not _is_sha(freshness.get("freshness_digest")) or freshness.get("admission_snapshot") is None:
            review.append("snapshot:identity_unavailable")
        else:
            expected_freshness = json_sha256({key: deepcopy(value) for key, value in freshness.items() if key != "freshness_digest"})
            if freshness.get("freshness_digest") != expected_freshness:
                refuse.append("snapshot:freshness_digest_mismatch")
            admission_snapshot = freshness.get("admission_snapshot")
            if not isinstance(admission_snapshot, Mapping) or not _is_sha(admission_snapshot.get("snapshot_sha256")):
                refuse.append("snapshot:admission_projection_invalid")
            else:
                expected_projection = json_sha256({key: deepcopy(value) for key, value in admission_snapshot.items() if key != "snapshot_sha256"})
                if admission_snapshot.get("snapshot_sha256") != expected_projection:
                    refuse.append("snapshot:admission_projection_digest_mismatch")
        if freshness.get("mutation_permitted") is not False or freshness.get("authority_granted") is not False:
            refuse.append("snapshot:authority_expansion")

        adapter = _closed(project_adapter, _ADAPTER_KEYS, "project_adapter", refuse)
        if adapter.get("schema") != ADAPTER_SCHEMA or not _text(adapter.get("generation")):
            refuse.append("project_adapter:identity_invalid")
        if adapter.get("snapshot_digest") != snapshot_digest:
            refuse.append("project_adapter:snapshot_mismatch")
        if adapter.get("status") == "UNAVAILABLE":
            review.append("project_adapter:unavailable")
        elif adapter.get("status") != "PASS":
            refuse.append("project_adapter:status_invalid")
        if adapter.get("authority_scope_sha256") != ticket_value.get("authority_scope_sha256") or adapter.get("writable_scope_sha256") != ticket_value.get("writable_scope_sha256"):
            refuse.append("project_adapter:authority_or_scope_mismatch")
        required_phases = adapter.get("required_phases")
        if not isinstance(required_phases, list) or not required_phases or any(phase not in PHASES for phase in required_phases):
            refuse.append("project_adapter:required_phases_invalid")
            required_phases = []

        plan = _closed(candidate_plan, _PLAN_KEYS, "candidate_plan", refuse)
        if plan.get("schema") != CANDIDATE_SCHEMA:
            refuse.append("candidate_plan:schema_invalid")
        identity_checks = {
            "ticket_id": ticket_value.get("id"),
            "ticket_spec_sha256": ticket_value.get("spec_sha256"),
            "acceptance_sha256": acceptance_sha,
            "authority_scope_sha256": ticket_value.get("authority_scope_sha256"),
            "writable_scope_sha256": ticket_value.get("writable_scope_sha256"),
            "snapshot_digest": snapshot_digest,
            "adapter_generation": adapter.get("generation"),
        }
        for field, expected in identity_checks.items():
            if plan.get(field) != expected:
                refuse.append(f"candidate_plan:{field}_mismatch")

        lanes_raw = plan.get("lanes")
        lanes_raw = lanes_raw if isinstance(lanes_raw, list) else []
        if not lanes_raw or len(lanes_raw) > PROFILE.max_operations:
            refuse.append("lanes:invalid")
        lanes: list[dict[str, Any]] = []
        lane_ids: set[str] = set()
        aliases: dict[str, str] = {}
        retired: set[str] = set()
        for index, raw in enumerate(lanes_raw):
            lane = _closed(raw, _LANE_KEYS, f"lanes[{index}]", refuse)
            lane_id = lane.get("id")
            if not _text(lane_id) or lane_id in lane_ids or not _text(lane.get("objective")) or lane.get("owner_kind") not in {"lane", "root"}:
                refuse.append(f"lanes[{index}]:invalid")
                continue
            lane_ids.add(str(lane_id))
            lane_aliases = lane.get("aliases")
            if not isinstance(lane_aliases, list) or any(not _text(alias) for alias in lane_aliases):
                refuse.append(f"lanes[{index}]:aliases_invalid")
                lane_aliases = []
            for alias in lane_aliases:
                if alias in aliases or alias in lane_ids:
                    refuse.append(f"lanes[{index}]:alias_conflict")
                aliases[str(alias)] = str(lane_id)
            if lane.get("retired") is not False:
                retired.add(str(lane_id))
            lanes.append(dict(lane))
        natural_lane_count = len([lane for lane in lanes if lane.get("retired") is False])
        if set(aliases) & lane_ids:
            refuse.append("lanes:alias_conflict")
        risks: list[dict[str, Any]] = []
        if natural_lane_count > 4:
            review.append("risk:natural_lane_overflow")
            risks.append({"kind": "natural_lane_overflow", "source_locator": "semantic-plan#lanes", "severity": "high"})

        resources_raw = plan.get("resources")
        resources_raw = resources_raw if isinstance(resources_raw, list) else []
        resources: list[dict[str, Any]] = []
        resource_by_id: dict[str, dict[str, Any]] = {}
        identities: dict[str, str] = {}
        for index, raw in enumerate(resources_raw):
            resource = _canonical_resource(raw, index, refuse)
            if resource is None:
                continue
            resource_id = str(resource["id"])
            identity = _resource_identity(resource)
            if resource_id in resource_by_id or identity in identities:
                refuse.append(f"resources[{index}]:duplicate_or_overlap")
            resource_by_id[resource_id] = resource
            identities[identity] = resource_id
            resources.append(resource)
        for left_index, left in enumerate(resources):
            for right in resources[left_index + 1 :]:
                if _concrete_overlap(left, right):
                    refuse.append(f"resources:concrete_overlap:{left['id']}:{right['id']}")
        protected = plan.get("protected_resources")
        if not isinstance(protected, list):
            refuse.append("protected_resources:invalid")
            protected = []
        protected_normalized = {unicodedata.normalize("NFC", str(item)).casefold() for item in protected if _text(item)}
        for identity, resource_id in identities.items():
            if identity.casefold() in protected_normalized or resource_id.casefold() in protected_normalized:
                refuse.append(f"resources:protected_overlap:{resource_id}")

        bindings = adapter.get("resource_bindings")
        bindings = bindings if isinstance(bindings, list) else []
        adapter_by_resource: dict[str, Mapping[str, Any]] = {}
        for index, raw in enumerate(bindings):
            binding = _closed(raw, _BINDING_KEYS, f"project_adapter.resource_bindings[{index}]", refuse)
            resource_id = binding.get("resource_id")
            if resource_id in adapter_by_resource or resource_id not in resource_by_id or not _text(binding.get("canonical_identity")) or not _text(binding.get("evidence_locator")):
                refuse.append(f"project_adapter.resource_bindings[{index}]:invalid")
                continue
            if binding.get("status") == "UNAVAILABLE":
                review.append(f"project_adapter:resource_unavailable:{resource_id}")
            elif binding.get("status") != "PASS":
                refuse.append(f"project_adapter:resource_refused:{resource_id}")
            if binding.get("canonical_identity") != _resource_identity(resource_by_id[str(resource_id)]):
                refuse.append(f"project_adapter:resource_disagreement:{resource_id}")
            adapter_by_resource[str(resource_id)] = binding
        if set(adapter_by_resource) != set(resource_by_id):
            review.append("project_adapter:resource_binding_incomplete")

        deliverables_raw = plan.get("deliverables")
        deliverables_raw = deliverables_raw if isinstance(deliverables_raw, list) else []
        deliverables: list[dict[str, Any]] = []
        deliverable_by_id: dict[str, dict[str, Any]] = {}
        for index, raw in enumerate(deliverables_raw):
            row = _closed(raw, _DELIVERABLE_KEYS, f"deliverables[{index}]", refuse)
            deliverable_id = row.get("id")
            criterion_refs = row.get("criterion_ids")
            if not _text(deliverable_id) or deliverable_id in deliverable_by_id or not _text(row.get("description")) or not isinstance(criterion_refs, list) or not criterion_refs or any(item not in criterion_ids for item in criterion_refs):
                refuse.append(f"deliverables[{index}]:invalid")
                continue
            deliverable_by_id[str(deliverable_id)] = dict(row)
            deliverables.append(dict(row))

        mappings_raw = plan.get("mappings")
        mappings_raw = mappings_raw if isinstance(mappings_raw, list) else []
        mappings: list[dict[str, Any]] = []
        mapping_keys: set[tuple[str, str, str]] = set()
        mapped_criteria: set[str] = set()
        mapped_phases: set[str] = set()
        resource_owners: dict[str, str] = {}
        for index, raw in enumerate(mappings_raw):
            row = _closed(raw, _MAPPING_KEYS, f"mappings[{index}]", refuse)
            criterion_id = row.get("criterion_id")
            deliverable_id = row.get("deliverable_id")
            resource_id = row.get("resource_id")
            owner_id = aliases.get(str(row.get("owner_id")), row.get("owner_id"))
            phase = row.get("phase")
            key = (str(criterion_id), str(deliverable_id), str(resource_id))
            if key in mapping_keys or criterion_id not in criterion_ids or deliverable_id not in deliverable_by_id or resource_id not in resource_by_id or owner_id not in lane_ids or phase not in PHASES or not _text(row.get("evidence_locator")):
                refuse.append(f"mappings[{index}]:invalid")
                continue
            if criterion_id not in deliverable_by_id[str(deliverable_id)].get("criterion_ids", []):
                refuse.append(f"mappings[{index}]:criterion_deliverable_mismatch")
            prior_owner = resource_owners.get(str(resource_id))
            if prior_owner is not None and prior_owner != owner_id:
                refuse.append(f"mappings[{index}]:duplicate_owner:{resource_id}")
            resource_owners[str(resource_id)] = str(owner_id)
            mapping_keys.add(key)
            mapped_criteria.add(str(criterion_id))
            mapped_phases.add(str(phase))
            normalized = dict(row)
            normalized["owner_id"] = owner_id
            mappings.append(normalized)
        if mapped_criteria != criterion_ids:
            refuse.append("mappings:criterion_closure_incomplete")
        for phase in required_phases:
            if phase not in mapped_phases:
                refuse.append(f"mappings:required_phase_missing:{phase}")
        if set(resource_owners) != set(resource_by_id):
            refuse.append("mappings:resource_owner_incomplete")

        dependencies_raw = plan.get("dependencies")
        dependencies_raw = dependencies_raw if isinstance(dependencies_raw, list) else []
        pair_rows: dict[tuple[str, str], dict[str, Any]] = {}
        edges: dict[str, set[str]] = {lane_id: set() for lane_id in lane_ids}
        for index, raw in enumerate(dependencies_raw):
            row = _closed(raw, _DEPENDENCY_KEYS, f"dependencies[{index}]", refuse)
            source = aliases.get(str(row.get("source")), row.get("source"))
            target = aliases.get(str(row.get("target")), row.get("target"))
            relation = row.get("relation")
            pair = (str(source), str(target))
            if source == target or source not in lane_ids or target not in lane_ids or source in retired or target in retired or pair in pair_rows or relation not in {"edge", "no_edge"} or not _text(row.get("evidence_locator")):
                refuse.append(f"dependencies[{index}]:invalid")
                continue
            if relation == "edge":
                deliverable_ids = row.get("deliverable_ids")
                resource_ids = row.get("resource_ids")
                if not isinstance(deliverable_ids, list) or not deliverable_ids or any(item not in deliverable_by_id for item in deliverable_ids) or not isinstance(resource_ids, list) or not resource_ids or any(item not in resource_by_id for item in resource_ids):
                    refuse.append(f"dependencies[{index}]:edge_evidence_invalid")
                edges[str(source)].add(str(target))
            else:
                if not _text(row.get("rationale")):
                    refuse.append(f"dependencies[{index}]:no_edge_rationale_invalid")
            normalized = dict(row)
            normalized["source"] = source
            normalized["target"] = target
            pair_rows[pair] = normalized
        active_ids = sorted(lane_id for lane_id in lane_ids if lane_id not in retired)
        expected_pairs = {(source, target) for source in active_ids for target in active_ids if source != target}
        if set(pair_rows) != expected_pairs:
            refuse.append("dependencies:ordered_pair_closure_incomplete")
        if _has_cycle(edges):
            refuse.append("dependencies:cycle")

        integration = _closed(plan.get("integration"), _INTEGRATION_KEYS, "integration", refuse)
        owner_kind = integration.get("owner_kind")
        owner_id = aliases.get(str(integration.get("owner_id")), integration.get("owner_id"))
        integration_resources = integration.get("resource_ids")
        if owner_kind not in {"lane", "root"} or owner_id not in lane_ids or not isinstance(integration_resources, list) or any(item not in resource_by_id for item in integration_resources):
            refuse.append("integration:owner_or_resources_invalid")
        if natural_lane_count >= 2 and owner_kind == "root":
            refuse.append("integration:coordination_root_cannot_integrate")
        for resource_id in integration_resources if isinstance(integration_resources, list) else []:
            if resource_owners.get(str(resource_id)) != owner_id:
                refuse.append(f"integration:owner_mismatch:{resource_id}")
        predecessor = integration.get("predecessor_evidence")
        if not isinstance(predecessor, list) or not predecessor or any(not _text(item) for item in predecessor):
            refuse.append("integration:predecessor_evidence_invalid")
        releases_raw = integration.get("release_conditions")
        releases_raw = releases_raw if isinstance(releases_raw, list) else []
        if not releases_raw:
            refuse.append("integration:release_conditions_missing")
        releases: list[dict[str, Any]] = []
        release_ids: set[str] = set()
        for index, raw in enumerate(releases_raw):
            row = _closed(raw, _RELEASE_KEYS, f"integration.release_conditions[{index}]", refuse)
            if not _text(row.get("id")) or row.get("id") in release_ids or not _text(row.get("kind")) or not _text(row.get("evidence_locator")) or not _is_sha(row.get("expected_sha256")) or row.get("status") not in {"required", "satisfied"}:
                refuse.append(f"integration.release_conditions[{index}]:invalid")
                continue
            release_ids.add(str(row["id"]))
            releases.append(dict(row))

        unknowns_raw = plan.get("unknowns")
        unknowns_raw = unknowns_raw if isinstance(unknowns_raw, list) else []
        unknowns: list[dict[str, Any]] = []
        for index, raw in enumerate(unknowns_raw):
            row = _closed(raw, _UNKNOWN_KEYS, f"unknowns[{index}]", refuse)
            if row.get("reason") not in UNKNOWN_REASONS or not _text(row.get("source_locator")) or not _text(row.get("detail"), allow_placeholder=True):
                refuse.append(f"unknowns[{index}]:invalid")
                continue
            unknowns.append(dict(row))
            review.append(f"unknown:{row['reason']}")

        risks_raw = plan.get("risks")
        risks_raw = risks_raw if isinstance(risks_raw, list) else []
        for index, raw in enumerate(risks_raw):
            row = _closed(raw, _RISK_KEYS, f"risks[{index}]", refuse)
            if row.get("kind") not in RISK_KINDS or not _text(row.get("source_locator")) or row.get("severity") not in {"low", "medium", "high", "critical"}:
                refuse.append(f"risks[{index}]:invalid")
                continue
            risks.append(dict(row))
            if row.get("kind") in REVIEW_RISKS or row.get("severity") in {"high", "critical"}:
                review.append(f"risk:{row['kind']}")
            if row.get("kind") in {"legacy_cycle", "authority_mismatch"}:
                refuse.append(f"risk:{row['kind']}")

        if adapter.get("issues"):
            review.append("project_adapter:reported_issues")
        disposition = REFUSE if refuse else REVIEW_REQUIRED if review else ADMIT
        normalized = {
            "criteria": sorted(criterion_rows, key=lambda row: row["id"]),
            "lanes": sorted(lanes, key=lambda row: row["id"]),
            "deliverables": sorted(deliverables, key=lambda row: row["id"]),
            "resources": sorted(resources, key=lambda row: row["id"]),
            "mappings": sorted(mappings, key=lambda row: (row["criterion_id"], row["deliverable_id"], row["resource_id"])),
            "dependencies": sorted(pair_rows.values(), key=lambda row: (row["source"], row["target"])),
            "integration": {"owner_kind": owner_kind, "owner_id": owner_id, "resource_ids": sorted(integration_resources) if isinstance(integration_resources, list) else [], "predecessor_evidence": sorted(predecessor) if isinstance(predecessor, list) else [], "release_conditions": sorted(releases, key=lambda row: row["id"])},
        }
        core = {
            "schema": DECISION_SCHEMA,
            "contract_version": CONTRACT_VERSION,
            "disposition": disposition,
            "admitted": disposition == ADMIT,
            "ticket_id": ticket_value.get("id"),
            "ticket_spec_sha256": ticket_value.get("spec_sha256"),
            "acceptance_sha256": acceptance_sha,
            "authority_scope_sha256": ticket_value.get("authority_scope_sha256"),
            "writable_scope_sha256": ticket_value.get("writable_scope_sha256"),
            "snapshot_digest": snapshot_digest if _is_sha(snapshot_digest) else None,
            "snapshot_freshness_digest": freshness.get("freshness_digest") if _is_sha(freshness.get("freshness_digest")) else None,
            "adapter_generation": adapter.get("generation"),
            "natural_lane_count": natural_lane_count,
            "normalized_plan": normalized,
            "unknowns": sorted(unknowns, key=lambda row: (row["reason"], row["source_locator"])),
            "risks": sorted(risks, key=lambda row: (row["kind"], row["source_locator"])),
            "reason_codes": sorted(set(refuse + review)),
            "evidence_pointer": "semantic-plan-v2#decision",
            "evidence_tier": "provider-free-verified" if disposition == ADMIT else "provider-free-deterministic",
            "mutation_permitted": False,
            "authority_granted": False,
            "workers_permitted": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        core["decision_digest"] = json_sha256(core)
        if len(canonical_bytes(core)) > PROFILE.canonical_json_bytes:
            raise ValueError("decision_output_too_large")
        return core
    except (HostileInputError, TypeError, ValueError, OverflowError):
        core = {
            "schema": DECISION_SCHEMA,
            "contract_version": CONTRACT_VERSION,
            "disposition": REFUSE,
            "admitted": False,
            "ticket_id": None,
            "ticket_spec_sha256": None,
            "acceptance_sha256": None,
            "authority_scope_sha256": None,
            "writable_scope_sha256": None,
            "snapshot_digest": None,
            "snapshot_freshness_digest": None,
            "adapter_generation": None,
            "natural_lane_count": 0,
            "normalized_plan": {},
            "unknowns": [],
            "risks": [],
            "reason_codes": ["contract:canonicalization_failed"],
            "evidence_pointer": "semantic-plan-v2#refusal",
            "evidence_tier": "provider-free-deterministic",
            "mutation_permitted": False,
            "authority_granted": False,
            "workers_permitted": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        core["decision_digest"] = json_sha256(core)
        return core


def evaluate_semantic_plan_v2(program: Any) -> dict[str, Any]:
    if not isinstance(program, Mapping) or set(program) != {"ticket", "acceptance_criteria", "candidate_plan", "evidence_snapshot", "project_adapter"}:
        return validate_semantic_plan_v2({}, [], {}, {}, {})
    return validate_semantic_plan_v2(
        program["ticket"],
        program["acceptance_criteria"],
        program["candidate_plan"],
        program["evidence_snapshot"],
        program["project_adapter"],
    )


def semantic_plan_receipt(decision: Any) -> dict[str, Any]:
    value = decision if isinstance(decision, Mapping) else {}
    core = {
        "schema": RECEIPT_SCHEMA,
        "contract_version": CONTRACT_VERSION,
        "disposition": value.get("disposition") if value.get("disposition") in {ADMIT, REVIEW_REQUIRED, REFUSE} else REFUSE,
        "ticket_id": value.get("ticket_id"),
        "ticket_spec_sha256": value.get("ticket_spec_sha256") if _is_sha(value.get("ticket_spec_sha256")) else None,
        "acceptance_sha256": value.get("acceptance_sha256") if _is_sha(value.get("acceptance_sha256")) else None,
        "snapshot_digest": value.get("snapshot_digest") if _is_sha(value.get("snapshot_digest")) else None,
        "snapshot_freshness_digest": value.get("snapshot_freshness_digest") if _is_sha(value.get("snapshot_freshness_digest")) else None,
        "decision_digest": value.get("decision_digest") if _is_sha(value.get("decision_digest")) else None,
        "natural_lane_count": value.get("natural_lane_count") if isinstance(value.get("natural_lane_count"), int) else 0,
        "unknown_reason_codes": sorted({row.get("reason") for row in value.get("unknowns", []) if isinstance(row, Mapping) and row.get("reason") in UNKNOWN_REASONS}),
        "risk_kinds": sorted({row.get("kind") for row in value.get("risks", []) if isinstance(row, Mapping) and row.get("kind") in RISK_KINDS}),
        "reason_codes": list(value.get("reason_codes", [])) if isinstance(value.get("reason_codes"), list) else ["contract:missing_decision"],
        "downstream_ticket": "54",
        "mutation_permitted": False,
        "authority_granted": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    core["receipt_digest"] = json_sha256(core)
    return core


__all__ = [
    "CONTRACT_VERSION",
    "TICKET_SCHEMA",
    "CRITERION_SCHEMA",
    "CANDIDATE_SCHEMA",
    "ADAPTER_SCHEMA",
    "DECISION_SCHEMA",
    "RECEIPT_SCHEMA",
    "ADMIT",
    "REVIEW_REQUIRED",
    "REFUSE",
    "PHASES",
    "UNKNOWN_REASONS",
    "RISK_KINDS",
    "validate_semantic_plan_v2",
    "evaluate_semantic_plan_v2",
    "semantic_plan_receipt",
    "canonical_bytes",
    "json_sha256",
]
