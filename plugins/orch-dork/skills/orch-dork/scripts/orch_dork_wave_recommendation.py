#!/usr/bin/env python3
"""Deterministic provider-free first-wave recommendations (FR49).

The estimator consumes caller-declared task, acceptance, capability, topology,
and scout evidence and emits one sealed advisory recommendation.  It does not
freeze a plan, inspect capacity, alter a ceiling, permit workers, or grant
authority.  The ordinary FR47 split gate remains the decision boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any

try:
    from orch_dork_hostile_input import (
        PROFILE,
        HostileInputError,
        canonicalize_bounded_json,
    )
except ImportError:  # pragma: no cover - isolated direct-file loading.
    _hostile_path = Path(__file__).resolve().with_name("orch_dork_hostile_input.py")
    _hostile_spec = importlib.util.spec_from_file_location(
        "orch_dork_hostile_input", _hostile_path
    )
    if _hostile_spec is None or _hostile_spec.loader is None:
        raise
    _hostile = importlib.util.module_from_spec(_hostile_spec)
    sys.modules.setdefault("orch_dork_hostile_input", _hostile)
    _hostile_spec.loader.exec_module(_hostile)
    PROFILE = _hostile.PROFILE
    HostileInputError = _hostile.HostileInputError
    canonicalize_bounded_json = _hostile.canonicalize_bounded_json

try:
    import orch_dork_topology as topology
except ImportError:  # pragma: no cover - isolated direct-file loading.
    _topology_path = Path(__file__).resolve().with_name("orch_dork_topology.py")
    _topology_spec = importlib.util.spec_from_file_location(
        "orch_dork_topology", _topology_path
    )
    if _topology_spec is None or _topology_spec.loader is None:
        raise
    topology = importlib.util.module_from_spec(_topology_spec)
    sys.modules.setdefault("orch_dork_topology", topology)
    _topology_spec.loader.exec_module(topology)


PROGRAM_SCHEMA = "orch-dork/wave-estimator-program/v1"
RECOMMENDATION_SCHEMA = "orch-dork/wave-recommendation/v1"
VALIDATION_SCHEMA = "orch-dork/wave-recommendation-validation/v1"
OUTCOME_EVIDENCE_SCHEMA = "orch-dork/wave-recommendation-outcome-evidence/v1"
OUTCOME_SCHEMA = "orch-dork/wave-recommendation-outcome/v1"
OUTCOME_REPORT_SCHEMA = "orch-dork/wave-recommendation-outcome-report/v1"
ESTIMATOR_VERSION = "first-wave-estimator/v0"

MAX_FIRST_WAVE_LANES = 32
DISPOSITIONS = frozenset({"RECOMMEND", "REFUSE"})

_PROGRAM_FIELDS = frozenset(
    {
        "schema",
        "recommendation_id",
        "task",
        "acceptance_units",
        "capability_profile",
        "coupling_prior",
        "scout_budget",
        "scout_deltas",
    }
)
_TASK_FIELDS = frozenset({"task_id", "touch_set"})
_ACCEPTANCE_FIELDS = frozenset(
    {"id", "independently_verifiable", "evidence_locator", "touch_set"}
)
_CAPABILITY_FIELDS = frozenset(
    {"model_profile", "effort_profile", "required_capabilities"}
)
_SCOUT_BUDGET_FIELDS = frozenset({"max_scouts"})
_PRIOR_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "root",
        "group_depth",
        "hub_in_degree",
        "nodes",
        "edges",
        "hubs",
        "graph_sha256",
    }
)
_PRIOR_NODE_FIELDS = frozenset({"id", "file_count", "line_count", "weight"})
_PRIOR_EDGE_FIELDS = frozenset({"src", "dst", "import_count", "weight"})
_RECOMMENDATION_FIELDS = frozenset(
    {
        "schema",
        "estimator_version",
        "status",
        "issues",
        "recommendation_id",
        "task_id",
        "disposition",
        "reason_codes",
        "lane_count",
        "candidate_cut",
        "confidence_bps",
        "evidence_basis",
        "scout_allocation",
        "estimator_input_sha256",
        "advisory_only",
        "split_gate_required",
        "plan_frozen",
        "workers_permitted",
        "authority_granted",
        "capacity_consulted",
        "capacity_ceiling_changed",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "recommendation_sha256",
    }
)
_LANE_FIELDS = frozenset(
    {
        "lane_id",
        "touch_set",
        "acceptance_units",
        "capability_profile",
        "evidence_basis",
    }
)
_LANE_BASIS_FIELDS = frozenset(
    {
        "touch_set_sha256",
        "acceptance_units_sha256",
        "capability_profile_sha256",
        "coupling_evidence_sha256",
    }
)
_EVIDENCE_BASIS_FIELDS = frozenset(
    {"source_hashes", "element_sources", "confidence_components"}
)
_SOURCE_HASH_FIELDS = frozenset(
    {
        "task_touch_set_sha256",
        "acceptance_units_sha256",
        "topology_graph_sha256",
        "scout_delta_sha256s",
        "capability_profile_sha256",
    }
)
_ELEMENT_SOURCE_FIELDS = frozenset(
    {"lane_count", "candidate_cut", "capability_profile", "confidence"}
)
_CONFIDENCE_FIELDS = frozenset(
    {
        "base_bps",
        "resolved_touch_bps",
        "acceptance_coverage_bps",
        "scout_confirmation_bps",
        "uncertainty_penalty_bps",
        "total_bps",
    }
)
_SCOUT_ALLOCATION_FIELDS = frozenset(
    {"max_scouts", "used_scouts", "territory_refs", "delta_sha256s", "bounded"}
)
_OUTCOME_EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "recommendation",
        "disposition",
        "selection",
        "realized_outcome",
        "trace",
    }
)
_SELECTION_FIELDS = frozenset(
    {"lane_count", "candidate_cut", "override_reason"}
)
_REALIZED_FIELDS = frozenset(
    {
        "status",
        "lane_count",
        "acceptance_unit_results",
        "wall_time",
        "integration_cost",
        "trace_sha256",
    }
)
_ACCEPTANCE_RESULT_FIELDS = frozenset({"id", "status"})
_MEASUREMENT_FIELDS = frozenset({"status", "value_ms", "reason"})
_OUTCOME_FIELDS = frozenset(
    {
        "schema",
        "recommendation",
        "disposition",
        "selection",
        "realized_outcome",
        "trace",
        "record_sha256",
    }
)
_TRACE_ACCEPTANCE_FIELDS = frozenset(
    {"schema", "recommendation_sha256", "acceptance_unit_id", "status"}
)
_TRACE_INTEGRATION_FIELDS = frozenset(
    {"schema", "recommendation_sha256", "duration_ms"}
)
TRACE_ACCEPTANCE_SCHEMA = "orch-dork/wave-acceptance-result/v1"
TRACE_INTEGRATION_SCHEMA = "orch-dork/wave-integration-cost/v1"

_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")

_ADVISORY_INVARIANTS: dict[str, Any] = {
    "advisory_only": True,
    "split_gate_required": True,
    "plan_frozen": False,
    "workers_permitted": False,
    "authority_granted": False,
    "capacity_consulted": False,
    "capacity_ceiling_changed": False,
    "provider_free": True,
    "model_calls": 0,
    "hosted_calls": 0,
}


def _load_trace_module() -> Any:
    """Load the trace ledger only for the mutating outcome-record seam."""

    try:
        import orch_dork_trace

        return orch_dork_trace
    except ImportError:  # pragma: no cover - isolated direct-file loading.
        trace_path = Path(__file__).resolve().with_name("orch_dork_trace.py")
        trace_spec = importlib.util.spec_from_file_location(
            "orch_dork_trace", trace_path
        )
        if trace_spec is None or trace_spec.loader is None:
            raise
        trace_module = importlib.util.module_from_spec(trace_spec)
        scripts_path = str(trace_path.parent)
        inserted_path = scripts_path not in sys.path
        if inserted_path:
            sys.path.insert(0, scripts_path)
        sys.modules.setdefault("orch_dork_trace", trace_module)
        try:
            trace_spec.loader.exec_module(trace_module)
        finally:
            if inserted_path and sys.path and sys.path[0] == scripts_path:
                sys.path.pop(0)
        return trace_module


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonicalize_bounded_json(raw, profile=PROFILE, batch=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _closed(
    value: Any,
    fields: frozenset[str],
    label: str,
    issues: list[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, f"{label}:type_invalid")
        return {}
    result = dict(value)
    for field in sorted(fields - set(result)):
        _issue(issues, f"{label}:missing_field:{field}")
    for field in sorted(set(result) - fields):
        _issue(issues, f"{label}:unknown_field:{field}")
    return result


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= PROFILE.max_string_bytes
    )


def _bounded_int(value: Any, *, maximum: int | None = None) -> bool:
    return (
        type(value) is int
        and value >= 0
        and (maximum is None or value <= maximum)
    )


def _string_list(
    value: Any,
    label: str,
    issues: list[str],
    *,
    identifiers: bool = False,
    allow_empty: bool = True,
) -> list[str]:
    if not isinstance(value, list) or len(value) > PROFILE.max_array_items:
        _issue(issues, f"{label}:array_invalid")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        valid = _identifier(item) if identifiers else _text(item)
        if not valid:
            _issue(issues, f"{label}[{index}]:value_invalid")
            continue
        result.append(str(item))
    if len(result) != len(set(result)):
        _issue(issues, f"{label}:duplicate")
    if not allow_empty and not result:
        _issue(issues, f"{label}:empty")
    return result


def _sha_valid(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _validate_capability_profile(
    value: Any,
    label: str,
    issues: list[str],
) -> dict[str, Any]:
    profile = _closed(value, _CAPABILITY_FIELDS, label, issues)
    if not _identifier(profile.get("model_profile")):
        _issue(issues, f"{label}:model_profile_invalid")
    if not _identifier(profile.get("effort_profile")):
        _issue(issues, f"{label}:effort_profile_invalid")
    capabilities = _string_list(
        profile.get("required_capabilities"),
        f"{label}.required_capabilities",
        issues,
        identifiers=True,
        allow_empty=False,
    )
    return {
        "model_profile": profile.get("model_profile"),
        "effort_profile": profile.get("effort_profile"),
        "required_capabilities": sorted(capabilities),
    }


def _validate_prior(value: Any, issues: list[str]) -> tuple[dict[str, Any], set[str], list[tuple[str, str]]]:
    prior = _closed(value, _PRIOR_FIELDS, "coupling_prior", issues)
    if prior.get("schema") != topology.PRIOR_SCHEMA:
        _issue(issues, "coupling_prior:schema_invalid")
    if prior.get("status") != "PASS" or prior.get("issues") != []:
        _issue(issues, "coupling_prior:not_pass")
    if (
        prior.get("provider_free") is not True
        or prior.get("model_calls") != 0
        or prior.get("hosted_calls") != 0
    ):
        _issue(issues, "coupling_prior:provider_boundary_invalid")
    if not _text(prior.get("root")):
        _issue(issues, "coupling_prior:root_invalid")
    for field in ("group_depth", "hub_in_degree"):
        if not _bounded_int(prior.get(field)) or prior.get(field) < 1:
            _issue(issues, f"coupling_prior:{field}_invalid")

    raw_nodes = prior.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes or len(raw_nodes) > PROFILE.max_array_items:
        _issue(issues, "coupling_prior.nodes:array_invalid")
        raw_nodes = []
    node_ids: list[str] = []
    for index, raw in enumerate(raw_nodes):
        node = _closed(raw, _PRIOR_NODE_FIELDS, f"coupling_prior.nodes[{index}]", issues)
        node_id = node.get("id")
        if not _text(node_id) or node_id in node_ids:
            _issue(issues, f"coupling_prior.nodes[{index}]:id_invalid_or_duplicate")
        else:
            node_ids.append(str(node_id))
        for field in ("file_count", "line_count", "weight"):
            if not _bounded_int(node.get(field)):
                _issue(issues, f"coupling_prior.nodes[{index}]:{field}_invalid")

    raw_edges = prior.get("edges")
    if not isinstance(raw_edges, list) or len(raw_edges) > PROFILE.max_array_items:
        _issue(issues, "coupling_prior.edges:array_invalid")
        raw_edges = []
    edges: list[tuple[str, str]] = []
    known_nodes = set(node_ids)
    for index, raw in enumerate(raw_edges):
        edge = _closed(raw, _PRIOR_EDGE_FIELDS, f"coupling_prior.edges[{index}]", issues)
        src, dst = edge.get("src"), edge.get("dst")
        if src not in known_nodes or dst not in known_nodes or src == dst:
            _issue(issues, f"coupling_prior.edges[{index}]:endpoint_invalid")
        else:
            edges.append((str(src), str(dst)))
        for field in ("import_count", "weight"):
            if not _bounded_int(edge.get(field)):
                _issue(issues, f"coupling_prior.edges[{index}]:{field}_invalid")

    hubs = _string_list(prior.get("hubs"), "coupling_prior.hubs", issues)
    if any(hub not in known_nodes for hub in hubs):
        _issue(issues, "coupling_prior:hubs_unknown")
    expected_graph_sha = None
    if isinstance(raw_nodes, list) and isinstance(raw_edges, list):
        try:
            expected_graph_sha = _sha256({"nodes": raw_nodes, "edges": raw_edges})
        except (HostileInputError, TypeError, ValueError, OverflowError):
            _issue(issues, "coupling_prior:graph_noncanonical")
    if prior.get("graph_sha256") != expected_graph_sha:
        _issue(issues, "coupling_prior:graph_sha256_mismatch")
    return prior, known_nodes, edges


def _malformed_recommendation(
    issues: list[str],
    estimator_input_sha256: str | None,
) -> dict[str, Any]:
    core = {
        "schema": RECOMMENDATION_SCHEMA,
        "estimator_version": ESTIMATOR_VERSION,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "recommendation_id": None,
        "task_id": None,
        "disposition": "REFUSE",
        "reason_codes": ["contract_invalid"],
        "lane_count": None,
        "candidate_cut": [],
        "confidence_bps": None,
        "evidence_basis": None,
        "scout_allocation": None,
        "estimator_input_sha256": estimator_input_sha256,
        **_ADVISORY_INVARIANTS,
    }
    return {**core, "recommendation_sha256": _sha256(core)}


def _resolved_node(touch: str, nodes: set[str]) -> str | None:
    matches = sorted(
        node
        for node in nodes
        if touch == node or touch.startswith(node.rstrip("/") + "/")
    )
    return max(matches, key=lambda node: (len(node), node)) if matches else None


def _component_indexes(
    unit_nodes: Sequence[set[str]],
    edges: set[frozenset[str]],
) -> list[list[int]]:
    parents = list(range(len(unit_nodes)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    for left in range(len(unit_nodes)):
        for right in range(left + 1, len(unit_nodes)):
            coupled = bool(unit_nodes[left] & unit_nodes[right]) or any(
                frozenset((a, b)) in edges
                for a in unit_nodes[left]
                for b in unit_nodes[right]
                if a != b
            )
            if coupled:
                union(left, right)
    grouped: dict[int, list[int]] = {}
    for index in range(len(unit_nodes)):
        grouped.setdefault(find(index), []).append(index)
    return list(grouped.values())


def recommend_first_wave(program: Any) -> dict[str, Any]:
    """Emit one sealed advisory first-wave recommendation."""

    issues: list[str] = []
    try:
        program_sha256 = _sha256(program)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        return _malformed_recommendation(["program:hostile_or_noncanonical"], None)

    value = _closed(program, _PROGRAM_FIELDS, "program", issues)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    recommendation_id = value.get("recommendation_id")
    if not _identifier(recommendation_id):
        _issue(issues, "program:recommendation_id_invalid")

    task = _closed(value.get("task"), _TASK_FIELDS, "task", issues)
    task_id = task.get("task_id")
    if not _identifier(task_id):
        _issue(issues, "task:task_id_invalid")
    task_touch_set = _string_list(
        task.get("touch_set"), "task.touch_set", issues, allow_empty=False
    )

    raw_units = value.get("acceptance_units")
    if not isinstance(raw_units, list) or len(raw_units) > PROFILE.max_array_items:
        _issue(issues, "acceptance_units:array_invalid")
        raw_units = []
    acceptance_units: list[dict[str, Any]] = []
    unit_ids: set[str] = set()
    for index, raw in enumerate(raw_units):
        label = f"acceptance_units[{index}]"
        unit = _closed(raw, _ACCEPTANCE_FIELDS, label, issues)
        unit_id = unit.get("id")
        if not _identifier(unit_id) or unit_id in unit_ids:
            _issue(issues, f"{label}:id_invalid_or_duplicate")
        else:
            unit_ids.add(str(unit_id))
        if not isinstance(unit.get("independently_verifiable"), bool):
            _issue(issues, f"{label}:independence_invalid")
        if not _text(unit.get("evidence_locator")):
            _issue(issues, f"{label}:evidence_locator_invalid")
        unit_touch_set = _string_list(
            unit.get("touch_set"), f"{label}.touch_set", issues, allow_empty=False
        )
        if any(touch not in task_touch_set for touch in unit_touch_set):
            _issue(issues, f"{label}:touch_outside_task")
        acceptance_units.append(
            {
                "id": unit_id,
                "independently_verifiable": unit.get("independently_verifiable"),
                "evidence_locator": unit.get("evidence_locator"),
                "touch_set": sorted(unit_touch_set),
            }
        )

    capability_profile = _validate_capability_profile(
        value.get("capability_profile"), "capability_profile", issues
    )
    prior, topology_nodes, prior_edges = _validate_prior(
        value.get("coupling_prior"), issues
    )

    scout_budget = _closed(
        value.get("scout_budget"), _SCOUT_BUDGET_FIELDS, "scout_budget", issues
    )
    max_scouts = scout_budget.get("max_scouts")
    if not _bounded_int(max_scouts, maximum=MAX_FIRST_WAVE_LANES):
        _issue(issues, "scout_budget:max_scouts_invalid")
        max_scouts = 0
    raw_deltas = value.get("scout_deltas")
    if not isinstance(raw_deltas, list) or len(raw_deltas) > PROFILE.max_array_items:
        _issue(issues, "scout_deltas:array_invalid")
        raw_deltas = []
    if len(raw_deltas) > int(max_scouts):
        _issue(issues, "scout_deltas:budget_exceeded")

    delta_hashes: list[str] = []
    delta_territories: list[str] = []
    scout_edges: list[tuple[str, str]] = []
    uncertainty_count = 0
    for index, raw in enumerate(raw_deltas):
        report = topology.validate_topology_delta(raw)
        if report.get("status") != "PASS":
            for item in report.get("issues", []):
                _issue(issues, f"scout_deltas[{index}]:{item}")
            continue
        digest = report.get("delta_sha256")
        if not _sha_valid(digest):
            _issue(issues, f"scout_deltas[{index}]:digest_unavailable")
            continue
        assert isinstance(raw, Mapping)
        delta_hashes.append(str(digest))
        delta_territories.append(str(raw.get("territory_ref")))
        topology_nodes.update(str(item) for item in raw.get("new_nodes", []))
        topology_nodes.update(str(item) for item in raw.get("validated_nodes", []))
        for edge in raw.get("new_edges", []):
            if isinstance(edge, Mapping):
                scout_edges.append((str(edge.get("src")), str(edge.get("dst"))))
        uncertainties = raw.get("uncertainties_remaining")
        if isinstance(uncertainties, list):
            uncertainty_count += len(uncertainties)

    if issues:
        return _malformed_recommendation(issues, program_sha256)

    acceptance_units.sort(key=lambda item: str(item["id"]))
    resolved_task = {
        touch: _resolved_node(touch, topology_nodes) for touch in task_touch_set
    }
    covered_touches = {
        touch
        for unit in acceptance_units
        for touch in unit["touch_set"]
    }
    independently_verifiable = bool(acceptance_units) and all(
        unit["independently_verifiable"] for unit in acceptance_units
    )
    coverage_complete = bool(task_touch_set) and covered_touches == set(task_touch_set)
    topology_complete = bool(task_touch_set) and all(resolved_task.values())

    reasons: list[str] = []
    if not acceptance_units:
        reasons.append("acceptance_unit_required")
    if acceptance_units and not independently_verifiable:
        reasons.append("acceptance_not_independently_verifiable")
    if not coverage_complete:
        reasons.append("touch_set_coverage_incomplete")
    if not topology_complete:
        reasons.append("topology_touch_unresolved")
    disposition = "REFUSE" if reasons else "RECOMMEND"

    graph_edges = {
        frozenset((src, dst))
        for src, dst in prior_edges + scout_edges
        if src != dst
    }
    candidate_cut: list[dict[str, Any]] = []
    if disposition == "RECOMMEND":
        unit_nodes = [
            {str(resolved_task[touch]) for touch in unit["touch_set"]}
            for unit in acceptance_units
        ]
        components = _component_indexes(unit_nodes, graph_edges)
        components.sort(key=lambda group: str(acceptance_units[group[0]]["id"]))
        if len(components) > MAX_FIRST_WAVE_LANES:
            components = components[: MAX_FIRST_WAVE_LANES - 1] + [
                [
                    index
                    for group in components[MAX_FIRST_WAVE_LANES - 1 :]
                    for index in group
                ]
            ]
        for lane_number, indexes in enumerate(components, start=1):
            lane_units = [acceptance_units[index] for index in indexes]
            lane_touch_set = sorted(
                {touch for unit in lane_units for touch in unit["touch_set"]}
            )
            lane_nodes = {
                str(resolved_task[touch]) for touch in lane_touch_set
            }
            internal_edges = sorted(
                sorted(edge)
                for edge in graph_edges
                if edge <= lane_nodes and len(edge) == 2
            )
            lane_basis = {
                "touch_set_sha256": _sha256(lane_touch_set),
                "acceptance_units_sha256": _sha256(lane_units),
                "capability_profile_sha256": _sha256(capability_profile),
                "coupling_evidence_sha256": _sha256(
                    {"nodes": sorted(lane_nodes), "edges": internal_edges}
                ),
            }
            candidate_cut.append(
                {
                    "lane_id": f"lane-{lane_number:03d}",
                    "touch_set": lane_touch_set,
                    "acceptance_units": lane_units,
                    "capability_profile": dict(capability_profile),
                    "evidence_basis": lane_basis,
                }
            )

    scout_confirmation_bps = min(2_000, 500 * len(delta_hashes))
    uncertainty_penalty_bps = min(3_000, 250 * uncertainty_count)
    confidence_components = {
        "base_bps": 5_000,
        "resolved_touch_bps": 1_000 if topology_complete else 0,
        "acceptance_coverage_bps": 1_000 if coverage_complete and independently_verifiable else 0,
        "scout_confirmation_bps": scout_confirmation_bps,
        "uncertainty_penalty_bps": uncertainty_penalty_bps,
        "total_bps": max(
            0,
            min(
                10_000,
                5_000
                + (1_000 if topology_complete else 0)
                + (1_000 if coverage_complete and independently_verifiable else 0)
                + scout_confirmation_bps
                - uncertainty_penalty_bps,
            ),
        ),
    }
    source_hashes = {
        "task_touch_set_sha256": _sha256(sorted(task_touch_set)),
        "acceptance_units_sha256": _sha256(acceptance_units),
        "topology_graph_sha256": prior["graph_sha256"],
        "scout_delta_sha256s": delta_hashes,
        "capability_profile_sha256": _sha256(capability_profile),
    }
    evidence_basis = {
        "source_hashes": source_hashes,
        "element_sources": {
            "lane_count": [
                "task_touch_set",
                "acceptance_units",
                "topology_prior",
                "scout_deltas",
                "first_wave_bound",
            ],
            "candidate_cut": [
                "task_touch_set",
                "acceptance_units",
                "topology_prior",
                "scout_deltas",
            ],
            "capability_profile": ["declared_capability_profile"],
            "confidence": [
                "confidence_components",
                "topology_resolution",
                "scout_deltas",
            ],
        },
        "confidence_components": confidence_components,
    }
    scout_allocation = {
        "max_scouts": int(max_scouts),
        "used_scouts": len(delta_hashes),
        "territory_refs": delta_territories,
        "delta_sha256s": delta_hashes,
        "bounded": len(delta_hashes) <= int(max_scouts),
    }
    core = {
        "schema": RECOMMENDATION_SCHEMA,
        "estimator_version": ESTIMATOR_VERSION,
        "status": "PASS",
        "issues": [],
        "recommendation_id": str(recommendation_id),
        "task_id": str(task_id),
        "disposition": disposition,
        "reason_codes": sorted(reasons),
        "lane_count": len(candidate_cut) if disposition == "RECOMMEND" else None,
        "candidate_cut": candidate_cut,
        "confidence_bps": confidence_components["total_bps"],
        "evidence_basis": evidence_basis,
        "scout_allocation": scout_allocation,
        "estimator_input_sha256": program_sha256,
        **_ADVISORY_INVARIANTS,
    }
    return {**core, "recommendation_sha256": _sha256(core)}


def _validate_lane_cut(value: Any, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_FIRST_WAVE_LANES:
        _issue(issues, "candidate_cut:array_invalid")
        return []
    lanes: list[dict[str, Any]] = []
    lane_ids: set[str] = set()
    owned_touches: set[str] = set()
    acceptance_ids: set[str] = set()
    for index, raw in enumerate(value):
        label = f"candidate_cut[{index}]"
        lane = _closed(raw, _LANE_FIELDS, label, issues)
        lane_id = lane.get("lane_id")
        if not _identifier(lane_id) or lane_id in lane_ids:
            _issue(issues, f"{label}:lane_id_invalid_or_duplicate")
        else:
            lane_ids.add(str(lane_id))
        touch_set = _string_list(
            lane.get("touch_set"), f"{label}.touch_set", issues, allow_empty=False
        )
        if owned_touches.intersection(touch_set):
            _issue(issues, "candidate_cut:touch_overlap")
        owned_touches.update(touch_set)
        raw_units = lane.get("acceptance_units")
        if not isinstance(raw_units, list) or not raw_units:
            _issue(issues, f"{label}.acceptance_units:array_invalid")
            raw_units = []
        units: list[dict[str, Any]] = []
        for unit_index, raw_unit in enumerate(raw_units):
            unit_label = f"{label}.acceptance_units[{unit_index}]"
            unit = _closed(raw_unit, _ACCEPTANCE_FIELDS, unit_label, issues)
            unit_id = unit.get("id")
            if not _identifier(unit_id) or unit_id in acceptance_ids:
                _issue(issues, f"{unit_label}:id_invalid_or_duplicate")
            else:
                acceptance_ids.add(str(unit_id))
            if unit.get("independently_verifiable") is not True:
                _issue(issues, f"{unit_label}:not_independently_verifiable")
            if not _text(unit.get("evidence_locator")):
                _issue(issues, f"{unit_label}:evidence_locator_invalid")
            unit_touches = _string_list(
                unit.get("touch_set"), f"{unit_label}.touch_set", issues, allow_empty=False
            )
            if any(touch not in touch_set for touch in unit_touches):
                _issue(issues, f"{unit_label}:touch_outside_lane")
            units.append(dict(unit))
        profile = _validate_capability_profile(
            lane.get("capability_profile"), f"{label}.capability_profile", issues
        )
        basis = _closed(
            lane.get("evidence_basis"), _LANE_BASIS_FIELDS, f"{label}.evidence_basis", issues
        )
        if basis.get("touch_set_sha256") != _sha256(touch_set):
            _issue(issues, f"{label}.evidence_basis:touch_set_sha256_mismatch")
        if basis.get("acceptance_units_sha256") != _sha256(units):
            _issue(issues, f"{label}.evidence_basis:acceptance_units_sha256_mismatch")
        if basis.get("capability_profile_sha256") != _sha256(profile):
            _issue(issues, f"{label}.evidence_basis:capability_profile_sha256_mismatch")
        if not _sha_valid(basis.get("coupling_evidence_sha256")):
            _issue(issues, f"{label}.evidence_basis:coupling_evidence_sha256_invalid")
        lanes.append(dict(lane))
    return lanes


def validate_wave_recommendation(recommendation: Any) -> dict[str, Any]:
    """Validate the exact closed recommendation and its internal evidence seals."""

    issues: list[str] = []
    value = _closed(
        recommendation, _RECOMMENDATION_FIELDS, "recommendation", issues
    )
    if value.get("schema") != RECOMMENDATION_SCHEMA:
        _issue(issues, "recommendation:schema_invalid")
    if value.get("estimator_version") != ESTIMATOR_VERSION:
        _issue(issues, "recommendation:estimator_version_invalid")
    if value.get("status") != "PASS" or value.get("issues") != []:
        _issue(issues, "recommendation:not_pass")
    if not _identifier(value.get("recommendation_id")):
        _issue(issues, "recommendation:recommendation_id_invalid")
    if not _identifier(value.get("task_id")):
        _issue(issues, "recommendation:task_id_invalid")
    disposition = value.get("disposition")
    if disposition not in DISPOSITIONS:
        _issue(issues, "recommendation:disposition_invalid")
    _string_list(
        value.get("reason_codes"),
        "recommendation.reason_codes",
        issues,
        identifiers=True,
    )
    lanes = _validate_lane_cut(value.get("candidate_cut"), issues)
    lane_count = value.get("lane_count")
    if disposition == "RECOMMEND":
        if (
            not _bounded_int(lane_count, maximum=MAX_FIRST_WAVE_LANES)
            or lane_count < 1
            or lane_count != len(lanes)
        ):
            _issue(issues, "recommendation:lane_count_invalid")
    elif lane_count is not None or lanes:
        _issue(issues, "recommendation:refusal_cut_invalid")
    if not _bounded_int(value.get("confidence_bps"), maximum=10_000):
        _issue(issues, "recommendation:confidence_bps_invalid")

    evidence = _closed(
        value.get("evidence_basis"),
        _EVIDENCE_BASIS_FIELDS,
        "recommendation.evidence_basis",
        issues,
    )
    source_hashes = _closed(
        evidence.get("source_hashes"),
        _SOURCE_HASH_FIELDS,
        "recommendation.evidence_basis.source_hashes",
        issues,
    )
    for field in (
        "task_touch_set_sha256",
        "acceptance_units_sha256",
        "topology_graph_sha256",
        "capability_profile_sha256",
    ):
        if not _sha_valid(source_hashes.get(field)):
            _issue(issues, f"recommendation.evidence_basis.source_hashes:{field}_invalid")
    delta_hashes = source_hashes.get("scout_delta_sha256s")
    if not isinstance(delta_hashes, list) or any(not _sha_valid(item) for item in delta_hashes):
        _issue(issues, "recommendation.evidence_basis.source_hashes:scout_delta_sha256s_invalid")
    if disposition == "RECOMMEND" and lanes:
        flattened_units = sorted(
            (
                dict(unit)
                for lane in lanes
                for unit in lane.get("acceptance_units", [])
                if isinstance(unit, Mapping)
            ),
            key=lambda unit: str(unit.get("id")),
        )
        flattened_touches = sorted(
            {
                touch
                for lane in lanes
                for touch in lane.get("touch_set", [])
                if isinstance(touch, str)
            }
        )
        profiles = [
            lane.get("capability_profile")
            for lane in lanes
            if isinstance(lane.get("capability_profile"), Mapping)
        ]
        if source_hashes.get("task_touch_set_sha256") != _sha256(flattened_touches):
            _issue(issues, "recommendation:evidence_touch_set_mismatch")
        if source_hashes.get("acceptance_units_sha256") != _sha256(flattened_units):
            _issue(issues, "recommendation:evidence_acceptance_units_mismatch")
        if (
            not profiles
            or any(profile != profiles[0] for profile in profiles[1:])
            or source_hashes.get("capability_profile_sha256") != _sha256(profiles[0])
        ):
            _issue(issues, "recommendation:evidence_capability_profile_mismatch")
    element_sources = _closed(
        evidence.get("element_sources"),
        _ELEMENT_SOURCE_FIELDS,
        "recommendation.evidence_basis.element_sources",
        issues,
    )
    for field in sorted(_ELEMENT_SOURCE_FIELDS):
        _string_list(
            element_sources.get(field),
            f"recommendation.evidence_basis.element_sources.{field}",
            issues,
            identifiers=True,
            allow_empty=False,
        )
    confidence = _closed(
        evidence.get("confidence_components"),
        _CONFIDENCE_FIELDS,
        "recommendation.evidence_basis.confidence_components",
        issues,
    )
    for field in _CONFIDENCE_FIELDS:
        if not _bounded_int(confidence.get(field), maximum=10_000):
            _issue(issues, f"recommendation.evidence_basis.confidence_components:{field}_invalid")
    if confidence.get("total_bps") != value.get("confidence_bps"):
        _issue(issues, "recommendation:evidence_confidence_mismatch")

    scout = _closed(
        value.get("scout_allocation"),
        _SCOUT_ALLOCATION_FIELDS,
        "recommendation.scout_allocation",
        issues,
    )
    max_scouts, used_scouts = scout.get("max_scouts"), scout.get("used_scouts")
    if not _bounded_int(max_scouts, maximum=MAX_FIRST_WAVE_LANES):
        _issue(issues, "recommendation.scout_allocation:max_scouts_invalid")
    if not _bounded_int(used_scouts, maximum=MAX_FIRST_WAVE_LANES):
        _issue(issues, "recommendation.scout_allocation:used_scouts_invalid")
    territory_refs = _string_list(
        scout.get("territory_refs"), "recommendation.scout_allocation.territory_refs", issues
    )
    recorded_delta_hashes = scout.get("delta_sha256s")
    if not isinstance(recorded_delta_hashes, list) or any(
        not _sha_valid(item) for item in recorded_delta_hashes
    ):
        _issue(issues, "recommendation.scout_allocation:delta_sha256s_invalid")
        recorded_delta_hashes = []
    if (
        type(max_scouts) is int
        and type(used_scouts) is int
        and (
            used_scouts > max_scouts
            or used_scouts != len(territory_refs)
            or used_scouts != len(recorded_delta_hashes)
            or scout.get("bounded") is not True
        )
    ):
        _issue(issues, "recommendation.scout_allocation:binding_invalid")
    if recorded_delta_hashes != delta_hashes:
        _issue(issues, "recommendation.scout_allocation:evidence_mismatch")

    for field, expected in _ADVISORY_INVARIANTS.items():
        if value.get(field) != expected:
            _issue(issues, f"recommendation:{field}_invalid")
    if not _sha_valid(value.get("estimator_input_sha256")):
        _issue(issues, "recommendation:estimator_input_sha256_invalid")
    core = dict(value)
    recorded_sha = core.pop("recommendation_sha256", None)
    try:
        actual_sha = _sha256(core)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        actual_sha = None
    if recorded_sha != actual_sha:
        _issue(issues, "recommendation:recommendation_sha256_mismatch")
    return {
        "schema": VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "recommendation_sha256": recorded_sha if not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _validate_measurement(value: Any, label: str, issues: list[str]) -> None:
    metric = _closed(value, _MEASUREMENT_FIELDS, label, issues)
    status = metric.get("status")
    duration = metric.get("value_ms")
    reason = metric.get("reason")
    if status == "observed":
        if not _bounded_int(duration) or reason is not None:
            _issue(issues, f"{label}:observed_invalid")
    elif status in {"unknown", "not_applicable"}:
        if duration is not None or not _identifier(reason):
            _issue(issues, f"{label}:{status}_invalid")
    else:
        _issue(issues, f"{label}:status_invalid")


def _outcome_report(
    issues: list[str],
    *,
    record: Mapping[str, Any] | None = None,
    chain_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": OUTCOME_REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "record": dict(record) if isinstance(record, Mapping) else None,
        "chain_receipt": dict(chain_receipt) if isinstance(chain_receipt, Mapping) else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _timestamp_ms(value: Any) -> int | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int(moment.timestamp() * 1_000)


def _bind_realized_outcome_to_trace(
    trace_value: Mapping[str, Any],
    recommendation_sha256: str,
    selected_cut: Sequence[Mapping[str, Any]],
    realized: Mapping[str, Any],
    issues: list[str],
) -> None:
    events = trace_value.get("events")
    if not isinstance(events, list):
        return

    selected_units: dict[str, str] = {}
    selected_lane_ids: set[str] = set()
    for lane in selected_cut:
        lane_id = lane.get("lane_id")
        if not isinstance(lane_id, str):
            continue
        selected_lane_ids.add(lane_id)
        for unit in lane.get("acceptance_units", []):
            if isinstance(unit, Mapping) and isinstance(unit.get("id"), str):
                selected_units[str(unit["id"])] = lane_id

    started_at: dict[str, int] = {}
    finished_at: dict[str, int] = {}
    trace_results: dict[str, str] = {}
    integration_events = 0
    integration_durations: list[int] = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        event_type = event.get("type")
        node_id = event.get("node_id")
        timestamp = _timestamp_ms(event.get("at"))
        if node_id in selected_lane_ids and timestamp is not None:
            if event_type == "start":
                started_at.setdefault(str(node_id), timestamp)
            elif event_type == "finish":
                finished_at[str(node_id)] = timestamp

        data = event.get("data")
        if event_type == "verify" and isinstance(data, Mapping) and data.get(
            "schema"
        ) == TRACE_ACCEPTANCE_SCHEMA:
            label = "trace.acceptance_result"
            row = _closed(data, _TRACE_ACCEPTANCE_FIELDS, label, issues)
            if row.get("recommendation_sha256") != recommendation_sha256:
                _issue(issues, label + ":recommendation_mismatch")
            unit_id = row.get("acceptance_unit_id")
            status = row.get("status")
            if unit_id not in selected_units or selected_units.get(str(unit_id)) != node_id:
                _issue(issues, label + ":unit_lane_mismatch")
            if status not in {"passed", "failed", "unknown", "not_run"}:
                _issue(issues, label + ":status_invalid")
            if isinstance(unit_id, str):
                if unit_id in trace_results:
                    _issue(issues, label + ":duplicate")
                trace_results[unit_id] = str(status)

        if event_type == "integrate":
            integration_events += 1
            if isinstance(data, Mapping) and data.get("schema") == TRACE_INTEGRATION_SCHEMA:
                label = "trace.integration_cost"
                row = _closed(data, _TRACE_INTEGRATION_FIELDS, label, issues)
                if row.get("recommendation_sha256") != recommendation_sha256:
                    _issue(issues, label + ":recommendation_mismatch")
                duration = row.get("duration_ms")
                if not _bounded_int(duration):
                    _issue(issues, label + ":duration_invalid")
                else:
                    integration_durations.append(int(duration))

    observed_lane_count = len(started_at)
    if realized.get("lane_count") != observed_lane_count:
        _issue(issues, "realized_outcome:trace_lane_count_mismatch")

    declared_results = {
        str(row.get("id")): str(row.get("status"))
        for row in realized.get("acceptance_unit_results", [])
        if isinstance(row, Mapping)
    }
    if trace_results != declared_results:
        _issue(issues, "realized_outcome:acceptance_results_trace_mismatch")

    wall_time = realized.get("wall_time")
    lifecycle_complete = bool(selected_lane_ids) and (
        selected_lane_ids == set(started_at) == set(finished_at)
        and all(finished_at[lane_id] >= started_at[lane_id] for lane_id in selected_lane_ids)
    )
    if lifecycle_complete:
        elapsed_ms = max(finished_at.values()) - min(started_at.values())
        if not isinstance(wall_time, Mapping) or wall_time != {
            "status": "observed",
            "value_ms": elapsed_ms,
            "reason": None,
        }:
            _issue(issues, "realized_outcome:wall_time_mismatch")
    elif not isinstance(wall_time, Mapping) or wall_time != {
        "status": "unknown",
        "value_ms": None,
        "reason": "lane_lifecycle_incomplete",
    }:
        _issue(issues, "realized_outcome:wall_time_mismatch")

    integration_cost = realized.get("integration_cost")
    if integration_events == 0:
        expected_integration = {
            "status": "not_applicable",
            "value_ms": None,
            "reason": "no_integration_event",
        }
    elif len(integration_durations) == integration_events:
        expected_integration = {
            "status": "observed",
            "value_ms": sum(integration_durations),
            "reason": None,
        }
    else:
        expected_integration = {
            "status": "unknown",
            "value_ms": None,
            "reason": "integration_evidence_incomplete",
        }
    if integration_cost != expected_integration:
        _issue(issues, "realized_outcome:integration_cost_trace_mismatch")


def record_wave_outcome(evidence: Any, ledger_path: str | Path) -> dict[str, Any]:
    """Validate, seal, and append one recommendation-versus-outcome record."""

    issues: list[str] = []
    value = _closed(
        evidence,
        _OUTCOME_EVIDENCE_FIELDS,
        "outcome_evidence",
        issues,
    )
    if value.get("schema") != OUTCOME_EVIDENCE_SCHEMA:
        _issue(issues, "outcome_evidence:schema_invalid")

    recommendation = value.get("recommendation")
    recommendation_report = validate_wave_recommendation(recommendation)
    if recommendation_report.get("status") != "PASS":
        for item in recommendation_report.get("issues", []):
            _issue(issues, "recommendation:" + str(item))
    recommendation_value = recommendation if isinstance(recommendation, Mapping) else {}

    disposition = value.get("disposition")
    if disposition not in {"accepted", "overridden"}:
        _issue(issues, "outcome_evidence:disposition_invalid")

    selection = _closed(
        value.get("selection"), _SELECTION_FIELDS, "selection", issues
    )
    selected_lane_count = selection.get("lane_count")
    if not _bounded_int(selected_lane_count, maximum=MAX_FIRST_WAVE_LANES):
        _issue(issues, "selection:lane_count_invalid")
        selected_lane_count = 0
    selected_cut = _validate_lane_cut(selection.get("candidate_cut"), issues)
    if selected_lane_count != len(selected_cut):
        _issue(issues, "selection:lane_count_cut_mismatch")
    override_reason = selection.get("override_reason")
    if disposition == "accepted":
        recommended_count = recommendation_value.get("lane_count")
        expected_count = 0 if recommended_count is None else recommended_count
        if (
            selected_lane_count != expected_count
            or selection.get("candidate_cut") != recommendation_value.get("candidate_cut")
            or override_reason is not None
        ):
            _issue(issues, "selection:accepted_binding_mismatch")
    elif not _text(override_reason):
        _issue(issues, "selection:override_reason_required")

    realized = _closed(
        value.get("realized_outcome"),
        _REALIZED_FIELDS,
        "realized_outcome",
        issues,
    )
    realized_status = realized.get("status")
    if realized_status not in {"succeeded", "failed", "incomplete", "not_run"}:
        _issue(issues, "realized_outcome:status_invalid")
    realized_lane_count = realized.get("lane_count")
    if not _bounded_int(realized_lane_count, maximum=MAX_FIRST_WAVE_LANES):
        _issue(issues, "realized_outcome:lane_count_invalid")
    if realized_status == "succeeded" and realized_lane_count != selected_lane_count:
        _issue(issues, "realized_outcome:succeeded_lane_count_mismatch")
    if (
        disposition == "accepted"
        and recommendation_value.get("disposition") == "REFUSE"
        and realized_status != "not_run"
    ):
        _issue(issues, "realized_outcome:accepted_refusal_must_not_run")
    if selected_lane_count == 0 and realized_status != "not_run":
        _issue(issues, "realized_outcome:empty_selection_must_not_run")

    selected_unit_ids = {
        unit.get("id")
        for lane in selected_cut
        if isinstance(lane, Mapping)
        for unit in lane.get("acceptance_units", [])
        if isinstance(unit, Mapping)
    }
    raw_results = realized.get("acceptance_unit_results")
    if not isinstance(raw_results, list) or len(raw_results) > PROFILE.max_array_items:
        _issue(issues, "realized_outcome.acceptance_unit_results:array_invalid")
        raw_results = []
    result_ids: set[str] = set()
    result_statuses: dict[str, str] = {}
    for index, raw in enumerate(raw_results):
        label = f"realized_outcome.acceptance_unit_results[{index}]"
        row = _closed(raw, _ACCEPTANCE_RESULT_FIELDS, label, issues)
        unit_id = row.get("id")
        if not _identifier(unit_id) or unit_id in result_ids:
            _issue(issues, f"{label}:id_invalid_or_duplicate")
        else:
            result_ids.add(str(unit_id))
        if unit_id not in selected_unit_ids:
            _issue(issues, f"{label}:unit_not_selected")
        if row.get("status") not in {"passed", "failed", "unknown", "not_run"}:
            _issue(issues, f"{label}:status_invalid")
        elif isinstance(unit_id, str):
            result_statuses[unit_id] = str(row.get("status"))
    if realized_status == "succeeded" and (
        result_ids != selected_unit_ids
        or any(status != "passed" for status in result_statuses.values())
    ):
        _issue(issues, "realized_outcome:succeeded_acceptance_incomplete")
    if realized_status == "not_run" and (
        realized_lane_count != 0
        or raw_results
        or realized.get("wall_time")
        != {"status": "not_applicable", "value_ms": None, "reason": "not_run"}
        or realized.get("integration_cost")
        != {"status": "not_applicable", "value_ms": None, "reason": "not_run"}
    ):
        _issue(issues, "realized_outcome:not_run_evidence_invalid")

    _validate_measurement(realized.get("wall_time"), "realized_outcome.wall_time", issues)
    _validate_measurement(
        realized.get("integration_cost"), "realized_outcome.integration_cost", issues
    )
    trace_sha256 = realized.get("trace_sha256")
    trace_value = value.get("trace")
    trace_module = None
    if realized_status == "not_run":
        if trace_sha256 is not None:
            _issue(issues, "realized_outcome:not_run_trace_present")
        if trace_value is not None:
            _issue(issues, "realized_outcome:not_run_trace_document_present")
    else:
        if not _sha_valid(trace_sha256):
            _issue(issues, "realized_outcome:trace_sha256_invalid")
        if not isinstance(trace_value, Mapping):
            _issue(issues, "realized_outcome:trace_document_required")
        else:
            try:
                trace_module = _load_trace_module()
            except (ImportError, OSError, ValueError):
                _issue(issues, "realized_outcome:trace_evaluator_unavailable")
            else:
                trace_report = trace_module.validate_run_trace(trace_value)
                if trace_report.get("status") != "PASS":
                    for item in trace_report.get("issues", []):
                        _issue(issues, "trace:" + str(item))
                elif trace_report.get("trace_sha256") != trace_sha256:
                    _issue(issues, "realized_outcome:trace_sha256_mismatch")
                else:
                    _bind_realized_outcome_to_trace(
                        trace_value,
                        str(recommendation_value.get("recommendation_sha256")),
                        selected_cut,
                        realized,
                        issues,
                    )

    if issues:
        return _outcome_report(issues)
    record_core = {
        "schema": OUTCOME_SCHEMA,
        "recommendation": dict(recommendation_value),
        "disposition": str(disposition),
        "selection": dict(selection),
        "realized_outcome": dict(realized),
        "trace": dict(trace_value) if isinstance(trace_value, Mapping) else None,
    }
    try:
        record = {**record_core, "record_sha256": _sha256(record_core)}
    except (HostileInputError, TypeError, ValueError, OverflowError):
        return _outcome_report(["outcome_record:hostile_or_noncanonical"])
    if set(record) != _OUTCOME_FIELDS:
        return _outcome_report(["outcome_record:internal_shape_invalid"])
    try:
        if trace_module is None:
            trace_module = _load_trace_module()
        chain_receipt = trace_module.append_trace_record(ledger_path, record)
    except ImportError:
        return _outcome_report(["ledger:trace_evaluator_unavailable"])
    except OSError:
        return _outcome_report(["ledger:write_failed"])
    except ValueError:
        return _outcome_report(["ledger:append_refused"])
    return _outcome_report([], record=record, chain_receipt=chain_receipt)


__all__ = [
    "DISPOSITIONS",
    "ESTIMATOR_VERSION",
    "MAX_FIRST_WAVE_LANES",
    "OUTCOME_EVIDENCE_SCHEMA",
    "OUTCOME_REPORT_SCHEMA",
    "OUTCOME_SCHEMA",
    "PROGRAM_SCHEMA",
    "RECOMMENDATION_SCHEMA",
    "TRACE_ACCEPTANCE_SCHEMA",
    "TRACE_INTEGRATION_SCHEMA",
    "VALIDATION_SCHEMA",
    "recommend_first_wave",
    "record_wave_outcome",
    "validate_wave_recommendation",
]
