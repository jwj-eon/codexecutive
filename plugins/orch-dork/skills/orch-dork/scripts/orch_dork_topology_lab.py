#!/usr/bin/env python3
"""CPU-only closed topology search and Pareto evidence for Issue 149.

This module enumerates one sealed finite genome, rejects structurally invalid
or Topology-Closure-uncovered candidates before scoring, and retains a bounded
multi-objective Pareto archive.  Its process pool performs only deterministic
local computation.  It has no model, transport, worker, tool, policy-mutation,
release, installation, or activation seam.
"""

from __future__ import annotations

from collections import deque
from concurrent.futures import ProcessPoolExecutor
from copy import deepcopy
import hashlib
import itertools
import json
import os
import re
from typing import Any, Iterable, Iterator, Mapping, Sequence


PROGRAM_SCHEMA = "orch-dork/topology-lab-program/v1"
REPORT_SCHEMA = "orch-dork/topology-lab-report/v1"
REGISTRY_DRAFT_SCHEMA = "orch-dork/topology-genome-registry-draft/v1"
REGISTRY_SCHEMA = "orch-dork/topology-genome-registry/v1"
CLOSURE_BASIS_DRAFT_SCHEMA = "orch-dork/topology-closure-basis-draft/v1"
CLOSURE_BASIS_SCHEMA = "orch-dork/topology-closure-basis/v1"
SCORING_POLICY_SCHEMA = "orch-dork/topology-scoring-policy/v1"
DIRECT_BASELINE_DRAFT_SCHEMA = "orch-dork/direct-baseline-draft/v1"
DIRECT_BASELINE_SCHEMA = "orch-dork/direct-baseline/v1"
CANDIDATE_SCHEMA = "orch-dork/topology-candidate/v1"
CANDIDATE_DECISION_SCHEMA = "orch-dork/topology-candidate-decision/v1"
ARCHIVE_SCHEMA = "orch-dork/topology-pareto-archive/v1"
SELECTION_SCHEMA = "orch-dork/future-qwen-selection/v1"

ACTIONS = (
    "seal_registry",
    "evaluate_candidate",
    "enumerate",
    "select_frontier",
)

AXIS_ORDER = (
    "profile_id",
    "lane_count",
    "dependency_cut",
    "context_policy",
    "join_class",
    "depth",
    "executor_roles",
    "early_exit",
    "model_profile_id",
    "budget_split_id",
)
PROFILE_IDS = (
    "best_of_n/v1",
    "direct/v1",
    "execute_verify_repair/v1",
    "finite_dag/v1",
    "parallel_join/v1",
)
DEPENDENCY_CUTS = (
    "dependency_layers",
    "independent",
    "none",
    "ownership_partitions",
)
CONTEXT_POLICIES = ("artifact_refs", "none")
JOIN_CLASSES = ("blinded_comparison", "mechanical", "none", "semantic")
EXECUTOR_ROLE_SETS = (
    "candidate_comparator",
    "executor_verifier",
    "parallel_executors_integrator",
    "planner_executors_integrator",
    "single_executor",
)
EARLY_EXIT_CONDITIONS = (
    "dependency_failure",
    "deterministic_pass",
    "none",
    "quorum_impossible",
)

OBJECTIVE_DIRECTIONS = {
    "correctness_bps": "maximize",
    "verified_coverage_bps": "maximize",
    "privacy_bps": "maximize",
    "authority_bps": "maximize",
    "safety_bps": "maximize",
    "critical_path_ms": "minimize",
    "tokens": "minimize",
    "cost_micros": "minimize",
    "sol_ingress_tokens": "minimize",
    "integration_cost_micros": "minimize",
    "repair_cost_micros": "minimize",
    "evidence_completeness_bps": "maximize",
}

MAX_CANONICAL_BYTES = 262_144
MAX_REGISTRY_CANONICAL_BYTES = 196_608
MAX_ARCHIVE_CANONICAL_BYTES = 196_608
MAX_NESTING = 32
MAX_COMPOSITE_NODES = 4096
MAX_CONTAINER_ITEMS = 512
MAX_CANDIDATES = 2_000_000
MAX_ARCHIVE_ENTRIES = 128
MAX_PROCESSES = 128
MAX_CHUNK_SIZE = 4096
MAX_METRIC = 10**15
MAX_DELTA = 10**12
MAX_SELECTION = 32

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")

_PROGRAM_FIELDS = frozenset({"schema", "action", "request"})
_SEAL_REGISTRY_FIELDS = frozenset({"registry"})
_EVALUATE_CANDIDATE_FIELDS = frozenset({"registry", "genome"})
_ENUMERATE_FIELDS = frozenset({"registry", "process_count"})
_SELECT_FIELDS = frozenset(
    {"registry", "archive", "candidate_sha256s", "process_count"}
)
_REGISTRY_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "registry_id",
        "axes",
        "model_profiles",
        "budget_splits",
        "topology_closure_basis",
        "scoring_policy",
        "objective_directions",
        "budget_envelope",
        "direct_baseline",
        "limits",
        "resident_qwen",
        "search_adapter",
    }
)
_REGISTRY_FIELDS = _REGISTRY_DRAFT_FIELDS | frozenset(
    {"budget_envelope_sha256", "registry_sha256"}
)
_MODEL_PROFILE_FIELDS = frozenset(
    {
        "model_profile_id",
        "executor",
        "verifier",
        "integrator",
        "runtime_identity_sha256",
    }
)
_BUDGET_SPLIT_FIELDS = frozenset(
    {
        "budget_split_id",
        "executor_bps",
        "verification_bps",
        "integration_bps",
        "reserve_bps",
    }
)
_CLOSURE_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "source_schema",
        "source_report_sha256",
        "profile_ids",
        "dependency_cuts",
        "context_policies",
        "join_classes",
        "max_lane_count",
        "max_depth",
    }
)
_CLOSURE_FIELDS = _CLOSURE_DRAFT_FIELDS | frozenset({"basis_sha256"})
_SCORING_FIELDS = frozenset(
    {"schema", "base_metrics", "axis_deltas", "evidence_sha256"}
)
_DELTA_FIELDS = frozenset({"value", "metrics"})
_ENVELOPE_FIELDS = frozenset({"total_tokens", "total_cost_micros"})
_BASELINE_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "profile_id",
        "budget_tokens",
        "budget_cost_micros",
        "metrics",
        "evidence_sha256",
    }
)
_BASELINE_FIELDS = _BASELINE_DRAFT_FIELDS | frozenset(
    {"budget_envelope_sha256", "baseline_sha256"}
)
_LIMIT_FIELDS = frozenset(
    {"max_candidates", "max_archive_entries", "max_processes", "chunk_size"}
)
_QWEN_FIELDS = frozenset(
    {"status", "unload_permitted", "observation_sha256"}
)
_GENOME_FIELDS = frozenset(AXIS_ORDER)
_CANDIDATE_FIELDS = frozenset(
    {
        "schema",
        "registry_sha256",
        "genome",
        "model_profile_sha256",
        "budget_split_sha256",
        "candidate_sha256",
    }
)
_DECISION_FIELDS = frozenset(
    {
        "schema",
        "candidate",
        "decision",
        "reasons",
        "topology_closure_sha256",
        "metrics",
        "metric_evidence_sha256",
        "metric_evidence_class",
        "evaluated",
        "decision_sha256",
    }
)
_FRONTIER_FIELDS = frozenset(
    {
        "candidate",
        "metrics",
        "topology_closure_sha256",
        "metric_evidence_sha256",
        "metric_evidence_class",
        "equivalent_candidate_count",
        "equivalent_candidates_sha256",
    }
)
_PRUNE_SUMMARY_FIELDS = frozenset({"reason", "count", "candidate_samples"})
_ARCHIVE_FIELDS = frozenset(
    {
        "schema",
        "registry_sha256",
        "candidate_count",
        "feasible_count",
        "pruned_count",
        "ordered_candidate_stream_sha256",
        "decision_counts",
        "prune_reasons",
        "objective_directions",
        "source_authority",
        "direct_baseline",
        "frontier",
        "frontier_candidate_sha256s",
        "max_archive_entries",
        "bounded_memory",
        "full_population_retained",
        "search_mode",
        "cpu_only",
        "resident_qwen_action",
        "future_qwen_selection_active",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "retries",
        "fallbacks",
        "replacements",
        "dispatch_permitted",
        "workers_permitted",
        "authority_granted",
        "archive_sha256",
    }
)
_SELECTION_FIELDS = frozenset(
    {
        "schema",
        "registry_sha256",
        "archive_sha256",
        "candidate_sha256s",
        "decision",
        "qwen_dispatch_permitted",
        "resident_qwen_action",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "retries",
        "fallbacks",
        "replacements",
        "tools_permitted",
        "workers_permitted",
        "authority_granted",
        "policy_mutated",
        "release_permitted",
        "installation_permitted",
        "activation_permitted",
        "selection_sha256",
    }
)


class ArchiveLimitError(RuntimeError):
    """Raised when the exact nondominated archive exceeds its sealed bound."""


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical_bytes_exceeded")
    return raw


def json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _shape_within_bounds(value: Any) -> bool:
    stack = [(value, 0)]
    composite_nodes = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, Mapping):
            composite_nodes += 1
            if (
                depth > MAX_NESTING
                or composite_nodes > MAX_COMPOSITE_NODES
                or len(current) > MAX_CONTAINER_ITEMS
            ):
                return False
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            composite_nodes += 1
            if (
                depth > MAX_NESTING
                or composite_nodes > MAX_COMPOSITE_NODES
                or len(current) > MAX_CONTAINER_ITEMS
            ):
                return False
            stack.extend((item, depth + 1) for item in current)
    return True


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result.pop(field, None)
    result[field] = json_sha256(result)
    return result


def _sealed(value: Any, field: str) -> bool:
    if not isinstance(value, Mapping) or not _sha(value.get(field)):
        return False
    core = dict(value)
    digest = core.pop(field)
    try:
        return digest == json_sha256(core)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False


def _sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _count(value: Any, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _signed_count(value: Any, maximum: int) -> bool:
    return type(value) is int and -maximum <= value <= maximum


def _closed(
    value: Any, fields: frozenset[str], label: str, issues: list[str]
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != fields:
        issues.append(label + ":contract_invalid")
        return None
    return deepcopy(dict(value))


def _value_token(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _axis_sort_key(value: Any) -> tuple[int, Any]:
    return (0, value) if type(value) is int else (1, value)


def _normalize_axis(
    axis: str, value: Any, issues: list[str]
) -> list[Any] | None:
    if not isinstance(value, list) or not value or len(value) > 32:
        issues.append("registry:axis_invalid:" + axis)
        return None
    if axis in {"lane_count", "depth"}:
        if any(not _count(item, 32) or item == 0 for item in value):
            issues.append("registry:axis_invalid:" + axis)
            return None
    elif axis == "profile_id":
        if any(item not in PROFILE_IDS for item in value):
            issues.append("registry:axis_invalid:" + axis)
            return None
    elif axis == "dependency_cut":
        if any(item not in DEPENDENCY_CUTS for item in value):
            issues.append("registry:axis_invalid:" + axis)
            return None
    elif axis == "context_policy":
        if any(item not in CONTEXT_POLICIES for item in value):
            issues.append("registry:axis_invalid:" + axis)
            return None
    elif axis == "join_class":
        if any(item not in JOIN_CLASSES for item in value):
            issues.append("registry:axis_invalid:" + axis)
            return None
    elif axis == "executor_roles":
        if any(item not in EXECUTOR_ROLE_SETS for item in value):
            issues.append("registry:axis_invalid:" + axis)
            return None
    elif axis == "early_exit":
        if any(item not in EARLY_EXIT_CONDITIONS for item in value):
            issues.append("registry:axis_invalid:" + axis)
            return None
    elif any(not _identifier(item) for item in value):
        issues.append("registry:axis_invalid:" + axis)
        return None
    tokens = [_value_token(item) for item in value]
    if len(tokens) != len(set(tokens)):
        issues.append("registry:axis_duplicate:" + axis)
        return None
    return sorted(value, key=_axis_sort_key)


def _normalize_metrics(
    value: Any,
    label: str,
    issues: list[str],
    *,
    signed: bool = False,
) -> dict[str, int] | None:
    initial_issue_count = len(issues)
    metrics = _closed(
        value, frozenset(OBJECTIVE_DIRECTIONS), label, issues
    )
    if metrics is None:
        return None
    for field in OBJECTIVE_DIRECTIONS:
        item = metrics.get(field)
        if signed:
            valid = _signed_count(item, MAX_DELTA)
        elif field.endswith("_bps"):
            valid = _count(item, 10_000)
        else:
            valid = _count(item, MAX_METRIC)
        if not valid:
            issues.append(label + ":metric_invalid:" + field)
    if len(issues) != initial_issue_count:
        return None
    return {field: metrics[field] for field in OBJECTIVE_DIRECTIONS}


def _normalize_model_profiles(
    value: Any, expected_ids: Sequence[str], issues: list[str]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 32:
        issues.append("registry:model_profiles_invalid")
        return []
    result: list[dict[str, Any]] = []
    for raw in value:
        item = _closed(raw, _MODEL_PROFILE_FIELDS, "registry:model_profile", issues)
        if item is None:
            continue
        if not _identifier(item.get("model_profile_id")):
            issues.append("registry:model_profile_id_invalid")
        for field in ("executor", "verifier", "integrator"):
            if item.get(field) not in {"sol", "qwen", "none"}:
                issues.append("registry:model_role_invalid")
        if item.get("executor") == "none" or item.get("verifier") == "none":
            issues.append("registry:model_required_role_missing")
        if not _sha(item.get("runtime_identity_sha256")):
            issues.append("registry:model_runtime_invalid")
        result.append(item)
    ids = [item.get("model_profile_id") for item in result]
    if len(ids) != len(set(ids)) or set(ids) != set(expected_ids):
        issues.append("registry:model_profile_membership_mismatch")
    return sorted(result, key=lambda item: str(item.get("model_profile_id")))


def _normalize_budget_splits(
    value: Any, expected_ids: Sequence[str], issues: list[str]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 32:
        issues.append("registry:budget_splits_invalid")
        return []
    result: list[dict[str, Any]] = []
    for raw in value:
        item = _closed(raw, _BUDGET_SPLIT_FIELDS, "registry:budget_split", issues)
        if item is None:
            continue
        if not _identifier(item.get("budget_split_id")):
            issues.append("registry:budget_split_id_invalid")
        fields = (
            "executor_bps",
            "verification_bps",
            "integration_bps",
            "reserve_bps",
        )
        if any(not _count(item.get(field), 10_000) for field in fields):
            issues.append("registry:budget_split_value_invalid")
        elif sum(item[field] for field in fields) != 10_000:
            issues.append("registry:budget_split_not_conserved")
        if item.get("executor_bps", 0) == 0 or item.get(
            "verification_bps", 0
        ) == 0:
            issues.append("registry:budget_required_allocation_missing")
        result.append(item)
    ids = [item.get("budget_split_id") for item in result]
    if len(ids) != len(set(ids)) or set(ids) != set(expected_ids):
        issues.append("registry:budget_split_membership_mismatch")
    return sorted(result, key=lambda item: str(item.get("budget_split_id")))


def _normalize_subset(
    value: Any,
    allowed: Sequence[Any],
    label: str,
    issues: list[str],
) -> list[Any]:
    if not isinstance(value, list) or not value or len(value) > 32:
        issues.append(label + ":invalid")
        return []
    tokens = [_value_token(item) for item in value]
    allowed_tokens = {_value_token(item) for item in allowed}
    if len(tokens) != len(set(tokens)) or not set(tokens) <= allowed_tokens:
        issues.append(label + ":invalid")
        return []
    return sorted(value, key=_axis_sort_key)


def _normalize_closure_basis(
    value: Any, axes: Mapping[str, Sequence[Any]], issues: list[str]
) -> dict[str, Any] | None:
    basis = _closed(value, _CLOSURE_DRAFT_FIELDS, "registry:closure", issues)
    if basis is None:
        return None
    if basis.get("schema") != CLOSURE_BASIS_DRAFT_SCHEMA:
        issues.append("registry:closure_schema_invalid")
    if basis.get("status") != "PASS":
        issues.append("registry:closure_not_pass")
    if basis.get("source_schema") != "orch-dork/topology-closure/v1":
        issues.append("registry:closure_source_schema_invalid")
    if not _sha(basis.get("source_report_sha256")):
        issues.append("registry:closure_source_invalid")
    mappings = (
        ("profile_ids", "profile_id"),
        ("dependency_cuts", "dependency_cut"),
        ("context_policies", "context_policy"),
        ("join_classes", "join_class"),
    )
    for field, axis in mappings:
        basis[field] = _normalize_subset(
            basis.get(field), axes.get(axis, []), "registry:closure:" + field, issues
        )
    if not _count(basis.get("max_lane_count"), 32) or basis.get(
        "max_lane_count"
    ) == 0:
        issues.append("registry:closure_lane_bound_invalid")
    if not _count(basis.get("max_depth"), 32) or basis.get("max_depth") == 0:
        issues.append("registry:closure_depth_bound_invalid")
    return basis


def _normalize_scoring_policy(
    value: Any, axes: Mapping[str, Sequence[Any]], issues: list[str]
) -> dict[str, Any] | None:
    policy = _closed(value, _SCORING_FIELDS, "registry:scoring", issues)
    if policy is None:
        return None
    if policy.get("schema") != SCORING_POLICY_SCHEMA:
        issues.append("registry:scoring_schema_invalid")
    if not _sha(policy.get("evidence_sha256")):
        issues.append("registry:scoring_evidence_invalid")
    base = _normalize_metrics(
        policy.get("base_metrics"), "registry:scoring:base", issues
    )
    raw_deltas = _closed(
        policy.get("axis_deltas"),
        frozenset(AXIS_ORDER),
        "registry:scoring:axis_deltas",
        issues,
    )
    normalized: dict[str, list[dict[str, Any]]] = {}
    if raw_deltas is not None:
        for axis in AXIS_ORDER:
            rows = raw_deltas.get(axis)
            if not isinstance(rows, list) or len(rows) != len(axes.get(axis, [])):
                issues.append("registry:scoring:coverage_mismatch:" + axis)
                continue
            by_token: dict[str, dict[str, Any]] = {}
            for raw in rows:
                row = _closed(raw, _DELTA_FIELDS, "registry:scoring:delta", issues)
                if row is None:
                    continue
                token = _value_token(row.get("value"))
                if token in by_token:
                    issues.append("registry:scoring:delta_duplicate:" + axis)
                metrics = _normalize_metrics(
                    row.get("metrics"),
                    "registry:scoring:delta_metrics",
                    issues,
                    signed=True,
                )
                if metrics is not None:
                    row["metrics"] = metrics
                    by_token[token] = row
            expected = [_value_token(item) for item in axes.get(axis, [])]
            if set(by_token) != set(expected):
                issues.append("registry:scoring:coverage_mismatch:" + axis)
            normalized[axis] = [
                by_token[token] for token in expected if token in by_token
            ]
    if (
        base is not None
        and len(normalized) == len(AXIS_ORDER)
        and all(normalized[axis] for axis in AXIS_ORDER)
    ):
        for field in OBJECTIVE_DIRECTIONS:
            minimum = base[field] + sum(
                min(row["metrics"][field] for row in normalized[axis])
                for axis in AXIS_ORDER
            )
            maximum = base[field] + sum(
                max(row["metrics"][field] for row in normalized[axis])
                for axis in AXIS_ORDER
            )
            upper = 10_000 if field.endswith("_bps") else MAX_METRIC
            if minimum < 0 or maximum > upper:
                issues.append("registry:scoring:range_invalid:" + field)
    if base is not None:
        policy["base_metrics"] = base
    if raw_deltas is not None:
        policy["axis_deltas"] = normalized
    return policy


def _normalize_baseline(
    value: Any,
    envelope: Mapping[str, Any] | None,
    axes: Mapping[str, Sequence[Any]],
    issues: list[str],
) -> dict[str, Any] | None:
    baseline = _closed(
        value, _BASELINE_DRAFT_FIELDS, "registry:direct_baseline", issues
    )
    if baseline is None:
        return None
    if baseline.get("schema") != DIRECT_BASELINE_DRAFT_SCHEMA:
        issues.append("registry:direct_baseline_schema_invalid")
    if baseline.get("profile_id") != "direct/v1" or "direct/v1" not in axes.get(
        "profile_id", []
    ):
        issues.append("registry:direct_baseline_profile_invalid")
    if not _sha(baseline.get("evidence_sha256")):
        issues.append("registry:direct_baseline_evidence_invalid")
    metrics = _normalize_metrics(
        baseline.get("metrics"), "registry:direct_baseline:metrics", issues
    )
    if metrics is not None:
        baseline["metrics"] = metrics
    if envelope is not None and (
        baseline.get("budget_tokens") != envelope.get("total_tokens")
        or baseline.get("budget_cost_micros")
        != envelope.get("total_cost_micros")
    ):
        issues.append("registry:direct_baseline_budget_mismatch")
    return baseline


def _normalize_registry_draft(
    value: Any, issues: list[str]
) -> dict[str, Any] | None:
    registry = _closed(value, _REGISTRY_DRAFT_FIELDS, "registry", issues)
    if registry is None:
        return None
    if registry.get("schema") != REGISTRY_DRAFT_SCHEMA:
        issues.append("registry:schema_invalid")
    if not _identifier(registry.get("registry_id")):
        issues.append("registry:id_invalid")
    axes = _closed(
        registry.get("axes"), frozenset(AXIS_ORDER), "registry:axes", issues
    )
    normalized_axes: dict[str, list[Any]] = {}
    if axes is None:
        issues.append("registry:axes_contract_invalid")
    else:
        for axis in AXIS_ORDER:
            normalized = _normalize_axis(axis, axes.get(axis), issues)
            if normalized is not None:
                normalized_axes[axis] = normalized
        registry["axes"] = normalized_axes
    if set(normalized_axes) != set(AXIS_ORDER):
        issues.append("registry:axes_contract_invalid")
    model_ids = normalized_axes.get("model_profile_id", [])
    budget_ids = normalized_axes.get("budget_split_id", [])
    registry["model_profiles"] = _normalize_model_profiles(
        registry.get("model_profiles"), model_ids, issues
    )
    registry["budget_splits"] = _normalize_budget_splits(
        registry.get("budget_splits"), budget_ids, issues
    )
    closure = _normalize_closure_basis(
        registry.get("topology_closure_basis"), normalized_axes, issues
    )
    scoring = _normalize_scoring_policy(
        registry.get("scoring_policy"), normalized_axes, issues
    )
    if closure is not None:
        registry["topology_closure_basis"] = closure
    if scoring is not None:
        registry["scoring_policy"] = scoring
    if registry.get("objective_directions") != OBJECTIVE_DIRECTIONS:
        issues.append("registry:objective_directions_invalid")
    registry["objective_directions"] = dict(OBJECTIVE_DIRECTIONS)
    envelope = _closed(
        registry.get("budget_envelope"),
        _ENVELOPE_FIELDS,
        "registry:budget_envelope",
        issues,
    )
    if envelope is not None:
        if not _count(envelope.get("total_tokens"), MAX_METRIC) or not _count(
            envelope.get("total_cost_micros"), MAX_METRIC
        ):
            issues.append("registry:budget_envelope_invalid")
        registry["budget_envelope"] = envelope
    baseline = _normalize_baseline(
        registry.get("direct_baseline"), envelope, normalized_axes, issues
    )
    if baseline is not None:
        registry["direct_baseline"] = baseline
    limits = _closed(
        registry.get("limits"), _LIMIT_FIELDS, "registry:limits", issues
    )
    product = 0
    if len(normalized_axes) == len(AXIS_ORDER):
        product = 1
        for axis in AXIS_ORDER:
            product *= len(normalized_axes[axis])
    if limits is not None:
        if not _count(limits.get("max_candidates"), MAX_CANDIDATES) or limits.get(
            "max_candidates"
        ) == 0:
            issues.append("registry:max_candidates_invalid")
        if not _count(
            limits.get("max_archive_entries"), MAX_ARCHIVE_ENTRIES
        ) or limits.get("max_archive_entries") == 0:
            issues.append("registry:max_archive_entries_invalid")
        if not _count(limits.get("max_processes"), MAX_PROCESSES) or limits.get(
            "max_processes"
        ) == 0:
            issues.append("registry:max_processes_invalid")
        if not _count(limits.get("chunk_size"), MAX_CHUNK_SIZE) or limits.get(
            "chunk_size"
        ) == 0:
            issues.append("registry:chunk_size_invalid")
        max_candidates = limits.get("max_candidates")
        candidate_ceiling = max_candidates if type(max_candidates) is int else 0
        if product == 0 or product > candidate_ceiling:
            issues.append("registry:candidate_product_exceeds_limit")
        registry["limits"] = limits
    qwen = _closed(
        registry.get("resident_qwen"), _QWEN_FIELDS, "registry:qwen", issues
    )
    if qwen is not None:
        if (
            qwen.get("status") != "loaded"
            or qwen.get("unload_permitted") is not False
            or not _sha(qwen.get("observation_sha256"))
        ):
            issues.append("registry:resident_qwen_policy_invalid")
        registry["resident_qwen"] = qwen
    if registry.get("search_adapter") is not None:
        issues.append("registry:search_adapter_active")
    registry["search_adapter"] = None
    return registry


def _seal_registry_from_normalized(value: Mapping[str, Any]) -> dict[str, Any]:
    registry = deepcopy(dict(value))
    closure = deepcopy(registry["topology_closure_basis"])
    closure["schema"] = CLOSURE_BASIS_SCHEMA
    registry["topology_closure_basis"] = _seal(closure, "basis_sha256")
    envelope_sha256 = json_sha256(registry["budget_envelope"])
    baseline = deepcopy(registry["direct_baseline"])
    baseline["schema"] = DIRECT_BASELINE_SCHEMA
    baseline["budget_envelope_sha256"] = envelope_sha256
    registry["direct_baseline"] = _seal(baseline, "baseline_sha256")
    registry["budget_envelope_sha256"] = envelope_sha256
    registry["schema"] = REGISTRY_SCHEMA
    return _seal(registry, "registry_sha256")


def _registry(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    normalized = _normalize_registry_draft(value, issues)
    if issues or normalized is None:
        return None, sorted(set(issues))
    try:
        registry = _seal_registry_from_normalized(normalized)
        if len(_canonical(registry)) > MAX_REGISTRY_CANONICAL_BYTES:
            return None, ["registry:canonical_size_exceeded"]
        return registry, []
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None, ["registry:canonical_size_exceeded"]


def validate_registry(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    record = _closed(value, _REGISTRY_FIELDS, "registry_record", issues)
    if record is not None:
        if record.get("schema") != REGISTRY_SCHEMA:
            issues.append("registry_record:schema_invalid")
        if not _sealed(record, "registry_sha256"):
            issues.append("registry_record:seal_invalid")
        closure = _closed(
            record.get("topology_closure_basis"),
            _CLOSURE_FIELDS,
            "registry_record:closure",
            issues,
        )
        if closure is not None and (
            closure.get("schema") != CLOSURE_BASIS_SCHEMA
            or not _sealed(closure, "basis_sha256")
        ):
            issues.append("registry_record:closure_invalid")
        baseline = _closed(
            record.get("direct_baseline"),
            _BASELINE_FIELDS,
            "registry_record:baseline",
            issues,
        )
        if baseline is not None and (
            baseline.get("schema") != DIRECT_BASELINE_SCHEMA
            or not _sealed(baseline, "baseline_sha256")
        ):
            issues.append("registry_record:baseline_invalid")
        envelope_sha256 = None
        try:
            envelope_sha256 = json_sha256(record.get("budget_envelope"))
        except (TypeError, ValueError, OverflowError, RecursionError):
            issues.append("registry_record:budget_envelope_invalid")
        if record.get("budget_envelope_sha256") != envelope_sha256:
            issues.append("registry_record:budget_envelope_invalid")
        if baseline is not None and baseline.get(
            "budget_envelope_sha256"
        ) != record.get("budget_envelope_sha256"):
            issues.append("registry_record:baseline_budget_binding_invalid")
        if closure is not None and baseline is not None:
            draft = deepcopy(record)
            draft.pop("registry_sha256", None)
            draft.pop("budget_envelope_sha256", None)
            draft["schema"] = REGISTRY_DRAFT_SCHEMA
            closure_draft = deepcopy(closure)
            closure_draft.pop("basis_sha256", None)
            closure_draft["schema"] = CLOSURE_BASIS_DRAFT_SCHEMA
            draft["topology_closure_basis"] = closure_draft
            baseline_draft = deepcopy(baseline)
            baseline_draft.pop("baseline_sha256", None)
            baseline_draft.pop("budget_envelope_sha256", None)
            baseline_draft["schema"] = DIRECT_BASELINE_DRAFT_SCHEMA
            draft["direct_baseline"] = baseline_draft
            normalized_issues: list[str] = []
            normalized = _normalize_registry_draft(draft, normalized_issues)
            if normalized_issues or normalized is None:
                issues.append("registry_record:semantic_invalid")
            else:
                try:
                    reproduced = _seal_registry_from_normalized(normalized)
                except (TypeError, ValueError, OverflowError, RecursionError):
                    reproduced = None
                if reproduced != record:
                    issues.append("registry_record:normalization_drift")
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _context_from_registry(registry: Mapping[str, Any]) -> dict[str, Any]:
    model_profiles = {
        item["model_profile_id"]: item for item in registry["model_profiles"]
    }
    budget_splits = {
        item["budget_split_id"]: item for item in registry["budget_splits"]
    }
    delta_maps = {
        axis: {
            _value_token(row["value"]): row["metrics"]
            for row in registry["scoring_policy"]["axis_deltas"][axis]
        }
        for axis in AXIS_ORDER
    }
    return {
        "registry_sha256": registry["registry_sha256"],
        "axes": registry["axes"],
        "model_profiles": model_profiles,
        "budget_splits": budget_splits,
        "closure": registry["topology_closure_basis"],
        "base_metrics": registry["scoring_policy"]["base_metrics"],
        "delta_maps": delta_maps,
        "metric_evidence_sha256": registry["scoring_policy"][
            "evidence_sha256"
        ],
    }


def _candidate_from_combo(
    combo: Sequence[Any], context: Mapping[str, Any]
) -> dict[str, Any]:
    genome = {axis: value for axis, value in zip(AXIS_ORDER, combo)}
    model = context["model_profiles"][genome["model_profile_id"]]
    budget = context["budget_splits"][genome["budget_split_id"]]
    core = {
        "schema": CANDIDATE_SCHEMA,
        "registry_sha256": context["registry_sha256"],
        "genome": genome,
        "model_profile_sha256": json_sha256(model),
        "budget_split_sha256": json_sha256(budget),
    }
    return _seal(core, "candidate_sha256")


def validate_candidate(
    value: Any, registry: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    issues: list[str] = []
    candidate = _closed(value, _CANDIDATE_FIELDS, "candidate", issues)
    if candidate is not None:
        if candidate.get("schema") != CANDIDATE_SCHEMA:
            issues.append("candidate:schema_invalid")
        if not _sealed(candidate, "candidate_sha256"):
            issues.append("candidate:seal_invalid")
        genome_value = _closed(
            candidate.get("genome"), _GENOME_FIELDS, "candidate:genome", issues
        )
        if genome_value is not None and registry is not None:
            if validate_registry(registry)["status"] != "PASS":
                issues.append("candidate:registry_invalid")
            else:
                context = _context_from_registry(registry)
                for axis in AXIS_ORDER:
                    tokens = {
                        _value_token(item) for item in registry["axes"][axis]
                    }
                    if _value_token(genome_value.get(axis)) not in tokens:
                        issues.append("candidate:axis_outside_registry:" + axis)
                if not issues:
                    reproduced = _candidate_from_combo(
                        tuple(genome_value[axis] for axis in AXIS_ORDER), context
                    )
                    if reproduced != candidate:
                        issues.append("candidate:registry_binding_invalid")
        elif genome_value is not None:
            for field in (
                "registry_sha256",
                "model_profile_sha256",
                "budget_split_sha256",
            ):
                if not _sha(candidate.get(field)):
                    issues.append("candidate:" + field + "_invalid")
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _profile_reasons(
    genome: Mapping[str, Any], model: Mapping[str, Any], budget: Mapping[str, Any]
) -> list[str]:
    profile = genome["profile_id"]
    lanes = genome["lane_count"]
    cut = genome["dependency_cut"]
    join = genome["join_class"]
    depth = genome["depth"]
    roles = genome["executor_roles"]
    early = genome["early_exit"]
    reasons: list[str] = []
    if profile == "direct/v1":
        if lanes != 1:
            reasons.append("feasibility:direct_lane_count")
        if cut != "none":
            reasons.append("feasibility:direct_cut")
        if join != "none":
            reasons.append("feasibility:direct_join")
        if depth != 1:
            reasons.append("feasibility:direct_depth")
        if roles != "single_executor":
            reasons.append("feasibility:direct_roles")
        if early not in {"none", "deterministic_pass"}:
            reasons.append("feasibility:direct_early_exit")
        if budget["integration_bps"] != 0:
            reasons.append("feasibility:direct_integration_budget")
    elif profile == "execute_verify_repair/v1":
        if lanes != 1:
            reasons.append("feasibility:repair_lane_count")
        if cut != "none" or join != "none":
            reasons.append("feasibility:repair_topology")
        if depth not in {2, 3}:
            reasons.append("feasibility:repair_depth")
        if roles != "executor_verifier":
            reasons.append("feasibility:repair_roles")
        if early not in {"none", "deterministic_pass"}:
            reasons.append("feasibility:repair_early_exit")
        if budget["integration_bps"] != 0:
            reasons.append("feasibility:repair_integration_budget")
    elif profile == "parallel_join/v1":
        if lanes < 2:
            reasons.append("feasibility:parallel_lane_count")
        if cut not in {"independent", "ownership_partitions"}:
            reasons.append("feasibility:parallel_cut")
        if join not in {"mechanical", "semantic"}:
            reasons.append("feasibility:parallel_join")
        if depth != 2:
            reasons.append("feasibility:parallel_depth")
        if roles != "parallel_executors_integrator":
            reasons.append("feasibility:parallel_roles")
        if early not in {"none", "quorum_impossible"}:
            reasons.append("feasibility:parallel_early_exit")
        if budget["integration_bps"] == 0:
            reasons.append("feasibility:parallel_integration_budget")
    elif profile == "best_of_n/v1":
        if not 2 <= lanes <= 8:
            reasons.append("feasibility:best_of_n_lane_count")
        if cut != "independent":
            reasons.append("feasibility:best_of_n_cut")
        if join != "blinded_comparison":
            reasons.append("feasibility:best_of_n_join")
        if depth != 2:
            reasons.append("feasibility:best_of_n_depth")
        if roles != "candidate_comparator":
            reasons.append("feasibility:best_of_n_roles")
        if early != "none":
            reasons.append("feasibility:best_of_n_early_exit")
        if budget["integration_bps"] == 0:
            reasons.append("feasibility:best_of_n_integration_budget")
    elif profile == "finite_dag/v1":
        if lanes < 2:
            reasons.append("feasibility:finite_dag_lane_count")
        if cut not in {"dependency_layers", "ownership_partitions"}:
            reasons.append("feasibility:finite_dag_cut")
        if join not in {"mechanical", "semantic"}:
            reasons.append("feasibility:finite_dag_join")
        if depth < 2:
            reasons.append("feasibility:finite_dag_depth")
        if roles != "planner_executors_integrator":
            reasons.append("feasibility:finite_dag_roles")
        if early not in {
            "none",
            "deterministic_pass",
            "dependency_failure",
            "quorum_impossible",
        }:
            reasons.append("feasibility:finite_dag_early_exit")
        if budget["integration_bps"] == 0:
            reasons.append("feasibility:finite_dag_integration_budget")
    if roles in {
        "candidate_comparator",
        "parallel_executors_integrator",
        "planner_executors_integrator",
    } and model.get("integrator") == "none":
        reasons.append("feasibility:model_integrator_missing")
    return reasons


def _closure_reasons(
    genome: Mapping[str, Any], basis: Mapping[str, Any]
) -> list[str]:
    reasons: list[str] = []
    mappings = (
        ("profile_id", "profile_ids", "profile"),
        ("dependency_cut", "dependency_cuts", "cut"),
        ("context_policy", "context_policies", "context"),
        ("join_class", "join_classes", "join"),
    )
    for genome_field, basis_field, label in mappings:
        if genome[genome_field] not in basis[basis_field]:
            reasons.append("topology_closure:" + label + "_uncovered")
    if genome["lane_count"] > basis["max_lane_count"]:
        reasons.append("topology_closure:lane_count_uncovered")
    if genome["depth"] > basis["max_depth"]:
        reasons.append("topology_closure:depth_uncovered")
    return reasons


def _score(
    genome: Mapping[str, Any], context: Mapping[str, Any]
) -> dict[str, int]:
    metrics = dict(context["base_metrics"])
    for axis in AXIS_ORDER:
        delta = context["delta_maps"][axis][_value_token(genome[axis])]
        for field in OBJECTIVE_DIRECTIONS:
            metrics[field] += delta[field]
    return metrics


def _evaluate_combo(
    combo: Sequence[Any], context: Mapping[str, Any]
) -> dict[str, Any]:
    candidate = _candidate_from_combo(combo, context)
    genome = candidate["genome"]
    model = context["model_profiles"][genome["model_profile_id"]]
    budget = context["budget_splits"][genome["budget_split_id"]]
    profile_reasons = _profile_reasons(genome, model, budget)
    closure_reasons = _closure_reasons(genome, context["closure"])
    reasons = sorted(set(profile_reasons + closure_reasons))
    closure_binding = json_sha256(
        {
            "schema": "orch-dork/candidate-topology-closure-binding/v1",
            "basis_sha256": context["closure"]["basis_sha256"],
            "candidate_sha256": candidate["candidate_sha256"],
            "closed": not closure_reasons,
        }
    )
    metrics = None if reasons else _score(genome, context)
    core = {
        "schema": CANDIDATE_DECISION_SCHEMA,
        "candidate": candidate,
        "decision": "PRUNED" if reasons else "FEASIBLE",
        "reasons": reasons,
        "topology_closure_sha256": closure_binding,
        "metrics": metrics,
        "metric_evidence_sha256": (
            None if reasons else context["metric_evidence_sha256"]
        ),
        "metric_evidence_class": (
            None if reasons else "submitted_structural_projection"
        ),
        "evaluated": not reasons,
    }
    return _seal(core, "decision_sha256")


def validate_candidate_decision(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    decision = _closed(value, _DECISION_FIELDS, "candidate_decision", issues)
    if decision is not None:
        if decision.get("schema") != CANDIDATE_DECISION_SCHEMA:
            issues.append("candidate_decision:schema_invalid")
        if not _sealed(decision, "decision_sha256"):
            issues.append("candidate_decision:seal_invalid")
        if validate_candidate(decision.get("candidate"))["status"] != "PASS":
            issues.append("candidate_decision:candidate_invalid")
        if decision.get("decision") not in {"FEASIBLE", "PRUNED"}:
            issues.append("candidate_decision:decision_invalid")
        reasons = decision.get("reasons")
        if (
            not isinstance(reasons, list)
            or any(not isinstance(item, str) or not item for item in reasons)
            or reasons != sorted(set(reasons))
        ):
            issues.append("candidate_decision:reasons_invalid")
        if not _sha(decision.get("topology_closure_sha256")):
            issues.append("candidate_decision:closure_invalid")
        feasible = decision.get("decision") == "FEASIBLE"
        if feasible:
            metric_issues: list[str] = []
            _normalize_metrics(
                decision.get("metrics"), "candidate_decision:metrics", metric_issues
            )
            if metric_issues or not _sha(decision.get("metric_evidence_sha256")):
                issues.append("candidate_decision:metrics_invalid")
            if (
                decision.get("metric_evidence_class")
                != "submitted_structural_projection"
            ):
                issues.append("candidate_decision:metrics_invalid")
            if reasons or decision.get("evaluated") is not True:
                issues.append("candidate_decision:feasible_state_invalid")
        elif (
            not reasons
            or decision.get("metrics") is not None
            or decision.get("metric_evidence_sha256") is not None
            or decision.get("metric_evidence_class") is not None
            or decision.get("evaluated") is not False
        ):
            issues.append("candidate_decision:pruned_state_invalid")
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


_POOL_CONTEXT: dict[str, Any] | None = None


def _initialize_pool(context: Mapping[str, Any]) -> None:
    global _POOL_CONTEXT
    _POOL_CONTEXT = deepcopy(dict(context))


def _evaluate_pool_chunk(chunk: Sequence[Sequence[Any]]) -> list[dict[str, Any]]:
    if _POOL_CONTEXT is None:
        raise RuntimeError("topology pool context unavailable")
    return [_evaluate_combo(combo, _POOL_CONTEXT) for combo in chunk]


def _chunks(
    values: Iterable[Sequence[Any]], size: int
) -> Iterator[list[Sequence[Any]]]:
    iterator = iter(values)
    while True:
        chunk = list(itertools.islice(iterator, size))
        if not chunk:
            return
        yield chunk


def _decision_rows(
    registry: Mapping[str, Any], process_count: int
) -> tuple[Iterator[list[dict[str, Any]]], dict[str, int], Any]:
    context = _context_from_registry(registry)
    combinations = itertools.product(
        *(registry["axes"][axis] for axis in AXIS_ORDER)
    )
    chunk_size = registry["limits"]["chunk_size"]
    chunk_iterator = _chunks(combinations, chunk_size)
    execution = {"peak_buffered_candidates": 0}
    if process_count == 1:
        def single() -> Iterator[list[dict[str, Any]]]:
            for chunk in chunk_iterator:
                execution["peak_buffered_candidates"] = max(
                    execution["peak_buffered_candidates"], len(chunk)
                )
                yield [_evaluate_combo(combo, context) for combo in chunk]

        return single(), execution, None

    executor = ProcessPoolExecutor(
        max_workers=process_count,
        initializer=_initialize_pool,
        initargs=(context,),
    )

    def parallel() -> Iterator[list[dict[str, Any]]]:
        pending: deque[tuple[Any, int]] = deque()
        max_pending = process_count * 2

        def submit_one() -> bool:
            try:
                chunk = next(chunk_iterator)
            except StopIteration:
                return False
            pending.append((executor.submit(_evaluate_pool_chunk, chunk), len(chunk)))
            buffered = sum(size for _, size in pending)
            execution["peak_buffered_candidates"] = max(
                execution["peak_buffered_candidates"], buffered
            )
            return True

        for _ in range(max_pending):
            if not submit_one():
                break
        while pending:
            future, _ = pending.popleft()
            rows = future.result()
            submit_one()
            yield rows

    return parallel(), execution, executor


def _dominates(left: Mapping[str, int], right: Mapping[str, int]) -> bool:
    at_least_as_good = True
    strictly_better = False
    for field, direction in OBJECTIVE_DIRECTIONS.items():
        if direction == "maximize":
            if left[field] < right[field]:
                at_least_as_good = False
                break
            strictly_better = strictly_better or left[field] > right[field]
        else:
            if left[field] > right[field]:
                at_least_as_good = False
                break
            strictly_better = strictly_better or left[field] < right[field]
    return at_least_as_good and strictly_better


class _ParetoAccumulator:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self.entries: list[dict[str, Any]] = []

    @staticmethod
    def _equivalence_hasher(candidate_sha256: str):
        hasher = hashlib.sha256()
        hasher.update(candidate_sha256.encode("ascii") + b"\n")
        return hasher

    def add(self, decision: Mapping[str, Any]) -> None:
        candidate = decision["candidate"]
        metrics = decision["metrics"]
        candidate_sha256 = candidate["candidate_sha256"]
        for entry in self.entries:
            if entry["metrics"] == metrics:
                entry["equivalent_candidate_count"] += 1
                entry["_equivalence_hasher"].update(
                    candidate_sha256.encode("ascii") + b"\n"
                )
                if candidate_sha256 < entry["candidate"]["candidate_sha256"]:
                    entry["candidate"] = deepcopy(candidate)
                    entry["topology_closure_sha256"] = decision[
                        "topology_closure_sha256"
                    ]
                    entry["metric_evidence_sha256"] = decision[
                        "metric_evidence_sha256"
                    ]
                return
            if _dominates(entry["metrics"], metrics):
                return
        self.entries = [
            entry
            for entry in self.entries
            if not _dominates(metrics, entry["metrics"])
        ]
        self.entries.append(
            {
                "candidate": deepcopy(candidate),
                "metrics": deepcopy(metrics),
                "topology_closure_sha256": decision[
                    "topology_closure_sha256"
                ],
                "metric_evidence_sha256": decision["metric_evidence_sha256"],
                "metric_evidence_class": decision["metric_evidence_class"],
                "equivalent_candidate_count": 1,
                "_equivalence_hasher": self._equivalence_hasher(
                    candidate_sha256
                ),
            }
        )
        if len(self.entries) > self.maximum:
            raise ArchiveLimitError("exact Pareto frontier exceeded bound")

    def finish(self) -> list[dict[str, Any]]:
        result = []
        for entry in self.entries:
            row = {
                key: deepcopy(value)
                for key, value in entry.items()
                if key != "_equivalence_hasher"
            }
            row["equivalent_candidates_sha256"] = entry[
                "_equivalence_hasher"
            ].hexdigest()
            result.append(row)
        return sorted(
            result, key=lambda row: row["candidate"]["candidate_sha256"]
        )


def _enumerate_registry(
    registry: Mapping[str, Any], process_count: int
) -> tuple[dict[str, Any] | None, dict[str, Any], list[str]]:
    rows, execution_state, executor = _decision_rows(registry, process_count)
    stream_hasher = hashlib.sha256()
    pareto = _ParetoAccumulator(registry["limits"]["max_archive_entries"])
    candidate_count = 0
    feasible_count = 0
    pruned_count = 0
    prune_counts: dict[str, int] = {}
    prune_samples: dict[str, list[str]] = {}
    issues: list[str] = []
    try:
        for chunk in rows:
            for decision in chunk:
                candidate_count += 1
                stream_hasher.update(_canonical(decision) + b"\n")
                if decision["decision"] == "FEASIBLE":
                    feasible_count += 1
                    pareto.add(decision)
                else:
                    pruned_count += 1
                    candidate_sha256 = decision["candidate"]["candidate_sha256"]
                    for reason in decision["reasons"]:
                        prune_counts[reason] = prune_counts.get(reason, 0) + 1
                        samples = prune_samples.setdefault(reason, [])
                        if len(samples) < 3:
                            samples.append(candidate_sha256)
    except ArchiveLimitError:
        issues.append("archive:limit_exceeded")
    except Exception:
        issues.append("enumeration:process_failed")
    finally:
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
    execution = {
        "mode": "cpu_exhaustive",
        "process_count": process_count,
        "peak_buffered_candidates": execution_state[
            "peak_buffered_candidates"
        ],
        "bounded_queue": True,
    }
    if issues:
        return None, execution, sorted(set(issues))
    frontier = pareto.finish()
    prune_reasons = [
        {
            "reason": reason,
            "count": prune_counts[reason],
            "candidate_samples": prune_samples[reason],
        }
        for reason in sorted(prune_counts)
    ]
    core = {
        "schema": ARCHIVE_SCHEMA,
        "registry_sha256": registry["registry_sha256"],
        "candidate_count": candidate_count,
        "feasible_count": feasible_count,
        "pruned_count": pruned_count,
        "ordered_candidate_stream_sha256": stream_hasher.hexdigest(),
        "decision_counts": {
            "FEASIBLE": feasible_count,
            "PRUNED": pruned_count,
        },
        "prune_reasons": prune_reasons,
        "objective_directions": dict(OBJECTIVE_DIRECTIONS),
        "source_authority": "submitted_inactive_evidence",
        "direct_baseline": deepcopy(registry["direct_baseline"]),
        "frontier": frontier,
        "frontier_candidate_sha256s": [
            entry["candidate"]["candidate_sha256"] for entry in frontier
        ],
        "max_archive_entries": registry["limits"]["max_archive_entries"],
        "bounded_memory": True,
        "full_population_retained": False,
        "search_mode": "exhaustive",
        "cpu_only": True,
        "resident_qwen_action": "UNCHANGED",
        "future_qwen_selection_active": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "dispatch_permitted": False,
        "workers_permitted": False,
        "authority_granted": False,
    }
    try:
        archive = _seal(core, "archive_sha256")
        if len(_canonical(archive)) > MAX_ARCHIVE_CANONICAL_BYTES:
            return None, execution, ["archive:canonical_size_exceeded"]
        return archive, execution, []
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None, execution, ["archive:canonical_size_exceeded"]


def validate_archive(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    archive = _closed(value, _ARCHIVE_FIELDS, "archive", issues)
    if archive is not None:
        if archive.get("schema") != ARCHIVE_SCHEMA:
            issues.append("archive:schema_invalid")
        if not _sealed(archive, "archive_sha256"):
            issues.append("archive:seal_invalid")
        for field in (
            "registry_sha256",
            "ordered_candidate_stream_sha256",
        ):
            if not _sha(archive.get(field)):
                issues.append("archive:" + field + "_invalid")
        counts = (
            archive.get("candidate_count"),
            archive.get("feasible_count"),
            archive.get("pruned_count"),
        )
        if any(not _count(item, MAX_CANDIDATES) for item in counts) or counts[0] != (
            counts[1] + counts[2]
        ):
            issues.append("archive:counts_invalid")
        if archive.get("decision_counts") != {
            "FEASIBLE": archive.get("feasible_count"),
            "PRUNED": archive.get("pruned_count"),
        }:
            issues.append("archive:decision_counts_invalid")
        if archive.get("objective_directions") != OBJECTIVE_DIRECTIONS:
            issues.append("archive:objectives_invalid")
        baseline = _closed(
            archive.get("direct_baseline"),
            _BASELINE_FIELDS,
            "archive:direct_baseline",
            issues,
        )
        if baseline is not None and (
            baseline.get("schema") != DIRECT_BASELINE_SCHEMA
            or baseline.get("profile_id") != "direct/v1"
            or not _sealed(baseline, "baseline_sha256")
            or not _sha(baseline.get("budget_envelope_sha256"))
        ):
            issues.append("archive:direct_baseline_invalid")
        if baseline is not None:
            baseline_metric_issues: list[str] = []
            _normalize_metrics(
                baseline.get("metrics"),
                "archive:direct_baseline:metrics",
                baseline_metric_issues,
            )
            if (
                baseline_metric_issues
                or not _count(baseline.get("budget_tokens"), MAX_METRIC)
                or not _count(baseline.get("budget_cost_micros"), MAX_METRIC)
                or not _sha(baseline.get("evidence_sha256"))
            ):
                issues.append("archive:direct_baseline_invalid")
        maximum = archive.get("max_archive_entries")
        if not _count(maximum, MAX_ARCHIVE_ENTRIES) or maximum == 0:
            issues.append("archive:limit_invalid")
            maximum = 0
        frontier = archive.get("frontier")
        normalized_frontier: list[dict[str, Any]] = []
        if not isinstance(frontier, list) or len(frontier) > maximum:
            issues.append("archive:frontier_invalid")
        else:
            for raw in frontier:
                entry = _closed(raw, _FRONTIER_FIELDS, "archive:frontier", issues)
                if entry is None:
                    continue
                entry_valid = True
                if validate_candidate(entry.get("candidate"))["status"] != "PASS":
                    issues.append("archive:frontier_candidate_invalid")
                    entry_valid = False
                metric_issues: list[str] = []
                _normalize_metrics(
                    entry.get("metrics"), "archive:frontier_metrics", metric_issues
                )
                if metric_issues:
                    issues.append("archive:frontier_metrics_invalid")
                    entry_valid = False
                if not _sha(entry.get("topology_closure_sha256")):
                    issues.append("archive:frontier_closure_invalid")
                    entry_valid = False
                if (
                    not _sha(entry.get("metric_evidence_sha256"))
                    or entry.get("metric_evidence_class")
                    != "submitted_structural_projection"
                ):
                    issues.append("archive:frontier_metric_evidence_invalid")
                    entry_valid = False
                if not _count(
                    entry.get("equivalent_candidate_count"), MAX_CANDIDATES
                ) or entry.get("equivalent_candidate_count") == 0:
                    issues.append("archive:frontier_equivalence_invalid")
                    entry_valid = False
                if not _sha(entry.get("equivalent_candidates_sha256")):
                    issues.append("archive:frontier_equivalence_invalid")
                    entry_valid = False
                if entry_valid:
                    normalized_frontier.append(entry)
        ids = [
            entry["candidate"]["candidate_sha256"]
            for entry in normalized_frontier
            if isinstance(entry.get("candidate"), Mapping)
        ]
        if ids != sorted(set(ids)) or archive.get(
            "frontier_candidate_sha256s"
        ) != ids:
            issues.append("archive:frontier_identity_invalid")
        feasible_value = archive.get("feasible_count")
        if (
            type(feasible_value) is int
            and feasible_value > 0
            and not normalized_frontier
        ):
            issues.append("archive:frontier_missing")
        for index, left in enumerate(normalized_frontier):
            for right in normalized_frontier[index + 1 :]:
                if left["metrics"] == right["metrics"] or _dominates(
                    left["metrics"], right["metrics"]
                ) or _dominates(right["metrics"], left["metrics"]):
                    issues.append("archive:frontier_dominance_invalid")
        prune_reasons = archive.get("prune_reasons")
        if not isinstance(prune_reasons, list):
            issues.append("archive:prune_reasons_invalid")
        else:
            labels = []
            for raw in prune_reasons:
                item = _closed(
                    raw, _PRUNE_SUMMARY_FIELDS, "archive:prune_reason", issues
                )
                if item is None:
                    continue
                if isinstance(item.get("reason"), str):
                    labels.append(item["reason"])
                samples = item.get("candidate_samples")
                if (
                    not isinstance(item.get("reason"), str)
                    or not _count(item.get("count"), MAX_CANDIDATES)
                    or not isinstance(samples, list)
                    or len(samples) > 3
                    or any(not _sha(sample) for sample in samples)
                ):
                    issues.append("archive:prune_reason_invalid")
            if labels != sorted(set(labels)):
                issues.append("archive:prune_reason_order_invalid")
        if (
            archive.get("bounded_memory") is not True
            or archive.get("source_authority")
            != "submitted_inactive_evidence"
            or archive.get("full_population_retained") is not False
            or archive.get("search_mode") != "exhaustive"
            or archive.get("cpu_only") is not True
            or archive.get("resident_qwen_action") != "UNCHANGED"
            or archive.get("future_qwen_selection_active") is not False
            or archive.get("provider_free") is not True
            or archive.get("model_calls") != 0
            or archive.get("hosted_calls") != 0
            or archive.get("retries") != 0
            or archive.get("fallbacks") != 0
            or archive.get("replacements") != 0
            or archive.get("dispatch_permitted") is not False
            or archive.get("workers_permitted") is not False
            or archive.get("authority_granted") is not False
        ):
            issues.append("archive:inactive_boundary_invalid")
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _valid_process_count(registry: Mapping[str, Any], value: Any) -> bool:
    return (
        type(value) is int
        and 1 <= value <= registry.get("limits", {}).get("max_processes", 0)
        and value <= (os.cpu_count() or 1)
    )


def _selection(
    registry: Any,
    archive: Any,
    candidate_sha256s: Any,
    process_count: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    if validate_registry(registry)["status"] != "PASS":
        issues.append("selection:registry_invalid")
        return None, None, issues
    if validate_archive(archive)["status"] != "PASS":
        issues.append("selection:archive_invalid")
        return None, None, issues
    if archive.get("registry_sha256") != registry.get("registry_sha256"):
        issues.append("selection:registry_binding_invalid")
        return None, None, issues
    if not _valid_process_count(registry, process_count):
        issues.append("selection:process_count_invalid")
        return None, None, issues
    reproduced, execution, reproduction_issues = _enumerate_registry(
        registry, process_count
    )
    if reproduction_issues or reproduced is None:
        issues.append("selection:archive_reproduction_failed")
        return None, execution, issues
    if reproduced != archive:
        issues.append("selection:archive_reproduction_mismatch")
        return None, execution, issues
    if (
        not isinstance(candidate_sha256s, list)
        or not candidate_sha256s
        or len(candidate_sha256s) > MAX_SELECTION
        or any(not _sha(item) for item in candidate_sha256s)
        or len(candidate_sha256s) != len(set(candidate_sha256s))
    ):
        issues.append("selection:candidates_invalid")
        return None, execution, issues
    frontier = set(archive["frontier_candidate_sha256s"])
    if not set(candidate_sha256s) <= frontier:
        issues.append("selection:candidate_not_frontier")
        return None, execution, issues
    core = {
        "schema": SELECTION_SCHEMA,
        "registry_sha256": registry["registry_sha256"],
        "archive_sha256": archive["archive_sha256"],
        "candidate_sha256s": sorted(candidate_sha256s),
        "decision": "INACTIVE_FUTURE_QWEN_SELECTION",
        "qwen_dispatch_permitted": False,
        "resident_qwen_action": "UNCHANGED",
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "tools_permitted": False,
        "workers_permitted": False,
        "authority_granted": False,
        "policy_mutated": False,
        "release_permitted": False,
        "installation_permitted": False,
        "activation_permitted": False,
    }
    return _seal(core, "selection_sha256"), execution, []


def validate_selection(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    record = _closed(value, _SELECTION_FIELDS, "selection", issues)
    if record is not None:
        if record.get("schema") != SELECTION_SCHEMA:
            issues.append("selection:schema_invalid")
        if not _sealed(record, "selection_sha256"):
            issues.append("selection:seal_invalid")
        if not _sha(record.get("registry_sha256")):
            issues.append("selection:registry_invalid")
        if not _sha(record.get("archive_sha256")):
            issues.append("selection:archive_invalid")
        candidates = record.get("candidate_sha256s")
        if (
            not isinstance(candidates, list)
            or not candidates
            or len(candidates) > MAX_SELECTION
            or any(not _sha(item) for item in candidates)
            or candidates != sorted(set(candidates))
        ):
            issues.append("selection:candidates_invalid")
        if (
            record.get("decision") != "INACTIVE_FUTURE_QWEN_SELECTION"
            or record.get("qwen_dispatch_permitted") is not False
            or record.get("resident_qwen_action") != "UNCHANGED"
            or record.get("provider_free") is not True
            or record.get("model_calls") != 0
            or record.get("hosted_calls") != 0
            or record.get("retries") != 0
            or record.get("fallbacks") != 0
            or record.get("replacements") != 0
        ):
            issues.append("selection:inactive_boundary_invalid")
        for field in (
            "tools_permitted",
            "workers_permitted",
            "authority_granted",
            "policy_mutated",
            "release_permitted",
            "installation_permitted",
            "activation_permitted",
        ):
            if record.get(field) is not False:
                issues.append("selection:inactive_boundary_invalid")
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _blank(action: str | None) -> dict[str, Any]:
    return {
        "action": action if action in ACTIONS else "unknown",
        "registry": None,
        "candidate_decision": None,
        "archive": None,
        "selection": None,
        "execution": None,
    }


def evaluate(program: Any) -> dict[str, Any]:
    issues: list[str] = []
    try:
        canonical_input = _canonical(program) if _shape_within_bounds(program) else None
    except (TypeError, ValueError, OverflowError, RecursionError):
        canonical_input = None
    if canonical_input is None:
        issues.append("input:hostile_or_noncanonical")
        envelope = None
    else:
        envelope = _closed(program, _PROGRAM_FIELDS, "program", issues)
    action: str | None = None
    payload = _blank(None)
    decision = "ENVELOPE_INVALID"
    if envelope is not None:
        raw_action = envelope.get("action")
        if envelope.get("schema") != PROGRAM_SCHEMA:
            issues.append("program:schema_invalid")
        if raw_action in ACTIONS:
            action = raw_action
            payload["action"] = action
        else:
            issues.append("program:action_invalid")
        if not issues and action == "seal_registry":
            request = _closed(
                envelope.get("request"),
                _SEAL_REGISTRY_FIELDS,
                "request",
                issues,
            )
            if request is not None:
                payload["registry"], found = _registry(request["registry"])
                issues.extend(found)
                decision = "REGISTRY_SEALED" if not found else "REJECTED"
        elif not issues and action == "evaluate_candidate":
            request = _closed(
                envelope.get("request"),
                _EVALUATE_CANDIDATE_FIELDS,
                "request",
                issues,
            )
            if request is not None:
                registry = request["registry"]
                if validate_registry(registry)["status"] != "PASS":
                    issues.append("candidate:registry_invalid")
                genome_value = _closed(
                    request["genome"], _GENOME_FIELDS, "candidate:genome", issues
                )
                if genome_value is not None and not issues:
                    context = _context_from_registry(registry)
                    for axis in AXIS_ORDER:
                        allowed = {
                            _value_token(item) for item in registry["axes"][axis]
                        }
                        if _value_token(genome_value.get(axis)) not in allowed:
                            issues.append("candidate:axis_outside_registry:" + axis)
                    if not issues:
                        combo = tuple(genome_value[axis] for axis in AXIS_ORDER)
                        payload["candidate_decision"] = _evaluate_combo(
                            combo, context
                        )
                        decision = payload["candidate_decision"]["decision"]
        elif not issues and action == "enumerate":
            request = _closed(
                envelope.get("request"), _ENUMERATE_FIELDS, "request", issues
            )
            if request is not None:
                registry = request["registry"]
                process_count = request["process_count"]
                if validate_registry(registry)["status"] != "PASS":
                    issues.append("enumeration:registry_invalid")
                elif not _valid_process_count(registry, process_count):
                    issues.append("enumeration:process_count_invalid")
                if not issues:
                    archive, execution, found = _enumerate_registry(
                        registry, process_count
                    )
                    payload["archive"] = archive
                    payload["execution"] = execution
                    issues.extend(found)
                    decision = "ENUMERATED" if not found else "REJECTED"
        elif not issues and action == "select_frontier":
            request = _closed(
                envelope.get("request"), _SELECT_FIELDS, "request", issues
            )
            if request is not None:
                payload["selection"], execution, found = _selection(
                    request["registry"],
                    request["archive"],
                    request["candidate_sha256s"],
                    request["process_count"],
                )
                payload["execution"] = execution
                issues.extend(found)
                decision = "FRONTIER_SELECTED" if not found else "REJECTED"
    unique = sorted(set(issues))
    report = {
        "schema": REPORT_SCHEMA,
        **payload,
        "status": "PASS" if not unique else "FAIL",
        "decision": decision,
        "issues": unique,
        "provider_free": True,
        "cpu_only": True,
        "resident_qwen_action": "UNCHANGED",
        "future_qwen_selection_active": False,
        "search_adapter_permitted": False,
        "model_calls": 0,
        "hosted_calls": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "mutation_permitted": False,
        "dispatch_permitted": False,
        "tools_permitted": False,
        "workers_permitted": False,
        "authority_granted": False,
        "policy_mutated": False,
        "release_permitted": False,
        "installation_permitted": False,
        "activation_permitted": False,
    }
    return _seal(report, "report_sha256")


__all__ = [
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "REGISTRY_DRAFT_SCHEMA",
    "REGISTRY_SCHEMA",
    "CLOSURE_BASIS_DRAFT_SCHEMA",
    "CLOSURE_BASIS_SCHEMA",
    "SCORING_POLICY_SCHEMA",
    "DIRECT_BASELINE_DRAFT_SCHEMA",
    "DIRECT_BASELINE_SCHEMA",
    "CANDIDATE_SCHEMA",
    "CANDIDATE_DECISION_SCHEMA",
    "ARCHIVE_SCHEMA",
    "SELECTION_SCHEMA",
    "ACTIONS",
    "AXIS_ORDER",
    "PROFILE_IDS",
    "DEPENDENCY_CUTS",
    "CONTEXT_POLICIES",
    "JOIN_CLASSES",
    "EXECUTOR_ROLE_SETS",
    "EARLY_EXIT_CONDITIONS",
    "OBJECTIVE_DIRECTIONS",
    "json_sha256",
    "validate_registry",
    "validate_candidate",
    "validate_candidate_decision",
    "validate_archive",
    "validate_selection",
    "evaluate",
]


if __name__ == "__main__":
    raise SystemExit("Import and call evaluate(program); no CLI is provided.")
