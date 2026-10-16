#!/usr/bin/env python3
"""Static coupling prior and scout-delta validation (north star P2).

``build_topology_prior`` walks one explicit source root and produces the
weighted dependency graph that seeds an initial decomposition: node weights
approximate work volume (lines), edge weights measure coupling (import
statements).  It reads only under the caller-supplied root, never executes
or imports the code it scans, and fails closed on oversized trees.

``validate_topology_delta`` checks the typed graph-delta a read-only scout
returns (never an essay), and ``partition_suggestion`` turns a passing prior
into an advisory grouping - a seed for root planning, not a gate.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

PRIOR_SCHEMA = "orch-dork/topology-prior/v1"
DELTA_SCHEMA = "orch-dork/topology-delta/v1"
DELTA_REPORT_SCHEMA = "orch-dork/topology-delta-report/v1"
PARTITION_SCHEMA = "orch-dork/topology-partition-report/v1"

MAX_DIR_FILES = 10000
SOURCE_SUFFIXES = (".py", ".js", ".ts")
SKIP_DIR_NAMES = {"node_modules", "__pycache__"}

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_JS_IMPORT = re.compile(
    r"import\s+(?:[\w$*,\s{}]+\s+from\s*)?[\"']([^\"']+)[\"']"
    r"|require\s*\(\s*[\"']([^\"']+)[\"']\s*\)"
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return False
    for key in sorted(keys - set(value)):
        _issue(issues, label + ":missing:" + str(key))
    for key in sorted(set(value) - keys):
        _issue(issues, label + ":unknown:" + str(key))
    return set(value) == keys


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: Any, label: str, issues: list[str], *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list):
        _issue(issues, label + ":not_array")
        return []
    out: list[str] = []
    for index, item in enumerate(value):
        if not _text(item):
            _issue(issues, f"{label}[{index}]:invalid")
        else:
            out.append(item)
    if not out and not allow_empty:
        _issue(issues, label + ":empty")
    return out


def _report(schema: str, issues: list[str], extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": schema,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    if extra:
        core.update(extra)
    return core


def _passes_filters(rel: str, include: list[str] | None, exclude: list[str] | None) -> bool:
    def matches(prefix: str) -> bool:
        clean = prefix.rstrip("/")
        return rel == clean or rel.startswith(clean + "/")

    if exclude and any(matches(p) for p in exclude):
        return False
    if include is not None:
        return any(matches(p) for p in include)
    return True


def _python_targets(text: str, rel_parts: list[str]) -> list[str]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    targets: list[str] = []
    package_parts = rel_parts[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                targets.append(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module:
                    targets.append(node.module.split(".")[0])
            else:
                base = package_parts[: len(package_parts) - (node.level - 1)]
                if base:
                    targets.append(base[0])
    return targets


def _js_targets(text: str, rel_parts: list[str], group_depth: int) -> list[str]:
    targets: list[str] = []
    for match in _JS_IMPORT.finditer(text):
        spec = match.group(1) or match.group(2)
        if not spec or not (spec.startswith("./") or spec.startswith("../")):
            continue
        parts = list(rel_parts[:-1])
        valid = True
        for segment in spec.split("/"):
            if segment in ("", "."):
                continue
            if segment == "..":
                if not parts:
                    valid = False
                    break
                parts.pop()
            else:
                parts.append(segment)
        if valid and parts:
            targets.append("/".join(parts[:group_depth]))
    return targets


def build_topology_prior(
    root: Any,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    *,
    group_depth: int = 1,
    hub_in_degree: int = 3,
) -> dict[str, Any]:
    """Build the weighted coupling prior for one source root."""

    issues: list[str] = []
    try:
        base = Path(root).resolve()
    except (TypeError, ValueError):
        return _report(PRIOR_SCHEMA, ["topology:root_invalid"])
    if not base.is_dir():
        return _report(PRIOR_SCHEMA, ["topology:root_missing"], {"root": str(base)})
    if not isinstance(group_depth, int) or isinstance(group_depth, bool) or group_depth < 1:
        return _report(PRIOR_SCHEMA, ["topology:group_depth_invalid"], {"root": str(base)})
    if not isinstance(hub_in_degree, int) or isinstance(hub_in_degree, bool) or hub_in_degree < 1:
        return _report(PRIOR_SCHEMA, ["topology:hub_in_degree_invalid"], {"root": str(base)})

    files: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(
            d for d in dirnames if not d.startswith(".") and d not in SKIP_DIR_NAMES
        )
        if len(filenames) > MAX_DIR_FILES:
            return _report(PRIOR_SCHEMA, ["topology:root_too_large"], {"root": str(base)})
        for name in sorted(filenames):
            if not name.endswith(SOURCE_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            if not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            if not _passes_filters(rel, include, exclude):
                continue
            try:
                with open(full, "rb") as handle:
                    raw = handle.read()
            except OSError:
                continue
            files.append((rel, raw.decode("utf-8", errors="replace")))

    node_files: dict[str, int] = {}
    node_lines: dict[str, int] = {}
    for rel, text in files:
        parts = rel.split("/")
        node_id = "/".join(parts[:group_depth])
        node_files[node_id] = node_files.get(node_id, 0) + 1
        node_lines[node_id] = node_lines.get(node_id, 0) + len(text.splitlines())

    edge_counts: dict[tuple[str, str], int] = {}
    for rel, text in files:
        parts = rel.split("/")
        src = "/".join(parts[:group_depth])
        if rel.endswith(".py"):
            targets = _python_targets(text, parts)
        else:
            targets = _js_targets(text, parts, group_depth)
        for target in targets:
            if target in node_files and target != src:
                key = (src, target)
                edge_counts[key] = edge_counts.get(key, 0) + 1

    nodes = [
        {
            "id": node_id,
            "file_count": node_files[node_id],
            "line_count": node_lines[node_id],
            "weight": node_lines[node_id],
        }
        for node_id in sorted(node_files)
    ]
    edges = [
        {"src": src, "dst": dst, "import_count": count, "weight": count}
        for (src, dst), count in sorted(edge_counts.items())
    ]
    indegree: dict[str, set[str]] = {}
    for src, dst in edge_counts:
        indegree.setdefault(dst, set()).add(src)
    hubs = sorted(node_id for node_id, sources in indegree.items() if len(sources) >= hub_in_degree)

    return _report(
        PRIOR_SCHEMA,
        issues,
        {
            "root": str(base),
            "group_depth": group_depth,
            "hub_in_degree": hub_in_degree,
            "nodes": nodes,
            "edges": edges,
            "hubs": hubs,
            "graph_sha256": _sha256({"nodes": nodes, "edges": edges}),
        },
    )


DELTA_FIELDS = {
    "schema",
    "territory_ref",
    "validated_nodes",
    "new_nodes",
    "new_edges",
    "hotspots",
    "proposed_owners",
    "acceptance_contracts",
    "evidence_refs",
    "uncertainties_remaining",
}


def validate_topology_delta(delta: Any) -> dict[str, Any]:
    """Validate one typed scout output: a graph delta, never an essay."""

    issues: list[str] = []
    value = delta if isinstance(delta, Mapping) else {}
    _exact(value, DELTA_FIELDS, "delta", issues)
    if value.get("schema") != DELTA_SCHEMA:
        _issue(issues, "delta:schema_invalid")
    if not _text(value.get("territory_ref")):
        _issue(issues, "delta:territory_ref_invalid")
    validated = _string_list(value.get("validated_nodes"), "delta.validated_nodes", issues)
    new_nodes = _string_list(value.get("new_nodes"), "delta.new_nodes", issues)
    known = set(validated) | set(new_nodes)
    raw_edges = value.get("new_edges")
    if not isinstance(raw_edges, list):
        _issue(issues, "delta.new_edges:not_array")
        raw_edges = []
    for index, edge in enumerate(raw_edges):
        label = f"delta.new_edges[{index}]"
        if not _exact(edge, {"src", "dst", "reason"}, label, issues):
            continue
        for field in ("src", "dst"):
            node_id = edge.get(field)
            if not _text(node_id):
                _issue(issues, f"{label}:{field}_invalid")
            elif node_id not in known:
                _issue(issues, "delta:edge_unknown_node:" + str(node_id))
        if not _text(edge.get("reason")):
            _issue(issues, f"{label}:reason_invalid")
    _string_list(value.get("hotspots"), "delta.hotspots", issues)
    _string_list(value.get("proposed_owners"), "delta.proposed_owners", issues)
    _string_list(value.get("acceptance_contracts"), "delta.acceptance_contracts", issues)
    evidence = _string_list(value.get("evidence_refs"), "delta.evidence_refs", issues)
    if not evidence:
        _issue(issues, "delta:evidence_required")
    _string_list(value.get("uncertainties_remaining"), "delta.uncertainties_remaining", issues)

    extra: dict[str, Any] = {}
    if not issues:
        extra["delta_sha256"] = _sha256(dict(value))
    return _report(DELTA_REPORT_SCHEMA, issues, extra)


def partition_suggestion(prior: Any, max_nodes: Any) -> dict[str, Any]:
    """Advisory grouping of a passing prior into at most max_nodes groups."""

    issues: list[str] = []
    value = prior if isinstance(prior, Mapping) else {}
    if value.get("schema") != PRIOR_SCHEMA or value.get("status") != "PASS":
        _issue(issues, "partition:prior_not_pass")
    if not isinstance(max_nodes, int) or isinstance(max_nodes, bool) or max_nodes < 1:
        _issue(issues, "partition:max_nodes_invalid")
    nodes = value.get("nodes")
    edges = value.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        _issue(issues, "partition:prior_graph_invalid")
    if issues:
        return _report(PARTITION_SCHEMA, issues, {"advisory": True})

    weights = {str(n.get("id")): int(n.get("weight", 0)) for n in nodes if isinstance(n, Mapping)}
    hubs = {str(h) for h in value.get("hubs", []) if isinstance(h, str)}
    groups: dict[str, dict[str, Any]] = {
        node_id: {"members": [node_id], "weight": weight, "has_hub": node_id in hubs}
        for node_id, weight in weights.items()
    }
    membership = {node_id: node_id for node_id in weights}
    edge_list = [
        (str(e.get("src")), str(e.get("dst")), int(e.get("weight", 0)))
        for e in edges
        if isinstance(e, Mapping) and str(e.get("src")) in weights and str(e.get("dst")) in weights
    ]

    while len(groups) > max_nodes:
        cross: dict[tuple[str, str], int] = {}
        for src, dst, weight in edge_list:
            ga, gb = membership[src], membership[dst]
            if ga == gb:
                continue
            key = (min(ga, gb), max(ga, gb))
            cross[key] = cross.get(key, 0) + weight
        best: tuple[int, int, str, str] | None = None
        for (ga, gb), cross_weight in cross.items():
            if groups[ga]["has_hub"] and groups[gb]["has_hub"]:
                continue
            combined = groups[ga]["weight"] + groups[gb]["weight"]
            candidate = (-cross_weight, combined, ga, gb)
            if best is None or candidate < best:
                best = candidate
        if best is None:
            break
        _, _, ga, gb = best
        merged_members = sorted(groups[ga]["members"] + groups[gb]["members"])
        merged = {
            "members": merged_members,
            "weight": groups[ga]["weight"] + groups[gb]["weight"],
            "has_hub": groups[ga]["has_hub"] or groups[gb]["has_hub"],
        }
        label = merged_members[0]
        del groups[ga]
        del groups[gb]
        groups[label] = merged
        for node_id, owner in list(membership.items()):
            if owner in (ga, gb):
                membership[node_id] = label

    cut_cost = 0
    for src, dst, weight in edge_list:
        if membership[src] != membership[dst]:
            cut_cost += weight
    suggestion = sorted(
        (
            {"members": group["members"], "weight": group["weight"], "contains_hub": group["has_hub"]}
            for group in groups.values()
        ),
        key=lambda g: (-g["weight"], g["members"][0]),
    )
    return _report(
        PARTITION_SCHEMA,
        [],
        {
            "advisory": True,
            "max_nodes": max_nodes,
            "reached_max_nodes": len(groups) <= max_nodes,
            "groups": suggestion,
            "cut_cost": cut_cost,
        },
    )
