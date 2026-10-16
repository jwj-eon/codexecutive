#!/usr/bin/env python3
"""Typed decomposition proposals: the transaction that replaces NEEDS_SPLIT.

A worker that discovers its assignment is really several independently
ownable tasks cannot spawn anything.  It checkpoints, freezes writes, and
submits one `orch-dork/decomposition-proposal/v1` transaction.  This module
is the deterministic gate (Stage A of three): mechanical validity only.
The economic gate and Sol's semantic review happen elsewhere; nothing here
launches work, reads the filesystem, or contacts a model.

It exists to close the four gaps the P0 probe measured in the replan path:

1. acceptance-criteria coverage was ignored (children could silently drop a
   parent objective);
2. failed/retained node specs could be rewritten invisibly (the replan diff
   compares id sets, not content);
3. proposals had no budget channel;
4. proposals had no per-node model/effort evidence channel.  The binder carries
   the approved model profile into the logical plan; effort/tools remain
   proposal evidence until a downstream executable task contract binds them.

The proposal is applied by the root through the existing replan machinery;
`bind_replan_revision` builds the revision-2 plan and records content hashes
for every retained node so rewrites become visible.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


def _load_sibling(name: str):
    """Load a sibling when this module itself was loaded by file path."""

    try:
        return __import__(name)
    except ImportError:
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


model_profiles = _load_sibling("orch_dork_model_profile_registry")

PROPOSAL_SCHEMA = "orch-dork/decomposition-proposal/v1"
REPORT_SCHEMA = "orch-dork/decomposition-proposal-report/v1"
BINDING_SCHEMA = "orch-dork/proposal-revision-binding/v1"

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")

# Deliberately small.  A proposal that wants more than this is not a split,
# it is a new program, and root should plan it as one.
MAX_CHILDREN = 16
MAX_REASON_CODES = 8
REASON_CODES = frozenset(
    {
        "surface_expanded",
        "independent_contracts_discovered",
        "critical_path_risk",
        "budget_exceeded",
        "context_exhausted",
        "boundary_discovered",
    }
)
# A child or join names one registered node profile by its exact identifier
# (Issue 185); the registry's historical replay adapter still resolves the
# three expand-step alias values for archived proposals.


def _node_profile(value: Any) -> dict[str, Any] | None:
    return model_profiles.resolve_node_profile(value)


def _root_labor(value: Any) -> bool:
    profile = _node_profile(value)
    return profile is not None and profile["model_binding"] == "root_executes"


EFFORT_PROFILES = frozenset({"low", "medium", "high", "xhigh"})


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_of(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


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


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


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


def _validate_root_spec(value: Any, issues: list[str]) -> None:
    if not _exact(value, {"ref", "sha256", "authorization_profile_ref"}, "root_spec", issues):
        return
    if not _text(value.get("ref")):
        _issue(issues, "root_spec:ref_invalid")
    if not _digest(value.get("sha256")):
        _issue(issues, "root_spec:sha256_invalid")
    if not _text(value.get("authorization_profile_ref")):
        _issue(issues, "root_spec:authorization_profile_ref_invalid")


def _validate_checkpoint(value: Any, issues: list[str]) -> None:
    keys = {"base_commit", "artifact_refs", "patch_ref", "writes_frozen", "acceptance_criteria_completed"}
    if not _exact(value, keys, "checkpoint", issues):
        return
    base = value.get("base_commit")
    if not (isinstance(base, str) and (re.fullmatch(r"[0-9a-f]{40}", base) or base == "WORKSPACE")):
        _issue(issues, "checkpoint:base_commit_invalid")
    _string_list(value.get("artifact_refs"), "checkpoint.artifact_refs", issues)
    patch = value.get("patch_ref")
    if patch is not None and not _text(patch):
        _issue(issues, "checkpoint:patch_ref_invalid")
    if value.get("writes_frozen") is not True:
        _issue(issues, "checkpoint:writes_not_frozen")
    _string_list(
        value.get("acceptance_criteria_completed"),
        "checkpoint.acceptance_criteria_completed",
        issues,
    )


def _validate_estimate(value: Any, label: str, issues: list[str]) -> None:
    if not _exact(value, {"p50_minutes", "p90_minutes"}, label, issues):
        return
    p50 = value.get("p50_minutes")
    p90 = value.get("p90_minutes")
    for name, item in (("p50_minutes", p50), ("p90_minutes", p90)):
        if not isinstance(item, (int, float)) or isinstance(item, bool) or item < 0:
            _issue(issues, f"{label}:{name}_invalid")
    if (
        isinstance(p50, (int, float))
        and isinstance(p90, (int, float))
        and not isinstance(p50, bool)
        and not isinstance(p90, bool)
        and p90 < p50
    ):
        _issue(issues, f"{label}:p90_below_p50")


def _validate_budget(value: Any, label: str, issues: list[str]) -> None:
    if not _exact(value, {"executor_tokens", "child_tokens", "wall_clock_minutes"}, label, issues):
        return
    for name in ("executor_tokens", "child_tokens", "wall_clock_minutes"):
        item = value.get(name)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            _issue(issues, f"{label}:{name}_invalid")


def _validate_child(value: Any, index: int, issues: list[str]) -> dict[str, Any]:
    label = f"children[{index}]"
    keys = {
        "proposed_id",
        "objective",
        "acceptance_contract",
        "dependencies",
        "context_manifest_ref",
        "read_set",
        "expected_write_set",
        "tools",
        "model_profile",
        "effort_profile",
        "estimate",
    }
    child = dict(value) if isinstance(value, Mapping) else {}
    if not _exact(value, keys, label, issues):
        return child
    if not _identifier(child.get("proposed_id")):
        _issue(issues, label + ":proposed_id_invalid")
    if not _text(child.get("objective")):
        _issue(issues, label + ":objective_invalid")
    _string_list(child.get("acceptance_contract"), label + ".acceptance_contract", issues, allow_empty=False)
    _string_list(child.get("dependencies"), label + ".dependencies", issues)
    if not _text(child.get("context_manifest_ref")):
        _issue(issues, label + ":context_manifest_ref_invalid")
    _string_list(child.get("read_set"), label + ".read_set", issues)
    _string_list(child.get("expected_write_set"), label + ".expected_write_set", issues)
    _string_list(child.get("tools"), label + ".tools", issues)
    if _node_profile(child.get("model_profile")) is None:
        _issue(issues, label + ":model_profile_invalid")
    if child.get("effort_profile") not in EFFORT_PROFILES:
        _issue(issues, label + ":effort_profile_invalid")
    _validate_estimate(child.get("estimate"), label + ".estimate", issues)
    return child


def _validate_join(value: Any, issues: list[str]) -> dict[str, Any]:
    keys = {"objective", "acceptance_contract", "model_profile", "verification_commands", "dependencies"}
    join = dict(value) if isinstance(value, Mapping) else {}
    if not _exact(value, keys, "join", issues):
        return join
    if not _text(join.get("objective")):
        _issue(issues, "join:objective_invalid")
    _string_list(join.get("acceptance_contract"), "join.acceptance_contract", issues, allow_empty=False)
    if _node_profile(join.get("model_profile")) is None:
        _issue(issues, "join:model_profile_invalid")
    _string_list(join.get("verification_commands"), "join.verification_commands", issues, allow_empty=False)
    _string_list(join.get("dependencies"), "join.dependencies", issues)
    return join


def _cycle(children: list[dict[str, Any]], join_dependencies: list[str], issues: list[str]) -> None:
    ids = [c.get("proposed_id") for c in children if _identifier(c.get("proposed_id"))]
    known = set(ids)
    if len(ids) != len(known):
        _issue(issues, "children:duplicate_ids")
    graph: dict[str, list[str]] = {}
    for child in children:
        cid = child.get("proposed_id")
        if not _identifier(cid):
            continue
        deps = [d for d in child.get("dependencies", []) if isinstance(d, str)]
        for dep in deps:
            if dep not in known:
                _issue(issues, f"children:{cid}:unknown_dependency:{dep}")
        graph[str(cid)] = [d for d in deps if d in known]
    for dep in join_dependencies:
        if dep not in known:
            _issue(issues, f"join:unknown_dependency:{dep}")
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> bool:
        state[node] = 1
        stack.append(node)
        for nxt in graph.get(node, []):
            if state.get(nxt, 0) == 1:
                cycle_ids = stack[stack.index(nxt):] if nxt in stack else [nxt]
                _issue(issues, "children:cycle:" + ",".join(sorted(set(cycle_ids))))
                return True
            if state.get(nxt, 0) == 0 and visit(nxt):
                return True
        stack.pop()
        state[node] = 2
        return False

    for node in sorted(graph):
        if state.get(node, 0) == 0 and visit(node):
            break


def _validate_coverage(value: Any, parent_criteria: list[str], child_ids: set[str], issues: list[str]) -> None:
    if not isinstance(value, list):
        _issue(issues, "coverage:not_array")
        return
    covered: dict[str, list[str]] = {}
    for index, item in enumerate(value):
        label = f"coverage[{index}]"
        if not _exact(item, {"parent_criterion", "covered_by"}, label, issues):
            continue
        criterion = item.get("parent_criterion")
        if not _text(criterion):
            _issue(issues, label + ":parent_criterion_invalid")
            continue
        if criterion not in parent_criteria:
            _issue(issues, label + ":unknown_criterion")
            continue
        owners = _string_list(item.get("covered_by"), label + ".covered_by", issues, allow_empty=False)
        for owner in owners:
            if owner not in child_ids and owner != "join":
                _issue(issues, f"{label}:unknown_child:{owner}")
        covered.setdefault(str(criterion), []).extend(owners)
    for criterion in parent_criteria:
        if criterion not in covered:
            _issue(issues, "coverage:criterion_uncovered:" + criterion)


def _validate_provenance(value: Any, issues: list[str]) -> None:
    if not _exact(value, {"discovered_by", "proposed_by", "owned_by"}, "provenance", issues):
        return
    if not _identifier(value.get("discovered_by")):
        _issue(issues, "provenance:discovered_by_invalid")
    if not _identifier(value.get("proposed_by")):
        _issue(issues, "provenance:proposed_by_invalid")
    if value.get("owned_by") != "root":
        _issue(issues, "provenance:owned_by_must_be_root")


def _validate_evidence(value: Any, issues: list[str]) -> None:
    keys = {
        "inspected_refs",
        "planned_surface",
        "discovered_surface",
        "dependency_edges",
        "budget_used_minutes",
        "budget_remaining_minutes",
    }
    if not _exact(value, keys, "evidence", issues):
        return
    _string_list(value.get("inspected_refs"), "evidence.inspected_refs", issues, allow_empty=False)
    for name in ("planned_surface", "discovered_surface"):
        item = value.get(name)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            _issue(issues, f"evidence:{name}_invalid")
    edges = value.get("dependency_edges")
    if not isinstance(edges, list):
        _issue(issues, "evidence.dependency_edges:not_array")
    for name in ("budget_used_minutes", "budget_remaining_minutes"):
        item = value.get(name)
        if not isinstance(item, (int, float)) or isinstance(item, bool) or item < 0:
            _issue(issues, f"evidence:{name}_invalid")


PROPOSAL_FIELDS = {
    "schema",
    "event_id",
    "base_plan_revision",
    "parent_node_id",
    "proposal_idempotency_key",
    "root_spec",
    "checkpoint",
    "reason_codes",
    "evidence",
    "children",
    "join",
    "coverage",
    "budget",
    "provenance",
}


def validate_decomposition_proposal(proposal: Any, *, parent_plan: Any = None) -> dict[str, Any]:
    """Stage A: deterministic mechanical validity for one split proposal.

    ``parent_plan`` is optional context: when the caller supplies the current
    logical plan, the parent node must exist in it, the base revision must
    match, and coverage is checked against the parent worker's own
    acceptance contract (its ``verification`` list) plus plan-level
    ``acceptance_criteria`` entries naming the parent.
    """

    issues: list[str] = []
    value = proposal if isinstance(proposal, Mapping) else {}
    _exact(value, PROPOSAL_FIELDS, "proposal", issues)
    if value.get("schema") != PROPOSAL_SCHEMA:
        _issue(issues, "proposal:schema_invalid")
    if not _identifier(value.get("event_id")):
        _issue(issues, "proposal:event_id_invalid")
    base_revision = value.get("base_plan_revision")
    if not isinstance(base_revision, int) or isinstance(base_revision, bool) or base_revision < 1:
        _issue(issues, "proposal:base_plan_revision_invalid")
    if not _identifier(value.get("parent_node_id")):
        _issue(issues, "proposal:parent_node_id_invalid")
    if not _text(value.get("proposal_idempotency_key")):
        _issue(issues, "proposal:idempotency_key_invalid")

    _validate_root_spec(value.get("root_spec"), issues)
    _validate_checkpoint(value.get("checkpoint"), issues)

    reasons = value.get("reason_codes")
    if not isinstance(reasons, list) or not reasons or len(reasons) > MAX_REASON_CODES:
        _issue(issues, "proposal:reason_codes_invalid")
    else:
        for index, reason in enumerate(reasons):
            if reason not in REASON_CODES:
                _issue(issues, f"reason_codes[{index}]:unknown:{reason}")

    _validate_evidence(value.get("evidence"), issues)

    raw_children = value.get("children")
    children: list[dict[str, Any]] = []
    if not isinstance(raw_children, list) or len(raw_children) < 2:
        _issue(issues, "proposal:children_minimum_two")
    elif len(raw_children) > MAX_CHILDREN:
        _issue(issues, "proposal:children_maximum:" + str(MAX_CHILDREN))
    else:
        children = [_validate_child(child, index, issues) for index, child in enumerate(raw_children)]

    join = _validate_join(value.get("join"), issues)
    join_deps = [d for d in join.get("dependencies", []) if isinstance(d, str)] if isinstance(join, Mapping) else []
    if children:
        _cycle(children, join_deps, issues)
        child_ids = {str(c.get("proposed_id")) for c in children if _identifier(c.get("proposed_id"))}
        for missing_child_id in sorted(child_ids - set(join_deps)):
            _issue(issues, "join:missing_child_dependency:" + missing_child_id)
    else:
        child_ids = set()

    parent_criteria: list[str] = []
    parent = parent_plan if isinstance(parent_plan, Mapping) else None
    if parent is not None:
        workers = parent.get("workers")
        parent_node = None
        if isinstance(workers, list):
            for worker in workers:
                if isinstance(worker, Mapping) and worker.get("id") == value.get("parent_node_id"):
                    parent_node = worker
                    break
        if parent_node is None:
            _issue(issues, "proposal:parent_not_in_plan")
        else:
            verification = parent_node.get("verification")
            if isinstance(verification, list):
                parent_criteria.extend(str(item) for item in verification if _text(item))
        plan_revision = parent.get("revision")
        if isinstance(plan_revision, int) and isinstance(base_revision, int) and plan_revision != base_revision:
            _issue(issues, "proposal:base_revision_mismatch")
    if not parent_criteria:
        checkpoint = value.get("checkpoint")
        if isinstance(checkpoint, Mapping):
            completed = checkpoint.get("acceptance_criteria_completed")
            if isinstance(completed, list):
                parent_criteria.extend(str(item) for item in completed if _text(item))
    coverage_source = value.get("coverage")
    if parent_criteria:
        _validate_coverage(coverage_source, parent_criteria, child_ids, issues)
    elif not isinstance(coverage_source, list):
        _issue(issues, "coverage:not_array")

    _validate_budget(value.get("budget"), "budget", issues)
    _validate_provenance(value.get("provenance"), issues)

    issues = sorted(set(issues))
    status = "PASS" if not issues else "FAIL"
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": status,
        "issues": issues,
        "event_id": value.get("event_id") if _identifier(value.get("event_id")) else None,
        "parent_node_id": value.get("parent_node_id") if _identifier(value.get("parent_node_id")) else None,
        "base_plan_revision": base_revision if isinstance(base_revision, int) and not isinstance(base_revision, bool) else None,
        "child_count": len(children),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    if status == "PASS":
        report["proposal_sha256"] = sha256_of(dict(value))
    return report


def node_content_sha(worker: Any) -> str:
    """Content hash of one logical worker node (identity for drift detection)."""

    if not isinstance(worker, Mapping):
        return sha256_of(None)
    return sha256_of({key: worker.get(key) for key in sorted(worker)})


def bind_replan_revision(current_plan: Any, proposal: Any, accepted_report: Any) -> dict[str, Any]:
    """Build the successor plan a PASSing proposal implies, with drift guards.

    Returns ``orch-dork/proposal-revision-binding/v1``: the proposed successor
    plan object (revision + 1, predecessor sha bound), plus content hashes for
    every retained node, the deterministically rewritten parent acceptance
    carrier, and the refreshed authority so any later rewrite is visible - the
    exact gap the P0 probe found in the replan diff.  The caller still submits
    the successor through ``evaluate_sol_replan``; this function never applies
    anything itself.
    """

    issues: list[str] = []
    plan = current_plan if isinstance(current_plan, Mapping) else None
    prop = proposal if isinstance(proposal, Mapping) else None
    report = accepted_report if isinstance(accepted_report, Mapping) else None
    if plan is None:
        _issue(issues, "binding:current_plan_invalid")
    if prop is None:
        _issue(issues, "binding:proposal_invalid")
    if report is None or report.get("status") != "PASS":
        _issue(issues, "binding:proposal_report_not_pass")
    if report is not None and prop is not None:
        expected = report.get("proposal_sha256")
        if not _digest(expected) or expected != sha256_of(dict(prop)):
            _issue(issues, "binding:proposal_sha_mismatch")
    if issues:
        return {
            "schema": BINDING_SCHEMA,
            "status": "FAIL",
            "issues": sorted(set(issues)),
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    assert plan is not None and prop is not None

    revision = plan.get("revision")
    parent_id = prop.get("parent_node_id")
    workers = plan.get("workers") if isinstance(plan.get("workers"), list) else []
    parent_worker = next(
        (
            worker
            for worker in workers
            if isinstance(worker, Mapping) and worker.get("id") == parent_id
        ),
        None,
    )
    if parent_worker is None:
        _issue(issues, "binding:parent_not_in_plan")
    if isinstance(revision, int) and prop.get("base_plan_revision") != revision:
        _issue(issues, "binding:base_revision_mismatch")
    parent_dependencies = (
        [item for item in parent_worker.get("dependencies", []) if isinstance(item, str)]
        if isinstance(parent_worker, Mapping)
        else []
    )

    retained_hashes: dict[str, str] = {}
    successor_workers: list[dict[str, Any]] = []
    bound_parent_content_sha256: str | None = None
    checkpoint = prop.get("checkpoint") if isinstance(prop.get("checkpoint"), Mapping) else {}
    checkpoint_refs = [r for r in checkpoint.get("artifact_refs", []) if isinstance(r, str)]
    join_id = str(parent_id) + ".join"
    for worker in workers:
        if not isinstance(worker, Mapping):
            continue
        wid = worker.get("id")
        clone = deepcopy(dict(worker))
        if wid == parent_id:
            # The parent endures as the group acceptance contract: it becomes
            # the join node's contract carrier rather than being deleted.
            clone["objective"] = str(worker.get("objective", "")) + " [decomposed: acceptance now proven by " + join_id + "]"
            clone["dependencies"] = sorted(set(list(worker.get("dependencies", [])) + [join_id]))
            acceptance_resource = "semantic:" + str(parent_id) + ".acceptance"
            clone["owned_resources"] = [acceptance_resource]
            clone["deliverables"] = [acceptance_resource]
            bound_parent_content_sha256 = node_content_sha(clone)
        retained_hashes[str(wid)] = node_content_sha(worker)
        successor_workers.append(clone)

    child_ids: list[str] = []
    for child in prop.get("children", []):
        if not isinstance(child, Mapping):
            continue
        cid = str(child.get("proposed_id"))
        model_profile = child.get("model_profile")
        child_ids.append(cid)
        successor_workers.append(
            {
                "id": cid,
                "executor": "sol" if _root_labor(model_profile) else "subagent",
                "justification": "decomposition of " + str(parent_id) + " via " + str(prop.get("event_id")),
                "objective": child.get("objective"),
                "deliverables": list(child.get("acceptance_contract", [])),
                "owned_resources": list(child.get("expected_write_set", []))
                or ["semantic:" + cid + ".analysis"],
                "excluded_resources": [],
                "dependencies": sorted(
                    set(parent_dependencies + list(child.get("dependencies", [])))
                ),
                "verification": list(child.get("acceptance_contract", [])),
                "optional": False,
                "model_profile": model_profile,
            }
        )
    join = prop.get("join") if isinstance(prop.get("join"), Mapping) else {}
    join_deps = sorted(set([d for d in join.get("dependencies", []) if isinstance(d, str)] or child_ids))
    successor_workers.append(
        {
            "id": join_id,
            "executor": "sol" if _root_labor(join.get("model_profile")) else "subagent",
            "justification": "join proving parent acceptance for " + str(parent_id),
            "objective": join.get("objective"),
            "deliverables": list(join.get("acceptance_contract", [])),
            "owned_resources": [join_id + ":integration"],
            "excluded_resources": [],
            "dependencies": join_deps,
            "verification": list(join.get("verification_commands", [])),
            "optional": False,
            "model_profile": (
                join.get("model_profile")
                if _node_profile(join.get("model_profile")) is not None
                else model_profiles.default_profile("escalation")["profile_id"]
            ),
        }
    )

    successor = deepcopy(dict(plan))
    successor["revision"] = (revision + 1) if isinstance(revision, int) else None
    successor["predecessor_plan_sha256"] = sha256_of(dict(plan))
    successor["workers"] = successor_workers
    successor["logical_worker_count"] = len(successor_workers)
    successor_authority = successor.get("authority")
    if isinstance(successor_authority, dict):
        successor_authority["authorized_worker_ids"] = sorted(
            str(worker["id"])
            for worker in successor_workers
            if isinstance(worker.get("id"), str)
        )
    bound_authority_sha256 = sha256_of(successor_authority)
    # A successor whose nodes name registry profiles freezes its sealed
    # routing policy into the plan (Issue 185); the governor is the one
    # resolver, loaded here so this module stays importable on its own.
    successor = _load_sibling("orch_dork_efficiency_governor").bind_routing_policy(successor)

    issues = sorted(set(issues))
    result: dict[str, Any] = {
        "schema": BINDING_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "proposal_sha256": sha256_of(dict(prop)),
        "parent_node_id": parent_id,
        "join_node_id": join_id,
        "added_node_ids": sorted(child_ids + [join_id]),
        "retained_node_content_sha256": dict(sorted(retained_hashes.items())),
        "bound_parent_content_sha256": bound_parent_content_sha256,
        "bound_authority_sha256": bound_authority_sha256,
        "checkpoint_artifact_refs": checkpoint_refs,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    if not issues:
        result["successor_plan"] = successor
        result["successor_plan_sha256"] = sha256_of(successor)
    return result


def verify_retained_content(binding: Any, submitted_successor: Any) -> dict[str, Any]:
    """Check a submitted successor plan against the binding's content hashes.

    Closes the P0 drift gap: a retained node (including a failed one) whose
    spec was rewritten between binding and submission is named explicitly.
    The deterministically rewritten parent acceptance carrier and refreshed
    authority are compared against their exact bound hashes.
    """

    issues: list[str] = []
    bind = binding if isinstance(binding, Mapping) else None
    successor = submitted_successor if isinstance(submitted_successor, Mapping) else None
    if bind is None or bind.get("status") != "PASS":
        _issue(issues, "verify:binding_not_pass")
    if successor is None:
        _issue(issues, "verify:successor_invalid")
    drifted: list[str] = []
    if not issues:
        assert bind is not None and successor is not None
        expected = bind.get("retained_node_content_sha256")
        expected = dict(expected) if isinstance(expected, Mapping) else {}
        parent_id = bind.get("parent_node_id")
        bound_parent_sha256 = bind.get("bound_parent_content_sha256")
        bound_authority_sha256 = bind.get("bound_authority_sha256")
        workers = successor.get("workers") if isinstance(successor.get("workers"), list) else []
        seen: dict[str, Any] = {}
        for worker in workers:
            if isinstance(worker, Mapping) and worker.get("id") is not None:
                seen[str(worker.get("id"))] = worker
        for node_id, want in sorted(expected.items()):
            got = seen.get(node_id)
            if got is None:
                _issue(issues, "verify:retained_node_missing:" + node_id)
                continue
            if node_id == parent_id:
                if not _digest(bound_parent_sha256) or node_content_sha(got) != bound_parent_sha256:
                    drifted.append(node_id)
                    _issue(issues, "verify:bound_parent_content_drift:" + node_id)
                continue
            if node_content_sha(got) != want:
                drifted.append(node_id)
        try:
            submitted_authority_sha256 = sha256_of(successor.get("authority"))
        except (TypeError, ValueError):
            submitted_authority_sha256 = ""
        if not _digest(bound_authority_sha256) or submitted_authority_sha256 != bound_authority_sha256:
            _issue(issues, "verify:bound_authority_drift")
        for node_id in drifted:
            _issue(issues, "verify:retained_content_drift:" + node_id)
    issues = sorted(set(issues))
    return {
        "schema": "orch-dork/retained-content-report/v1",
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "drifted_node_ids": sorted(drifted),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
