#!/usr/bin/env python3
"""Closed provider-free Workflow Profile and review-disposition contracts.

The module is deliberately pure.  It registers the only five production
profile families, validates their bounded parameter envelopes, and validates
the fixed-order PASS/REPAIR/ESCALATE review disposition used by the Control
Tower.  It does not schedule, execute, mutate canonical run state, or grant
authority.
"""

from __future__ import annotations

from copy import deepcopy
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
        previous = sys.modules.get(name)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
            raise
        return module


contracts = _load_sibling("orch_dork_adaptive_contracts")


PROFILE_SCHEMA = "orch-dork/workflow-profile/v1"
EXECUTE_REPAIR_SUBMISSION_SCHEMA = (
    "orch-dork/execute-verify-repair-submission/v1"
)
BEST_OF_N_SUBMISSION_SCHEMA = "orch-dork/best-of-n-submission/v1"
FINITE_DAG_SUBMISSION_SCHEMA = "orch-dork/finite-dag-submission/v1"
REVIEW_DISPOSITION_SCHEMA = "orch-dork/review-disposition/v1"

PROFILE_IDS = (
    "direct/v1",
    "execute_verify_repair/v1",
    "parallel_join/v1",
    "best_of_n/v1",
    "finite_dag/v1",
)
VERIFICATION_LAYERS = (
    "orchestration_invariants",
    "deterministic_checks",
    "execution_grounded",
    "independent_review",
    "human_approval",
)

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_MAX_CANONICAL_BYTES = 262144
_MAX_TEXT_BYTES = 4096
# The finite repair ceiling an execute-verify-repair workflow may declare.
MAX_DECLARED_REPAIRS = 2

_PROFILE_FIELDS = frozenset(
    {
        "schema",
        "profile_id",
        "version",
        "compiler_id",
        "parameter_schema",
        "applicability_rules",
        "topology_invariants",
        "repair_limit",
        "required_verification",
        "output_plan_schema",
        "profile_sha256",
    }
)
_EXECUTE_FIELDS = frozenset(
    {"schema", "max_repairs", "failure_policy", "submission_sha256"}
)
_BEST_FIELDS = frozenset(
    {
        "schema",
        "candidate_count",
        "candidate_independence_groups",
        "comparator_independence_group",
        "selection_mode",
        "direct_baseline",
        "submission_sha256",
    }
)
_BASELINE_FIELDS = frozenset({"profile_id", "status", "evidence_sha256"})
_FINITE_FIELDS = frozenset(
    {
        "schema",
        "planning_submission",
        "topology_submission",
        "integration_node_id",
        "submission_sha256",
    }
)
_DISPOSITION_FIELDS = frozenset(
    {
        "schema",
        "profile_id",
        "verification_receipt",
        "layers",
        "decision",
        "failed_check_ids",
        "permitted_source_refs",
        "immutable_acceptance_sha256",
        "immutable_scope_sha256",
        "repair_instruction",
        "repair_sequence",
        "unresolved",
        "disposition_sha256",
    }
)
_LAYER_FIELDS = frozenset(
    {"layer", "status", "evidence_sha256", "failed_check_ids"}
)


class WorkflowProfileError(ValueError):
    """A closed Workflow Profile contract refused the submitted value."""


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > _MAX_CANONICAL_BYTES:
        raise WorkflowProfileError("canonical_bytes_exceeded")
    return raw


def json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def reseal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    core = deepcopy(dict(value))
    core.pop(field, None)
    core[field] = json_sha256(core)
    return core


def _sealed(value: Mapping[str, Any], field: str) -> bool:
    digest = value.get(field)
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        return False
    core = dict(value)
    core.pop(field, None)
    try:
        return digest == json_sha256(core)
    except (TypeError, ValueError, OverflowError, WorkflowProfileError):
        return False


def _profile_record(
    profile_id: str,
    compiler_id: str,
    parameter_schema: str,
    applicability_rules: list[str],
    topology_invariants: list[str],
    repair_limit: int,
    required_verification: str,
) -> dict[str, Any]:
    return reseal(
        {
            "schema": PROFILE_SCHEMA,
            "profile_id": profile_id,
            "version": 1,
            "compiler_id": compiler_id,
            "parameter_schema": parameter_schema,
            "applicability_rules": applicability_rules,
            "topology_invariants": topology_invariants,
            "repair_limit": repair_limit,
            "required_verification": required_verification,
            "output_plan_schema": "orch-dork/logical-plan/v1",
        },
        "profile_sha256",
    )


_REGISTRY = (
    _profile_record(
        "direct/v1",
        "direct-compiler/v1",
        "direct-parameters/v1",
        ["one coherent bounded executor", "local authority envelope"],
        ["one executor", "one final verifier", "no repair node"],
        0,
        "layered_final",
    ),
    _profile_record(
        "execute_verify_repair/v1",
        "execute-verify-repair-compiler/v1",
        EXECUTE_REPAIR_SUBMISSION_SCHEMA,
        ["objective checks available", "finite repair is explicitly selected"],
        ["serial executor", "zero to two declared repair nodes", "one final verifier"],
        2,
        "layered_each_revision",
    ),
    _profile_record(
        "parallel_join/v1",
        "parallel-join-compiler/v1",
        "orch-dork/parallel-join-submission/v1",
        ["two or more closure-proven producers", "declared join owns combined criteria"],
        ["topology closure passes", "all producer artifacts enter the join", "one final verifier"],
        0,
        "join_and_layered_final",
    ),
    _profile_record(
        "best_of_n/v1",
        "best-of-n-compiler/v1",
        BEST_OF_N_SUBMISSION_SCHEMA,
        ["multiple plausible solutions", "budget-matched independent candidates"],
        ["candidate identities are blinded", "comparator independence group differs", "one final verifier"],
        0,
        "comparison_and_layered_final",
    ),
    _profile_record(
        "finite_dag/v1",
        "finite-dag-compiler/v1",
        FINITE_DAG_SUBMISSION_SCHEMA,
        ["genuinely complex explicit dependencies", "requirement-bound planner proposal"],
        ["finite acyclic graph", "topology closure passes", "flat authority", "one final verifier"],
        0,
        "node_and_layered_final",
    ),
)
_BY_ID = {record["profile_id"]: record for record in _REGISTRY}


def registry() -> tuple[dict[str, Any], ...]:
    """Return the entire immutable registry in stable production order."""

    return tuple(deepcopy(record) for record in _REGISTRY)


def profile(profile_id: str) -> dict[str, Any]:
    """Return one registered profile or fail closed for an unknown family."""

    record = _BY_ID.get(profile_id)
    if record is None:
        raise WorkflowProfileError("profile_unregistered")
    return deepcopy(record)


def validate_profile(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    if not isinstance(value, Mapping) or set(value) != _PROFILE_FIELDS:
        issues.append("profile:contract_invalid")
        normalized: dict[str, Any] = {}
    else:
        normalized = deepcopy(dict(value))
        expected = _BY_ID.get(value.get("profile_id"))
        if expected is None:
            issues.append("profile:unregistered")
        elif normalized != expected:
            issues.append("profile:registry_mismatch")
        if not _sealed(value, "profile_sha256"):
            issues.append("profile:seal_invalid")
    return {
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "normalized": normalized,
    }


def _identifier_list(
    value: Any,
    label: str,
    issues: list[str],
    *,
    minimum: int = 0,
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= 64:
        issues.append(label + "_invalid")
        return []
    normalized = []
    for item in value:
        if not isinstance(item, str) or _IDENTIFIER.fullmatch(item) is None:
            issues.append(label + "_invalid")
        else:
            normalized.append(item)
    if len(normalized) != len(set(normalized)):
        issues.append(label + "_duplicate")
    return normalized


def _workflow_core(profile_id: str, value: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not isinstance(value, Mapping):
        return {}, ["submission:contract_invalid"]
    normalized = deepcopy(dict(value))
    if profile_id == "execute_verify_repair/v1":
        if set(value) != _EXECUTE_FIELDS:
            issues.append("submission:contract_invalid")
        if value.get("schema") != EXECUTE_REPAIR_SUBMISSION_SCHEMA:
            issues.append("submission:schema_invalid")
        if type(value.get("max_repairs")) is not int or not 0 <= value.get("max_repairs", -1) <= MAX_DECLARED_REPAIRS:
            issues.append("submission:max_repairs_invalid")
        if value.get("failure_policy") not in {"fail", "escalate"}:
            issues.append("submission:failure_policy_invalid")
    elif profile_id == "best_of_n/v1":
        if set(value) != _BEST_FIELDS:
            issues.append("submission:contract_invalid")
        if value.get("schema") != BEST_OF_N_SUBMISSION_SCHEMA:
            issues.append("submission:schema_invalid")
        count = value.get("candidate_count")
        if type(count) is not int or not 2 <= count <= 8:
            issues.append("submission:candidate_count_invalid")
            count = 0
        groups = _identifier_list(
            value.get("candidate_independence_groups"),
            "submission:candidate_groups",
            issues,
            minimum=2,
        )
        if len(groups) != count:
            issues.append("submission:candidate_groups_count_mismatch")
        comparator = value.get("comparator_independence_group")
        if not isinstance(comparator, str) or _IDENTIFIER.fullmatch(comparator) is None:
            issues.append("submission:comparator_group_invalid")
        elif comparator in groups:
            issues.append("submission:comparator_not_independent")
        if value.get("selection_mode") not in {"winner", "winner_or_synthesis"}:
            issues.append("submission:selection_mode_invalid")
        baseline = value.get("direct_baseline")
        if not isinstance(baseline, Mapping) or set(baseline) != _BASELINE_FIELDS:
            issues.append("submission:direct_baseline_invalid")
        else:
            if baseline.get("profile_id") != "direct/v1" or baseline.get("status") != "DECLARED":
                issues.append("submission:direct_baseline_invalid")
            if not isinstance(baseline.get("evidence_sha256"), str) or _SHA256.fullmatch(baseline["evidence_sha256"]) is None:
                issues.append("submission:direct_baseline_invalid")
    elif profile_id == "finite_dag/v1":
        if set(value) != _FINITE_FIELDS:
            issues.append("submission:contract_invalid")
        if value.get("schema") != FINITE_DAG_SUBMISSION_SCHEMA:
            issues.append("submission:schema_invalid")
        if not isinstance(value.get("planning_submission"), Mapping):
            issues.append("submission:planning_submission_invalid")
        if not isinstance(value.get("topology_submission"), Mapping):
            issues.append("submission:topology_submission_invalid")
        integration_node_id = value.get("integration_node_id")
        if not isinstance(integration_node_id, str) or _IDENTIFIER.fullmatch(integration_node_id) is None:
            issues.append("submission:integration_node_id_invalid")
    else:
        issues.append("submission:profile_has_no_parameter_contract")
    if not _sealed(value, "submission_sha256"):
        issues.append("submission:seal_invalid")
    return normalized, issues


def validate_workflow_submission(profile_id: str, value: Any) -> dict[str, Any]:
    """Validate one profile's closed, content-addressed parameter envelope."""

    if profile_id not in _BY_ID:
        return {
            "status": "FAIL",
            "issues": ["submission:profile_unregistered"],
            "normalized": {},
            "submission_sha256": None,
        }
    try:
        normalized, issues = _workflow_core(profile_id, value)
    except (TypeError, ValueError, OverflowError, WorkflowProfileError):
        normalized, issues = {}, ["submission:hostile_or_non_json_input"]
    return {
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "normalized": normalized if not issues else {},
        "submission_sha256": (
            value.get("submission_sha256")
            if not issues and isinstance(value, Mapping)
            else None
        ),
    }


def seal_workflow_submission(profile_id: str, value: Mapping[str, Any]) -> dict[str, Any]:
    sealed = reseal(value, "submission_sha256")
    report = validate_workflow_submission(profile_id, sealed)
    if report["status"] != "PASS":
        raise WorkflowProfileError(",".join(report["issues"]))
    return report["normalized"]


def _text_list(value: Any, label: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > 64:
        issues.append(label + "_invalid")
        return []
    normalized = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item.encode("utf-8")) > _MAX_TEXT_BYTES
        ):
            issues.append(label + "_invalid")
        else:
            normalized.append(item)
    if len(normalized) != len(set(normalized)):
        issues.append(label + "_duplicate")
    return normalized


def _artifact_refs(value: Any, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 64:
        issues.append("disposition:permitted_source_refs_invalid")
        return []
    refs = []
    for item in value:
        report = contracts.validate_artifact_ref(item)
        if report.get("status") != "PASS":
            issues.append("disposition:permitted_source_refs_invalid")
        else:
            refs.append(report["normalized"])
    keys = [(ref["uri"], ref["sha256"]) for ref in refs]
    if len(keys) != len(set(keys)):
        issues.append("disposition:permitted_source_refs_duplicate")
    return sorted(refs, key=lambda ref: (ref["uri"], ref["sha256"]))


def validate_review_disposition(
    value: Any,
    *,
    task_spec: Any,
    handoff_receipt: Any,
    expected_profile_id: str,
    repair_limit: int,
    completed_repairs: int,
    acceptance_sha256: str,
    scope_sha256: str,
) -> dict[str, Any]:
    """Validate fixed-order evidence and one monotone terminal disposition."""

    issues: list[str] = []
    normalized: dict[str, Any] = {}
    try:
        if not isinstance(value, Mapping) or set(value) != _DISPOSITION_FIELDS:
            return {
                "status": "FAIL",
                "issues": ["disposition:contract_invalid"],
                "normalized": {},
            }
        normalized = deepcopy(dict(value))
        if value.get("schema") != REVIEW_DISPOSITION_SCHEMA:
            issues.append("disposition:schema_invalid")
        if value.get("profile_id") != expected_profile_id:
            issues.append("disposition:profile_mismatch")
        if not _sealed(value, "disposition_sha256"):
            issues.append("disposition:seal_invalid")
        verification_report = contracts.validate_verification_receipt(
            value.get("verification_receipt"),
            task_spec=task_spec,
            handoff_receipt=handoff_receipt,
        )
        if verification_report.get("status") != "PASS":
            issues.append("disposition:verification_receipt_invalid")
            verification = {}
        else:
            verification = verification_report["normalized"]
            normalized["verification_receipt"] = verification

        raw_layers = value.get("layers")
        layers: list[dict[str, Any]] = []
        if not isinstance(raw_layers, list) or len(raw_layers) != len(VERIFICATION_LAYERS):
            issues.append("disposition:verification_layers_invalid")
            raw_layers = []
        for raw in raw_layers:
            if not isinstance(raw, Mapping) or set(raw) != _LAYER_FIELDS:
                issues.append("disposition:verification_layer_invalid")
                continue
            status = raw.get("status")
            if status not in {"PASS", "FAIL", "UNKNOWN", "NOT_REQUIRED"}:
                issues.append("disposition:verification_layer_status_invalid")
            evidence = raw.get("evidence_sha256")
            if not isinstance(evidence, str) or _SHA256.fullmatch(evidence) is None:
                issues.append("disposition:verification_layer_evidence_invalid")
            failed = _identifier_list(
                raw.get("failed_check_ids"),
                "disposition:failed_check_ids",
                issues,
            )
            if status == "FAIL" and not failed:
                issues.append("disposition:failed_layer_without_checks")
            if status != "FAIL" and failed:
                issues.append("disposition:nonfailed_layer_has_checks")
            layers.append(
                {
                    "layer": raw.get("layer"),
                    "status": status,
                    "evidence_sha256": evidence,
                    "failed_check_ids": failed,
                }
            )
        if tuple(layer.get("layer") for layer in layers) != VERIFICATION_LAYERS:
            issues.append("disposition:verification_layer_order_invalid")
        normalized["layers"] = layers

        decision = value.get("decision")
        if decision not in {"PASS", "REPAIR", "ESCALATE"}:
            issues.append("disposition:decision_invalid")
        failed_ids = _identifier_list(
            value.get("failed_check_ids"),
            "disposition:failed_check_ids",
            issues,
        )
        layer_failed_ids = sorted(
            {
                check_id
                for layer in layers
                if layer.get("status") == "FAIL"
                for check_id in layer.get("failed_check_ids", [])
            }
        )
        if sorted(failed_ids) != layer_failed_ids:
            issues.append("disposition:failed_checks_mismatch")
        normalized["failed_check_ids"] = sorted(failed_ids)

        refs = _artifact_refs(value.get("permitted_source_refs"), issues)
        normalized["permitted_source_refs"] = refs
        if value.get("immutable_acceptance_sha256") != acceptance_sha256:
            issues.append("disposition:acceptance_mismatch")
        if value.get("immutable_scope_sha256") != scope_sha256:
            issues.append("disposition:scope_mismatch")
        if type(repair_limit) is not int or not 0 <= repair_limit <= MAX_DECLARED_REPAIRS:
            issues.append("disposition:repair_limit_invalid")
        if type(completed_repairs) is not int or completed_repairs < 0:
            issues.append("disposition:completed_repairs_invalid")

        instruction = value.get("repair_instruction")
        sequence = value.get("repair_sequence")
        unresolved = _text_list(
            value.get("unresolved"), "disposition:unresolved", issues
        )
        normalized["unresolved"] = unresolved
        nonpassing_layers = [
            layer for layer in layers if layer.get("status") in {"FAIL", "UNKNOWN"}
        ]
        artifact_keys = {
            (ref["uri"], ref["sha256"])
            for ref in verification.get("artifact_refs", [])
        }
        ref_keys = {(ref["uri"], ref["sha256"]) for ref in refs}

        if decision == "PASS":
            if verification.get("pass") is not True or nonpassing_layers:
                issues.append("disposition:earlier_failure_cannot_pass")
            if failed_ids or refs or instruction is not None or sequence != 0 or unresolved:
                issues.append("disposition:pass_has_failure_payload")
        elif decision == "REPAIR":
            if verification.get("pass") is not False or not layer_failed_ids:
                issues.append("disposition:repair_without_failure")
            if not isinstance(instruction, str) or not instruction or len(instruction.encode("utf-8")) > _MAX_TEXT_BYTES:
                issues.append("disposition:repair_instruction_invalid")
            if sequence != completed_repairs + 1 or sequence > repair_limit:
                issues.append("disposition:repair_sequence_invalid")
            if not refs or not ref_keys <= artifact_keys:
                issues.append("disposition:repair_sources_invalid")
            if unresolved:
                issues.append("disposition:repair_has_unresolved")
        elif decision == "ESCALATE":
            if verification.get("pass") is True or not nonpassing_layers:
                issues.append("disposition:escalate_without_unresolved_failure")
            if refs or instruction is not None or sequence != 0 or not unresolved:
                issues.append("disposition:escalate_payload_invalid")

        normalized["repair_instruction"] = instruction
        normalized["repair_sequence"] = sequence
    except (TypeError, ValueError, OverflowError, WorkflowProfileError):
        issues.append("disposition:hostile_or_non_json_input")
        normalized = {}
    return {
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "normalized": normalized if not issues else {},
        "disposition_sha256": (
            value.get("disposition_sha256")
            if not issues and isinstance(value, Mapping)
            else None
        ),
    }


def seal_review_disposition(
    value: Mapping[str, Any],
    *,
    task_spec: Any,
    handoff_receipt: Any,
    expected_profile_id: str,
    repair_limit: int,
    completed_repairs: int,
    acceptance_sha256: str,
    scope_sha256: str,
) -> dict[str, Any]:
    sealed = reseal(value, "disposition_sha256")
    report = validate_review_disposition(
        sealed,
        task_spec=task_spec,
        handoff_receipt=handoff_receipt,
        expected_profile_id=expected_profile_id,
        repair_limit=repair_limit,
        completed_repairs=completed_repairs,
        acceptance_sha256=acceptance_sha256,
        scope_sha256=scope_sha256,
    )
    if report["status"] != "PASS":
        raise WorkflowProfileError(",".join(report["issues"]))
    normalized = reseal(report["normalized"], "disposition_sha256")
    final_report = validate_review_disposition(
        normalized,
        task_spec=task_spec,
        handoff_receipt=handoff_receipt,
        expected_profile_id=expected_profile_id,
        repair_limit=repair_limit,
        completed_repairs=completed_repairs,
        acceptance_sha256=acceptance_sha256,
        scope_sha256=scope_sha256,
    )
    if final_report["status"] != "PASS":
        raise WorkflowProfileError(",".join(final_report["issues"]))
    return final_report["normalized"]


__all__ = [
    "PROFILE_SCHEMA",
    "EXECUTE_REPAIR_SUBMISSION_SCHEMA",
    "BEST_OF_N_SUBMISSION_SCHEMA",
    "FINITE_DAG_SUBMISSION_SCHEMA",
    "REVIEW_DISPOSITION_SCHEMA",
    "PROFILE_IDS",
    "VERIFICATION_LAYERS",
    "WorkflowProfileError",
    "json_sha256",
    "reseal",
    "registry",
    "profile",
    "validate_profile",
    "validate_workflow_submission",
    "seal_workflow_submission",
    "validate_review_disposition",
    "seal_review_disposition",
]
