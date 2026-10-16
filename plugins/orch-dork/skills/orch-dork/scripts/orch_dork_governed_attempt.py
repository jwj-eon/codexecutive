#!/usr/bin/env python3
"""Staged, fail-closed authority for one governed Orch Dork attempt.

The module composes existing deep validators instead of accepting their
independent PASS labels. It never launches workers, grants provider authority,
or performs model calls. Callers may act only on the next action in a sealed
receipt; a red stage emits no authority, and a budget/tool stop emits only a
stop receipt.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from datetime import datetime
from typing import Any, Mapping


PROGRAM_SCHEMA = "orch-dork/governed-attempt-program/v1"
CHECKPOINT_PROGRAM_SCHEMA = "orch-dork/governed-attempt-program/v2"
WORKER_CHECKPOINT_PROFILE = "orch-dork/qualification-worker-checkpoint/v1"
REPORT_SCHEMA = "orch-dork/governed-attempt-report/v1"
RECEIPT_SCHEMA = "orch-dork/governed-attempt-receipt/v1"
OPERATIONS = frozenset(
    {
        "pre_spawn",
        "capacity_admission",
        "capacity_settlement",
        "worker_start",
        "worker_results",
        "result_aggregation",
        "review_submission",
        "semantic_review",
        "terminal_verification",
        "cleanup",
        "failure_closure",
        "final_qualification",
        "owner_disposition",
        "progress",
        "recovery",
        "terminal",
    }
)
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_WORKER_RESULT_ACTIONS = {
    "AWAITING_WORKER_RESULTS": "collect_results",
    "AWAITING_RESULT_AGGREGATION": "aggregate",
    "WORKER_RESULTS_FAILED": "result_failure",
    "WORKER_RESULT_EVIDENCE_REQUIRED": "result_evidence",
}
_PROGRAM_FIELDS = frozenset({"schema", "operation", "identity", "predecessor_receipt", "payload"})
_IDENTITY_FIELDS = frozenset(
    {
        "run_id",
        "attempt_id",
        "root_task_id",
        "root_model",
        "root_effort",
        "source_version",
        "installed_version",
        "task_loaded_version",
        "fresh_task",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "stage",
        "status",
        "run_id",
        "attempt_id",
        "root_task_id",
        "plan_id",
        "plan_revision",
        "plan_sha256",
        "identity_sha256",
        "predecessor_receipt_sha256",
        "next_action",
        "bindings",
        "receipt_sha256",
    }
)
_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "operation",
        "disposition",
        "final_verdict",
        "run_id",
        "attempt_id",
        "root_task_id",
        "spawn_authorized",
        "work_authorized",
        "continuation_authorized",
        "terminal_claim_permitted",
        "next_action",
        "stages",
        "receipt",
        "tool",
        "graph",
        "routing",
        "token_ingress",
        "verification",
        "issues",
        "provider_free",
        "live_task_operations",
        "model_calls",
        "hosted_calls",
        "automatic_retries",
        "automatic_replacements",
        "automatic_fallbacks",
    }
)


def _load(name: str):
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name + " unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


adaptive_contracts = _load("orch_dork_adaptive_contracts")
admission_kernel = _load("orch_dork_admission_kernel")
attempt_observer = _load("orch_dork_attempt_observer")
coordinator_capsule = _load("orch_dork_coordinator_capsule")
dogfood_recovery = _load("orch_dork_dogfood_recovery")
efficiency_governor = _load("orch_dork_efficiency_governor")
execution_readiness = _load("orch_dork_execution_readiness")
project_ground = _load("orch_dork_project_ground_enforcement")
research_manifest = _load("orch_dork_research_manifest")
route_policy = _load("orch_dork_route_policy")
run_trace = _load("orch_dork_trace")
shared_capacity = _load("orch_dork_shared_capacity")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, fields: frozenset[str] | set[str], path: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, path + ":not_object")
        return {}
    for field in sorted(set(fields) - set(value)):
        _issue(issues, path + ":missing:" + field)
    for field in sorted(set(value) - set(fields)):
        _issue(issues, path + ":unknown:" + str(field))
    return value


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value.encode("utf-8")) <= 4096


def _manifest_version() -> str | None:
    path = Path(__file__).resolve().parents[3] / ".codex-plugin" / "plugin.json"
    try:
        if path.is_symlink() or path.stat().st_size > 65_536:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value.get("version") if isinstance(value, Mapping) and value.get("name") == "orch-dork" else None


def _stage(name: str, status: str, report: Mapping[str, Any] | None, issues: list[str]) -> dict[str, Any]:
    value = dict(report) if isinstance(report, Mapping) else {}
    return {
        "name": name,
        "status": status,
        "report_sha256": value.get("report_sha256")
        or value.get("receipt_sha256")
        or value.get("admission_digest")
        or value.get("manifest_sha256")
        or value.get("capsule_sha256")
        or _sha(value),
        "issues": sorted(set(issues)),
    }


def _receipt(
    *,
    stage: str,
    status: str,
    identity: Mapping[str, Any],
    plan: Mapping[str, Any],
    plan_sha256: str,
    predecessor: Mapping[str, Any] | None,
    next_action: str,
    bindings: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "schema": RECEIPT_SCHEMA,
        "stage": stage,
        "status": status,
        "run_id": identity.get("run_id"),
        "attempt_id": identity.get("attempt_id"),
        "root_task_id": identity.get("root_task_id"),
        "plan_id": plan.get("plan_id"),
        "plan_revision": plan.get("revision"),
        "plan_sha256": plan_sha256,
        "identity_sha256": _sha(dict(identity)),
        "predecessor_receipt_sha256": (
            predecessor.get("receipt_sha256") if isinstance(predecessor, Mapping) else None
        ),
        "next_action": next_action,
        "bindings": dict(bindings),
    }
    return {**core, "receipt_sha256": _sha(core)}


def _validate_receipt(
    value: Any,
    identity: Mapping[str, Any],
    issues: list[str],
    *,
    allowed_stages: set[str],
    allowed_actions: set[str],
) -> Mapping[str, Any]:
    receipt = _exact(value, _RECEIPT_FIELDS, "predecessor_receipt", issues)
    if receipt.get("schema") != RECEIPT_SCHEMA:
        _issue(issues, "predecessor_receipt:schema_invalid")
    core = {key: child for key, child in receipt.items() if key != "receipt_sha256"}
    try:
        valid_seal = receipt.get("receipt_sha256") == _sha(core)
    except (TypeError, ValueError, OverflowError):
        valid_seal = False
    if not valid_seal:
        _issue(issues, "predecessor_receipt:seal_mismatch")
    for field in ("run_id", "attempt_id", "root_task_id"):
        if receipt.get(field) != identity.get(field):
            _issue(issues, "predecessor_receipt:" + field + "_mismatch")
    if receipt.get("identity_sha256") != _sha(dict(identity)):
        _issue(issues, "predecessor_receipt:identity_mismatch")
    if receipt.get("stage") not in allowed_stages:
        _issue(issues, "predecessor_receipt:stage_invalid")
    if receipt.get("next_action") not in allowed_actions:
        _issue(issues, "predecessor_receipt:action_invalid")
    return receipt


def build_capacity_admission_program(
    pre_spawn_program: Any,
    pre_spawn_report: Any,
) -> dict[str, Any]:
    """Derive the sole capacity successor or raise without a partial program.

    The passing receipt is the authority for the evaluated pre-spawn payload;
    returned identity and receipt values are isolated defensive copies.
    """

    issues: list[str] = []
    program = _exact(
        pre_spawn_program,
        _PROGRAM_FIELDS,
        "pre_spawn_program",
        issues,
    )
    identity = _validate_identity(program.get("identity"), issues)
    if program.get("schema") not in (PROGRAM_SCHEMA, CHECKPOINT_PROGRAM_SCHEMA):
        _issue(issues, "pre_spawn_program:schema_invalid")
    if program.get("operation") != "pre_spawn":
        _issue(issues, "pre_spawn_program:operation_invalid")
    if program.get("predecessor_receipt") is not None:
        _issue(issues, "pre_spawn_program:predecessor_present")
    if not isinstance(program.get("payload"), Mapping):
        _issue(issues, "pre_spawn_program:payload_invalid")

    report = pre_spawn_report if isinstance(pre_spawn_report, Mapping) else {}
    if not isinstance(pre_spawn_report, Mapping):
        _issue(issues, "pre_spawn_report:not_object")
    if report.get("schema") != REPORT_SCHEMA:
        _issue(issues, "pre_spawn_report:schema_invalid")
    if report.get("status") != "PASS":
        _issue(issues, "pre_spawn_report:status_invalid")
    if report.get("operation") != "pre_spawn":
        _issue(issues, "pre_spawn_report:operation_invalid")
    if report.get("disposition") != "SHARED_CAPACITY_ADMISSION_REQUIRED":
        _issue(issues, "pre_spawn_report:disposition_invalid")
    if report.get("next_action") != "capacity_admission":
        _issue(issues, "pre_spawn_report:next_action_invalid")
    for field in ("run_id", "attempt_id", "root_task_id"):
        if report.get(field) != identity.get(field):
            _issue(issues, "pre_spawn_report:" + field + "_mismatch")

    try:
        receipt = _validate_receipt(
            report.get("receipt"),
            identity,
            issues,
            allowed_stages={"pre_spawn"},
            allowed_actions={"capacity_admission"},
        )
    except (TypeError, ValueError, OverflowError):
        receipt = {}
        _issue(issues, "pre_spawn_report:receipt_invalid")
    if issues:
        raise ValueError(";".join(sorted(set(issues))))
    return {
        "schema": PROGRAM_SCHEMA,
        "operation": "capacity_admission",
        "identity": deepcopy(dict(identity)),
        "predecessor_receipt": deepcopy(dict(receipt)),
        "payload": {},
    }


def worker_results_next_action(root_task_id: str, receipt: Mapping[str, Any]) -> str:
    """Derive the result receipt's next action without granting authority."""
    bindings = receipt.get("bindings")
    if not isinstance(bindings, Mapping):
        raise ValueError("worker_results:bindings_invalid")
    decision = _load("orch_dork_qualification_results").join_decision(
        bindings.get("worker_results"), bindings=bindings, root_task_id=root_task_id
    )
    if decision not in _WORKER_RESULT_ACTIONS:
        raise ValueError("worker_results:decision_invalid")
    return _WORKER_RESULT_ACTIONS[decision]


def post_batch_next_action(root_task_id: str, receipt: Mapping[str, Any]) -> str:
    """Derive pending quality work independently of physical lane release."""
    try:
        bindings = receipt["bindings"]
        stage = receipt["stage"]
        if stage == "failure_closure":
            from orch_dork_qualification_closure import failure_closure_next_action
            return failure_closure_next_action(root_task_id, receipt)
        if stage == "final_qualification":
            from orch_dork_qualification_final import final_qualification_next_action
            return final_qualification_next_action(root_task_id, receipt)
        if stage == "owner_disposition":
            from orch_dork_qualification_owner import owner_disposition_next_action
            return owner_disposition_next_action(root_task_id, receipt)
        if stage not in {"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification", "cleanup", "capacity_settlement"}:
            raise ValueError("invalid post-batch stage")
        phase = bindings.get("quality_phase")
        if ("quality_phase" not in bindings and stage in {"worker_results", "result_aggregation"}
                and bindings.get("current_wave_logical_lane_ids") == ["spec", "standards"]):
            phase = stage  # Historical active-wave reports predate phase tracking.
        if phase not in {"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification"}:
            raise ValueError("invalid quality phase")
        if stage == "cleanup" and phase != "terminal_verification":
            raise ValueError("cleanup requires terminal verification")
        if stage not in {"capacity_settlement", "cleanup"} and phase != stage:
            raise ValueError("quality phase does not match stage")
        if stage == "capacity_settlement" and bindings.get("current_wave_logical_lane_ids") != []:
            raise ValueError("settlement has an active wave")
        action = worker_results_next_action(root_task_id, receipt)
        if phase == "terminal_verification":
            _stable_terminal_verification_evidence(root_task_id, receipt)
            if stage == "cleanup":
                if bindings["current_wave_logical_lane_ids"] != ["spec", "standards"]:
                    raise ValueError("cleanup requires the active verified lanes")
                return "stop"
            return ("cleanup" if bindings["current_wave_logical_lane_ids"] != [] else
                    "final_qualification" if bindings["terminal_verification"]["outcome"] == "success" else "failure_closure")
        if phase in {"result_aggregation", "review_submission", "semantic_review"}:
            if action != "aggregate":
                raise ValueError("aggregation requires complete results")
            if phase in {"review_submission", "semantic_review"}:
                _stable_review_submission_evidence(root_task_id, receipt)
                return _REVIEW_OUTCOME_ACTIONS[bindings["review_outcome"]] if phase == "semantic_review" else "observe_sol_review"
            return "sol_review"
        return action
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
        raise ValueError("post_batch:quality_invalid") from error


def _worker_results_predecessor(
    identity: Mapping[str, Any], value: Any, issues: list[str]
) -> Mapping[str, Any]:
    try:
        receipt = _validate_receipt(
            value, identity, issues,
            allowed_stages={"worker_start", "progress", "worker_results", "capacity_settlement"},
            allowed_actions={"continue", *_WORKER_RESULT_ACTIONS.values()},
        )
        stage = receipt.get("stage")
        if stage in {"worker_start", "progress"}:
            if stage == "worker_start" and receipt.get("bindings", {}).get("worker_checkpoint_profile") == WORKER_CHECKPOINT_PROFILE:
                _issue(issues, "worker_results:checkpoint_required")
            status, action = "AUTHORIZED", "continue"
            if receipt.get("status") != status:
                _issue(issues, "predecessor_receipt:status_invalid")
            if receipt.get("next_action") != action:
                _issue(issues, "predecessor_receipt:action_invalid")
        else:
            action = post_batch_next_action(identity.get("root_task_id"), receipt)
            if action not in _WORKER_RESULT_ACTIONS.values():
                raise ValueError("worker results phase is closed")
            _check_result_receipt(receipt, identity, stage=stage,
                                  status="SETTLED" if stage == "capacity_settlement" else "OBSERVED", action=action)
        return receipt
    except (KeyError, TypeError, ValueError, OverflowError):
        _issue(issues, "worker_results:predecessor_invalid")
        return {}


def _capacity_settlement_predecessor(
    identity: Mapping[str, Any],
    value: Any,
    issues: list[str],
) -> Mapping[str, Any]:
    """Bind a whole producer report to one supported settlement receipt."""

    if (isinstance(value, Mapping) and isinstance(value.get("receipt"), Mapping)
            and value["receipt"].get("stage") in ("worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification", "cleanup", "capacity_settlement")):
        return _post_batch_predecessor_report(identity, value, issues)

    # Retain the original public argument and diagnostic names for admission callers.
    report = _exact(
        value,
        _REPORT_FIELDS,
        "capacity_admission_report",
        issues,
    )
    receipt_shapes = {
        "capacity_admission": ("capacity_admission", "PASS", "SPAWN_AUTHORIZED", "AUTHORIZED", "spawn"),
        "worker_start": ("worker_start", "PASS", "WORK_AUTHORIZED", "AUTHORIZED", "continue"),
        "progress": ("progress", "PASS", "CONTINUE", "AUTHORIZED", "continue"),
        "stopped": ("progress", "BLOCKED", "STOP_REQUIRED", "STOP_REQUIRED", "stop"),
        "worker_results": ("worker_results", "PASS", "RESULTS_OBSERVED", "OBSERVED", None),
        "result_aggregation": ("result_aggregation", "PASS", "RESULTS_AGGREGATED", "AGGREGATED", "sol_review"),
    }
    try:
        receipt = _validate_receipt(
            report.get("receipt"),
            identity,
            issues,
            allowed_stages=set(receipt_shapes),
            allowed_actions={"spawn", "continue", "stop", "sol_review", *_WORKER_RESULT_ACTIONS.values()},
        )
    except (TypeError, ValueError, OverflowError):
        receipt = {}
        _issue(issues, "capacity_admission_report:receipt_invalid")
    stage = receipt.get("stage")
    shape = receipt_shapes.get(stage) if isinstance(stage, str) else None
    if stage == "worker_results":
        try:
            shape = (*shape[:-1], worker_results_next_action(identity.get("root_task_id"), receipt))
        except (KeyError, TypeError, ValueError, OverflowError):
            _issue(issues, "worker_results:predecessor_invalid")
    elif stage == "result_aggregation":
        _result_aggregation_predecessor(identity, receipt, issues, aggregated=True)
        if validate_result_aggregation_report(value)["valid"] is not True:
            _issue(issues, "result_aggregation:predecessor_report_invalid")
    if report.get("schema") != REPORT_SCHEMA:
        _issue(issues, "capacity_admission_report:schema_invalid")
    if shape is not None:
        operation, status, disposition, receipt_status, action = shape
        for field, expected, reason in (
            ("operation", operation, "operation_invalid"),
            ("status", status, "status_invalid"),
            ("disposition", disposition, "disposition_invalid"),
            ("final_verdict", disposition, "verdict_invalid"),
            ("next_action", action, "next_action_invalid"),
        ):
            if report.get(field) != expected:
                _issue(issues, "capacity_admission_report:" + reason)
        if receipt.get("status") != receipt_status:
            _issue(issues, "predecessor_receipt:status_invalid")
        if receipt.get("next_action") != action:
            _issue(issues, "predecessor_receipt:action_invalid")
    if stage == "stopped":
        bindings = receipt.get("bindings")
        stop_reasons = bindings.get("stop_reasons") if isinstance(bindings, Mapping) else None
        if (
            not isinstance(stop_reasons, list)
            or not stop_reasons
            or not all(_text(reason) for reason in stop_reasons)
            or report.get("issues") != stop_reasons
        ):
            _issue(issues, "capacity_admission_report:stop_reasons_invalid")
    elif report.get("issues") != []:
        _issue(issues, "capacity_admission_report:issues_present")
    if report.get("provider_free") is not True:
        _issue(issues, "capacity_admission_report:provider_boundary_crossed")
    for field in ("run_id", "attempt_id", "root_task_id"):
        if report.get(field) != identity.get(field):
            _issue(issues, "capacity_admission_report:" + field + "_mismatch")
    if not isinstance(report.get("stages"), list) or any(
        not isinstance(row, Mapping) for row in report.get("stages", [])
    ):
        _issue(issues, "capacity_admission_report:stages_invalid")
    if not issues and shape is not None:
        try:
            expected_report = _report(
                operation=operation,
                identity=identity,
                status=status,
                disposition=disposition,
                issues=report["issues"],
                stages=report["stages"],
                receipt=receipt,
            )
            matches = _canonical(report) == _canonical(expected_report)
        except (TypeError, ValueError, OverflowError):
            matches = False
        if not matches:
            _issue(issues, "capacity_admission_report:receipt_report_mismatch")
    return receipt


def build_capacity_settlement_program(
    identity: Any,
    capacity_admission_report: Any,
    release_receipts: Any,
) -> dict[str, Any]:
    """Build settlement from the whole current admission, work, result, or stop report.

    The admission-named argument remains compatible with existing callers.
    Construction performs no authority operation; the evaluator validates signed
    release evidence and current reservations before committing settlement.
    """

    issues: list[str] = []
    identity_value = _validate_identity(identity, issues)
    receipt = _capacity_settlement_predecessor(
        identity_value, capacity_admission_report, issues
    )
    bindings = receipt.get("bindings")
    if (not isinstance(bindings, Mapping) or not bindings.get("current_wave_logical_lane_ids")
            or not bindings.get("capacity_authority_lane_ids")):
        _issue(issues, "shared_capacity:settlement_wave_binding_invalid")
    if not isinstance(release_receipts, list) or any(
        not isinstance(item, Mapping) for item in release_receipts
    ):
        _issue(issues, "release_receipts:not_object_list")
    if issues:
        raise ValueError(";".join(sorted(set(issues))))
    return {
        "schema": PROGRAM_SCHEMA,
        "operation": "capacity_settlement",
        "identity": deepcopy(dict(identity_value)),
        "predecessor_receipt": deepcopy(dict(receipt)),
        "payload": {
            "release_receipts": [
                deepcopy(dict(item)) for item in release_receipts
            ]
        },
    }


def _check_result_receipt(
    receipt: Mapping[str, Any], identity: Mapping[str, Any], *, stage: str, status: str, action: str,
) -> None:
    if (receipt["schema"] != RECEIPT_SCHEMA or receipt["stage"] != stage
            or receipt["status"] != status or not _identifier(receipt["plan_id"])
            or type(receipt["plan_revision"]) is not int or receipt["plan_revision"] < 0
            or any(receipt[field] != identity[field] for field in ("run_id", "attempt_id", "root_task_id"))
            or any(type(receipt[field]) is not str or _SHA256.fullmatch(receipt[field]) is None
                   for field in ("plan_sha256", "identity_sha256", "predecessor_receipt_sha256", "receipt_sha256"))
            or receipt["receipt_sha256"] != _sha({k: v for k, v in receipt.items() if k != "receipt_sha256"})
            or receipt["next_action"] != action):
        raise ValueError("invalid result receipt")


def _post_batch_stages(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    bindings = receipt["bindings"]
    if receipt["stage"] in {"terminal_verification", "cleanup"}:
        return [_stage(receipt["stage"], "PASS", bindings["terminal_verification"], [])]
    if receipt["stage"] == "semantic_review":
        return [_stage("semantic_review", "PASS", {
            "review_observation": bindings["review_observation"], "review_outcome": bindings["review_outcome"],
        }, [])]
    if receipt["stage"] == "review_submission":
        return [_stage("review_submission", "PASS", {key: bindings[key] for key in _REVIEW_BINDING_FIELDS}, [])]
    if receipt["stage"] == "capacity_settlement":
        return [_stage("shared_capacity_settlement", "PASS", {
            "authority_state_sha256": bindings["capacity_authority_state_sha256"],
            "released_authority_lane_ids": [receipt["run_id"] + ":" + lane for lane in ("spec", "standards")],
            "terminal_logical_lane_ids": ["spec", "standards"], "pending_logical_lane_ids": [],
        }, [])]
    return [_stage(receipt["stage"], "PASS", {"worker_results": bindings["worker_results"]}, [])]


def _post_batch_report(identity: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any]:
    return _report(
        operation=receipt["stage"], identity=identity, status="PASS",
        disposition=("TERMINAL_VERIFIED_" + receipt["bindings"]["terminal_verification"]["outcome"].upper()
                     if receipt["stage"] == "terminal_verification" else "SEMANTIC_REVIEW_" + receipt["bindings"]["review_outcome"].upper()
                     if receipt["stage"] == "semantic_review" else
                     {"worker_results": "RESULTS_OBSERVED", "result_aggregation": "RESULTS_AGGREGATED",
                     "review_submission": "REVIEW_SUBMITTED",
                     "cleanup": "CLEANUP_AUTHORIZED",
                     "capacity_settlement": "CAPACITY_RELEASED"}[receipt["stage"]]),
        issues=[], stages=_post_batch_stages(receipt), receipt=receipt,
    )


def _validate_result_report_transport(report: Any, *, operation: str) -> dict[str, Any]:
    try:
        issues: list[str] = []
        value = _exact(report, _REPORT_FIELDS, operation + "_report", issues)
        receipt = _exact(value.get("receipt"), _RECEIPT_FIELDS, "receipt", issues)
        identity = {field: value.get(field) for field in ("run_id", "attempt_id", "root_task_id")}
        identity.update(root_model=value["routing"]["root"]["model"],
                        root_effort=value["routing"]["root"]["effort"], installed_version=value["tool"]["version"])
        if issues or any(not _identifier(item) for item in identity.values()):
            raise ValueError("invalid report identity")
        derived_action = post_batch_next_action(identity["root_task_id"], receipt)
        _check_result_receipt(
            receipt, identity, stage=operation,
            status=(receipt["bindings"]["review_outcome"].upper() if operation == "semantic_review" else
                    {"worker_results": "OBSERVED", "result_aggregation": "AGGREGATED",
                     "review_submission": "SUBMITTED", "terminal_verification": "VERIFIED",
                     "cleanup": "AUTHORIZED",
                     "capacity_settlement": "SETTLED"}[operation]),
            action=derived_action,
        )
        if receipt["bindings"].get("quality_phase") in {"review_submission", "semantic_review", "terminal_verification"}:
            source = receipt["bindings"]["review_packet"]["source_report"]
            if (_canonical(source["routing"]["root"]) != _canonical(value["routing"]["root"])
                    or _canonical(source["tool"]) != _canonical(value["tool"])):
                raise ValueError("review source identity mismatch")
        expected = _post_batch_report(identity, receipt)
        if _canonical(value) != _canonical(expected):
            raise ValueError("noncanonical result report")
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return {"valid": False, "issues": [operation + ":report_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def validate_worker_results_report(report: Any) -> dict[str, Any]:
    """Check canonical result-report transport; no dispatch or identity authority."""
    return _validate_result_report_transport(report, operation="worker_results")


def validate_result_aggregation_report(report: Any) -> dict[str, Any]:
    """Check canonical aggregation transport; no dispatch or identity authority."""
    return _validate_result_report_transport(report, operation="result_aggregation")


def validate_post_batch_report(report: Any) -> dict[str, Any]:
    """Validate canonical active or completed-release quality transport only."""
    operation = report.get("operation") if isinstance(report, Mapping) else None
    if operation == "failure_closure":
        from orch_dork_qualification_closure import validate_failure_closure_report
        return validate_failure_closure_report(report)
    if operation == "final_qualification":
        from orch_dork_qualification_final import validate_final_qualification_report
        return validate_final_qualification_report(report)
    if operation == "owner_disposition":
        from orch_dork_qualification_owner import validate_owner_disposition_report
        return validate_owner_disposition_report(report)
    if operation not in ("worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification", "cleanup", "capacity_settlement"):
        return {"valid": False, "issues": ["post_batch:report_invalid"], "scope": "canonical_transport"}
    return _validate_result_report_transport(report, operation=operation)


def _post_batch_predecessor_report(identity: Mapping[str, Any], report: Any, issues: list[str]) -> Mapping[str, Any]:
    if validate_post_batch_report(report)["valid"] is not True:
        _issue(issues, "post_batch:predecessor_report_invalid")
        return {}
    receipt = _validate_receipt(
        report["receipt"], identity, issues,
        allowed_stages={"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification", "cleanup", "capacity_settlement"},
        allowed_actions={"sol_review", "observe_sol_review", "verify", "review_evidence", "cleanup", "stop", "final_qualification", "failure_closure", *_WORKER_RESULT_ACTIONS.values()},
    )
    if _canonical(report) != _canonical(_post_batch_report(identity, receipt)):
        _issue(issues, "post_batch:identity_report_mismatch")
    return receipt


def _result_aggregation_predecessor(
    identity: Mapping[str, Any], value: Any, issues: list[str], *, aggregated: bool = False,
) -> Mapping[str, Any]:
    stages = {"result_aggregation"} if aggregated else {"worker_results", "capacity_settlement"}
    action = "sol_review" if aggregated else "aggregate"
    try:
        receipt = _validate_receipt(value, identity, issues, allowed_stages=stages, allowed_actions={action})
        stage = receipt.get("stage")
        _check_result_receipt(
            receipt, identity, stage=stage,
            status="SETTLED" if stage == "capacity_settlement" else "AGGREGATED" if aggregated else "OBSERVED", action=action,
        )
        if post_batch_next_action(identity["root_task_id"], receipt) != action:
            raise ValueError("aggregation requires complete results")
        return receipt
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        _issue(issues, "result_aggregation:predecessor_invalid")
        return {}


def build_result_aggregation_program(identity: Any, predecessor_report: Any) -> dict[str, Any]:
    """Construct aggregation only from the canonical complete worker-results report."""
    issues: list[str] = []
    identity_value = _validate_identity(identity, issues)
    receipt = _post_batch_predecessor_report(identity_value, predecessor_report, issues)
    receipt = _result_aggregation_predecessor(
        identity_value, receipt, issues,
    )
    if issues:
        raise ValueError(";".join(sorted(set(issues))))
    return {"schema": PROGRAM_SCHEMA, "operation": "result_aggregation", "identity": deepcopy(dict(identity_value)),
            "predecessor_receipt": deepcopy(dict(receipt)), "payload": {}}


def _evaluate_result_aggregation(identity: Mapping[str, Any], predecessor_value: Any, payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    predecessor = _result_aggregation_predecessor(identity, predecessor_value, issues)
    _exact(payload, set(), "payload", issues)
    if issues:
        return _report(operation="result_aggregation", identity=identity, status="BLOCKED",
                       disposition="RESULT_AGGREGATION_REFUSED", issues=issues, stages=[])
    bindings = deepcopy(dict(predecessor["bindings"]))
    bindings["quality_phase"] = "result_aggregation"
    receipt = _receipt(
        stage="result_aggregation", status="AGGREGATED", identity=identity,
        plan={"plan_id": predecessor["plan_id"], "revision": predecessor["plan_revision"]},
        plan_sha256=predecessor["plan_sha256"], predecessor=predecessor, next_action="sol_review", bindings=bindings,
    )
    return _report(
        operation="result_aggregation", identity=identity, status="PASS", disposition="RESULTS_AGGREGATED",
        issues=[], stages=[_stage("result_aggregation", "PASS", {"worker_results": bindings["worker_results"]}, [])],
        receipt=receipt,
    )


_REVIEW_BINDING_FIELDS = ("review_packet", "review_submission", "review_context",
                          "review_acknowledgement")
_REVIEW_PAYLOAD_FIELDS = {"review_submission", "review_context"}
_REVIEW_OUTCOME_ACTIONS = {"pending": "observe_sol_review", "evidence_required": "review_evidence",
                           "accepted": "verify", "rejected": "verify"}


def _review_submission_values(packet: Any, submission: Any, context: Any) -> dict[str, Any]:
    review = _load("orch_dork_qualification_review")
    return {
        "review_packet": deepcopy(packet), "review_submission": deepcopy(submission), "review_context": deepcopy(context),
        "review_acknowledgement": review.build_review_acknowledgement(packet, submission, context),
    }


def _stable_review_submission_evidence(root_task_id: str, receipt: Mapping[str, Any]) -> None:
    """Check retained submission against its whole original review source."""
    bindings = receipt["bindings"]
    evidence = _review_submission_values(bindings["review_packet"], bindings["review_submission"], bindings["review_context"])
    source = evidence["review_packet"]["source_report"]
    prior = source["receipt"]
    identity_fields = ("identity_sha256", "run_id", "attempt_id", "root_task_id", "plan_id", "plan_revision", "plan_sha256")
    if (root_task_id != source["root_task_id"]
            or _canonical({key: receipt[key] for key in identity_fields}) != _canonical({key: prior[key] for key in identity_fields})):
        raise ValueError("review_submission:source_identity_mismatch")
    phase = bindings["quality_phase"]
    expected = {**deepcopy(prior["bindings"]), **evidence, "quality_phase": phase}
    if phase == "semantic_review":
        outcome = _load("orch_dork_qualification_review").review_observation_decision(
            evidence["review_packet"], evidence["review_submission"], evidence["review_context"], bindings["review_observation"],
        )
        expected.update(review_observation=deepcopy(bindings["review_observation"]), review_outcome=outcome)
    if bindings.get("current_wave_logical_lane_ids") == []:
        # Only the physical release fields change; the completed join was checked above.
        for key in ("completed_logical_lane_ids", "failed_logical_lane_ids", "cancelled_logical_lane_ids",
                    "current_wave_logical_lane_ids", "capacity_authority_lane_ids", "capacity_authority_state_sha256",
                    "capacity_authority_store_id"):
            expected[key] = bindings[key]
    if receipt["stage"] == "review_submission" and receipt["predecessor_receipt_sha256"] != prior["receipt_sha256"]:
        raise ValueError("review_submission:source_receipt_mismatch")
    if _canonical(bindings) != _canonical(expected):
        raise ValueError("review_submission:retained_evidence_mismatch")


def _review_submitted_predecessor(identity: Mapping[str, Any], value: Any, issues: list[str]) -> Mapping[str, Any]:
    try:
        receipt = _validate_receipt(value, identity, issues, allowed_stages={"review_submission"},
                                    allowed_actions={"observe_sol_review"})
        _check_result_receipt(receipt, identity, stage="review_submission", status="SUBMITTED", action="observe_sol_review")
        if post_batch_next_action(identity["root_task_id"], receipt) != "observe_sol_review":
            raise ValueError("invalid submitted review")
        return receipt
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        _issue(issues, "review_submission:predecessor_invalid")
        return {}


def build_review_submission_program(identity: Any, predecessor_report: Any, submission: Any, context: Any) -> dict[str, Any]:
    """Persist a submitted review from the exact current report; grant no review acceptance."""
    issues: list[str] = []
    identity_value = _validate_identity(identity, issues)
    predecessor = _post_batch_predecessor_report(identity_value, predecessor_report, issues)
    if issues:
        raise ValueError(";".join(sorted(set(issues))))
    review = _load("orch_dork_qualification_review")
    packet = review.build_review_packet(predecessor_report)
    values = _review_submission_values(packet, submission, context)
    return {"schema": PROGRAM_SCHEMA, "operation": "review_submission", "identity": deepcopy(dict(identity_value)),
            "predecessor_receipt": deepcopy(dict(predecessor)),
            "payload": {key: values[key] for key in _REVIEW_PAYLOAD_FIELDS}}


def _evaluate_review_submission(identity: Mapping[str, Any], predecessor_value: Any, payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    value = _exact(payload, _REVIEW_PAYLOAD_FIELDS, "payload", issues)
    try:
        predecessor = _validate_receipt(predecessor_value, identity, issues,
                                        allowed_stages={"result_aggregation", "capacity_settlement"}, allowed_actions={"sol_review"})
        _check_result_receipt(predecessor, identity, stage=predecessor["stage"],
                              status="AGGREGATED" if predecessor["stage"] == "result_aggregation" else "SETTLED", action="sol_review")
        if post_batch_next_action(identity["root_task_id"], predecessor) != "sol_review":
            raise ValueError("review_submission:predecessor_invalid")
        if not issues:
            # The public builder admits only this exact whole producer transport.
            source = _post_batch_report(identity, predecessor)
            program = build_review_submission_program(identity, source, value["review_submission"], value["review_context"])
            if (_canonical(program["predecessor_receipt"]) != _canonical(predecessor_value)
                    or _canonical(program["payload"]) != _canonical(value)):
                raise ValueError("review_submission:program_mismatch")
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        _issue(issues, "review_submission:program_invalid")
    if issues:
        return _report(operation="review_submission", identity=identity, status="BLOCKED",
                       disposition="REVIEW_SUBMISSION_REFUSED", issues=issues, stages=[])
    packet = _load("orch_dork_qualification_review").build_review_packet(source)
    values = _review_submission_values(packet, value["review_submission"], value["review_context"])
    receipt = _receipt(
        stage="review_submission", status="SUBMITTED", identity=identity,
        plan={"plan_id": predecessor_value["plan_id"], "revision": predecessor_value["plan_revision"]},
        plan_sha256=predecessor_value["plan_sha256"], predecessor=predecessor_value, next_action="observe_sol_review",
        bindings={**deepcopy(predecessor_value["bindings"]), **values, "quality_phase": "review_submission"},
    )
    return _post_batch_report(identity, receipt)


def _semantic_review_predecessor(
    identity: Mapping[str, Any], value: Any, issues: list[str], *, pending_only: bool = True,
) -> Mapping[str, Any]:
    try:
        receipt = _validate_receipt(
            value, identity, issues, allowed_stages={"review_submission", "semantic_review", "capacity_settlement"},
            allowed_actions={"observe_sol_review"} if pending_only else set(_REVIEW_OUTCOME_ACTIONS.values()),
        )
        if receipt["bindings"].get("quality_phase") not in {"review_submission", "semantic_review"}:
            raise ValueError("review not submitted")
        _post_batch_predecessor_report(identity, receipt["bindings"]["review_packet"]["source_report"], issues)
        action = post_batch_next_action(identity["root_task_id"], receipt)
        stage = receipt["stage"]
        status = (receipt["bindings"]["review_outcome"].upper() if stage == "semantic_review"
                  else "SUBMITTED" if stage == "review_submission" else "SETTLED")
        _check_result_receipt(receipt, identity, stage=stage, status=status, action=action)
        if pending_only and action != "observe_sol_review":
            raise ValueError("review already resolved")
        return receipt
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        _issue(issues, "semantic_review:predecessor_invalid")
        return {}


def build_semantic_review_program(identity: Any, predecessor_report: Any) -> dict[str, Any]:
    """Construct one observation request from canonical pending review transport.

    A tentative PENDING evaluator receipt is a valid transport predecessor here.
    Native continuity separately binds the actual stored tip; native polling must
    leave that tip and its cursor unchanged instead of committing this candidate.
    """
    issues: list[str] = []
    identity_value = _validate_identity(identity, issues)
    predecessor = _post_batch_predecessor_report(identity_value, predecessor_report, issues)
    predecessor = _semantic_review_predecessor(identity_value, predecessor, issues)
    if issues:
        raise ValueError(";".join(sorted(set(issues))))
    return {"schema": PROGRAM_SCHEMA, "operation": "semantic_review", "identity": deepcopy(dict(identity_value)),
            "predecessor_receipt": deepcopy(dict(predecessor)), "payload": {}}


def _semantic_review_report(
    identity: Mapping[str, Any], predecessor: Mapping[str, Any], observation: Any,
) -> dict[str, Any]:
    """Canonical evaluator candidate from retained evidence, without an owner read.

    A PENDING receipt is tentative transport, not a durable semantic stage.
    """
    bindings = deepcopy(predecessor["bindings"])
    outcome = _load("orch_dork_qualification_review").review_observation_decision(
        bindings["review_packet"], bindings["review_submission"], bindings["review_context"], observation,
    )
    bindings.update(quality_phase="semantic_review", review_observation=deepcopy(observation), review_outcome=outcome)
    receipt = _receipt(
        stage="semantic_review", status=outcome.upper(), identity=identity,
        plan={"plan_id": predecessor["plan_id"], "revision": predecessor["plan_revision"]},
        plan_sha256=predecessor["plan_sha256"], predecessor=predecessor,
        next_action=_REVIEW_OUTCOME_ACTIONS[outcome], bindings=bindings,
    )
    return _post_batch_report(identity, receipt)


def _evaluate_semantic_review(identity: Mapping[str, Any], predecessor_value: Any, payload: Any) -> dict[str, Any]:
    """Read once and return a candidate without writing controller state.

    Native handling exposes PENDING as a read report without an intent, result,
    receipt or cursor update. Nonpending candidates retain the single observation
    for the normal durable transition, including the REFUSED evidence barrier.
    """
    issues: list[str] = []
    predecessor = _semantic_review_predecessor(identity, predecessor_value, issues)
    _exact(payload, set(), "payload", issues)
    if not issues:
        try:
            bindings = predecessor["bindings"]
            expectation = _load("orch_dork_qualification_review").review_observation_expectation(
                bindings["review_packet"], bindings["review_submission"], bindings["review_context"],
            )
            # Only this evaluator acquires evidence. Programs cannot supply an observation.
            observation = _load("orch_dork_local_task_runtime").observe_current_local_task_mcp_call(expectation)
            return _semantic_review_report(identity, predecessor, observation)
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
            _issue(issues, "semantic_review:observation_invalid")
    return _report(operation="semantic_review", identity=identity, status="BLOCKED",
                   disposition="SEMANTIC_REVIEW_REFUSED", issues=issues, stages=[])


def validate_semantic_review_transition(
    identity: Any, predecessor_report: Any, program: Any, report: Any,
) -> dict[str, Any]:
    """Check candidate transport from retained evidence without another owner read.

    This does not establish the durable controller tip or authorize committing a
    PENDING candidate; native polling keeps the stored receipt and cursor intact.
    """
    try:
        expected_program = build_semantic_review_program(identity, predecessor_report)
        if (_canonical(program) != _canonical(expected_program)
                or validate_post_batch_report(report)["valid"] is not True):
            raise ValueError("invalid semantic review transition")
        expected_report = _semantic_review_report(
            expected_program["identity"], expected_program["predecessor_receipt"],
            report["receipt"]["bindings"]["review_observation"],
        )
        if _canonical(report) != _canonical(expected_report):
            raise ValueError("noncanonical semantic review transition")
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return {"valid": False, "issues": ["semantic_review:transition_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


_PHYSICAL_RELEASE_FIELDS = (
    "completed_logical_lane_ids", "failed_logical_lane_ids", "cancelled_logical_lane_ids",
    "current_wave_logical_lane_ids", "capacity_authority_lane_ids", "capacity_authority_state_sha256",
    "capacity_authority_store_id",
)


def _stable_terminal_verification_evidence(root_task_id: str, receipt: Mapping[str, Any]) -> None:
    """Keep the exact verified lineage while allowing its later physical release."""
    bindings = receipt["bindings"]
    verification = bindings["terminal_verification"]
    verifier = _load("orch_dork_qualification_verification")
    if verifier.validate_terminal_verification(verification).get("valid") is not True:
        raise ValueError("terminal_verification:artifact_invalid")
    source = verification["source_report"]["receipt"]
    identity_fields = ("identity_sha256", "run_id", "attempt_id", "root_task_id", "plan_id", "plan_revision", "plan_sha256")
    if (root_task_id != source["root_task_id"]
            or _canonical({key: receipt[key] for key in identity_fields}) != _canonical({key: source[key] for key in identity_fields})):
        raise ValueError("terminal_verification:source_identity_mismatch")
    expected = {**deepcopy(source["bindings"]), "quality_phase": "terminal_verification",
                "terminal_verification": deepcopy(verification)}
    if (receipt["stage"] == "capacity_settlement" and bindings.get("current_wave_logical_lane_ids") == []
            and source["bindings"].get("current_wave_logical_lane_ids") != []):
        for key in _PHYSICAL_RELEASE_FIELDS:
            expected[key] = bindings[key]
    if (receipt["stage"] == "terminal_verification"
            and receipt["predecessor_receipt_sha256"] != source["receipt_sha256"]):
        raise ValueError("terminal_verification:source_receipt_mismatch")
    if receipt["stage"] == "cleanup":
        verified = {key:deepcopy(value) for key,value in receipt.items() if key != "receipt_sha256"}
        verified.update(stage="terminal_verification",status="VERIFIED",next_action="cleanup",
                        predecessor_receipt_sha256=source["receipt_sha256"])
        if receipt["predecessor_receipt_sha256"] != _sha(verified):
            raise ValueError("terminal_verification:cleanup_predecessor_mismatch")
    if _canonical(bindings) != _canonical(expected):
        raise ValueError("terminal_verification:retained_evidence_mismatch")


def build_terminal_verification_program(identity: Any, predecessor_report: Any) -> dict[str, Any]:
    """Construct one verification of retained evidence, without a terminal claim."""
    issues: list[str] = []
    identity_value = _validate_identity(identity, issues)
    predecessor = _post_batch_predecessor_report(identity_value, predecessor_report, issues)
    if issues:
        raise ValueError(";".join(sorted(set(issues))))
    if predecessor.get("next_action") != "verify":
        raise ValueError("terminal_verification:predecessor_not_ready")
    _load("orch_dork_qualification_verification").build_terminal_verification(predecessor_report)
    return {"schema": PROGRAM_SCHEMA, "operation": "terminal_verification", "identity": deepcopy(dict(identity_value)),
            "predecessor_receipt": deepcopy(dict(predecessor)), "payload": {}}


def _evaluate_terminal_verification(identity: Mapping[str, Any], predecessor_value: Any, payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    predecessor = _validate_receipt(predecessor_value, identity, issues,
                                    allowed_stages={"semantic_review", "capacity_settlement"}, allowed_actions={"verify"})
    _exact(payload, set(), "payload", issues)
    if not issues:
        try:
            source_report = _post_batch_report(identity, predecessor)
            _post_batch_predecessor_report(identity, source_report, issues)
            if issues:
                raise ValueError("invalid verification predecessor")
            verification = _load("orch_dork_qualification_verification").build_terminal_verification(source_report)
            receipt = _receipt(
                stage="terminal_verification", status="VERIFIED", identity=identity,
                plan={"plan_id": predecessor["plan_id"], "revision": predecessor["plan_revision"]},
                plan_sha256=predecessor["plan_sha256"], predecessor=predecessor,
                next_action=("cleanup" if predecessor["bindings"]["current_wave_logical_lane_ids"] != [] else
                             "final_qualification" if verification["outcome"] == "success" else "failure_closure"),
                bindings={**deepcopy(predecessor["bindings"]), "quality_phase": "terminal_verification",
                          "terminal_verification": verification},
            )
            return _post_batch_report(identity, receipt)
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
            _issue(issues, "terminal_verification:evidence_invalid")
    return _report(operation="terminal_verification", identity=identity, status="BLOCKED",
                   disposition="TERMINAL_VERIFICATION_REFUSED", issues=issues, stages=[])


def build_verified_cleanup_program(identity: Any, predecessor_report: Any) -> dict[str, Any]:
    """Authorize closing the verified active lanes; perform no cleanup or release."""
    issues: list[str] = []
    identity_value = _validate_identity(identity,issues)
    predecessor = _post_batch_predecessor_report(identity_value,predecessor_report,issues)
    if (issues or predecessor.get("stage") != "terminal_verification"
            or predecessor.get("next_action") != "cleanup"):
        raise ValueError("verified_cleanup:predecessor_not_ready")
    return {"schema":PROGRAM_SCHEMA,"operation":"cleanup","identity":deepcopy(dict(identity_value)),
            "predecessor_receipt":deepcopy(dict(predecessor)),"payload":{}}


def _evaluate_verified_cleanup(identity: Mapping[str, Any], predecessor_value: Any, payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    predecessor = _validate_receipt(predecessor_value,identity,issues,
        allowed_stages={"terminal_verification"},allowed_actions={"cleanup"})
    _exact(payload,set(),"payload",issues)
    if not issues:
        try:
            _post_batch_predecessor_report(identity,_post_batch_report(identity,predecessor),issues)
            bindings = predecessor["bindings"]
            if (issues or bindings["current_wave_logical_lane_ids"] != ["spec", "standards"]
                    or bindings["capacity_authority_lane_ids"] != [identity["run_id"] + ":" + lane for lane in ("spec", "standards")]):
                raise ValueError("different active verified lanes")
            receipt = _receipt(stage="cleanup",status="AUTHORIZED",identity=identity,
                plan={"plan_id":predecessor["plan_id"],"revision":predecessor["plan_revision"]},
                plan_sha256=predecessor["plan_sha256"],predecessor=predecessor,next_action="stop",bindings=deepcopy(bindings))
            return _post_batch_report(identity,receipt)
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
            _issue(issues,"verified_cleanup:evidence_invalid")
    return _report(operation="cleanup",identity=identity,status="BLOCKED",disposition="VERIFIED_CLEANUP_REFUSED",issues=issues,stages=[])


def validate_verified_cleanup_report(report: Any) -> dict[str, Any]:
    return _validate_result_report_transport(report,operation="cleanup")


def build_worker_results_program(
    identity: Any, predecessor_report: Any, worker_results: Any,
) -> dict[str, Any]:
    """Construct the exact result-observation program from whole producer values.

    Merge preserves accepted reports and unresolved evidence. Construction neither
    reads workers nor advances a controller, grant, observer, or capacity authority.
    """
    issues: list[str] = []
    identity_value = _validate_identity(identity, issues)
    receipt = _capacity_settlement_predecessor(identity_value, predecessor_report, issues)
    receipt = _worker_results_predecessor(identity_value, receipt, issues)
    if issues:
        raise ValueError(";".join(sorted(set(issues))))
    bindings = receipt.get("bindings")
    if not isinstance(bindings, Mapping):
        raise ValueError("worker_results:bindings_invalid")
    merged = _load("orch_dork_qualification_results").merge_results(
        bindings.get("worker_results"), worker_results,
        bindings=bindings, root_task_id=identity_value.get("root_task_id"),
    )
    return {
        "schema": PROGRAM_SCHEMA,
        "operation": "worker_results",
        "identity": deepcopy(dict(identity_value)),
        "predecessor_receipt": deepcopy(dict(receipt)),
        "payload": {"worker_results": deepcopy(merged)},
    }


def _evaluate_worker_results(
    identity: Mapping[str, Any], predecessor_value: Any, payload: Any,
) -> dict[str, Any]:
    """Retain whole result observations in a pure predecessor-sealed receipt."""
    issues: list[str] = []
    predecessor = _worker_results_predecessor(identity, predecessor_value, issues)
    value = _exact(payload, {"worker_results"}, "payload", issues)
    bindings = predecessor.get("bindings")
    if not isinstance(bindings, Mapping):
        _issue(issues, "worker_results:bindings_invalid")
    if not issues:
        try:
            results = _load("orch_dork_qualification_results")
            merged = results.merge_results(
                bindings.get("worker_results"), value.get("worker_results"),
                bindings=bindings, root_task_id=identity.get("root_task_id"),
            )
            decision = results.join_decision(
                merged, bindings=bindings, root_task_id=identity.get("root_task_id")
            )
            if decision not in _WORKER_RESULT_ACTIONS:
                raise ValueError("worker_results:decision_invalid")
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            _issue(issues, str(error) or "worker_results:reports_invalid")
    if issues:
        return _report(
            operation="worker_results", identity=identity, status="BLOCKED",
            disposition="WORKER_RESULTS_REFUSED", issues=issues, stages=[],
        )
    receipt = _receipt(
        stage="worker_results", status="OBSERVED", identity=identity,
        plan={"plan_id": predecessor.get("plan_id"), "revision": predecessor.get("plan_revision")},
        plan_sha256=predecessor["plan_sha256"], predecessor=predecessor,
        next_action=_WORKER_RESULT_ACTIONS[decision],
        bindings={**deepcopy(dict(bindings)), "worker_results": deepcopy(merged), "quality_phase": "worker_results"},
    )
    return _report(
        operation="worker_results", identity=identity, status="PASS",
        disposition="RESULTS_OBSERVED", issues=[],
        stages=[_stage("worker_results", "PASS", {"worker_results": merged}, [])], receipt=receipt,
    )


def build_pre_spawn_program(
    identity: Mapping[str, Any],
    *,
    ticket_admission: Mapping[str, Any],
    hard_admission: Mapping[str, Any],
    logical_plan: Mapping[str, Any],
    wave_preflight: Mapping[str, Any],
    budget_program: Mapping[str, Any],
    execution_readiness: Mapping[str, Any],
    project_ground: Mapping[str, Any],
    coordinator_capsule: Mapping[str, Any],
    research_manifest: Mapping[str, Any] | None,
    attempt_limits: Mapping[str, Any],
    require_worker_checkpoint: bool = False,
    checkpoint_reservation_profile: str | None = None,
    checkpoint_accounting_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct the canonical pre-spawn wrapper from whole stage values."""

    identity_value = _exact(
        identity,
        _IDENTITY_FIELDS,
        "identity",
        [],
    )
    if set(identity_value) != _IDENTITY_FIELDS:
        raise ValueError("identity:shape_invalid")
    if type(require_worker_checkpoint) is not bool:
        raise ValueError("worker_checkpoint:profile_invalid")
    if checkpoint_reservation_profile is not None:
        progress = _load("orch_dork_qualification_progress")
        if not require_worker_checkpoint or checkpoint_reservation_profile != progress.RESERVATION_PROFILE:
            raise ValueError("worker_checkpoint:reservation_profile_invalid")
    if checkpoint_accounting_policy is not None:
        accounting = _load("orch_dork_qualification_budget")
        if checkpoint_reservation_profile is None or not accounting.validate_checkpoint_accounting_policy(checkpoint_accounting_policy):
            raise ValueError("worker_checkpoint:accounting_policy_invalid")
    return {
        "schema": CHECKPOINT_PROGRAM_SCHEMA if require_worker_checkpoint else PROGRAM_SCHEMA,
        "operation": "pre_spawn",
        "identity": deepcopy(dict(identity_value)),
        "predecessor_receipt": None,
        "payload": {
            **({"checkpoint_reservation_profile":checkpoint_reservation_profile}
               if checkpoint_reservation_profile is not None else {}),
            **({"checkpoint_accounting_policy":deepcopy(dict(checkpoint_accounting_policy))}
               if checkpoint_accounting_policy is not None else {}),
            "ticket_admission": deepcopy(dict(ticket_admission)),
            "hard_admission": deepcopy(dict(hard_admission)),
            "logical_plan": deepcopy(dict(logical_plan)),
            "wave_preflight": deepcopy(dict(wave_preflight)),
            "budget_program": deepcopy(dict(budget_program)),
            "execution_readiness": deepcopy(dict(execution_readiness)),
            "project_ground": deepcopy(dict(project_ground)),
            "coordinator_capsule": deepcopy(dict(coordinator_capsule)),
            "research_manifest": (
                deepcopy(dict(research_manifest))
                if isinstance(research_manifest, Mapping)
                else None
            ),
            "attempt_limits": deepcopy(dict(attempt_limits)),
        },
    }


def _report(
    *,
    operation: str | None,
    identity: Mapping[str, Any],
    status: str,
    disposition: str,
    issues: list[str],
    stages: list[dict[str, Any]],
    receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    next_action = (
        receipt.get("next_action")
        if isinstance(receipt, Mapping)
        else "stop"
    )
    bindings = (
        receipt.get("bindings", {})
        if isinstance(receipt, Mapping) and isinstance(receipt.get("bindings"), Mapping)
        else {}
    )
    lane_bindings = [
        dict(row)
        for row in bindings.get("lane_bindings", [])
        if isinstance(row, Mapping)
    ]
    task_specs = {
        str(row.get("logical_worker_id")): row
        for row in bindings.get("task_specs", [])
        if isinstance(row, Mapping)
    }
    native_by_lane = {
        str(row.get("logical_worker_id")): row for row in lane_bindings
    }
    graph_lanes = [
        dict(row)
        for row in bindings.get("graph_lanes", [])
        if isinstance(row, Mapping)
    ]
    rendered_lanes = [
        {**row, **dict(native_by_lane.get(str(row.get("logical_worker_id")), {}))}
        for row in graph_lanes
    ]
    if not rendered_lanes:
        rendered_lanes = lane_bindings
    graph_edges = [
        {"from": dependency, "to": row.get("logical_worker_id")}
        for row in graph_lanes
        for dependency in row.get("dependencies", [])
        if isinstance(dependency, str)
    ]
    return {
        "schema": REPORT_SCHEMA,
        "status": status,
        "operation": operation,
        "disposition": disposition,
        "final_verdict": disposition,
        "run_id": identity.get("run_id"),
        "attempt_id": identity.get("attempt_id"),
        "root_task_id": identity.get("root_task_id"),
        "spawn_authorized": disposition == "SPAWN_AUTHORIZED",
        "work_authorized": disposition in {"WORK_AUTHORIZED", "CONTINUE"},
        "continuation_authorized": disposition == "CONTINUE",
        "terminal_claim_permitted": disposition == "TERMINALLY_QUALIFIED",
        "next_action": next_action,
        "stages": stages,
        "receipt": dict(receipt) if isinstance(receipt, Mapping) else None,
        "tool": {
            "name": "orch-dork",
            "version": identity.get("installed_version"),
            "contract": PROGRAM_SCHEMA,
        },
        "graph": {
            "plan_id": receipt.get("plan_id") if isinstance(receipt, Mapping) else None,
            "revision": receipt.get("plan_revision") if isinstance(receipt, Mapping) else None,
            "lanes": rendered_lanes,
            "edges": graph_edges,
        },
        "routing": {
            "root": {
                "model": identity.get("root_model"),
                "effort": identity.get("root_effort"),
            },
            "workers": [
                {
                    "logical_worker_id": lane_id,
                    "model_profile": row.get("model_profile"),
                    "model": row.get("model"),
                    "effort": row.get("effort"),
                    "resolution": row.get("resolution"),
                    "context_policy": "none",
                }
                for lane_id, row in sorted(task_specs.items())
            ],
        },
        "token_ingress": dict(bindings.get("latest_ingress", {}))
        if isinstance(bindings.get("latest_ingress"), Mapping)
        else None,
        "verification": {
            "verification_digests": dict(bindings.get("verification_digests", {}))
            if isinstance(bindings.get("verification_digests"), Mapping)
            else {},
            "claim_ledger_digests": dict(bindings.get("claim_ledger_digests", {}))
            if isinstance(bindings.get("claim_ledger_digests"), Mapping)
            else {},
            "observer_report_sha256": bindings.get("observer_report_sha256"),
            "trace_sha256": bindings.get("trace_sha256"),
        },
        "issues": sorted(set(issues)),
        "provider_free": True,
        "live_task_operations": 0,
        "model_calls": 0,
        "hosted_calls": 0,
        "automatic_retries": 0,
        "automatic_replacements": 0,
        "automatic_fallbacks": 0,
    }


def _validate_identity(value: Any, issues: list[str]) -> Mapping[str, Any]:
    identity = _exact(value, _IDENTITY_FIELDS, "identity", issues)
    for field in (
        "run_id",
        "attempt_id",
        "root_task_id",
        "root_model",
        "root_effort",
        "source_version",
        "installed_version",
        "task_loaded_version",
    ):
        if not _identifier(identity.get(field)):
            _issue(issues, "identity:" + field + "_invalid")
    if not isinstance(identity.get("fresh_task"), bool):
        _issue(issues, "identity:fresh_task_invalid")
    return identity


def _admission_projection(plan: Mapping[str, Any]) -> dict[str, Any]:
    workers = plan.get("workers") if isinstance(plan.get("workers"), list) else []
    return {
        "lanes": [
            {
                "id": worker.get("id"),
                "objective": worker.get("objective"),
                "dependencies": list(worker.get("dependencies", [])),
                "owned_resources": list(worker.get("owned_resources", [])),
                "excluded_resources": list(worker.get("excluded_resources", [])),
                "deliverables": list(worker.get("deliverables", [])),
                "verification": list(worker.get("verification", [])),
            }
            for worker in workers
            if isinstance(worker, Mapping)
        ]
    }


def build_admission_plan_projection(
    logical_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Project one logical plan into the admission-kernel lane contract."""

    return _admission_projection(logical_plan)


def _task_spec_bindings(wave: Mapping[str, Any], issues: list[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    values = wave.get("task_specs")
    if not isinstance(values, list):
        _issue(issues, "wave_preflight:task_specs_missing")
        return result
    for index, raw in enumerate(values):
        item = raw if isinstance(raw, Mapping) else {}
        report = adaptive_contracts.validate_task_spec(item.get("task_spec"))
        normalized = report.get("normalized")
        if not report.get("valid") or not isinstance(normalized, Mapping):
            _issue(issues, f"wave_preflight:task_spec_invalid:{index}")
            continue
        lane_id = item.get("logical_worker_id")
        if normalized.get("id") != lane_id:
            _issue(issues, f"wave_preflight:task_spec_lane_mismatch:{index}")
        result.append(
            {
                "logical_worker_id": lane_id,
                "task_spec_sha256": report.get("digest"),
                "allowed_tools": list(normalized.get("allowed_tools", [])),
                "dependencies": list(normalized.get("dependencies", [])),
                "model_profile": normalized.get("model_profile"),
            }
        )
    return sorted(result, key=lambda row: str(row["logical_worker_id"]))


def _evaluate_pre_spawn(
    identity: Mapping[str, Any],
    payload: Any,
    *,
    source_roots: Mapping[str, str | Path] | None,
    now: datetime | None,
    require_worker_checkpoint: bool = False,
) -> dict[str, Any]:
    issues: list[str] = []
    stages: list[dict[str, Any]] = []
    value = _exact(
        payload,
        frozenset(
            {
                "ticket_admission",
                "hard_admission",
                "logical_plan",
                "wave_preflight",
                "budget_program",
                "execution_readiness",
                "project_ground",
                "coordinator_capsule",
                "research_manifest",
                "attempt_limits",
            }
            | ({"checkpoint_reservation_profile"} if require_worker_checkpoint
               and isinstance(payload, Mapping) and "checkpoint_reservation_profile" in payload else set())
            | ({"checkpoint_accounting_policy"} if require_worker_checkpoint
               and isinstance(payload, Mapping) and "checkpoint_accounting_policy" in payload else set())
        ),
        "payload",
        issues,
    )
    plan = value.get("logical_plan") if isinstance(value.get("logical_plan"), Mapping) else {}

    generation_issues: list[str] = []
    generation = plan.get("generation") if isinstance(plan.get("generation"), Mapping) else {}
    package_version = _manifest_version()
    for field in ("source_version", "installed_version", "task_loaded_version", "fresh_task"):
        if generation.get(field) != identity.get(field):
            _issue(generation_issues, "generation:" + field + "_identity_mismatch")
    if not (
        identity.get("source_version")
        == identity.get("installed_version")
        == identity.get("task_loaded_version")
        == package_version
    ):
        _issue(generation_issues, "generation:source_install_task_mismatch")
    if identity.get("fresh_task") is not True:
        _issue(generation_issues, "generation:fresh_task_required")
    issues.extend(generation_issues)
    stages.append(_stage("generation", "PASS" if not generation_issues else "FAIL", generation, generation_issues))

    ticket_issues: list[str] = []
    ticket = value.get("ticket_admission") if isinstance(value.get("ticket_admission"), Mapping) else {}
    if ticket.get("schema") != efficiency_governor.TICKET_ADMISSION_SCHEMA:
        _issue(ticket_issues, "ticket_admission:schema_invalid")
    if ticket.get("policy_version") != efficiency_governor.TICKET_ADMISSION_POLICY_VERSION:
        _issue(ticket_issues, "ticket_admission:policy_invalid")
    if ticket.get("decision") != "ORCHESTRATION_PLAN_REQUIRED":
        _issue(ticket_issues, "ticket_admission:decision_invalid")
    if ticket.get("root_task_id") != identity.get("root_task_id"):
        _issue(ticket_issues, "ticket_admission:root_mismatch")
    if not _text(ticket.get("admission_sha256")):
        _issue(ticket_issues, "ticket_admission:seal_missing")
    issues.extend(ticket_issues)
    stages.append(_stage("ticket_admission", "PASS" if not ticket_issues else "FAIL", ticket, ticket_issues))

    observed_roots = dict(source_roots or {})
    raw_project = plan.get("project") if isinstance(plan.get("project"), Mapping) else {}
    raw_workspace = raw_project.get("workspace_root")
    if _text(raw_workspace):
        try:
            observed_roots.setdefault("project", Path(str(raw_workspace)).resolve(strict=True))
        except (OSError, ValueError):
            pass
    hard = admission_kernel.evaluate_admission_kernel(
        value.get("hard_admission"),
        source_roots=observed_roots,
        now=now,
    )
    hard_issues: list[str] = []
    if hard.get("decision") != admission_kernel.ADMIT or hard.get("mutation_permitted") is not True:
        _issue(hard_issues, "hard_admission:not_admitted")
    if hard.get("attempt_id") != identity.get("attempt_id"):
        _issue(hard_issues, "hard_admission:attempt_mismatch")
    if hard.get("root_task_id") != identity.get("root_task_id"):
        _issue(hard_issues, "hard_admission:root_mismatch")
    candidate = (
        value.get("hard_admission", {}).get("candidate_plan", {})
        if isinstance(value.get("hard_admission"), Mapping)
        else {}
    )
    if candidate.get("plan") != _admission_projection(plan):
        _issue(hard_issues, "hard_admission:logical_plan_projection_mismatch")
    semantic = candidate.get("semantic_decision") if isinstance(candidate, Mapping) else {}
    if isinstance(semantic, Mapping) and semantic.get("ticket_id") != ticket.get("ticket_id"):
        _issue(hard_issues, "hard_admission:ticket_mismatch")
    hard_issues.extend("hard_admission:" + str(item) for item in hard.get("reasons", []))
    issues.extend(hard_issues)
    stages.append(_stage("hard_admission", "PASS" if not hard_issues else "FAIL", hard, hard_issues))

    plan_report = efficiency_governor.validate_logical_plan(plan)
    plan_issues = list(plan_report.get("issues", []))
    if plan_report.get("status") != "PASS":
        _issue(plan_issues, "logical_plan:not_valid")
    if plan_report.get("planner_model") != identity.get("root_model"):
        _issue(plan_issues, "logical_plan:root_model_mismatch")
    if plan_report.get("planner_effort") != identity.get("root_effort"):
        _issue(plan_issues, "logical_plan:root_effort_mismatch")
    project = plan_report.get("project") if isinstance(plan_report.get("project"), Mapping) else {}
    workspace = project.get("workspace_root")
    try:
        resolved_workspace = str(Path(str(workspace)).resolve(strict=True))
    except (OSError, ValueError):
        resolved_workspace = ""
        _issue(plan_issues, "logical_plan:workspace_unavailable")
    if project.get("workspace_root_sha256") != hashlib.sha256(resolved_workspace.encode()).hexdigest():
        _issue(plan_issues, "logical_plan:workspace_root_digest_mismatch")
    issues.extend(plan_issues)
    stages.append(_stage("logical_plan", "PASS" if not plan_issues else "FAIL", plan_report, plan_issues))

    closure_report = plan_report.get("acceptance_resource_closure", {})
    closure_issues: list[str] = []
    if not isinstance(closure_report, Mapping) or closure_report.get("status") != "PASS" or closure_report.get("closed") is not True:
        _issue(closure_issues, "acceptance_resource_closure:not_closed")
    issues.extend(closure_issues)
    stages.append(_stage("acceptance_resource_closure", "PASS" if not closure_issues else "FAIL", closure_report, closure_issues))

    research_issues: list[str] = []
    research_report: Mapping[str, Any] = {}
    if project.get("research_manifest_required") is True:
        if not isinstance(value.get("research_manifest"), Mapping):
            _issue(research_issues, "research_manifest:required")
        elif resolved_workspace:
            research_report = research_manifest.validate_markdown_manifest(
                value.get("research_manifest"), resolved_workspace
            )
            if research_report.get("status") != "PASS":
                research_issues.extend(
                    "research_manifest:" + str(item)
                    for item in research_report.get("issues", [])
                )
    elif value.get("research_manifest") is not None:
        _issue(research_issues, "research_manifest:unexpected")
    issues.extend(research_issues)
    stages.append(_stage("research_manifest", "PASS" if not research_issues else "FAIL", research_report, research_issues))

    readiness_report = execution_readiness.evaluate_execution_readiness(value.get("execution_readiness"))
    readiness_issues: list[str] = []
    if readiness_report.get("status") != "READY_FOR_AUTHORITY" or readiness_report.get("ready") is not True:
        _issue(readiness_issues, "execution_readiness:not_ready")
    if readiness_report.get("attempt_id") != identity.get("attempt_id"):
        _issue(readiness_issues, "execution_readiness:attempt_mismatch")
    if (value.get("execution_readiness") or {}).get("plan_sha256") != plan_report.get("plan_sha256"):
        _issue(readiness_issues, "execution_readiness:plan_mismatch")
    readiness_issues.extend("execution_readiness:" + str(item) for item in readiness_report.get("issues", []))
    issues.extend(readiness_issues)
    stages.append(_stage("execution_readiness", "PASS" if not readiness_issues else "FAIL", readiness_report, readiness_issues))

    ground_report = project_ground.evaluate_project_ground_enforcement(value.get("project_ground"))
    ground_issues: list[str] = []
    if ground_report.get("status") != "PASS" or ground_report.get("decision") != "HEALTHY":
        _issue(ground_issues, "project_ground:not_healthy")
    ground_identity = ground_report.get("identity") if isinstance(ground_report.get("identity"), Mapping) else {}
    if ground_identity.get("project_id") != project.get("project_id"):
        _issue(ground_issues, "project_ground:project_mismatch")
    if ground_identity.get("generation") != project.get("binding_generation"):
        _issue(ground_issues, "project_ground:generation_mismatch")
    if ground_identity.get("plan_sha256") != plan_report.get("plan_sha256"):
        _issue(ground_issues, "project_ground:plan_mismatch")
    if ground_identity.get("lease_owner_thread_id") != identity.get("root_task_id"):
        _issue(ground_issues, "project_ground:root_mismatch")
    ground_issues.extend("project_ground:" + str(item) for item in ground_report.get("reason_codes", []))
    issues.extend(ground_issues)
    stages.append(_stage("project_ground", "PASS" if not ground_issues else "FAIL", ground_report, ground_issues))

    capsule_report = coordinator_capsule.evaluate_coordinator_capsule(value.get("coordinator_capsule"))
    capsule_issues: list[str] = []
    if capsule_report.get("status") != "PASS" or not _text(capsule_report.get("capsule_sha256")):
        _issue(capsule_issues, "coordinator_capsule:not_sealed")
    capsule_identity = (
        capsule_report.get("capsule", {}).get("identity", {})
        if isinstance(capsule_report.get("capsule"), Mapping)
        else {}
    )
    if capsule_identity.get("plan_sha256") != plan_report.get("plan_sha256"):
        _issue(capsule_issues, "coordinator_capsule:plan_mismatch")
    if capsule_identity.get("admission_sha256") != ticket.get("admission_sha256"):
        _issue(capsule_issues, "coordinator_capsule:admission_mismatch")
    capsule_issues.extend("coordinator_capsule:" + str(item) for item in capsule_report.get("issues", []))
    issues.extend(capsule_issues)
    stages.append(_stage("coordinator_capsule", "PASS" if not capsule_issues else "FAIL", capsule_report, capsule_issues))

    limit_issues: list[str] = []
    attempt_limits = _exact(
        value.get("attempt_limits"),
        frozenset(
            {"max_sol_ingress_tokens", "max_total_tokens", "max_tool_calls"}
        ),
        "attempt_limits",
        limit_issues,
    )
    for field in (
        "max_sol_ingress_tokens",
        "max_total_tokens",
        "max_tool_calls",
    ):
        if type(attempt_limits.get(field)) is not int or attempt_limits.get(field, 0) <= 0:
            _issue(limit_issues, "attempt_limits:" + field + "_invalid")
    if (
        type(attempt_limits.get("max_sol_ingress_tokens")) is int
        and type(attempt_limits.get("max_total_tokens")) is int
        and attempt_limits["max_sol_ingress_tokens"] > attempt_limits["max_total_tokens"]
    ):
        _issue(limit_issues, "attempt_limits:sol_exceeds_total")
    issues.extend(limit_issues)
    stages.append(
        _stage(
            "attempt_limits",
            "PASS" if not limit_issues else "FAIL",
            attempt_limits,
            limit_issues,
        )
    )

    budget_report = efficiency_governor.evaluate_budget_program(value.get("budget_program"))
    budget_issues: list[str] = []
    if budget_report.get("status") != "PASS":
        _issue(budget_issues, "budget_reservation:not_admitted")
    if budget_report.get("plan_sha256") != plan_report.get("plan_sha256"):
        _issue(budget_issues, "budget_reservation:plan_mismatch")
    expected_delegated = {
        str(worker.get("id"))
        for worker in plan.get("workers", [])
        if isinstance(worker, Mapping) and worker.get("executor") == "subagent"
    }
    reserved = {
        str(row.get("node_id"))
        for row in budget_report.get("admission_decisions", [])
        if isinstance(row, Mapping) and row.get("status") == "RESERVED"
    }
    if reserved != expected_delegated:
        _issue(budget_issues, "budget_reservation:worker_set_mismatch")
    if "checkpoint_reservation_profile" in value:
        progress = _load("orch_dork_qualification_progress")
        if (value["checkpoint_reservation_profile"] != progress.RESERVATION_PROFILE
                or progress.validate_checkpoint_reservation_program(value["budget_program"],plan,
                    accounting_policy=value.get("checkpoint_accounting_policy")) is not True
                or budget_report.get("limits", {}).get("tokens") != attempt_limits.get("max_total_tokens")):
            _issue(budget_issues, "budget_reservation:checkpoint_profile_invalid")
    if "checkpoint_accounting_policy" in value:
        accounting = _load("orch_dork_qualification_budget")
        if ("checkpoint_reservation_profile" not in value
                or not accounting.validate_checkpoint_accounting_policy(value["checkpoint_accounting_policy"])):
            _issue(budget_issues, "budget_reservation:accounting_policy_invalid")
    budget_issues.extend("budget_reservation:" + str(item) for item in budget_report.get("issues", []))
    issues.extend(budget_issues)
    stages.append(_stage("budget_reservation", "PASS" if not budget_issues else "FAIL", budget_report, budget_issues))

    wave = value.get("wave_preflight") if isinstance(value.get("wave_preflight"), Mapping) else {}
    wave_report = efficiency_governor.run_wave_program(wave)
    wave_issues: list[str] = []
    if wave.get("schema") != efficiency_governor.WAVE_PROGRAM_SCHEMA_V3:
        _issue(wave_issues, "wave_v3_preflight:schema_invalid")
    if wave.get("observations") != []:
        _issue(wave_issues, "wave_v3_preflight:post_spawn_observations_present")
    if wave.get("logical_plan") != plan:
        _issue(wave_issues, "wave_v3_preflight:logical_plan_mismatch")
    if wave_report.get("status") != "WAITING" or wave_report.get("spawn_permitted") is not True:
        _issue(wave_issues, "wave_v3_preflight:not_permitted")
    if wave_report.get("plan_sha256") != plan_report.get("plan_sha256"):
        _issue(wave_issues, "wave_v3_preflight:plan_digest_mismatch")
    wave_issues.extend("wave_v3_preflight:" + str(item) for item in wave_report.get("issues", []))
    task_bindings = _task_spec_bindings(wave, wave_issues)
    if require_worker_checkpoint and not wave_issues:
        tasks = wave.get("task_specs")
        if (not isinstance(tasks, list) or len(tasks) != 2
                or sorted(row.get("logical_worker_id", "") for row in tasks if isinstance(row, Mapping)) != ["spec", "standards"]
                or any(not isinstance(row, Mapping) or not isinstance(row.get("task_spec"), Mapping)
                       or row["task_spec"].get("schema") != "orch-dork/task-spec/v2"
                       or not isinstance(row["task_spec"].get("deliverable"), Mapping)
                       or row["task_spec"]["deliverable"].get("schema") != adaptive_contracts.HANDOFF_RECEIPT_SCHEMA
                       for row in tasks)):
            _issue(wave_issues, "worker_checkpoint:task_profile_invalid")
    node_routing = (
        plan_report.get("node_routing", {})
        if isinstance(plan_report.get("node_routing"), Mapping)
        else {}
    )
    for task_binding in task_bindings:
        route = node_routing.get(str(task_binding.get("logical_worker_id")), {})
        if not isinstance(route, Mapping):
            route = {}
        task_binding.update(
            {
                "model": route.get("model"),
                "effort": route.get("effort"),
                "resolution": route.get("resolution"),
            }
        )
    if {str(row.get("logical_worker_id")) for row in task_bindings} != expected_delegated:
        _issue(wave_issues, "wave_v3_preflight:task_spec_worker_set_mismatch")
    if "checkpoint_accounting_policy" in value:
        accounting = _load("orch_dork_qualification_budget")
        # A valid accounting policy names a registered orchestrator as its
        # root (the budget stage already named an invalid policy); the attempt
        # root and the plan's declared root must both be that exact model.
        # Every read is shape-guarded so a malformed policy is a named issue.
        accounting_policy = value["checkpoint_accounting_policy"]
        accounted = accounting_policy.get("root") if isinstance(accounting_policy, Mapping) else None
        accounted_root = accounted.get("model") if isinstance(accounted, Mapping) else None
        declared_root = plan_report.get("planner_model")
        if (accounted_root is None
                or identity.get("root_model") != accounted_root
                or declared_root != accounted_root
                or any(row.get("model") != accounting.WORKER_MODEL for row in task_bindings)):
            _issue(wave_issues, "worker_checkpoint:accounting_route_mismatch")
    issues.extend(wave_issues)
    stages.append(_stage("wave_v3_preflight", "PASS" if not wave_issues else "FAIL", wave_report, wave_issues))

    if issues:
        return _report(
            operation="pre_spawn",
            identity=identity,
            status="BLOCKED",
            disposition="PRE_SPAWN_REFUSED",
            issues=issues,
            stages=stages,
        )
    bindings = {
        "ticket_id": ticket.get("ticket_id"),
        "ticket_admission_sha256": ticket.get("admission_sha256"),
        "hard_admission_sha256": hard.get("admission_digest"),
        "project_id": project.get("project_id"),
        "binding_generation": project.get("binding_generation"),
        "binding_manifest_sha256": project.get("binding_manifest_sha256"),
        "generation": dict(generation),
        "attempt_limits": dict(attempt_limits),
        "completion_reserve": deepcopy(wave.get("completion_reserve")),
        "progress_prefixes": {},
        "task_specs": task_bindings,
        "all_task_specs": task_bindings,
        "graph_lanes": [
            {
                "logical_worker_id": worker.get("id"),
                "executor": worker.get("executor"),
                "dependencies": list(worker.get("dependencies", [])),
            }
            for worker in plan.get("workers", [])
            if isinstance(worker, Mapping)
        ],
        "lane_bindings": [],
        "all_lane_bindings": [],
        "completed_logical_lane_ids": [],
        "failed_logical_lane_ids": [],
        "cancelled_logical_lane_ids": [],
        "capacity_wave_index": 0,
        "task_node_budget": plan.get(
            "task_node_budget", plan.get("logical_worker_count")
        ),
        "plan_predecessor_sha256": plan.get("predecessor_plan_sha256"),
        "configured_concurrency_budget": (
            ((value.get("budget_program") or {}).get("budget_policy") or {})
            .get("limits", {})
            .get("concurrency")
        ),
        "research_manifest_sha256": research_report.get("manifest_sha256") if research_report else None,
        "readiness_receipt_sha256": readiness_report.get("receipt_sha256"),
        "project_ground_sha256": ground_report.get("report_sha256"),
        "capsule_sha256": capsule_report.get("capsule_sha256"),
        "budget_receipt_sha256": budget_report.get("receipt_sha256"),
        "wave_preflight_sha256": wave_report.get("plan_sha256"),
    }
    if require_worker_checkpoint:
        bindings["worker_checkpoint_profile"] = WORKER_CHECKPOINT_PROFILE
        bindings["checkpoint_budget_program"] = deepcopy(value["budget_program"])
        if "checkpoint_reservation_profile" in value:
            bindings["checkpoint_reservation_profile"] = value["checkpoint_reservation_profile"]
        if "checkpoint_accounting_policy" in value:
            bindings["checkpoint_accounting_policy"] = deepcopy(value["checkpoint_accounting_policy"])
    receipt = _receipt(
        stage="pre_spawn",
        status="READY",
        identity=identity,
        plan=plan,
        plan_sha256=str(plan_report.get("plan_sha256")),
        predecessor=None,
        next_action="capacity_admission",
        bindings=bindings,
    )
    return _report(
        operation="pre_spawn",
        identity=identity,
        status="PASS",
        disposition="SHARED_CAPACITY_ADMISSION_REQUIRED",
        issues=[],
        stages=stages,
        receipt=receipt,
    )


def _evaluate_capacity_admission(
    identity: Mapping[str, Any],
    predecessor_value: Any,
    payload: Any,
    *,
    capacity_authority: Any,
) -> dict[str, Any]:
    """Atomically reserve one dependency-ready wave, never the whole DAG."""

    issues: list[str] = []
    stages: list[dict[str, Any]] = []
    predecessor = _validate_receipt(
        predecessor_value,
        identity,
        issues,
        allowed_stages={"pre_spawn", "capacity_settlement"},
        allowed_actions={"capacity_admission"},
    )
    _exact(payload, frozenset(), "payload", issues)
    bindings = (
        predecessor.get("bindings", {})
        if isinstance(predecessor.get("bindings"), Mapping)
        else {}
    )
    all_task_specs = [
        row
        for row in bindings.get(
            "all_task_specs", bindings.get("task_specs", [])
        )
        if isinstance(row, Mapping)
    ]
    all_logical_lane_ids = sorted(
        str(row.get("logical_worker_id")) for row in all_task_specs
    )
    if (
        not all_logical_lane_ids
        or any(not _identifier(lane_id) for lane_id in all_logical_lane_ids)
        or len(all_logical_lane_ids) != len(set(all_logical_lane_ids))
    ):
        _issue(issues, "shared_capacity:delegated_lane_set_invalid")
    graph = {
        str(row.get("logical_worker_id")): row
        for row in bindings.get("graph_lanes", [])
        if isinstance(row, Mapping)
    }
    if set(all_logical_lane_ids) - set(graph):
        _issue(issues, "shared_capacity:graph_lane_set_invalid")
    wave_index = bindings.get("capacity_wave_index")
    if type(wave_index) is not int or wave_index < 0:
        _issue(issues, "shared_capacity:wave_index_invalid")
    terminal_sets: dict[str, set[str]] = {}
    for name in ("completed", "failed", "cancelled"):
        raw = bindings.get(name + "_logical_lane_ids", [])
        if (
            not isinstance(raw, list)
            or any(not _identifier(item) for item in raw)
            or len(raw) != len(set(raw))
        ):
            _issue(issues, "shared_capacity:" + name + "_lane_set_invalid")
            raw = []
        terminal_sets[name] = set(raw)
    terminal_ids = set().union(*terminal_sets.values())
    if (
        terminal_ids - set(all_logical_lane_ids)
        or sum(len(value) for value in terminal_sets.values())
        != len(terminal_ids)
    ):
        _issue(issues, "shared_capacity:terminal_lane_sets_invalid")
    ready_lane_ids = sorted(
        lane_id
        for lane_id in all_logical_lane_ids
        if lane_id not in terminal_ids
        and set(graph.get(lane_id, {}).get("dependencies", []))
        <= terminal_sets["completed"]
    )
    if not ready_lane_ids:
        _issue(issues, "shared_capacity:no_dependency_ready_lane")
    task_node_budget = bindings.get("task_node_budget")
    configured_cap = bindings.get("configured_concurrency_budget")
    if (
        type(task_node_budget) is not int
        or task_node_budget < len(all_logical_lane_ids)
    ):
        _issue(issues, "shared_capacity:task_node_budget_invalid")
    if (
        type(configured_cap) is not int
        or configured_cap < 1
        or configured_cap > shared_capacity.MAX_CONCURRENT_LANES
    ):
        _issue(issues, "shared_capacity:configured_cap_invalid")
    reader = getattr(capacity_authority, "read", None)
    if not callable(reader):
        reader = getattr(
            capacity_authority, "read_shared_capacity_authority", None
        )
    committer = getattr(capacity_authority, "commit", None)
    if not callable(committer):
        committer = getattr(
            capacity_authority, "commit_shared_capacity_authority", None
        )
    if not callable(reader) or not callable(committer):
        _issue(issues, "shared_capacity:authority_adapter_required")

    authority_read: Mapping[str, Any] = {}
    successor: Mapping[str, Any] | None = None
    authority_lane_ids: list[str] = []
    selected_lane_ids: list[str] = []
    readback: Mapping[str, Any] = {}
    if not issues:
        try:
            authority_read = reader()
            if (
                not isinstance(authority_read, Mapping)
                or authority_read.get("status") != "VERIFIED"
                or authority_read.get("continuity_verified") is not True
            ):
                raise ValueError("shared_capacity:authority_read_unverified")
            base_state = authority_read.get("state")
            authority = shared_capacity.validate_authority_state(base_state)
            if authority.get("status") != "RESOLVED":
                raise ValueError("shared_capacity:authority_state_invalid")
            available = min(
                configured_cap, shared_capacity.MAX_CONCURRENT_LANES
            ) - len(authority["active_lane_ids"])
            if available <= 0:
                raise ValueError("capacity:max_concurrent_lanes_reached")
            selected_lane_ids = ready_lane_ids[:available]
            if not selected_lane_ids:
                raise ValueError("capacity:no_available_lane")

            run_id = str(identity.get("run_id"))
            root_task_id = str(identity.get("root_task_id"))
            plan_revision = predecessor.get("plan_revision")
            plan_sha256 = predecessor.get("plan_sha256")
            state = base_state
            run = authority["runs"].get(run_id)
            if run is None:
                if plan_revision != 1:
                    raise ValueError("shared_capacity:initial_revision_invalid")
                registered = shared_capacity.register_run_authority(
                    state,
                    run_id=run_id,
                    root_thread_id=root_task_id,
                    task_node_budget=task_node_budget,
                    plan_sha256=plan_sha256,
                )
                if registered.get("status") != "REGISTERED":
                    raise ValueError("shared_capacity:run_registration_failed")
                state = registered["state"]
            else:
                if (
                    run.get("root_thread_id") != root_task_id
                    or run.get("task_node_budget") != task_node_budget
                ):
                    raise ValueError("shared_capacity:run_binding_mismatch")
                current_plan = run.get("plan_revisions", [])[-1]
                requested_plan = {
                    "revision": plan_revision,
                    "plan_sha256": plan_sha256,
                }
                if current_plan != requested_plan:
                    if (
                        plan_revision != current_plan.get("revision", 0) + 1
                        or bindings.get("plan_predecessor_sha256")
                        != current_plan.get("plan_sha256")
                    ):
                        raise ValueError("shared_capacity:run_revision_mismatch")
                    revised = shared_capacity.revise_run_authority(
                        state,
                        run_id=run_id,
                        predecessor_plan_sha256=current_plan["plan_sha256"],
                        successor_plan_sha256=plan_sha256,
                    )
                    if revised.get("status") != "REVISED":
                        raise ValueError("shared_capacity:run_revision_failed")
                    state = revised["state"]

            for logical_lane_id in selected_lane_ids:
                authority_lane_id = run_id + ":" + logical_lane_id
                reserved = shared_capacity.reserve_authority_lane(
                    state,
                    lane_id=authority_lane_id,
                    run_id=run_id,
                    route="native_luna",
                    plan_revision=plan_revision,
                    plan_sha256=plan_sha256,
                )
                if reserved.get("status") != "RESERVED":
                    reason = (reserved.get("reason_codes") or [
                        "shared_capacity:lane_reservation_failed"
                    ])[0]
                    raise ValueError(str(reason))
                state = reserved["state"]
                authority_lane_ids.append(authority_lane_id)
            successor = shared_capacity.collapse_authority_transition(
                base_state, state
            )
            committed = committer(successor)
            if not (
                isinstance(committed, Mapping)
                and committed.get("status") == "COMMITTED"
                and committed.get("state_sha256")
                == successor.get("state_sha256")
                and committed.get("reason_codes", []) == []
            ):
                raise ValueError("shared_capacity:authority_commit_conflict")
            readback = reader()
            readback_state = shared_capacity.validate_authority_state(
                readback.get("state")
                if isinstance(readback, Mapping)
                else None
            )
            if (
                not isinstance(readback, Mapping)
                or readback.get("status") != "VERIFIED"
                or readback.get("continuity_verified") is not True
                or readback.get("state_sha256")
                != successor.get("state_sha256")
                or readback_state.get("status") != "RESOLVED"
                or not set(authority_lane_ids)
                <= readback_state.get("active_lane_ids", set())
                or any(
                    readback_state.get("ledger", {})
                    .get("bindings", {})
                    .get(lane_id)
                    != {"run_id": run_id, "route": "native_luna"}
                    for lane_id in authority_lane_ids
                )
            ):
                raise ValueError("shared_capacity:authority_readback_mismatch")
        except Exception as exc:
            _issue(issues, str(exc) or "shared_capacity:reservation_failed")

    stage_report = {
        "authority_state_sha256": (
            successor.get("state_sha256")
            if isinstance(successor, Mapping) and not issues
            else None
        ),
        "authority_lane_ids": authority_lane_ids if not issues else [],
        "selected_logical_lane_ids": selected_lane_ids if not issues else [],
        "store_id": authority_read.get("store_id"),
    }
    stages.append(
        _stage(
            "shared_capacity_reservation",
            "PASS" if not issues else "FAIL",
            stage_report,
            issues,
        )
    )
    if issues:
        return _report(
            operation="capacity_admission",
            identity=identity,
            status="BLOCKED",
            disposition="SHARED_CAPACITY_REFUSED",
            issues=issues,
            stages=stages,
        )
    receipt = _receipt(
        stage="capacity_admission",
        status="AUTHORIZED",
        identity=identity,
        plan={
            "plan_id": predecessor.get("plan_id"),
            "revision": predecessor.get("plan_revision"),
        },
        plan_sha256=str(predecessor.get("plan_sha256")),
        predecessor=predecessor,
        next_action="spawn",
        bindings={
            **dict(bindings),
            "task_specs": [
                dict(row)
                for row in all_task_specs
                if str(row.get("logical_worker_id")) in set(selected_lane_ids)
            ],
            "all_task_specs": [dict(row) for row in all_task_specs],
            "capacity_authority_lane_ids": authority_lane_ids,
            "current_wave_logical_lane_ids": selected_lane_ids,
            "capacity_wave_index": wave_index + 1,
            "capacity_authority_state_sha256": successor.get(
                "state_sha256"
            ),
            "capacity_authority_store_id": readback.get("store_id"),
        },
    )
    return _report(
        operation="capacity_admission",
        identity=identity,
        status="PASS",
        disposition="SPAWN_AUTHORIZED",
        issues=[],
        stages=stages,
        receipt=receipt,
    )


def _evaluate_capacity_settlement(
    identity: Mapping[str, Any],
    predecessor_value: Any,
    payload: Any,
    *,
    capacity_authority: Any,
    observer_evaluation_time: datetime | None,
) -> dict[str, Any]:
    """Commit cleanup-proven terminal releases for one admitted wave."""

    issues: list[str] = []
    stages: list[dict[str, Any]] = []
    predecessor = _validate_receipt(
        predecessor_value,
        identity,
        issues,
        allowed_stages={
            "capacity_admission",
            "worker_start",
            "progress",
            "stopped",
            "worker_results",
            "result_aggregation",
            "review_submission",
            "semantic_review",
            "terminal_verification",
            "cleanup",
        },
        allowed_actions=(
            {
                "worker_results": set(_WORKER_RESULT_ACTIONS.values()),
                "result_aggregation": {"sol_review"},
                "review_submission": {"observe_sol_review"},
                "semantic_review": set(_REVIEW_OUTCOME_ACTIONS.values()),
                "terminal_verification": {"cleanup", "final_qualification", "failure_closure"},
            }.get(predecessor_value.get("stage"), {"spawn", "continue", "stop"})
            if isinstance(predecessor_value, Mapping) and isinstance(predecessor_value.get("stage"), str)
            else {"spawn", "continue", "stop"}
        ),
    )
    if predecessor.get("stage") == "worker_results":
        predecessor = _worker_results_predecessor(identity, predecessor, issues)
    elif predecessor.get("stage") == "result_aggregation":
        predecessor = _result_aggregation_predecessor(identity, predecessor, issues, aggregated=True)
    elif predecessor.get("stage") == "review_submission":
        predecessor = _review_submitted_predecessor(identity, predecessor, issues)
    elif predecessor.get("stage") == "semantic_review":
        predecessor = _semantic_review_predecessor(identity, predecessor, issues, pending_only=False)
    elif predecessor.get("stage") in {"terminal_verification", "cleanup"}:
        predecessor = _post_batch_predecessor_report(identity, _post_batch_report(identity, predecessor), issues)
    value = _exact(
        payload,
        frozenset({"release_receipts"}),
        "payload",
        issues,
    )
    bindings = (
        predecessor.get("bindings", {})
        if isinstance(predecessor.get("bindings"), Mapping)
        else {}
    )
    expected_lane_ids = bindings.get("capacity_authority_lane_ids")
    current_logical_ids = bindings.get("current_wave_logical_lane_ids")
    if (
        not isinstance(expected_lane_ids, list)
        or not expected_lane_ids
        or any(not _identifier(item) for item in expected_lane_ids)
        or len(expected_lane_ids) != len(set(expected_lane_ids))
        or not isinstance(current_logical_ids, list)
        or len(current_logical_ids) != len(expected_lane_ids)
    ):
        _issue(issues, "shared_capacity:settlement_wave_binding_invalid")
        expected_lane_ids = []
        current_logical_ids = []
    release_receipts = value.get("release_receipts")
    if not isinstance(release_receipts, list):
        _issue(issues, "shared_capacity:release_receipts_invalid")
        release_receipts = []
    receipts_by_lane = {
        str(receipt.get("lane_id")): receipt
        for receipt in release_receipts
        if isinstance(receipt, Mapping)
    }
    if (
        len(receipts_by_lane) != len(release_receipts)
        or set(receipts_by_lane) != set(expected_lane_ids)
        or observer_evaluation_time is None
    ):
        _issue(issues, "shared_capacity:release_receipt_set_invalid")
    reader = getattr(capacity_authority, "read", None)
    if not callable(reader):
        reader = getattr(
            capacity_authority, "read_shared_capacity_authority", None
        )
    committer = getattr(capacity_authority, "commit", None)
    if not callable(committer):
        committer = getattr(
            capacity_authority, "commit_shared_capacity_authority", None
        )
    if not callable(reader) or not callable(committer):
        _issue(issues, "shared_capacity:authority_adapter_required")

    completed = set(bindings.get("completed_logical_lane_ids", []))
    failed = set(bindings.get("failed_logical_lane_ids", []))
    cancelled = set(bindings.get("cancelled_logical_lane_ids", []))
    if not issues:
        logical_by_authority = {
            str(identity.get("run_id")) + ":" + str(logical_id): str(logical_id)
            for logical_id in current_logical_ids
        }
        for lane_id, receipt in receipts_by_lane.items():
            logical_id = logical_by_authority.get(lane_id)
            if logical_id is None:
                _issue(issues, "shared_capacity:settlement_wave_binding_invalid")
                continue
            terminal_state = receipt.get("terminal_state")
            if terminal_state == "completed":
                completed.add(logical_id)
            elif terminal_state == "failed":
                failed.add(logical_id)
            elif terminal_state == "cancelled":
                cancelled.add(logical_id)
            else:
                _issue(issues, "shared_capacity:terminal_outcome_invalid")
    all_specs = [
        dict(row)
        for row in bindings.get("all_task_specs", [])
        if isinstance(row, Mapping)
    ]
    all_ids = {str(row.get("logical_worker_id")) for row in all_specs}
    terminal_ids = completed | failed | cancelled
    pending_ids = all_ids - terminal_ids
    next_action = (
        "recovery"
        if (failed or cancelled) and not issues
        else "terminal"
        if not pending_ids and not issues
        else "capacity_admission"
    )
    settled_bindings = {
        **deepcopy(dict(bindings)),
        "task_specs": deepcopy(all_specs) if next_action == "terminal" else [],
        "completed_logical_lane_ids": sorted(completed),
        "failed_logical_lane_ids": sorted(failed),
        "cancelled_logical_lane_ids": sorted(cancelled),
        "capacity_authority_lane_ids": [],
        "current_wave_logical_lane_ids": [],
        "lane_bindings": deepcopy(bindings.get("all_lane_bindings", [])) if next_action == "terminal" else [],
    }
    tracked = "quality_phase" in bindings or predecessor.get("stage") in {"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification"}
    if tracked:
        settled_bindings["quality_phase"] = bindings.get("quality_phase", predecessor.get("stage"))
        if not issues and not (failed or cancelled):
            # Preserve the admitted join; validate completion before any physical commit.
            settled_bindings["task_specs"] = deepcopy(bindings.get("task_specs"))
            settled_bindings["lane_bindings"] = deepcopy(bindings.get("lane_bindings"))
            try:
                next_action = post_batch_next_action(identity.get("root_task_id"), {
                    **predecessor, "stage": "capacity_settlement", "bindings": settled_bindings,
                })
            except ValueError:
                _issue(issues, "shared_capacity:settlement_quality_invalid")

    authority_read: Mapping[str, Any] = {}
    successor: Mapping[str, Any] | None = None
    readback: Mapping[str, Any] = {}
    if not issues:
        try:
            authority_read = reader()
            authority = shared_capacity.validate_authority_state(
                authority_read.get("state")
                if isinstance(authority_read, Mapping)
                else None
            )
            if (
                not isinstance(authority_read, Mapping)
                or authority_read.get("status") != "VERIFIED"
                or authority_read.get("continuity_verified") is not True
                or authority.get("status") != "RESOLVED"
                or not set(expected_lane_ids)
                <= authority.get("active_lane_ids", set())
            ):
                raise ValueError("shared_capacity:settlement_read_unverified")
            base_state = authority_read["state"]
            state = base_state
            for lane_id in sorted(expected_lane_ids):
                receipt = receipts_by_lane[lane_id]
                if not shared_capacity.validate_release_receipt(
                    receipt,
                    lane_id=lane_id,
                    run_id=str(identity.get("run_id")),
                    route="native_luna",
                    terminal_state=receipt.get("terminal_state"),
                ):
                    raise ValueError("shared_capacity:release_receipt_invalid")
                released = shared_capacity.release_authority_lane(
                    state,
                    receipt,
                    observer_evaluation_time=observer_evaluation_time,
                )
                if released.get("status") != "RELEASED":
                    reason = (released.get("reason_codes") or [
                        "shared_capacity:release_refused"
                    ])[0]
                    raise ValueError(str(reason))
                state = released["state"]
            successor = shared_capacity.collapse_authority_transition(
                base_state,
                state,
                release_receipts=release_receipts,
                observer_evaluation_time=observer_evaluation_time,
            )
            committed = committer(
                successor, release_receipts=release_receipts
            )
            if not (
                isinstance(committed, Mapping)
                and committed.get("status") == "COMMITTED"
                and committed.get("state_sha256")
                == successor.get("state_sha256")
                and committed.get("reason_codes", []) == []
            ):
                raise ValueError("shared_capacity:settlement_commit_conflict")
            readback = reader()
            readback_state = shared_capacity.validate_authority_state(
                readback.get("state")
                if isinstance(readback, Mapping)
                else None
            )
            if (
                not isinstance(readback, Mapping)
                or readback.get("status") != "VERIFIED"
                or readback.get("continuity_verified") is not True
                or readback.get("state_sha256")
                != successor.get("state_sha256")
                or readback_state.get("status") != "RESOLVED"
                or set(expected_lane_ids)
                & readback_state.get("active_lane_ids", set())
            ):
                raise ValueError("shared_capacity:settlement_readback_mismatch")
        except Exception as exc:
            _issue(issues, str(exc) or "shared_capacity:settlement_failed")

    stage_report = {
        "authority_state_sha256": (
            successor.get("state_sha256")
            if isinstance(successor, Mapping) and not issues
            else None
        ),
        "released_authority_lane_ids": (
            sorted(expected_lane_ids) if not issues else []
        ),
        "terminal_logical_lane_ids": sorted(terminal_ids) if not issues else [],
        "pending_logical_lane_ids": sorted(pending_ids) if not issues else [],
    }
    stages.append(
        _stage(
            "shared_capacity_settlement",
            "PASS" if not issues else "FAIL",
            stage_report,
            issues,
        )
    )
    if issues:
        return _report(
            operation="capacity_settlement",
            identity=identity,
            status="BLOCKED",
            disposition="SHARED_CAPACITY_SETTLEMENT_REFUSED",
            issues=issues,
            stages=stages,
        )
    receipt = _receipt(
        stage="capacity_settlement",
        status="SETTLED",
        identity=identity,
        plan={
            "plan_id": predecessor.get("plan_id"),
            "revision": predecessor.get("plan_revision"),
        },
        plan_sha256=str(predecessor.get("plan_sha256")),
        predecessor=predecessor,
        next_action=next_action,
        bindings={
            **settled_bindings,
            "capacity_authority_state_sha256": successor.get("state_sha256"),
            "capacity_authority_store_id": readback.get("store_id"),
        },
    )
    return _report(
        operation="capacity_settlement",
        identity=identity,
        status="PASS",
        disposition="CAPACITY_RELEASED",
        issues=[],
        stages=stages,
        receipt=receipt,
    )


def _tool_event(value: Any, path: str, issues: list[str]) -> Mapping[str, Any]:
    event = _exact(
        value,
        frozenset(
            {"seq", "logical_worker_id", "worker_id", "session_id", "tool", "source_pointer"}
        ),
        path,
        issues,
    )
    if type(event.get("seq")) is not int or event.get("seq", 0) < 1:
        _issue(issues, path + ":seq_invalid")
    for field in ("logical_worker_id", "worker_id", "session_id", "tool"):
        if not _identifier(event.get(field)) and not (
            field == "worker_id" and isinstance(event.get(field), str) and event[field].startswith("/")
        ):
            _issue(issues, path + ":" + field + "_invalid")
    if not _text(event.get("source_pointer")):
        _issue(issues, path + ":source_pointer_invalid")
    return event


def _capacity_settlement_stage(
    identity: Mapping[str, Any],
    predecessor: Mapping[str, Any],
    capacity_authority: Any,
) -> tuple[dict[str, Any], list[str]]:
    """Verify every lane reserved by this attempt is authoritatively released."""

    issues: list[str] = []
    bindings = (
        predecessor.get("bindings", {})
        if isinstance(predecessor.get("bindings"), Mapping)
        else {}
    )
    all_task_specs = bindings.get(
        "all_task_specs", bindings.get("task_specs", [])
    )
    lane_ids = (
        [
            str(identity.get("run_id"))
            + ":"
            + str(row.get("logical_worker_id"))
            for row in all_task_specs
            if isinstance(row, Mapping)
        ]
        if isinstance(all_task_specs, list)
        else []
    )
    if (
        not isinstance(lane_ids, list)
        or not lane_ids
        or any(not _identifier(lane_id) for lane_id in lane_ids)
        or len(lane_ids) != len(set(lane_ids))
    ):
        _issue(issues, "shared_capacity:settlement_lane_set_invalid")
        lane_ids = []
    reader = getattr(capacity_authority, "read", None)
    if not callable(reader):
        reader = getattr(
            capacity_authority, "read_shared_capacity_authority", None
        )
    authority_read: Mapping[str, Any] = {}
    resolved: Mapping[str, Any] = {}
    if not callable(reader):
        _issue(issues, "shared_capacity:settlement_authority_required")
    else:
        try:
            authority_read = reader()
            if (
                not isinstance(authority_read, Mapping)
                or authority_read.get("status") != "VERIFIED"
                or authority_read.get("continuity_verified") is not True
            ):
                raise ValueError("shared_capacity:settlement_read_unverified")
            resolved = shared_capacity.validate_authority_state(
                authority_read.get("state")
            )
            if resolved.get("status") != "RESOLVED":
                raise ValueError("shared_capacity:settlement_state_invalid")
            active = resolved.get("active_lane_ids", set())
            if set(lane_ids) & set(active):
                raise ValueError("shared_capacity:lanes_still_occupying")
            ledger_bindings = resolved.get("ledger", {}).get("bindings", {})
            run_id = str(identity.get("run_id"))
            if any(
                ledger_bindings.get(lane_id)
                != {"run_id": run_id, "route": "native_luna"}
                for lane_id in lane_ids
            ):
                raise ValueError("shared_capacity:settlement_binding_invalid")
        except Exception as exc:
            _issue(issues, str(exc) or "shared_capacity:settlement_unknown")
    report = {
        "status": "PASS" if not issues else "FAIL",
        "authority_state_sha256": authority_read.get("state_sha256"),
        "settled_lane_ids": sorted(lane_ids) if not issues else [],
    }
    return report, issues


def _evaluate_worker_start(identity: Mapping[str, Any], predecessor_value: Any, payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    stages: list[dict[str, Any]] = []
    predecessor = _validate_receipt(
        predecessor_value,
        identity,
        issues,
        allowed_stages={"capacity_admission"},
        allowed_actions={"spawn"},
    )
    value = _exact(
        payload,
        frozenset({"creations", "deliveries", "route_observations", "tool_events"}),
        "payload",
        issues,
    )
    specs = {
        str(row.get("logical_worker_id")): row
        for row in (predecessor.get("bindings", {}).get("task_specs", []) if isinstance(predecessor.get("bindings"), Mapping) else [])
        if isinstance(row, Mapping)
    }
    creations_value = value.get("creations")
    if not isinstance(creations_value, list):
        _issue(issues, "worker_start:creations_not_array")
        creations_value = []
    creations: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(creations_value):
        creation = _exact(
            raw,
            frozenset({"logical_worker_id", "worker_id", "session_id", "status", "fresh", "parent_thread_id"}),
            f"creations[{index}]",
            issues,
        )
        lane_id = creation.get("logical_worker_id")
        if lane_id in creations:
            _issue(issues, "worker_start:duplicate_creation:" + str(lane_id))
        creations[str(lane_id)] = dict(creation)
        if lane_id not in specs:
            _issue(issues, "worker_start:unexpected_creation:" + str(lane_id))
        if creation.get("status") != "created" or creation.get("fresh") is not True:
            _issue(issues, "worker_start:creation_not_fresh:" + str(lane_id))
        if creation.get("parent_thread_id") != identity.get("root_task_id"):
            _issue(issues, "worker_start:creation_parent_mismatch:" + str(lane_id))
        if not _identifier(creation.get("session_id")):
            _issue(issues, "worker_start:session_invalid:" + str(lane_id))
    if set(creations) != set(specs):
        _issue(issues, "worker_start:creation_set_mismatch")

    deliveries_value = value.get("deliveries")
    if not isinstance(deliveries_value, list):
        _issue(issues, "worker_start:deliveries_not_array")
        deliveries_value = []
    deliveries: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(deliveries_value):
        report = route_policy.evaluate_route_policy(raw)
        payload_value = raw.get("payload", {}) if isinstance(raw, Mapping) else {}
        lane_id = payload_value.get("expected_lane_id")
        if lane_id in deliveries:
            _issue(issues, "worker_start:duplicate_delivery:" + str(lane_id))
        deliveries[str(lane_id)] = dict(report)
        creation = creations.get(str(lane_id), {})
        spec = specs.get(str(lane_id), {})
        if report.get("status") != "PASS" or report.get("decision") != "ACCEPTED":
            _issue(issues, "worker_start:delivery_refused:" + str(lane_id))
        if payload_value.get("expected_task_spec_sha256") != spec.get("task_spec_sha256"):
            _issue(issues, "worker_start:delivery_task_mismatch:" + str(lane_id))
        if payload_value.get("expected_native_worker_id") != creation.get("worker_id"):
            _issue(issues, "worker_start:delivery_worker_mismatch:" + str(lane_id))
        if payload_value.get("expected_session_id") != creation.get("session_id"):
            _issue(issues, "worker_start:delivery_session_mismatch:" + str(lane_id))
    if set(deliveries) != set(specs):
        _issue(issues, "worker_start:delivery_set_mismatch")

    route_values = value.get("route_observations")
    if not isinstance(route_values, list):
        _issue(issues, "worker_start:route_observations_not_array")
        route_values = []
    routed: set[str] = set()
    route_digests: dict[str, str] = {}
    route_issues: list[str] = []
    for index, raw in enumerate(route_values):
        route_row = _exact(
            raw,
            frozenset({"logical_worker_id", "worker_id", "session_id", "observation"}),
            f"route_observations[{index}]",
            route_issues,
        )
        lane_id = str(route_row.get("logical_worker_id"))
        if lane_id in routed or lane_id not in specs:
            _issue(route_issues, "worker_start:route_lane_invalid_or_duplicate:" + lane_id)
        routed.add(lane_id)
        creation = creations.get(lane_id, {})
        spec = specs.get(lane_id, {})
        if (
            route_row.get("worker_id") != creation.get("worker_id")
            or route_row.get("session_id") != creation.get("session_id")
        ):
            _issue(route_issues, "worker_start:route_creation_mismatch:" + lane_id)
        route_report = efficiency_governor.routing_verify.validate_session_runtime_observation(
            route_row.get("observation")
        )
        if not route_report.get("valid"):
            _issue(route_issues, "worker_start:route_observation_invalid:" + lane_id)
            continue
        route_digests[lane_id] = str(route_report.get("digest"))
        observation = route_report.get("normalized", {})
        route = observation.get("route") if isinstance(observation.get("route"), Mapping) else {}
        if route.get("session_id") != creation.get("session_id"):
            _issue(route_issues, "worker_start:route_session_mismatch:" + lane_id)
        if route.get("model") != spec.get("model"):
            _issue(route_issues, "worker_start:route_model_mismatch:" + lane_id)
        if route.get("effort") != spec.get("effort"):
            _issue(route_issues, "worker_start:route_effort_mismatch:" + lane_id)
        if route.get("context_policy") != "none" or route.get("inherited_history") is not False:
            _issue(route_issues, "worker_start:route_context_mismatch:" + lane_id)
        delivery_result = deliveries.get(lane_id, {}).get("result", {})
        expected_pre_work_receipt = route_policy.task_spec_pre_work_receipt(
            logical_lane_id=lane_id,
            task_spec_sha256=str(spec.get("task_spec_sha256")),
        )
        terminal_is_delivery_ack = bool(
            observation.get("terminal_schema")
            == route_policy.TASK_SPEC_ACK_SCHEMA
            and observation.get("terminal_json_sha256")
            == delivery_result.get("ack_sha256")
        )
        terminal_is_pre_work_receipt = bool(
            observation.get("terminal_schema")
            == route_policy.TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA
            and observation.get("terminal_json_sha256")
            == route_policy.canonical_sha256(expected_pre_work_receipt)
        )
        if not (terminal_is_delivery_ack or terminal_is_pre_work_receipt):
            _issue(route_issues, "worker_start:ack_not_runtime_bound:" + lane_id)
        usage = observation.get("usage") if isinstance(observation.get("usage"), Mapping) else {}
        if usage.get("status") != "observed" or usage.get("tool_calls") != 0:
            _issue(route_issues, "worker_start:work_observed_before_authority:" + lane_id)
    if routed != set(specs):
        _issue(route_issues, "worker_start:route_observation_set_mismatch")
    issues.extend(route_issues)
    stages.append(
        _stage(
            "created_worker_routing",
            "PASS" if not route_issues else "FAIL",
            {"routed_lanes": sorted(routed)},
            route_issues,
        )
    )
    tool_values = value.get("tool_events")
    if not isinstance(tool_values, list):
        _issue(issues, "worker_start:tool_events_not_array")
        tool_values = []
    for index, raw in enumerate(tool_values):
        _tool_event(raw, f"tool_events[{index}]", issues)
    if tool_values:
        _issue(issues, "worker_start:substantive_work_before_authority")
    delivery_issues = [item for item in issues if item not in route_issues]
    stages.append(
        _stage(
            "spawn_and_task_spec_delivery",
            "PASS" if not delivery_issues else "FAIL",
            {},
            delivery_issues,
        )
    )
    if issues:
        return _report(
            operation="worker_start",
            identity=identity,
            status="BLOCKED",
            disposition="WORK_AUTHORITY_REFUSED",
            issues=issues,
            stages=stages,
        )
    lane_bindings = [
        {
            "logical_worker_id": lane_id,
            "worker_id": creations[lane_id]["worker_id"],
            "session_id": creations[lane_id]["session_id"],
            "task_spec_sha256": specs[lane_id]["task_spec_sha256"],
            "allowed_tools": list(specs[lane_id].get("allowed_tools", [])),
            "delivery_ack_sha256": deliveries[lane_id].get("result", {}).get("ack_sha256"),
            "route_observation_sha256": route_digests.get(lane_id),
        }
        for lane_id in sorted(specs)
    ]
    bindings = dict(predecessor.get("bindings", {}))
    bindings["lane_bindings"] = lane_bindings
    bindings["all_lane_bindings"] = [
        *[
            dict(row)
            for row in bindings.get("all_lane_bindings", [])
            if isinstance(row, Mapping)
        ],
        *lane_bindings,
    ]
    receipt = _receipt(
        stage="worker_start",
        status="AUTHORIZED",
        identity=identity,
        plan={"plan_id": predecessor.get("plan_id"), "revision": predecessor.get("plan_revision")},
        plan_sha256=str(predecessor.get("plan_sha256")),
        predecessor=predecessor,
        next_action="continue",
        bindings=bindings,
    )
    return _report(
        operation="worker_start",
        identity=identity,
        status="PASS",
        disposition="WORK_AUTHORIZED",
        issues=[],
        stages=stages,
        receipt=receipt,
    )


def _progress_continuity(predecessor: Mapping[str, Any], program: Any,
                         report: Mapping[str, Any], *, source_valid: bool = True) -> tuple[dict, list[str]]:
    """Bind each fresh complete prefix to the admitted wave and retain its bytes.

    The standalone progress evaluator validates a submitted prefix. Admission
    additionally requires new evidence for every lane receiving another turn.
    Previous waves remain retained under their capacity-wave identity.
    """
    bindings = predecessor.get("bindings", {})
    prefixes = deepcopy(bindings.get("progress_prefixes", {})) if isinstance(bindings, Mapping) else {}
    issues: list[str] = []
    try:
        if type(prefixes) is not dict or type(program) is not dict:
            raise ValueError("shape")
        if _canonical(program.get("completion_reserve")) != _canonical(bindings.get("completion_reserve")):
            raise ValueError("reserve_mismatch")
        wave = bindings["capacity_wave_index"]
        if type(wave) is not int or wave <= 0:
            raise ValueError("wave_invalid")
        lanes = bindings["lane_bindings"]
        specs = bindings["task_specs"]
        expected = {row["logical_worker_id"]: (row["worker_id"], row["task_spec_sha256"]) for row in lanes}
        if (len(expected) != len(lanes) or not expected
                or set(expected) != set(bindings["current_wave_logical_lane_ids"])
                or {row["logical_worker_id"]: row["task_spec_sha256"] for row in specs}
                   != {key: row[1] for key, row in expected.items()}):
            raise ValueError("admitted_membership_invalid")
        submitted = program["task_specs"]
        if (type(submitted) is not list or len(submitted) != len(expected)
                or {row["logical_worker_id"]: (row["worker_id"], adaptive_contracts.validate_task_spec(row["task_spec"]).get("digest"))
                    for row in submitted} != expected):
            raise ValueError("admitted_task_mismatch")
        prior = prefixes.get(str(wave))
        if prior is None:
            if predecessor.get("stage") == "progress":
                raise ValueError("prior_prefix_missing")
            previous = []
        else:
            if (type(prior) is not dict or set(prior) != {"progress_id", "events"}
                    or prior["progress_id"] != program["progress_id"] or type(prior["events"]) is not list):
                raise ValueError("prior_prefix_invalid")
            previous = prior["events"]
        events = program["events"]
        if (type(events) is not list or len(events) <= len(previous)
                or _canonical(events[:len(previous)]) != _canonical(previous)):
            raise ValueError("prefix_replayed_or_changed")
        if {event["logical_worker_id"] for event in events[len(previous):]} != set(expected):
            raise ValueError("fresh_lane_evidence_missing")
        if report.get("status") == "PASS" and source_valid:
            prefixes[str(wave)] = {"progress_id": program["progress_id"], "events": deepcopy(events)}
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
        reason = str(error) if type(error) is ValueError else "shape"
        # Only fixed local reason codes, never malformed caller values.
        allowed = {"shape", "reserve_mismatch", "wave_invalid", "admitted_membership_invalid", "admitted_task_mismatch",
                   "prior_prefix_missing", "prior_prefix_invalid", "prefix_replayed_or_changed", "fresh_lane_evidence_missing"}
        issues.append("progress:" + (reason if reason in allowed else "shape"))
    return prefixes, issues


def _evaluate_progress(identity: Mapping[str, Any], predecessor_value: Any, payload: Any, *, now: datetime | None = None) -> dict[str, Any]:
    issues: list[str] = []
    stages: list[dict[str, Any]] = []
    predecessor = _validate_receipt(
        predecessor_value,
        identity,
        issues,
        allowed_stages={"worker_start", "progress"},
        allowed_actions={"continue"},
    )
    checkpoint_profile = predecessor.get("bindings", {}).get("worker_checkpoint_profile") == WORKER_CHECKPOINT_PROFILE
    value = _exact(
        payload,
        frozenset(
            {
                "progress_program",
                "budget_program",
                "tool_events",
                "ingress_observation",
            }
            | ({"checkpoint_sources"} if checkpoint_profile else set())
        ),
        "payload",
        issues,
    )
    progress_report = efficiency_governor.evaluate_wave_progress(value.get("progress_program"))
    progress_issues: list[str] = []
    source_issues: list[str] = []
    checkpoint_bindings: dict[str, Any] = {}
    if checkpoint_profile:
        try:
            source = value.get("checkpoint_sources")
            if type(source) is not dict or set(source) != {"coordinator", "workers"}:
                raise ValueError("invalid checkpoint source bundle")
            progress = _load("orch_dork_qualification_progress")
            ingress = progress.build_checkpoint_ingress_observation(identity, source["coordinator"], source["workers"])
            reports = [source["workers"]["evidence"]["workers"][lane]["progress_report"] for lane in ("spec", "standards")]
            expected = progress.build_checkpoint_progress_program(predecessor, reports)
            if (_canonical(expected) != _canonical(value.get("progress_program"))
                    or _canonical(ingress) != _canonical(value.get("ingress_observation"))
                    or value.get("tool_events") != []):
                raise ValueError("checkpoint prefix differs")
            checkpoint_bindings["checkpoint_sources_sha256"] = _sha(source)
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
            source_issues.append("progress:checkpoint_sources_invalid")
        stages.append(_stage("worker_checkpoints", "FAIL" if source_issues else "PASS",
                             checkpoint_bindings, source_issues))
        progress_issues.extend(source_issues)
    if progress_report.get("status") != "PASS":
        _issue(progress_issues, "progress:contract_invalid")
    progress_issues.extend("progress:" + str(item) for item in progress_report.get("issues", []))
    progress_prefixes, continuity_issues = _progress_continuity(predecessor, value.get("progress_program"), progress_report,
                                                            source_valid=not source_issues)
    progress_issues.extend(continuity_issues)
    stages.append(_stage("typed_progress", "PASS" if not progress_issues else "FAIL", progress_report, progress_issues))

    effective_budget = value.get("budget_program")
    budget_issues: list[str] = []
    if checkpoint_profile and "checkpoint_accounting_policy" in predecessor.get("bindings", {}):
        try:
            progress = _load("orch_dork_qualification_progress")
            accounting = _load("orch_dork_qualification_budget")
            source = value["checkpoint_sources"]
            if _canonical(effective_budget) != _canonical(progress.build_checkpoint_budget_program(predecessor,source)):
                raise ValueError("different checkpoint budget template")
            effective_budget, observed_budget = accounting.build_checkpoint_admission_budget(predecessor,source,now=now)
            checkpoint_bindings["checkpoint_budget_observation"] = observed_budget
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
            _issue(budget_issues, "progress:budget_accounting_unobserved")
    budget_report = efficiency_governor.evaluate_budget_program(effective_budget)
    if budget_report.get("plan_sha256") != predecessor.get("plan_sha256"):
        _issue(budget_issues, "progress:budget_plan_mismatch")
    if budget_report.get("status") != "PASS":
        _issue(budget_issues, "progress:budget_" + str(budget_report.get("status")).lower())
    budget_issues.extend("progress:budget:" + str(item) for item in budget_report.get("issues", []))
    stages.append(_stage("native_budget", "PASS" if not budget_issues else "FAIL", budget_report, budget_issues))

    lane_bindings = {
        str(row.get("logical_worker_id")): row
        for row in (predecessor.get("bindings", {}).get("lane_bindings", []) if isinstance(predecessor.get("bindings"), Mapping) else [])
        if isinstance(row, Mapping)
    }
    tool_issues: list[str] = []
    previous_tool_seq = (
        predecessor.get("bindings", {}).get("last_tool_seq_by_lane", {})
        if isinstance(predecessor.get("bindings"), Mapping)
        else {}
    )
    if not isinstance(previous_tool_seq, Mapping):
        previous_tool_seq = {}
        _issue(tool_issues, "progress:prior_tool_sequence_invalid")
    latest_tool_seq = {
        str(key): value for key, value in previous_tool_seq.items()
    }
    new_tool_events = 0
    tools = value.get("tool_events")
    if not isinstance(tools, list):
        _issue(tool_issues, "progress:tool_events_not_array")
        tools = []
    for index, raw in enumerate(tools):
        event = _tool_event(raw, f"tool_events[{index}]", tool_issues)
        lane_id = str(event.get("logical_worker_id"))
        binding = lane_bindings.get(lane_id)
        if binding is None:
            _issue(tool_issues, "progress:tool_unknown_lane:" + lane_id)
            continue
        if event.get("worker_id") != binding.get("worker_id") or event.get("session_id") != binding.get("session_id"):
            _issue(tool_issues, "progress:tool_identity_mismatch:" + lane_id)
        if event.get("tool") not in binding.get("allowed_tools", []):
            _issue(tool_issues, "progress:tool_not_allowed:" + lane_id + ":" + str(event.get("tool")))
        prior_seq = latest_tool_seq.get(lane_id, 0)
        if type(prior_seq) is not int or event.get("seq", 0) <= prior_seq:
            _issue(tool_issues, "progress:tool_sequence_replayed:" + lane_id)
        else:
            latest_tool_seq[lane_id] = event.get("seq")
            new_tool_events += 1
    stages.append(_stage("allowed_tools", "PASS" if not tool_issues else "FAIL", {}, tool_issues))

    ingress_issues: list[str] = []
    ingress = _exact(
        value.get("ingress_observation"),
        frozenset(
            {
                "status",
                "sol_ingress_tokens",
                "total_tokens",
                "tool_calls",
                "source_pointer",
            }
        ),
        "ingress_observation",
        ingress_issues,
    )
    if ingress.get("status") == "observed":
        for field in ("sol_ingress_tokens", "total_tokens", "tool_calls"):
            if type(ingress.get(field)) is not int or ingress.get(field, -1) < 0:
                _issue(ingress_issues, "ingress_observation:" + field + "_invalid")
        if (
            type(ingress.get("sol_ingress_tokens")) is int
            and type(ingress.get("total_tokens")) is int
            and ingress["sol_ingress_tokens"] > ingress["total_tokens"]
        ):
            _issue(ingress_issues, "ingress_observation:arithmetic_invalid")
    elif ingress.get("status") == "unknown":
        if any(ingress.get(field) is not None for field in ("sol_ingress_tokens", "total_tokens", "tool_calls")):
            _issue(ingress_issues, "ingress_observation:unknown_has_values")
        _issue(ingress_issues, "ingress_observation:unknown")
    else:
        _issue(ingress_issues, "ingress_observation:status_invalid")
    if not _text(ingress.get("source_pointer")):
        _issue(ingress_issues, "ingress_observation:source_pointer_invalid")
    limits = (
        predecessor.get("bindings", {}).get("attempt_limits", {})
        if isinstance(predecessor.get("bindings"), Mapping)
        else {}
    )
    if ingress.get("status") == "observed":
        comparisons = (
            ("sol_ingress_tokens", "max_sol_ingress_tokens"),
            ("total_tokens", "max_total_tokens"),
            ("tool_calls", "max_tool_calls"),
        )
        for observed, maximum in comparisons:
            if (
                type(ingress.get(observed)) is int
                and type(limits.get(maximum)) is int
                and ingress[observed] > limits[maximum]
            ):
                _issue(ingress_issues, "ingress_observation:limit_exceeded:" + observed)
        previous_ingress = (
            predecessor.get("bindings", {}).get("latest_ingress", {})
            if isinstance(predecessor.get("bindings"), Mapping)
            else {}
        )
        if isinstance(previous_ingress, Mapping):
            for field in ("sol_ingress_tokens", "total_tokens", "tool_calls"):
                previous_value = previous_ingress.get(field)
                current_value = ingress.get(field)
                if type(previous_value) is int and (
                    type(current_value) is not int or current_value < previous_value
                ):
                    _issue(ingress_issues, "ingress_observation:regressed:" + field)
            prior_calls = previous_ingress.get("tool_calls", 0)
            current_calls = ingress.get("tool_calls")
            if type(prior_calls) is int and (
                type(current_calls) is not int
                or current_calls < prior_calls + new_tool_events
            ):
                _issue(ingress_issues, "ingress_observation:new_tools_not_accounted")
    stages.append(
        _stage(
            "native_ingress",
            "PASS" if not ingress_issues else "FAIL",
            ingress,
            ingress_issues,
        )
    )

    structural = [item for item in issues if item.startswith(("predecessor_receipt:", "payload:"))]
    stop_reasons = sorted(
        set(progress_issues + budget_issues + tool_issues + ingress_issues)
    )
    if structural:
        return _report(
            operation="progress",
            identity=identity,
            status="BLOCKED",
            disposition="PROGRESS_REFUSED",
            issues=structural + stop_reasons,
            stages=stages,
        )
    stop_ids = list(progress_report.get("stop_required_worker_ids", []))
    if stop_ids:
        stop_reasons.append("progress:completion_reserve_reached")
    if stop_reasons:
        receipt = _receipt(
            stage="stopped",
            status="STOP_REQUIRED",
            identity=identity,
            plan={"plan_id": predecessor.get("plan_id"), "revision": predecessor.get("plan_revision")},
            plan_sha256=str(predecessor.get("plan_sha256")),
            predecessor=predecessor,
            next_action="stop",
            bindings={
                **dict(predecessor.get("bindings", {})),
                "stop_reasons": sorted(set(stop_reasons)),
                "progress_report_sha256": progress_report.get("report_sha256"),
                "budget_receipt_sha256": budget_report.get("receipt_sha256"),
                "ingress_observation_sha256": _sha(dict(ingress)),
                "latest_ingress": dict(ingress),
                "last_tool_seq_by_lane": latest_tool_seq,
                "progress_prefixes": progress_prefixes,
                **checkpoint_bindings,
            },
        )
        return _report(
            operation="progress",
            identity=identity,
            status="BLOCKED",
            disposition="STOP_REQUIRED",
            issues=stop_reasons,
            stages=stages,
            receipt=receipt,
        )
    receipt = _receipt(
        stage="progress",
        status="AUTHORIZED",
        identity=identity,
        plan={"plan_id": predecessor.get("plan_id"), "revision": predecessor.get("plan_revision")},
        plan_sha256=str(predecessor.get("plan_sha256")),
        predecessor=predecessor,
        next_action="continue",
        bindings={
            **dict(predecessor.get("bindings", {})),
            "progress_report_sha256": progress_report.get("report_sha256"),
            "budget_receipt_sha256": budget_report.get("receipt_sha256"),
            "ingress_observation_sha256": _sha(dict(ingress)),
            "latest_ingress": dict(ingress),
            "last_tool_seq_by_lane": latest_tool_seq,
            "progress_prefixes": progress_prefixes,
            **checkpoint_bindings,
        },
    )
    return _report(
        operation="progress",
        identity=identity,
        status="PASS",
        disposition="CONTINUE",
        issues=[],
        stages=stages,
        receipt=receipt,
    )


def _evaluate_recovery(
    identity: Mapping[str, Any],
    predecessor_value: Any,
    payload: Any,
    *,
    source_roots: Mapping[str, str | Path] | None,
    now: datetime | None,
) -> dict[str, Any]:
    issues: list[str] = []
    predecessor = _validate_receipt(
        predecessor_value,
        identity,
        issues,
        allowed_stages={"capacity_settlement"},
        allowed_actions={"recovery"},
    )
    value = _exact(payload, frozenset({"successor_pre_spawn"}), "payload", issues)
    successor = value.get("successor_pre_spawn")
    successor_value = successor if isinstance(successor, Mapping) else {}
    successor_identity = successor_value.get("identity") if isinstance(successor_value.get("identity"), Mapping) else {}
    successor_plan = (
        successor_value.get("payload", {}).get("logical_plan", {})
        if isinstance(successor_value.get("payload"), Mapping)
        else {}
    )
    if successor_value.get("schema") != PROGRAM_SCHEMA or successor_value.get("operation") != "pre_spawn":
        _issue(issues, "recovery:successor_program_invalid")
    if successor_identity.get("attempt_id") == identity.get("attempt_id") or not _identifier(successor_identity.get("attempt_id")):
        _issue(issues, "recovery:attempt_not_fresh")
    if successor_identity.get("run_id") != identity.get("run_id") or successor_identity.get("root_task_id") != identity.get("root_task_id"):
        _issue(issues, "recovery:run_or_root_changed")
    if successor_plan.get("revision") != predecessor.get("plan_revision", 0) + 1:
        _issue(issues, "recovery:successor_revision_invalid")
    if successor_plan.get("predecessor_plan_sha256") != predecessor.get("plan_sha256"):
        _issue(issues, "recovery:predecessor_plan_mismatch")
    if issues:
        return _report(
            operation="recovery",
            identity=identity,
            status="BLOCKED",
            disposition="FRESH_ADMISSION_REQUIRED",
            issues=issues,
            stages=[],
        )
    report = evaluate_governed_attempt(successor, source_roots=source_roots, now=now)
    if report.get("disposition") != "SHARED_CAPACITY_ADMISSION_REQUIRED":
        recovery_issues = ["recovery:fresh_admission_failed"] + [
            "recovery:" + str(item) for item in report.get("issues", [])
        ]
        return _report(
            operation="recovery",
            identity=identity,
            status="BLOCKED",
            disposition="FRESH_ADMISSION_REQUIRED",
            issues=recovery_issues,
            stages=list(report.get("stages", [])),
        )
    result = dict(report)
    result["operation"] = "recovery"
    result["disposition"] = "RECOVERY_SHARED_CAPACITY_ADMISSION_REQUIRED"
    result["final_verdict"] = "RECOVERY_SHARED_CAPACITY_ADMISSION_REQUIRED"
    result["spawn_authorized"] = False
    return result


def _terminal_worker_evidence(identity: Mapping[str, Any], predecessor: Mapping[str, Any],
                              wave_program: Any, contract_values: Any) -> dict[str, Any]:
    """Check the wave and typed contracts against one already-validated receipt.

    This pure helper grants no final authority. Legacy and native final gates
    must independently validate their own predecessor, observer and remaining
    terminal checks before accepting its evidence.
    """
    stages: list[dict[str, Any]] = []
    wave = wave_program if isinstance(wave_program, Mapping) else {}
    wave_report = efficiency_governor.run_wave_program(wave)
    wave_issues: list[str] = []
    if wave.get("schema") != efficiency_governor.WAVE_PROGRAM_SCHEMA_V3:
        _issue(wave_issues, "terminal:wave_schema_invalid")
    if wave_report.get("status") != "DRAINED":
        _issue(wave_issues, "terminal:wave_not_cleanly_drained")
    if wave_report.get("plan_sha256") != predecessor.get("plan_sha256"):
        _issue(wave_issues, "terminal:wave_plan_mismatch")
    if wave_report.get("failed_worker_ids"):
        _issue(wave_issues, "terminal:failed_workers_present")
    for index, observation_row in enumerate(wave.get("observations", [])):
        routing_program = (
            observation_row.get("routing_program", {})
            if isinstance(observation_row, Mapping)
            else {}
        )
        if routing_program.get("plan_root_model") != identity.get("root_model"):
            _issue(wave_issues, f"terminal:wave_root_model_mismatch:{index}")
        if routing_program.get("plan_root_effort") != identity.get("root_effort"):
            _issue(wave_issues, f"terminal:wave_root_effort_mismatch:{index}")
    wave_issues.extend("terminal:wave:" + str(item) for item in wave_report.get("issues", []))

    expected_specs = {
        str(row.get("logical_worker_id")): row
        for row in (
            predecessor.get("bindings", {}).get("task_specs", [])
            if isinstance(predecessor.get("bindings"), Mapping)
            else []
        )
        if isinstance(row, Mapping)
    }
    reconciled = {
        str(row.get("logical_worker_id")): row
        for row in wave_report.get("reconciliation", [])
        if isinstance(row, Mapping)
    }
    bindings = predecessor.get("bindings", {})
    lane_rows = bindings.get("lane_bindings", [])
    lanes = {str(row.get("logical_worker_id")): row for row in lane_rows if isinstance(row, Mapping)}
    task_rows = bindings.get("task_specs", [])
    if (not expected_specs or len(expected_specs) != len(task_rows)
            or len(lanes) != len(lane_rows) or set(lanes) != set(expected_specs)
            or len(reconciled) != len(wave_report.get("reconciliation", []))
            or set(reconciled) != set(expected_specs)):
        _issue(wave_issues, "terminal:wave_admitted_membership_mismatch")
    for lane_id, lane in lanes.items():
        if (reconciled.get(lane_id, {}).get("worker_id") != lane.get("worker_id")
                or lane.get("task_spec_sha256") != expected_specs.get(lane_id, {}).get("task_spec_sha256")):
            _issue(wave_issues, "terminal:wave_worker_mismatch:" + lane_id)
    stages.append(_stage("wave_v3_terminal", "PASS" if not wave_issues else "FAIL", wave_report, wave_issues))
    contract_issues: list[str] = []
    if not isinstance(contract_values, list):
        _issue(contract_issues, "terminal:contracts_not_array")
        contract_values = []
    seen: set[str] = set()
    verification_digests: dict[str, str] = {}
    ledger_digests: dict[str, str] = {}
    for index, raw in enumerate(contract_values):
        row = _exact(
            raw,
            frozenset(
                {
                    "logical_worker_id",
                    "task_spec",
                    "handoff_receipt",
                    "verification_receipt",
                    "claim_ledger",
                }
            ),
            f"terminal_contracts[{index}]",
            contract_issues,
        )
        lane_id = str(row.get("logical_worker_id"))
        if lane_id in seen or lane_id not in expected_specs:
            _issue(contract_issues, "terminal:contract_lane_invalid_or_duplicate:" + lane_id)
        seen.add(lane_id)
        task_report = adaptive_contracts.validate_task_spec(row.get("task_spec"))
        if not task_report.get("valid"):
            _issue(contract_issues, "terminal:task_spec_invalid:" + lane_id)
            continue
        if task_report.get("digest") != expected_specs.get(lane_id, {}).get("task_spec_sha256"):
            _issue(contract_issues, "terminal:task_spec_mismatch:" + lane_id)
        handoff_report = adaptive_contracts.validate_handoff_receipt(
            row.get("handoff_receipt"), task_spec=row.get("task_spec")
        )
        if not handoff_report.get("valid") or handoff_report.get("normalized", {}).get("disposition") != "complete":
            _issue(contract_issues, "terminal:handoff_invalid:" + lane_id)
        reconciled_handoff = reconciled.get(lane_id, {}).get("handoff_receipt")
        if (
            not isinstance(reconciled_handoff, Mapping)
            or reconciled_handoff.get("handoff_sha256") != handoff_report.get("digest")
        ):
            _issue(contract_issues, "terminal:handoff_not_runtime_bound:" + lane_id)
        verification_report = adaptive_contracts.validate_verification_receipt(
            row.get("verification_receipt"),
            task_spec=row.get("task_spec"),
            handoff_receipt=row.get("handoff_receipt"),
        )
        if not verification_report.get("valid") or verification_report.get("normalized", {}).get("pass") is not True:
            _issue(contract_issues, "terminal:verification_invalid:" + lane_id)
        else:
            verification_digests[lane_id] = str(verification_report.get("digest"))
        verification = verification_report.get("normalized")
        if not isinstance(verification, Mapping) or verification.get("implementer_identity") != lanes.get(lane_id, {}).get("worker_id"):
            _issue(contract_issues, "terminal:verification_implementer_mismatch:" + lane_id)
        ledger_report = adaptive_contracts.validate_claim_ledger(
            row.get("claim_ledger"), task_spec=row.get("task_spec")
        )
        if not ledger_report.get("valid"):
            _issue(contract_issues, "terminal:claim_ledger_invalid:" + lane_id)
        else:
            ledger_digests[lane_id] = str(ledger_report.get("digest"))
            # A ledger may retain a subset of accepted handoff claims. It may
            # not introduce a different claim or an unreviewed artifact.
            ledger = ledger_report["normalized"]
            handoff = handoff_report.get("normalized")
            handoff = handoff if isinstance(handoff, Mapping) else {}
            claims = {_canonical(item) for item in handoff.get("claims", [])}
            artifacts = {_canonical(item) for item in handoff.get("artifact_refs", [])}
            if (any(_canonical(item) not in claims for item in ledger["claims"])
                    or any(_canonical(item) not in artifacts for item in ledger["artifacts"])):
                _issue(contract_issues, "terminal:claim_ledger_handoff_mismatch:" + lane_id)
    if seen != set(expected_specs):
        _issue(contract_issues, "terminal:contract_worker_set_mismatch")
    stages.append(
        _stage(
            "typed_terminal_contracts",
            "PASS" if not contract_issues else "FAIL",
            {"verification_digests": verification_digests, "ledger_digests": ledger_digests},
            contract_issues,
        )
    )

    return deepcopy({"wave_report": wave_report, "expected_specs": expected_specs,
        "verification_digests": verification_digests, "ledger_digests": ledger_digests,
        "stages": stages, "issues": wave_issues + contract_issues})


def _evaluate_terminal(
    identity: Mapping[str, Any],
    predecessor_value: Any,
    payload: Any,
    *,
    observer: Any,
    capacity_authority: Any,
) -> dict[str, Any]:
    issues: list[str] = []
    stages: list[dict[str, Any]] = []
    predecessor = _validate_receipt(
        predecessor_value,
        identity,
        issues,
        allowed_stages={"capacity_settlement"},
        allowed_actions={"terminal"},
    )
    bindings = predecessor.get("bindings")
    if isinstance(bindings, Mapping) and ("quality_phase" in bindings or "worker_checkpoint_profile" in bindings):
        _issue(issues, "terminal:quality_review_pending")
        return _report(operation="terminal", identity=identity, status="BLOCKED",
                       disposition="TERMINAL_REFUSED", issues=issues, stages=[])
    value = _exact(
        payload,
        frozenset(
            {
                "wave_program",
                "terminal_contracts",
                "observer_manifest",
                "trace",
                "coordinator_capsule",
                "dogfood",
            }
        ),
        "payload",
        issues,
    )

    worker_evidence = _terminal_worker_evidence(identity, predecessor, value.get("wave_program"), value.get("terminal_contracts"))
    wave_report = worker_evidence["wave_report"]
    expected_specs = worker_evidence["expected_specs"]
    verification_digests = worker_evidence["verification_digests"]
    ledger_digests = worker_evidence["ledger_digests"]
    stages.extend(worker_evidence["stages"])
    issues.extend(worker_evidence["issues"])

    observer_issues: list[str] = []
    manifest = value.get("observer_manifest")
    try:
        observation = observer(manifest)
    except Exception:
        observation = {}
        _issue(observer_issues, "terminal:observer_unavailable")
    if not isinstance(observation, Mapping):
        observation = {}
        _issue(observer_issues, "terminal:observer_invalid")
    if observation.get("schema") != attempt_observer.SCHEMA:
        _issue(observer_issues, "terminal:observer_schema_invalid")
    if observation.get("status") != "PASS" or observation.get("binding_status") != "BOUND":
        _issue(observer_issues, "terminal:observer_not_bound")
    if observation.get("attempt_id") != identity.get("attempt_id"):
        _issue(observer_issues, "terminal:observer_attempt_mismatch")
    graph = observation.get("graph") if isinstance(observation.get("graph"), Mapping) else {}
    root = graph.get("root") if isinstance(graph.get("root"), Mapping) else {}
    if root.get("thread_id") != identity.get("root_task_id"):
        _issue(observer_issues, "terminal:observer_root_mismatch")
    observed_children = {
        (str(row.get("lane_id")), str(row.get("thread_id")))
        for row in graph.get("children", [])
        if isinstance(row, Mapping)
    }
    expected_children = {
        (str(row.get("logical_worker_id")), str(row.get("worker_id")))
        for row in (
            predecessor.get("bindings", {}).get("lane_bindings", [])
            if isinstance(predecessor.get("bindings"), Mapping)
            else []
        )
        if isinstance(row, Mapping)
    }
    if observed_children != expected_children:
        _issue(observer_issues, "terminal:observer_membership_mismatch")
    allowed_by_lane = {
        lane_id: set(row.get("allowed_tools", []))
        for lane_id, row in expected_specs.items()
    }
    for child in graph.get("children", []):
        if not isinstance(child, Mapping):
            continue
        lane_id = str(child.get("lane_id"))
        actions = child.get("actions") if isinstance(child.get("actions"), Mapping) else {}
        items = actions.get("items") if isinstance(actions.get("items"), list) else None
        if items is None or actions.get("count") != len(items):
            _issue(observer_issues, "terminal:observer_actions_unknown:" + lane_id)
            continue
        for action in items:
            name = action.get("name") if isinstance(action, Mapping) else None
            if name not in allowed_by_lane.get(lane_id, set()):
                _issue(
                    observer_issues,
                    "terminal:observer_tool_not_allowed:"
                    + lane_id
                    + ":"
                    + str(name),
                )
    for field in ("usage", "timing", "custody"):
        fact = observation.get(field) if isinstance(observation.get(field), Mapping) else {}
        if fact.get("status") in {None, "unknown", "FAIL"}:
            _issue(observer_issues, "terminal:observer_" + field + "_unknown")
    observed_usage = observation.get("usage") if isinstance(observation.get("usage"), Mapping) else {}
    root_usage = observed_usage.get("root") if isinstance(observed_usage.get("root"), Mapping) else {}
    combined_usage = observed_usage.get("combined") if isinstance(observed_usage.get("combined"), Mapping) else {}
    observed_limits = (
        predecessor.get("bindings", {}).get("attempt_limits", {})
        if isinstance(predecessor.get("bindings"), Mapping)
        else {}
    )
    if type(root_usage.get("input_tokens")) is not int:
        _issue(observer_issues, "terminal:observer_sol_ingress_unknown")
    elif root_usage["input_tokens"] > observed_limits.get("max_sol_ingress_tokens", -1):
        _issue(observer_issues, "terminal:observer_sol_ingress_exceeded")
    if type(combined_usage.get("total_tokens")) is not int:
        _issue(observer_issues, "terminal:observer_total_tokens_unknown")
    elif combined_usage["total_tokens"] > observed_limits.get("max_total_tokens", -1):
        _issue(observer_issues, "terminal:observer_total_tokens_exceeded")
    all_actions = observation.get("actions") if isinstance(observation.get("actions"), Mapping) else {}
    action_items = all_actions.get("items") if isinstance(all_actions.get("items"), list) else None
    action_total = all_actions.get("count")
    if type(action_total) is not int or action_total < 0 or action_items is None or action_total != len(action_items):
        _issue(observer_issues, "terminal:observer_total_tool_calls_unknown")
        action_total = None
    if type(action_total) is int and action_total > observed_limits.get("max_tool_calls", -1):
        _issue(observer_issues, "terminal:observer_tool_calls_exceeded")
    previous_ingress = (
        predecessor.get("bindings", {}).get("latest_ingress", {})
        if isinstance(predecessor.get("bindings"), Mapping)
        else {}
    )
    terminal_values = {
        "sol_ingress_tokens": root_usage.get("input_tokens"),
        "total_tokens": combined_usage.get("total_tokens"),
        "tool_calls": action_total,
    }
    for field, terminal_value in terminal_values.items():
        previous_value = previous_ingress.get(field) if isinstance(previous_ingress, Mapping) else None
        if type(previous_value) is int and (
            type(terminal_value) is not int or terminal_value < previous_value
        ):
            _issue(observer_issues, "terminal:observer_ingress_regressed:" + field)
    final_ingress = {
        "status": "observed",
        **terminal_values,
        "source_pointer": "independent_attempt_observer:" + _sha(dict(observation)),
    }
    observation_issues = observation.get("issues")
    if not isinstance(observation_issues, list):
        _issue(observer_issues, "terminal:observer_issues_invalid")
        observation_issues = []
    observer_issues.extend("terminal:observer:" + str(item) for item in observation_issues)
    stages.append(
        _stage(
            "independent_attempt_observer",
            "PASS" if not observer_issues else "FAIL",
            observation,
            observer_issues,
        )
    )

    trace_report = run_trace.validate_run_trace(value.get("trace"))
    trace_issues: list[str] = []
    if trace_report.get("status") != "PASS":
        _issue(trace_issues, "terminal:trace_invalid")
    if trace_report.get("run_id") != identity.get("run_id"):
        _issue(trace_issues, "terminal:trace_run_mismatch")
    trace_value = value.get("trace") if isinstance(value.get("trace"), Mapping) else {}
    if trace_value.get("plan_revisions") != [
        {
            "revision": predecessor.get("plan_revision"),
            "plan_sha256": predecessor.get("plan_sha256"),
        }
    ]:
        _issue(trace_issues, "terminal:trace_plan_history_mismatch")
    traced_nodes = {
        str(row.get("node_id"))
        for row in trace_value.get("events", [])
        if isinstance(row, Mapping) and row.get("node_id") is not None
    }
    if not traced_nodes.issubset(set(expected_specs)):
        _issue(trace_issues, "terminal:trace_unknown_node")
    trace_issues.extend("terminal:trace:" + str(item) for item in trace_report.get("issues", []))
    stages.append(_stage("run_trace", "PASS" if not trace_issues else "FAIL", trace_report, trace_issues))

    capsule_report = coordinator_capsule.evaluate_coordinator_capsule(value.get("coordinator_capsule"))
    capsule_issues: list[str] = []
    capsule_value = capsule_report.get("capsule") if isinstance(capsule_report.get("capsule"), Mapping) else {}
    if capsule_report.get("status") != "PASS" or not _text(capsule_report.get("capsule_sha256")):
        _issue(capsule_issues, "terminal:capsule_invalid")
    if capsule_value.get("identity", {}).get("plan_sha256") != predecessor.get("plan_sha256"):
        _issue(capsule_issues, "terminal:capsule_plan_mismatch")
    if capsule_value.get("identity", {}).get("admission_sha256") != predecessor.get("bindings", {}).get("ticket_admission_sha256"):
        _issue(capsule_issues, "terminal:capsule_admission_mismatch")
    capsule_issues.extend("terminal:capsule:" + str(item) for item in capsule_report.get("issues", []))
    stages.append(_stage("coordinator_capsule", "PASS" if not capsule_issues else "FAIL", capsule_report, capsule_issues))

    dogfood_issues: list[str] = []
    dogfood = _exact(
        value.get("dogfood"),
        frozenset({"spine", "session_path", "analysis_seen", "label_mode"}),
        "dogfood",
        dogfood_issues,
    )
    session_path = dogfood.get("session_path")
    if not _text(session_path):
        _issue(dogfood_issues, "terminal:dogfood_session_invalid")
        spine_report = {}
    else:
        try:
            path = Path(str(session_path))
            if path.is_symlink() or not path.is_file():
                raise ValueError("session unavailable")
            spine_report = dogfood_recovery.verify_spine(dogfood.get("spine"), path)
        except Exception:
            spine_report = {}
            _issue(dogfood_issues, "terminal:dogfood_spine_unverifiable")
    spine = dogfood.get("spine") if isinstance(dogfood.get("spine"), Mapping) else {}
    if spine_report.get("verified") is not True:
        _issue(dogfood_issues, "terminal:dogfood_spine_invalid")
    if spine.get("run_key") != identity.get("run_id"):
        _issue(dogfood_issues, "terminal:dogfood_run_mismatch")
    if spine.get("source", {}).get("session_id") != identity.get("root_task_id"):
        _issue(dogfood_issues, "terminal:dogfood_root_mismatch")
    if not isinstance(dogfood.get("analysis_seen"), bool):
        _issue(dogfood_issues, "terminal:dogfood_analysis_seen_invalid")
    expected_label_mode = "non_blind" if dogfood.get("analysis_seen") is True else "blind_permitted"
    if dogfood.get("label_mode") != expected_label_mode:
        _issue(dogfood_issues, "terminal:dogfood_label_mode_invalid")
    stages.append(_stage("dogfood_spine", "PASS" if not dogfood_issues else "FAIL", spine_report, dogfood_issues))

    settlement_report, settlement_issues = _capacity_settlement_stage(
        identity, predecessor, capacity_authority
    )
    stages.append(
        _stage(
            "shared_capacity_settlement",
            "PASS" if not settlement_issues else "FAIL",
            settlement_report,
            settlement_issues,
        )
    )

    issues.extend(observer_issues)
    issues.extend(trace_issues)
    issues.extend(capsule_issues)
    issues.extend(dogfood_issues)
    issues.extend(settlement_issues)
    if issues:
        return _report(
            operation="terminal",
            identity=identity,
            status="BLOCKED",
            disposition="TERMINAL_REFUSED",
            issues=issues,
            stages=stages,
        )
    receipt = _receipt(
        stage="terminal",
        status="QUALIFIED",
        identity=identity,
        plan={"plan_id": predecessor.get("plan_id"), "revision": predecessor.get("plan_revision")},
        plan_sha256=str(predecessor.get("plan_sha256")),
        predecessor=predecessor,
        next_action=(
            "record_non_blind_dogfood_label"
            if dogfood.get("analysis_seen") is True
            else "record_dogfood_label"
        ),
        bindings={
            **dict(predecessor.get("bindings", {})),
            "wave_report_sha256": _sha(dict(wave_report)),
            "observer_report_sha256": _sha(dict(observation)),
            "latest_ingress": final_ingress,
            "trace_sha256": trace_report.get("trace_sha256"),
            "capsule_sha256": capsule_report.get("capsule_sha256"),
            "dogfood_spine_sha256": spine.get("spine_sha256"),
            "verification_digests": verification_digests,
            "claim_ledger_digests": ledger_digests,
        },
    )
    return _report(
        operation="terminal",
        identity=identity,
        status="PASS",
        disposition="TERMINALLY_QUALIFIED",
        issues=[],
        stages=stages,
        receipt=receipt,
    )


def evaluate_governed_attempt(
    program: Any,
    *,
    source_roots: Mapping[str, str | Path] | None = None,
    now: datetime | None = None,
    observer: Any = None,
    capacity_authority: Any = None,
) -> dict[str, Any]:
    """Evaluate one stage; only host-injected capacity admission mutates."""

    issues: list[str] = []
    value = _exact(program, _PROGRAM_FIELDS, "program", issues)
    identity = _validate_identity(value.get("identity"), issues)
    operation = value.get("operation")
    checkpoint_profile = value.get("schema") == CHECKPOINT_PROGRAM_SCHEMA
    if value.get("schema") != PROGRAM_SCHEMA and not (checkpoint_profile and operation == "pre_spawn"):
        _issue(issues, "program:schema_invalid")
    if operation not in OPERATIONS:
        _issue(issues, "program:operation_invalid")
    if operation == "pre_spawn" and value.get("predecessor_receipt") is not None:
        _issue(issues, "pre_spawn:predecessor_present")
    if issues:
        return _report(
            operation=str(operation) if isinstance(operation, str) else None,
            identity=identity,
            status="BLOCKED",
            disposition="PROGRAM_REFUSED",
            issues=issues,
            stages=[],
        )
    if operation == "pre_spawn":
        return _evaluate_pre_spawn(
            identity,
            value.get("payload"),
            source_roots=source_roots,
            now=now,
            require_worker_checkpoint=checkpoint_profile,
        )
    if operation == "capacity_admission":
        return _evaluate_capacity_admission(
            identity,
            value.get("predecessor_receipt"),
            value.get("payload"),
            capacity_authority=capacity_authority,
        )
    if operation == "capacity_settlement":
        return _evaluate_capacity_settlement(
            identity,
            value.get("predecessor_receipt"),
            value.get("payload"),
            capacity_authority=capacity_authority,
            observer_evaluation_time=now,
        )
    if operation == "worker_start":
        return _evaluate_worker_start(identity, value.get("predecessor_receipt"), value.get("payload"))
    if operation == "worker_results":
        return _evaluate_worker_results(identity, value.get("predecessor_receipt"), value.get("payload"))
    if operation == "result_aggregation":
        return _evaluate_result_aggregation(identity, value.get("predecessor_receipt"), value.get("payload"))
    if operation == "review_submission":
        return _evaluate_review_submission(identity, value.get("predecessor_receipt"), value.get("payload"))
    if operation == "semantic_review":
        return _evaluate_semantic_review(identity, value.get("predecessor_receipt"), value.get("payload"))
    if operation == "terminal_verification":
        return _evaluate_terminal_verification(identity, value.get("predecessor_receipt"), value.get("payload"))
    if operation == "cleanup":
        return _evaluate_verified_cleanup(identity, value.get("predecessor_receipt"), value.get("payload"))
    if operation == "failure_closure":
        from orch_dork_qualification_closure import evaluate_failure_closure
        return evaluate_failure_closure(identity, value.get("predecessor_receipt"), value.get("payload"), observer=observer)
    if operation == "final_qualification":
        from orch_dork_qualification_final import evaluate_final_qualification
        return evaluate_final_qualification(identity, value.get("predecessor_receipt"), value.get("payload"), observer=observer)
    if operation == "owner_disposition":
        from orch_dork_qualification_owner import evaluate_owner_disposition
        return evaluate_owner_disposition(identity, value.get("predecessor_receipt"), value.get("payload"), observer=observer)
    if operation == "progress":
        return _evaluate_progress(identity, value.get("predecessor_receipt"), value.get("payload"), now=now)
    if operation == "recovery":
        return _evaluate_recovery(
            identity,
            value.get("predecessor_receipt"),
            value.get("payload"),
            source_roots=source_roots,
            now=now,
        )
    return _evaluate_terminal(
        identity,
        value.get("predecessor_receipt"),
        value.get("payload"),
        observer=observer or attempt_observer.observe_attempt,
        capacity_authority=capacity_authority,
    )


__all__ = [
    "OPERATIONS",
    "PROGRAM_SCHEMA",
    "CHECKPOINT_PROGRAM_SCHEMA",
    "WORKER_CHECKPOINT_PROFILE",
    "RECEIPT_SCHEMA",
    "REPORT_SCHEMA",
    "build_admission_plan_projection",
    "build_capacity_admission_program",
    "build_capacity_settlement_program",
    "build_worker_results_program",
    "build_result_aggregation_program",
    "build_review_submission_program",
    "build_semantic_review_program",
    "build_terminal_verification_program",
    "build_verified_cleanup_program",
    "validate_verified_cleanup_report",
    "validate_semantic_review_transition",
    "worker_results_next_action",
    "post_batch_next_action",
    "validate_post_batch_report",
    "validate_worker_results_report",
    "validate_result_aggregation_report",
    "build_pre_spawn_program",
    "evaluate_governed_attempt",
]
