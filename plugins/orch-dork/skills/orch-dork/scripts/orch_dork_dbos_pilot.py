#!/usr/bin/env python3
"""Optional DBOS durability port for an already-frozen finite DAG.

DBOS owns durable workflow/step checkpoint mechanics in this pilot. Orch Dork
continues to own topology, semantic retries, fallbacks, replacements, budgets,
cancellation, evidence acceptance, and terminal qualification. The module has
no DBOS import at load time and supports a provider-free API fixture.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:  # pragma: no cover - isolated direct-file loading.
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault(name, module)
        spec.loader.exec_module(module)
        return module


contracts = _load_sibling("orch_dork_adaptive_contracts")
governor = _load_sibling("orch_dork_efficiency_governor")
hostile = _load_sibling("orch_dork_hostile_input")
PROFILE = hostile.PROFILE

PROGRAM_SCHEMA = "orch-dork/dbos-pilot-program/v1"
REPORT_SCHEMA = "orch-dork/dbos-pilot-report/v1"
START_REPORT_SCHEMA = "orch-dork/dbos-pilot-start-report/v1"
PILOT_VERSION = "dbos-durability-pilot/v1"

_PROGRAM_FIELDS = frozenset(
    {
        "schema",
        "pilot_id",
        "mode",
        "workflow_id",
        "logical_plan",
        "dispatch_order",
        "task_bindings",
        "storage",
        "recovery_policy",
    }
)
_TASK_BINDING_FIELDS = frozenset({"worker_id", "idempotency_key", "task_spec"})
_STORAGE_FIELDS = frozenset({"backend", "distributed"})
_RECOVERY_FIELDS = frozenset(
    {
        "owner",
        "semantic_retry_owner",
        "step_retries_allowed",
        "max_step_attempts",
        "max_recovery_attempts",
        "fallbacks",
        "replacements",
        "deterministic_workflow",
        "idempotent_steps_attested",
    }
)
_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hostile.canonicalize_bounded_json(raw, profile=PROFILE, batch=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _closed(value: Any, fields: frozenset[str], label: str, issues: list[str]) -> dict:
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


def _string_list(value: Any, label: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > PROFILE.max_array_items:
        _issue(issues, f"{label}:array_invalid")
        return []
    result = []
    for index, item in enumerate(value):
        if not _identifier(item):
            _issue(issues, f"{label}[{index}]:identifier_invalid")
        else:
            result.append(str(item))
    if len(result) != len(set(result)):
        _issue(issues, f"{label}:duplicate")
    return result


def _base_report(
    *,
    status: str,
    decision: str,
    issues: list[str],
    program_sha256: str | None,
    mode: str | None,
    plan_sha256: str | None = None,
    dispatch_order: list[str] | None = None,
    storage_backend: str | None = None,
    dependency_available: bool = False,
) -> dict[str, Any]:
    provider_free = mode == "provider_free_fixture"
    core = {
        "schema": REPORT_SCHEMA,
        "pilot_version": PILOT_VERSION,
        "status": status,
        "decision": decision,
        "issues": sorted(set(issues)),
        "program_sha256": program_sha256,
        "logical_plan_sha256": plan_sha256,
        "execution_profile": "finite_dag/v1" if plan_sha256 else None,
        "dispatch_order": list(dispatch_order or []),
        "storage_backend": storage_backend,
        "dependency_available": dependency_available,
        "dependency_required": False,
        "topology_authority": False,
        "semantic_retry_authority": False,
        "budget_authority": False,
        "completion_authority": False,
        "step_retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "provider_free": provider_free,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _sha(core)}


def _validate(program: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
    issues: list[str] = []
    try:
        program_sha256 = _sha(program)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return (
            _base_report(
                status="FAIL",
                decision="CONFIGURATION_REJECTED",
                issues=["program:hostile_or_noncanonical"],
                program_sha256=None,
                mode=None,
            ),
            None,
        )
    value = _closed(program, _PROGRAM_FIELDS, "program", issues)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not _identifier(value.get("pilot_id")):
        _issue(issues, "program:pilot_id_invalid")
    mode = value.get("mode")
    if mode not in {"provider_free_fixture", "live_pilot"}:
        _issue(issues, "program:mode_invalid")
        mode = None
    if not _identifier(value.get("workflow_id")):
        _issue(issues, "program:workflow_id_invalid")

    plan_report = governor.validate_logical_plan(value.get("logical_plan"))
    if plan_report.get("status") != "PASS":
        for issue in plan_report.get("issues", []):
            _issue(issues, "logical_plan:" + issue)
    if plan_report.get("execution_profile") != "finite_dag/v1":
        _issue(issues, "logical_plan:finite_dag_required")
    plan = plan_report.get("canonical_plan") or {}
    workers = plan.get("workers") if isinstance(plan, Mapping) else []
    workers = workers if isinstance(workers, list) else []
    worker_ids = [
        str(worker.get("id")) for worker in workers if isinstance(worker, Mapping)
    ]
    if any(worker.get("executor") != "subagent" for worker in workers):
        _issue(issues, "logical_plan:dbos_dispatch_requires_subagent_nodes")

    dispatch_order = _string_list(value.get("dispatch_order"), "dispatch_order", issues)
    if set(dispatch_order) != set(worker_ids) or len(dispatch_order) != len(worker_ids):
        _issue(issues, "dispatch_order:worker_set_mismatch")
    position = {worker_id: index for index, worker_id in enumerate(dispatch_order)}
    for worker in workers:
        worker_id = worker.get("id")
        for predecessor in worker.get("dependencies", []):
            if position.get(predecessor, len(dispatch_order)) >= position.get(
                worker_id, -1
            ):
                _issue(issues, "dispatch_order:not_topological")

    bindings_raw = value.get("task_bindings")
    if not isinstance(bindings_raw, list) or len(bindings_raw) > PROFILE.max_array_items:
        _issue(issues, "task_bindings:array_invalid")
        bindings_raw = []
    bindings: dict[str, dict[str, Any]] = {}
    idempotency_keys: set[str] = set()
    resources_by_worker = {
        worker.get("id"): set(worker.get("owned_resources", [])) for worker in workers
    }
    for index, raw in enumerate(bindings_raw):
        label = f"task_bindings[{index}]"
        row = _closed(raw, _TASK_BINDING_FIELDS, label, issues)
        worker_id = row.get("worker_id")
        if worker_id not in worker_ids or worker_id in bindings:
            _issue(issues, f"{label}:worker_invalid_or_duplicate")
            continue
        idempotency_key = row.get("idempotency_key")
        if not _identifier(idempotency_key) or idempotency_key in idempotency_keys:
            _issue(issues, f"{label}:idempotency_key_invalid_or_duplicate")
        else:
            idempotency_keys.add(str(idempotency_key))
        task_report = contracts.validate_task_spec(row.get("task_spec"))
        if not task_report.get("valid"):
            _issue(issues, f"{label}:task_spec_invalid")
            continue
        task = task_report["normalized"]
        if task.get("budgets", {}).get("retries") != 0:
            _issue(issues, f"{label}:task_retry_present")
        if not set(task.get("write_scope", [])).issubset(
            resources_by_worker.get(worker_id, set())
        ):
            _issue(issues, f"{label}:write_scope_outside_worker_ownership")
        bindings[str(worker_id)] = {
            "worker_id": str(worker_id),
            "idempotency_key": str(idempotency_key),
            "task_spec": task,
        }
    if set(bindings) != set(worker_ids):
        _issue(issues, "task_bindings:worker_set_mismatch")

    storage = _closed(value.get("storage"), _STORAGE_FIELDS, "storage", issues)
    backend = storage.get("backend")
    distributed = storage.get("distributed")
    if backend not in {"sqlite_prototype", "postgres"}:
        _issue(issues, "storage:backend_invalid")
    if not isinstance(distributed, bool):
        _issue(issues, "storage:distributed_invalid")
    elif distributed and backend != "postgres":
        _issue(issues, "storage:postgres_required_for_distributed")

    recovery = _closed(
        value.get("recovery_policy"), _RECOVERY_FIELDS, "recovery_policy", issues
    )
    if recovery.get("owner") != "dbos_runtime":
        _issue(issues, "recovery_policy:owner_invalid")
    if recovery.get("semantic_retry_owner") != "orch_dork_controller":
        _issue(issues, "recovery_policy:semantic_retry_owner_invalid")
    if recovery.get("step_retries_allowed") is not False:
        _issue(issues, "recovery_policy:step_retries_present")
    if recovery.get("max_step_attempts") != 1:
        _issue(issues, "recovery_policy:max_step_attempts_invalid")
    max_recovery = recovery.get("max_recovery_attempts")
    if type(max_recovery) is not int or max_recovery < 1:
        _issue(issues, "recovery_policy:max_recovery_attempts_invalid")
    for field in ("fallbacks", "replacements"):
        if recovery.get(field) != 0:
            _issue(issues, f"recovery_policy:{field}_present")
    for field in ("deterministic_workflow", "idempotent_steps_attested"):
        if recovery.get(field) is not True:
            _issue(issues, f"recovery_policy:{field}_required")

    plan_sha256 = plan_report.get("plan_sha256") if plan_report.get("status") == "PASS" else None
    if issues:
        return (
            _base_report(
                status="FAIL",
                decision="CONFIGURATION_REJECTED",
                issues=issues,
                program_sha256=program_sha256,
                mode=mode,
                plan_sha256=plan_sha256,
                dispatch_order=dispatch_order,
                storage_backend=backend if isinstance(backend, str) else None,
            ),
            None,
        )
    normalized = {
        "pilot_id": value["pilot_id"],
        "mode": mode,
        "workflow_id": value["workflow_id"],
        "logical_plan_sha256": plan_sha256,
        "dispatch_order": dispatch_order,
        "task_bindings": bindings,
        "storage_backend": backend,
        "max_recovery_attempts": max_recovery,
    }
    return (
        _base_report(
            status="PASS",
            decision="READY",
            issues=[],
            program_sha256=program_sha256,
            mode=mode,
            plan_sha256=plan_sha256,
            dispatch_order=dispatch_order,
            storage_backend=backend,
        ),
        normalized,
    )


def validate_dbos_pilot(program: Any) -> dict[str, Any]:
    """Validate the optional durability mapping without importing DBOS."""

    return _validate(program)[0]


def _dependency_available() -> bool:
    try:
        return importlib.util.find_spec("dbos") is not None
    except (ImportError, AttributeError, ValueError):
        return False


class DBOSPilotStepError(RuntimeError):
    """Stable sanitized step-boundary failure."""


class DBOSPilotBinding:
    def __init__(
        self,
        report: Mapping[str, Any],
        *,
        normalized: Mapping[str, Any] | None = None,
        dbos_api: Any = None,
        workflow_id_context: Callable[[str], Any] | None = None,
        workflow: Callable[[], Any] | None = None,
    ) -> None:
        self.report = dict(report)
        self.ready = self.report.get("status") == "PASS" and workflow is not None
        self._normalized = dict(normalized or {})
        self._dbos_api = dbos_api
        self._workflow_id_context = workflow_id_context
        self._workflow = workflow

    def start(self) -> dict[str, Any]:
        """Durably start once by workflow ID; never wait for completion."""

        if not self.ready:
            return dict(self.report)
        workflow_id = self._normalized["workflow_id"]
        provider_free = self._normalized["mode"] == "provider_free_fixture"
        try:
            with self._workflow_id_context(workflow_id):
                handle = self._dbos_api.start_workflow(self._workflow)
            observed_id = handle.get_workflow_id()
            if observed_id != workflow_id:
                raise DBOSPilotStepError("workflow_id_mismatch")
        except Exception:
            decision = "START_FAILED"
            status = "FAIL"
            issues = ["workflow_start_failed"]
        else:
            decision = "STARTED"
            status = "PASS"
            issues = []
        core = {
            "schema": START_REPORT_SCHEMA,
            "pilot_version": PILOT_VERSION,
            "status": status,
            "decision": decision,
            "issues": issues,
            "workflow_id": workflow_id,
            "logical_plan_sha256": self._normalized["logical_plan_sha256"],
            "completion_claimed": False,
            "result_waited": False,
            "topology_authority": False,
            "semantic_retry_authority": False,
            "completion_authority": False,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
            "provider_free": provider_free,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        return {**core, "report_sha256": _sha(core)}


def prepare_dbos_pilot(
    program: Any,
    *,
    node_executor: Callable[[str, Mapping[str, Any], str], Any],
    dbos_api: Any = None,
    workflow_id_context: Callable[[str], Any] | None = None,
    availability_probe: Callable[[], bool] | None = None,
) -> DBOSPilotBinding:
    """Bind the frozen program to DBOS decorators without starting it."""

    report, normalized = _validate(program)
    if normalized is None:
        return DBOSPilotBinding(report)
    mode = normalized["mode"]
    if mode == "provider_free_fixture" and (
        dbos_api is None or workflow_id_context is None
    ):
        refused = _base_report(
            status="FAIL",
            decision="CONFIGURATION_REJECTED",
            issues=["fixture_dbos_api_required"],
            program_sha256=report["program_sha256"],
            mode=mode,
            plan_sha256=normalized["logical_plan_sha256"],
            dispatch_order=normalized["dispatch_order"],
            storage_backend=normalized["storage_backend"],
        )
        return DBOSPilotBinding(refused)
    if dbos_api is None:
        available = (availability_probe or _dependency_available)()
        if not available:
            unavailable = _base_report(
                status="UNAVAILABLE",
                decision="DEPENDENCY_UNAVAILABLE",
                issues=["dbos_not_installed"],
                program_sha256=report["program_sha256"],
                mode=mode,
                plan_sha256=normalized["logical_plan_sha256"],
                dispatch_order=normalized["dispatch_order"],
                storage_backend=normalized["storage_backend"],
            )
            return DBOSPilotBinding(unavailable)
        module = importlib.import_module("dbos")
        dbos_api = module.DBOS
        workflow_id_context = module.SetWorkflowID

    bindings = normalized["task_bindings"]
    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", normalized["pilot_id"])

    def dispatch_node(worker_id: str):
        binding = bindings[worker_id]
        output = node_executor(
            worker_id,
            binding["task_spec"],
            binding["idempotency_key"],
        )
        handoff_report = contracts.validate_handoff_receipt(
            output, task_spec=binding["task_spec"]
        )
        if not handoff_report.get("valid"):
            raise DBOSPilotStepError("invalid_handoff")
        return handoff_report["normalized"]

    try:
        durable_step = dbos_api.step(
            name=f"orch_dork_{safe_name}_dispatch",
            retries_allowed=False,
            max_attempts=1,
        )(dispatch_node)

        def frozen_workflow():
            return [durable_step(worker_id) for worker_id in normalized["dispatch_order"]]

        durable_workflow = dbos_api.workflow(
            name=f"orch_dork_{safe_name}_workflow",
            max_recovery_attempts=normalized["max_recovery_attempts"],
        )(frozen_workflow)
    except Exception:
        failed = _base_report(
            status="FAIL",
            decision="BIND_FAILED",
            issues=["dbos_binding_failed"],
            program_sha256=report["program_sha256"],
            mode=mode,
            plan_sha256=normalized["logical_plan_sha256"],
            dispatch_order=normalized["dispatch_order"],
            storage_backend=normalized["storage_backend"],
            dependency_available=True,
        )
        return DBOSPilotBinding(failed)
    ready = dict(report)
    ready["dependency_available"] = True
    ready["report_sha256"] = _sha({k: v for k, v in ready.items() if k != "report_sha256"})
    return DBOSPilotBinding(
        ready,
        normalized=normalized,
        dbos_api=dbos_api,
        workflow_id_context=workflow_id_context,
        workflow=durable_workflow,
    )


__all__ = [
    "DBOSPilotBinding",
    "DBOSPilotStepError",
    "PILOT_VERSION",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "START_REPORT_SCHEMA",
    "prepare_dbos_pilot",
    "validate_dbos_pilot",
]
