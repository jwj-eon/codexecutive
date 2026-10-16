#!/usr/bin/env python3
"""Single provider-free governed-run owner for Orch Dork.

This module composes the existing ticket, plan, capacity, adapter, limit,
active-controller, and independent-observer boundaries.  It does not launch
workers or providers.  A caller supplies closed native receipts and runtime
evidence; the coordinator owns stage order and cross-stage identity binding.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any, Mapping


PROGRAM_SCHEMA = "orch-dork/governed-run-program/v1"
REPORT_SCHEMA = "orch-dork/governed-run-report/v1"
ENTRYPOINT_VERSION = "governed-run/v1"


def _load(name: str):
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name + " unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


project_adapter = _load("orch_dork_project_adapter")
efficiency_governor = _load("orch_dork_efficiency_governor")
governed_completion = _load("orch_dork_governed_completion")


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


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return False
    for key in sorted(keys - set(value)):
        _issue(issues, label + ":missing:" + key)
    for key in sorted(set(value) - keys):
        _issue(issues, label + ":unknown:" + str(key))
    return set(value) == keys


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _ticket_hash(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    for key in ("admission_sha256", "admission_hash"):
        candidate = value.get(key)
        if _text(candidate):
            return str(candidate)
    for key in ("identity", "record", "binding"):
        found = _ticket_hash(value.get(key))
        if found is not None:
            return found
    return None


def _ticket_id(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    if _text(value.get("ticket_id")):
        return str(value["ticket_id"])
    for key in ("identity", "record", "binding"):
        found = _ticket_id(value.get(key))
        if found is not None:
            return found
    return None


def _root_id(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    for key in ("root_task_id", "root_thread_id"):
        if _text(value.get(key)):
            return str(value[key])
    identity = value.get("identity")
    return _root_id(identity) if isinstance(identity, Mapping) else None


def _stage(name: str, report: Mapping[str, Any] | None) -> dict[str, Any]:
    value = dict(report) if isinstance(report, Mapping) else {}
    return {
        "name": name,
        "status": value.get("status"),
        "report_sha256": value.get("report_sha256") or _sha(value),
        "issues": list(value.get("issues", [])) if isinstance(value.get("issues"), list) else [],
    }


def _base_report(
    value: Mapping[str, Any],
    issues: list[str],
    stages: list[dict[str, Any]],
    *,
    disposition: str,
    controller_ready: bool = False,
    runtime_observed: bool = False,
    terminally_qualified: bool = False,
    controller_report: Mapping[str, Any] | None = None,
    completion_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    controller = dict(controller_report) if isinstance(controller_report, Mapping) else {}
    completion = dict(completion_report) if isinstance(completion_report, Mapping) else {}
    cursor = {
        "version": ((value.get("controller") or {}).get("previous_packet") or {}).get("version"),
        "last_event_seq": max(
            [
                event.get("seq", 0)
                for event in ((value.get("controller") or {}).get("events") or [])
                if isinstance(event, Mapping) and type(event.get("seq")) is int
            ]
            or [0]
        ),
        "stable_evidence_pointers": sorted(
            {
                str(event.get("source_pointer"))
                for event in ((value.get("controller") or {}).get("events") or [])
                if isinstance(event, Mapping) and _text(event.get("source_pointer"))
            }
        ),
    }
    core = {
        "schema": REPORT_SCHEMA,
        "entrypoint_version": ENTRYPOINT_VERSION,
        "status": "PASS" if not issues and terminally_qualified else (
            "CONTROLLER_READY" if not issues and controller_ready else "BLOCKED"
        ),
        "disposition": disposition,
        "run_id": value.get("run_id"),
        "attempt_id": value.get("attempt_id"),
        "ticket_id": _ticket_id(value.get("ticket_admission")),
        "ticket_admission_sha256": _ticket_hash(value.get("ticket_admission")),
        "plan_sha256": next(
            (stage.get("plan_sha256") for stage in stages if stage.get("plan_sha256")),
            None,
        ),
        "evidence_levels": {
            "advisory": True,
            "controller_ready": controller_ready,
            "runtime_observed": runtime_observed,
            "terminally_qualified": False,
        },
        "governance_mode": "compatibility_replay",
        "fresh_native_activation": False,
        "activation_status": "not_proven_provider_free_fixture",
        "stages": stages,
        "event_cursor": cursor,
        "sol_wake": bool(controller.get("sol_wake", False)),
        "sol_packet": controller.get("sol_packet"),
        "independent_runtime": completion.get("independent_runtime"),
        "terminal_claim_permitted": False,
        "issues": sorted(set(issues)),
        "automatic_retries": 0,
        "automatic_replacements": 0,
        "automatic_fallbacks": 0,
        "provider_free": True,
        "live_task_operations": 0,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _sha(core)}


def evaluate_governed_run(
    program: Any,
    *,
    policy_module: Any = None,
    capacity_authority: Any = None,
) -> dict[str, Any]:
    """Replay one legacy governed lifecycle without execution authority."""

    issues: list[str] = []
    value = dict(program) if isinstance(program, Mapping) else {}
    _exact(
        value,
        {
            "schema",
            "run_id",
            "attempt_id",
            "root_task_id",
            "ticket_admission",
            "plan",
            "inventory",
            "spawn_results",
            "adapter_pre",
            "limits",
            "controller",
            "adapter_post",
            "observer_manifest",
            "submitted_qualification",
            "acceptance_context",
        },
        "program",
        issues,
    )
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    for field in ("run_id", "attempt_id", "root_task_id"):
        if not _text(value.get(field)):
            _issue(issues, "program:" + field + "_invalid")
    acceptance = value.get("acceptance_context")
    _exact(
        acceptance,
        {"kind", "native_call_authorized", "attempt_count", "source_pointer"},
        "acceptance_context",
        issues,
    )
    if isinstance(acceptance, Mapping):
        if acceptance.get("kind") not in {"provider_free_fixture", "fresh_native_acceptance"}:
            _issue(issues, "acceptance_context:kind_invalid")
        elif acceptance.get("kind") == "fresh_native_acceptance":
            _issue(
                issues,
                "acceptance_context:fresh_native_acceptance_requires_governed_attempt",
            )
        if not isinstance(acceptance.get("native_call_authorized"), bool):
            _issue(issues, "acceptance_context:authority_invalid")
        if type(acceptance.get("attempt_count")) is not int or acceptance.get("attempt_count") < 0:
            _issue(issues, "acceptance_context:attempt_count_invalid")
        if acceptance.get("kind") == "provider_free_fixture" and (
            acceptance.get("native_call_authorized") is not False
            or acceptance.get("attempt_count") != 0
        ):
            _issue(issues, "acceptance_context:provider_free_boundary_violated")
        if not _text(acceptance.get("source_pointer")):
            _issue(issues, "acceptance_context:source_pointer_invalid")

    policy = policy_module if policy_module is not None else _load("orch_dork_policy")
    stages: list[dict[str, Any]] = []
    admission = value.get("ticket_admission")
    admission_hash = _ticket_hash(admission)
    ticket_id = _ticket_id(admission)
    root_id = _root_id(admission)
    if not isinstance(admission, Mapping):
        _issue(issues, "ticket_admission:missing")
    else:
        if admission.get("schema") != "orch-dork/ticket-admission/v2":
            _issue(issues, "ticket_admission:schema_invalid")
        if admission.get("policy_version") != "classification-policy/v2":
            _issue(issues, "ticket_admission:policy_invalid")
        if admission.get("decision") != "ORCHESTRATION_PLAN_REQUIRED":
            _issue(issues, "ticket_admission:decision_invalid")
        if not _text(admission_hash) or not _text(ticket_id):
            _issue(issues, "ticket_admission:identity_invalid")
        if root_id != value.get("root_task_id"):
            _issue(issues, "ticket_admission:root_mismatch")
    stages.append(
        {
            "name": "ticket_admission",
            "status": "PASS" if not any(item.startswith("ticket_admission:") for item in issues) else "FAIL",
            "report_sha256": admission_hash,
            "issues": [item for item in issues if item.startswith("ticket_admission:")],
        }
    )
    if issues:
        return _base_report(value, issues, stages, disposition="REFUSED_ADMISSION")

    plan = value.get("plan")
    plan_report = policy.validate_plan(plan)
    plan_stage = _stage("plan_freeze", plan_report)
    plan_stage["plan_sha256"] = plan_report.get("plan_sha256")
    stages.append(plan_stage)
    closure = plan_report.get("acceptance_resource_closure", {})
    if (
        plan_report.get("status") != "PASS"
        or closure.get("status") != "PASS"
        or plan_report.get("freeze_permitted") is not True
        or plan_report.get("spawn_permitted") is not True
    ):
        _issue(issues, "plan:closure_or_freeze_refused")
        issues.extend("plan:" + str(item) for item in plan_report.get("issues", []))
        return _base_report(value, issues, stages, disposition="REFUSED_PLAN")
    plan_sha = plan_report["plan_sha256"]

    inventory = value.get("inventory")
    if isinstance(inventory, Mapping) and inventory.get("root_thread_id") != value.get("root_task_id"):
        _issue(issues, "inventory:root_mismatch")
    # governed-run/v1 is retained only for deterministic compatibility replay.
    # Keep the obsolete argument for API compatibility, but never let this
    # read-only evaluator consult or mutate the shared execution authority.
    authority_reader = None
    authority_committer = None
    capacity = policy.validate_admission(
        plan,
        inventory,
        run_id=value.get("run_id"),
        authority_state_reader=authority_reader,
        authority_state_committer=authority_committer,
    )
    capacity_stage = _stage("capacity_admission", capacity)
    capacity_stage["plan_sha256"] = capacity.get("plan_sha256")
    stages.append(capacity_stage)
    if (
        capacity.get("status") != "PASS"
        or capacity.get("plan_sha256") != plan_sha
    ):
        _issue(issues, "capacity:refused")
        issues.extend("capacity:" + str(item) for item in capacity.get("issues", []))
        return _base_report(value, issues, stages, disposition="REFUSED_CAPACITY")

    wave = policy.validate_spawn_wave(
        plan,
        capacity,
        value.get("spawn_results"),
        authority_state_reader=authority_reader,
        structural_replay=True,
    )
    wave_stage = _stage("spawn_wave", wave)
    wave_stage["plan_sha256"] = wave.get("plan_sha256")
    stages.append(wave_stage)
    if wave.get("status") != "PASS" or wave.get("plan_sha256") != plan_sha:
        _issue(issues, "spawn_wave:refused")
        issues.extend("spawn_wave:" + str(item) for item in wave.get("issues", []))
        return _base_report(value, issues, stages, disposition="REFUSED_SPAWN_WAVE")

    adapter_pre = value.get("adapter_pre")
    pre_report = project_adapter.evaluate_project_adapter(adapter_pre)
    stages.append(_stage("project_adapter_pre", pre_report))
    if (
        pre_report.get("status") != "PASS"
        or pre_report.get("implementation_permitted") is not True
        or pre_report.get("ticket_admission_binding_status") != "BOUND"
        or pre_report.get("ticket_admission_sha256") != admission_hash
    ):
        _issue(issues, "adapter_pre:refused_or_unbound")
        issues.extend("adapter_pre:" + str(item) for item in pre_report.get("issues", []))
        issues.extend("adapter_pre:" + str(item) for item in pre_report.get("blockers", []))
        return _base_report(value, issues, stages, disposition="REFUSED_ADAPTER_PRE")

    limits = efficiency_governor.evaluate_limit_policy(value.get("limits"))
    stages.append(_stage("limits", limits))
    if limits.get("status") not in {"PASS", "SOFT_REMEDIATION"} or limits.get("candidate_admitted") is not True:
        _issue(issues, "limits:not_admitted")
        issues.extend("limits:" + str(item) for item in limits.get("issues", []))
        return _base_report(value, issues, stages, disposition="REFUSED_LIMITS")
    if (value.get("limits") or {}).get("plan_sha256") != plan_sha:
        _issue(issues, "limits:plan_hash_mismatch")
        return _base_report(value, issues, stages, disposition="REFUSED_LIMITS")

    controller_program = value.get("controller")
    if not isinstance(controller_program, Mapping):
        _issue(issues, "controller:program_missing")
        return _base_report(value, issues, stages, disposition="REFUSED_CONTROLLER")
    expected_logical = efficiency_governor.logical_plan_from_v1(
        plan,
        plan_id=str(controller_program.get("logical_plan", {}).get("plan_id")),
        root_thread_id=str(value.get("root_task_id")),
        authority_id=str(controller_program.get("authority", {}).get("authority_id")),
    )
    if controller_program.get("logical_plan") != expected_logical:
        _issue(issues, "controller:logical_plan_not_derived_from_frozen_plan")
    if controller_program.get("root_thread_id") != value.get("root_task_id"):
        _issue(issues, "controller:root_mismatch")
    if _ticket_hash(controller_program.get("ticket_admission")) != admission_hash:
        _issue(issues, "controller:ticket_admission_mismatch")
    controller_adapter = controller_program.get("adapter", {})
    if controller_adapter.get("status") != "PASS" or controller_adapter.get("source_pointer") != pre_report.get("report_sha256"):
        _issue(issues, "controller:adapter_receipt_mismatch")
    if issues:
        return _base_report(value, issues, stages, disposition="REFUSED_CONTROLLER")
    controller_report = efficiency_governor.run_active_controller(controller_program)
    stages.append(_stage("active_controller", controller_report))

    wave_members = {
        (str(item.get("lane_id")), str(item.get("worker_id")))
        for item in wave.get("members", [])
    }
    controller_members = {
        (str(item.get("node_id")), str(item.get("worker_id")))
        for item in controller_report.get("memberships", [])
    }
    if wave_members != controller_members:
        _issue(issues, "controller:spawn_membership_mismatch")
    if controller_report.get("ticket_admission_sha256") != admission_hash or controller_report.get("ticket_admission_bound") is not True:
        _issue(issues, "controller:ticket_admission_unbound")
    if controller_report.get("status") == "SOL_DECISION_REQUIRED":
        return _base_report(
            value,
            issues,
            stages,
            disposition="SOL_DECISION_REQUIRED",
            controller_ready=not issues,
            controller_report=controller_report,
        )
    if controller_report.get("status") == "ACTIVE":
        return _base_report(
            value,
            issues,
            stages,
            disposition="CONTROLLER_ACTIVE",
            controller_ready=not issues,
            controller_report=controller_report,
        )
    if controller_report.get("status") != "TERMINAL_HANDOFF" or controller_report.get("terminal_handoff_permitted") is not True:
        _issue(issues, "controller:terminal_handoff_refused")
        issues.extend("controller:" + str(item) for item in controller_report.get("issues", []))
        return _base_report(
            value,
            issues,
            stages,
            disposition="REFUSED_CONTROLLER",
            controller_report=controller_report,
        )
    failed_controller_nodes = [
        item
        for item in controller_report.get("states", [])
        if isinstance(item, Mapping)
        and item.get("status") in {"failed", "timed_out"}
    ]
    if failed_controller_nodes:
        for item in failed_controller_nodes:
            _issue(
                issues,
                "controller:terminal_node_"
                + str(item.get("status"))
                + ":"
                + str(item.get("node_id")),
            )
        return _base_report(
            value,
            issues,
            stages,
            disposition="RUNTIME_TERMINAL_FAILURE",
            controller_ready=True,
            controller_report=controller_report,
        )

    post_report = project_adapter.evaluate_project_adapter(value.get("adapter_post"))
    stages.append(_stage("project_adapter_post", post_report))
    if (
        post_report.get("status") != "PASS"
        or post_report.get("ticket_admission_binding_status") != "BOUND"
        or post_report.get("ticket_admission_sha256") != admission_hash
    ):
        _issue(issues, "adapter_post:refused_or_unbound")
        issues.extend("adapter_post:" + str(item) for item in post_report.get("issues", []))
        issues.extend("adapter_post:" + str(item) for item in post_report.get("blockers", []))
        return _base_report(
            value,
            issues,
            stages,
            disposition="REFUSED_ADAPTER_POST",
            controller_ready=True,
            controller_report=controller_report,
        )

    manifest = value.get("observer_manifest")
    if not isinstance(manifest, Mapping) or manifest.get("attempt_id") != value.get("attempt_id"):
        _issue(issues, "observer:attempt_identity_mismatch")
        return _base_report(
            value,
            issues,
            stages,
            disposition="REFUSED_OBSERVER",
            controller_ready=True,
            controller_report=controller_report,
        )
    completion = governed_completion.evaluate_governed_completion(
        plan,
        manifest,
        value.get("submitted_qualification"),
    )
    stages.append(_stage("independent_terminal_observer", completion))
    runtime_observed = completion.get("binding_status") == "BOUND"
    observed_children = {
        (str(item.get("lane_id")), str(item.get("thread_id")))
        for item in (completion.get("independent_runtime") or {}).get("graph", {}).get("children", [])
        if isinstance(item, Mapping)
    }
    observed_root = (
        (completion.get("independent_runtime") or {}).get("graph", {}).get("root", {}) or {}
    ).get("thread_id")
    independent_runtime = completion.get("independent_runtime") or {}
    observed_terminal = independent_runtime.get("terminal_state")
    if observed_terminal is None:
        observed_terminal = (independent_runtime.get("lifecycle") or {}).get(
            "terminal_state"
        )
    if str(observed_terminal).lower() not in {
        "completed",
        "complete",
        "success",
        "succeeded",
        "pass",
        "passed",
    }:
        _issue(
            issues,
            "observer:terminal_disposition_not_success:"
            + str(observed_terminal),
        )
    if observed_children != wave_members:
        _issue(issues, "observer:spawn_membership_mismatch")
    if observed_root != value.get("root_task_id"):
        _issue(issues, "observer:root_identity_mismatch")
    qualified = completion.get("status") == "PASS" and completion.get("claim_permitted") is True and not issues
    if not qualified:
        _issue(issues, "observer:terminal_qualification_refused")
        issues.extend("observer:" + str(item) for item in completion.get("issues", []))
    return _base_report(
        value,
        issues,
        stages,
        disposition="COMPATIBILITY_TERMINAL_REPLAY" if qualified else "RUNTIME_OBSERVED_NOT_QUALIFIED",
        controller_ready=True,
        runtime_observed=runtime_observed,
        terminally_qualified=qualified,
        controller_report=controller_report,
        completion_report=completion,
    )


__all__ = [
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "ENTRYPOINT_VERSION",
    "evaluate_governed_run",
    "governed_completion",
]
