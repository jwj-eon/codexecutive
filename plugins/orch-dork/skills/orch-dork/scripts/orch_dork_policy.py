#!/usr/bin/env python3
"""Deterministic plan and submitted-trace policy service for Orch Dork."""

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import sys
import types
from pathlib import Path


def _load_optional_sibling(name: str, *, publish: bool = False):
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    if publish:
        sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


try:
    from orch_dork_hostile_input import MCP_ACTION_ADVANCE_RESPONSE_BUDGET_BYTES
except ImportError:  # pragma: no cover - standalone pinned file loaders.
    _hostile_input_constants = _load_optional_sibling("orch_dork_hostile_input", publish=True)
    MCP_ACTION_ADVANCE_RESPONSE_BUDGET_BYTES = _hostile_input_constants.MCP_ACTION_ADVANCE_RESPONSE_BUDGET_BYTES


try:
    import orch_dork_evidence_core as evidence_core
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _evidence_core_path = Path(__file__).resolve().with_name(
        "orch_dork_evidence_core.py"
    )
    _evidence_core_spec = importlib.util.spec_from_file_location(
        "orch_dork_evidence_core", _evidence_core_path
    )
    if _evidence_core_spec is None or _evidence_core_spec.loader is None:
        raise
    evidence_core = importlib.util.module_from_spec(_evidence_core_spec)
    _evidence_core_spec.loader.exec_module(evidence_core)


try:
    import orch_dork_ownership as ownership
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _ownership_path = Path(__file__).resolve().with_name("orch_dork_ownership.py")
    _ownership_spec = importlib.util.spec_from_file_location(
        "orch_dork_ownership", _ownership_path
    )
    if _ownership_spec is None or _ownership_spec.loader is None:
        ownership = None
    else:
        ownership = importlib.util.module_from_spec(_ownership_spec)
        _ownership_spec.loader.exec_module(ownership)

try:
    import orch_dork_worker_default as worker_default
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _worker_default_path = Path(__file__).resolve().with_name(
        "orch_dork_worker_default.py"
    )
    _worker_default_spec = importlib.util.spec_from_file_location(
        "orch_dork_worker_default", _worker_default_path
    )
    if _worker_default_spec is None or _worker_default_spec.loader is None:
        raise
    worker_default = importlib.util.module_from_spec(_worker_default_spec)
    # Publish before executing so later loaders reuse this exact instance;
    # a second instance would carry its own governed-default state.
    sys.modules.setdefault("orch_dork_worker_default", worker_default)
    _worker_default_spec.loader.exec_module(worker_default)

try:
    import orch_dork_custody as custody
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _custody_path = Path(__file__).resolve().with_name("orch_dork_custody.py")
    _custody_spec = importlib.util.spec_from_file_location(
        "orch_dork_custody", _custody_path
    )
    if _custody_spec is None or _custody_spec.loader is None:
        custody = None
    else:
        custody = importlib.util.module_from_spec(_custody_spec)
        _custody_spec.loader.exec_module(custody)

try:
    import orch_dork_read_custody as read_custody_audit
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _read_custody_path = Path(__file__).resolve().with_name(
        "orch_dork_read_custody.py"
    )
    if not _read_custody_path.is_file():
        read_custody_audit = None
    else:
        _read_custody_spec = importlib.util.spec_from_file_location(
            "orch_dork_read_custody", _read_custody_path
        )
        if _read_custody_spec is None or _read_custody_spec.loader is None:
            read_custody_audit = None
        else:
            read_custody_audit = importlib.util.module_from_spec(
                _read_custody_spec
            )
            _read_custody_spec.loader.exec_module(read_custody_audit)

try:
    import orch_dork_efficiency_governor as efficiency_governor
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _efficiency_path = Path(__file__).resolve().with_name(
        "orch_dork_efficiency_governor.py"
    )
    _efficiency_spec = importlib.util.spec_from_file_location(
        "orch_dork_efficiency_governor", _efficiency_path
    )
    if _efficiency_spec is None or _efficiency_spec.loader is None:
        efficiency_governor = None
    else:
        efficiency_governor = importlib.util.module_from_spec(_efficiency_spec)
        _efficiency_spec.loader.exec_module(efficiency_governor)

try:
    import orch_dork_live_view as live_view
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _live_view_path = Path(__file__).resolve().with_name("orch_dork_live_view.py")
    _live_view_spec = importlib.util.spec_from_file_location(
        "orch_dork_live_view", _live_view_path
    )
    if _live_view_spec is None or _live_view_spec.loader is None:
        live_view = None
    else:
        live_view = importlib.util.module_from_spec(_live_view_spec)
        _live_view_spec.loader.exec_module(live_view)

try:
    import orch_dork_decomposition as decomposition
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _decomposition_path = Path(__file__).resolve().with_name(
        "orch_dork_decomposition.py"
    )
    _decomposition_spec = importlib.util.spec_from_file_location(
        "orch_dork_decomposition", _decomposition_path
    )
    if _decomposition_spec is None or _decomposition_spec.loader is None:
        decomposition = None
    else:
        decomposition = importlib.util.module_from_spec(_decomposition_spec)
        _decomposition_spec.loader.exec_module(decomposition)

try:
    import orch_dork_relay as relay
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _relay_path = Path(__file__).resolve().with_name("orch_dork_relay.py")
    _relay_spec = importlib.util.spec_from_file_location("orch_dork_relay", _relay_path)
    if _relay_spec is None or _relay_spec.loader is None:
        relay = None
    else:
        relay = importlib.util.module_from_spec(_relay_spec)
        _relay_spec.loader.exec_module(relay)

try:
    import orch_dork_routing_verify as routing_verify
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _routing_verify_path = Path(__file__).resolve().with_name("orch_dork_routing_verify.py")
    _routing_verify_spec = importlib.util.spec_from_file_location(
        "orch_dork_routing_verify", _routing_verify_path
    )
    if _routing_verify_spec is None or _routing_verify_spec.loader is None:
        routing_verify = None
    else:
        routing_verify = importlib.util.module_from_spec(_routing_verify_spec)
        _routing_verify_spec.loader.exec_module(routing_verify)

try:
    import orch_dork_current_turn_route as current_turn_route
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _current_turn_route_path = Path(__file__).resolve().with_name(
        "orch_dork_current_turn_route.py"
    )
    _current_turn_route_spec = importlib.util.spec_from_file_location(
        "orch_dork_current_turn_route", _current_turn_route_path
    )
    if _current_turn_route_spec is None or _current_turn_route_spec.loader is None:
        current_turn_route = None
    else:
        current_turn_route = importlib.util.module_from_spec(_current_turn_route_spec)
        _current_turn_route_spec.loader.exec_module(current_turn_route)

try:
    import orch_dork_local_task_runtime as local_task_runtime
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _local_task_runtime_path = Path(__file__).resolve().with_name(
        "orch_dork_local_task_runtime.py"
    )
    _local_task_runtime_spec = importlib.util.spec_from_file_location(
        "orch_dork_local_task_runtime", _local_task_runtime_path
    )
    if _local_task_runtime_spec is None or _local_task_runtime_spec.loader is None:
        local_task_runtime = None
    else:
        local_task_runtime = importlib.util.module_from_spec(
            _local_task_runtime_spec
        )
        _local_task_runtime_spec.loader.exec_module(local_task_runtime)

try:
    import orch_dork_project_adapter as project_adapter
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _project_adapter_path = Path(__file__).resolve().with_name(
        "orch_dork_project_adapter.py"
    )
    _project_adapter_spec = importlib.util.spec_from_file_location(
        "orch_dork_project_adapter", _project_adapter_path
    )
    if _project_adapter_spec is None or _project_adapter_spec.loader is None:
        project_adapter = None
    else:
        project_adapter = importlib.util.module_from_spec(_project_adapter_spec)
        _project_adapter_spec.loader.exec_module(project_adapter)

try:
    import orch_dork_project_ground as project_ground
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _project_ground_path = Path(__file__).resolve().with_name(
        "orch_dork_project_ground.py"
    )
    _project_ground_spec = importlib.util.spec_from_file_location(
        "orch_dork_project_ground", _project_ground_path
    )
    if _project_ground_spec is None or _project_ground_spec.loader is None:
        project_ground = None
    else:
        project_ground = importlib.util.module_from_spec(_project_ground_spec)
        _project_ground_spec.loader.exec_module(project_ground)

try:
    import orch_dork_project_ground_enforcement as project_ground_enforcement
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _project_ground_enforcement_path = Path(__file__).resolve().with_name(
        "orch_dork_project_ground_enforcement.py"
    )
    _project_ground_enforcement_spec = importlib.util.spec_from_file_location(
        "orch_dork_project_ground_enforcement", _project_ground_enforcement_path
    )
    if (
        _project_ground_enforcement_spec is None
        or _project_ground_enforcement_spec.loader is None
    ):
        project_ground_enforcement = None
    else:
        project_ground_enforcement = importlib.util.module_from_spec(
            _project_ground_enforcement_spec
        )
        _project_ground_enforcement_spec.loader.exec_module(
            project_ground_enforcement
        )

try:
    import orch_dork_project_ground_migration as project_ground_migration
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _project_ground_migration_path = Path(__file__).resolve().with_name(
        "orch_dork_project_ground_migration.py"
    )
    _project_ground_migration_spec = importlib.util.spec_from_file_location(
        "orch_dork_project_ground_migration", _project_ground_migration_path
    )
    if (
        _project_ground_migration_spec is None
        or _project_ground_migration_spec.loader is None
    ):
        project_ground_migration = None
    else:
        project_ground_migration = importlib.util.module_from_spec(
            _project_ground_migration_spec
        )
        _project_ground_migration_spec.loader.exec_module(project_ground_migration)

try:
    import orch_dork_worker_port as worker_port
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    worker_port = _load_optional_sibling("orch_dork_worker_port")

try:
    import orch_dork_control_tower as control_tower
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    control_tower = _load_optional_sibling(
        "orch_dork_control_tower", publish=True
    )

try:
    import orch_dork_ticket_admission as ticket_admission
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    ticket_admission = _load_optional_sibling("orch_dork_ticket_admission")

try:
    import orch_dork_split_decision as split_decision
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _split_decision_path = Path(__file__).resolve().with_name(
        "orch_dork_split_decision.py"
    )
    _split_decision_spec = importlib.util.spec_from_file_location(
        "orch_dork_split_decision", _split_decision_path
    )
    if _split_decision_spec is None or _split_decision_spec.loader is None:
        split_decision = None
    else:
        split_decision = importlib.util.module_from_spec(_split_decision_spec)
        _split_decision_spec.loader.exec_module(split_decision)

try:
    import orch_dork_deepening_policy as deepening_policy
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _deepening_policy_path = Path(__file__).resolve().with_name(
        "orch_dork_deepening_policy.py"
    )
    _deepening_policy_spec = importlib.util.spec_from_file_location(
        "orch_dork_deepening_policy", _deepening_policy_path
    )
    if _deepening_policy_spec is None or _deepening_policy_spec.loader is None:
        deepening_policy = None
    else:
        deepening_policy = importlib.util.module_from_spec(_deepening_policy_spec)
        _deepening_policy_spec.loader.exec_module(deepening_policy)

try:
    import orch_dork_learned_policy as learned_policy
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _learned_policy_path = Path(__file__).resolve().with_name(
        "orch_dork_learned_policy.py"
    )
    _learned_policy_spec = importlib.util.spec_from_file_location(
        "orch_dork_learned_policy", _learned_policy_path
    )
    if _learned_policy_spec is None or _learned_policy_spec.loader is None:
        learned_policy = None
    else:
        learned_policy = importlib.util.module_from_spec(_learned_policy_spec)
        _learned_policy_spec.loader.exec_module(learned_policy)

try:
    import orch_dork_wave_recommendation as wave_recommendation
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _wave_recommendation_path = Path(__file__).resolve().with_name(
        "orch_dork_wave_recommendation.py"
    )
    _wave_recommendation_spec = importlib.util.spec_from_file_location(
        "orch_dork_wave_recommendation", _wave_recommendation_path
    )
    if _wave_recommendation_spec is None or _wave_recommendation_spec.loader is None:
        wave_recommendation = None
    else:
        wave_recommendation = importlib.util.module_from_spec(
            _wave_recommendation_spec
        )
        _wave_recommendation_spec.loader.exec_module(wave_recommendation)

try:
    import orch_dork_admission_kernel as admission_kernel
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _admission_kernel_path = Path(__file__).resolve().with_name(
        "orch_dork_admission_kernel.py"
    )
    _admission_kernel_spec = importlib.util.spec_from_file_location(
        "orch_dork_admission_kernel", _admission_kernel_path
    )
    if _admission_kernel_spec is None or _admission_kernel_spec.loader is None:
        admission_kernel = None
    else:
        admission_kernel = importlib.util.module_from_spec(_admission_kernel_spec)
        sys.modules.setdefault("orch_dork_admission_kernel", admission_kernel)
        _admission_kernel_spec.loader.exec_module(admission_kernel)

try:
    import orch_dork_semantic_plan_v2 as semantic_plan_v2
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _semantic_plan_path = Path(__file__).resolve().with_name("orch_dork_semantic_plan_v2.py")
    _semantic_plan_spec = importlib.util.spec_from_file_location("orch_dork_semantic_plan_v2", _semantic_plan_path)
    if _semantic_plan_spec is None or _semantic_plan_spec.loader is None:
        semantic_plan_v2 = None
    else:
        semantic_plan_v2 = importlib.util.module_from_spec(_semantic_plan_spec)
        sys.modules.setdefault("orch_dork_semantic_plan_v2", semantic_plan_v2)
        _semantic_plan_spec.loader.exec_module(semantic_plan_v2)

try:
    import orch_dork_plan_closure as plan_closure
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _plan_closure_path = Path(__file__).resolve().with_name(
        "orch_dork_plan_closure.py"
    )
    _plan_closure_spec = importlib.util.spec_from_file_location(
        "orch_dork_plan_closure", _plan_closure_path
    )
    if _plan_closure_spec is None or _plan_closure_spec.loader is None:
        plan_closure = None
    else:
        plan_closure = importlib.util.module_from_spec(_plan_closure_spec)
        _plan_closure_spec.loader.exec_module(plan_closure)

try:
    import orch_dork_task_creation as task_creation
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _task_creation_path = Path(__file__).resolve().with_name(
        "orch_dork_task_creation.py"
    )
    _task_creation_spec = importlib.util.spec_from_file_location(
        "orch_dork_task_creation", _task_creation_path
    )
    if _task_creation_spec is None or _task_creation_spec.loader is None:
        task_creation = None
    else:
        task_creation = importlib.util.module_from_spec(_task_creation_spec)
        _task_creation_spec.loader.exec_module(task_creation)

try:
    import orch_dork_worker_lifecycle as worker_lifecycle
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _worker_lifecycle_path = Path(__file__).resolve().with_name(
        "orch_dork_worker_lifecycle.py"
    )
    _worker_lifecycle_spec = importlib.util.spec_from_file_location(
        "orch_dork_worker_lifecycle", _worker_lifecycle_path
    )
    if _worker_lifecycle_spec is None or _worker_lifecycle_spec.loader is None:
        worker_lifecycle = None
    else:
        worker_lifecycle = importlib.util.module_from_spec(_worker_lifecycle_spec)
        _worker_lifecycle_spec.loader.exec_module(worker_lifecycle)

try:
    import orch_dork_agent_lifecycle as agent_lifecycle
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _agent_lifecycle_path = Path(__file__).resolve().with_name(
        "orch_dork_agent_lifecycle.py"
    )
    _agent_lifecycle_spec = importlib.util.spec_from_file_location(
        "orch_dork_agent_lifecycle", _agent_lifecycle_path
    )
    agent_lifecycle = importlib.util.module_from_spec(_agent_lifecycle_spec)
    _agent_lifecycle_spec.loader.exec_module(agent_lifecycle)

try:
    import orch_dork_capacity_inventory as capacity_inventory
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _capacity_inventory_path = Path(__file__).resolve().with_name(
        "orch_dork_capacity_inventory.py"
    )
    _capacity_inventory_spec = importlib.util.spec_from_file_location(
        "orch_dork_capacity_inventory", _capacity_inventory_path
    )
    if _capacity_inventory_spec is None or _capacity_inventory_spec.loader is None:
        capacity_inventory = None
    else:
        capacity_inventory = importlib.util.module_from_spec(_capacity_inventory_spec)
        _capacity_inventory_spec.loader.exec_module(capacity_inventory)

try:
    import orch_dork_execution_readiness as execution_readiness
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _execution_readiness_path = Path(__file__).resolve().with_name(
        "orch_dork_execution_readiness.py"
    )
    _execution_readiness_spec = importlib.util.spec_from_file_location(
        "orch_dork_execution_readiness", _execution_readiness_path
    )
    if (
        _execution_readiness_spec is None
        or _execution_readiness_spec.loader is None
    ):
        execution_readiness = None
    else:
        execution_readiness = importlib.util.module_from_spec(
            _execution_readiness_spec
        )
        _execution_readiness_spec.loader.exec_module(execution_readiness)

try:
    import orch_dork_coordinator_capsule as coordinator_capsule
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _coordinator_capsule_path = Path(__file__).resolve().with_name(
        "orch_dork_coordinator_capsule.py"
    )
    _coordinator_capsule_spec = importlib.util.spec_from_file_location(
        "orch_dork_coordinator_capsule", _coordinator_capsule_path
    )
    if (
        _coordinator_capsule_spec is None
        or _coordinator_capsule_spec.loader is None
    ):
        coordinator_capsule = None
    else:
        coordinator_capsule = importlib.util.module_from_spec(
            _coordinator_capsule_spec
        )
        _coordinator_capsule_spec.loader.exec_module(coordinator_capsule)

try:
    import orch_dork_adaptive_finite_dag as adaptive_finite_dag
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    # The adaptive controller imports these already-loaded policy siblings by
    # their public module names.  Publish the exact instances before executing
    # an isolated sibling spec so the policy does not create a second governed
    # default or validator state.
    for _module_name, _module in (
        ("orch_dork_decomposition", decomposition),
        ("orch_dork_efficiency_governor", efficiency_governor),
        ("orch_dork_ownership", ownership),
    ):
        if _module is not None:
            sys.modules.setdefault(_module_name, _module)
    _adaptive_finite_dag_path = Path(__file__).resolve().with_name(
        "orch_dork_adaptive_finite_dag.py"
    )
    _adaptive_finite_dag_spec = importlib.util.spec_from_file_location(
        "orch_dork_adaptive_finite_dag", _adaptive_finite_dag_path
    )
    if (
        _adaptive_finite_dag_spec is None
        or _adaptive_finite_dag_spec.loader is None
    ):
        adaptive_finite_dag = None
    else:
        adaptive_finite_dag = importlib.util.module_from_spec(
            _adaptive_finite_dag_spec
        )
        _adaptive_finite_dag_spec.loader.exec_module(adaptive_finite_dag)

try:
    import orch_dork_adaptive_contracts as adaptive_contracts
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _adaptive_contracts_path = Path(__file__).resolve().with_name(
        "orch_dork_adaptive_contracts.py"
    )
    _adaptive_contracts_spec = importlib.util.spec_from_file_location(
        "orch_dork_adaptive_contracts", _adaptive_contracts_path
    )
    if _adaptive_contracts_spec is None or _adaptive_contracts_spec.loader is None:
        adaptive_contracts = None
    else:
        adaptive_contracts = importlib.util.module_from_spec(
            _adaptive_contracts_spec
        )
        _adaptive_contracts_spec.loader.exec_module(adaptive_contracts)

try:
    import orch_dork_advisory_scan as advisory_scan
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _advisory_scan_path = Path(__file__).resolve().with_name(
        "orch_dork_advisory_scan.py"
    )
    _advisory_scan_spec = importlib.util.spec_from_file_location(
        "orch_dork_advisory_scan", _advisory_scan_path
    )
    if _advisory_scan_spec is None or _advisory_scan_spec.loader is None:
        advisory_scan = None
    else:
        advisory_scan = importlib.util.module_from_spec(_advisory_scan_spec)
        _advisory_scan_spec.loader.exec_module(advisory_scan)

try:
    import orch_dork_native_scan_observer as native_scan_observer
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _native_scan_observer_path = Path(__file__).resolve().with_name(
        "orch_dork_native_scan_observer.py"
    )
    _native_scan_observer_spec = importlib.util.spec_from_file_location(
        "orch_dork_native_scan_observer", _native_scan_observer_path
    )
    if (
        _native_scan_observer_spec is None
        or _native_scan_observer_spec.loader is None
    ):
        native_scan_observer = None
    else:
        native_scan_observer = importlib.util.module_from_spec(
            _native_scan_observer_spec
        )
        _native_scan_observer_spec.loader.exec_module(native_scan_observer)

try:
    import orch_dork_evidence_policy as evidence_policy
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _evidence_policy_path = Path(__file__).resolve().with_name("orch_dork_evidence_policy.py")
    _evidence_policy_spec = importlib.util.spec_from_file_location(
        "orch_dork_evidence_policy", _evidence_policy_path
    )
    if _evidence_policy_spec is None or _evidence_policy_spec.loader is None:
        evidence_policy = None
    else:
        evidence_policy = importlib.util.module_from_spec(_evidence_policy_spec)
        _evidence_policy_spec.loader.exec_module(evidence_policy)

try:
    import orch_dork_route_policy as route_policy
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _route_policy_path = Path(__file__).resolve().with_name("orch_dork_route_policy.py")
    _route_policy_spec = importlib.util.spec_from_file_location(
        "orch_dork_route_policy", _route_policy_path
    )
    if _route_policy_spec is None or _route_policy_spec.loader is None:
        route_policy = None
    else:
        route_policy = importlib.util.module_from_spec(_route_policy_spec)
        _route_policy_spec.loader.exec_module(route_policy)

try:
    import orch_dork_campaign_policy as campaign_policy
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _campaign_policy_path = Path(__file__).resolve().with_name("orch_dork_campaign_policy.py")
    _campaign_policy_spec = importlib.util.spec_from_file_location(
        "orch_dork_campaign_policy", _campaign_policy_path
    )
    if _campaign_policy_spec is None or _campaign_policy_spec.loader is None:
        campaign_policy = None
    else:
        campaign_policy = importlib.util.module_from_spec(_campaign_policy_spec)
        _campaign_policy_spec.loader.exec_module(campaign_policy)

try:
    import orch_dork_experiment_campaign as experiment_campaign
except ImportError:  # pragma: no cover - defensive for unusual import loaders.
    _experiment_campaign_path = Path(__file__).resolve().with_name(
        "orch_dork_experiment_campaign.py"
    )
    _experiment_campaign_spec = importlib.util.spec_from_file_location(
        "orch_dork_experiment_campaign", _experiment_campaign_path
    )
    if _experiment_campaign_spec is None or _experiment_campaign_spec.loader is None:
        experiment_campaign = None
    else:
        experiment_campaign = importlib.util.module_from_spec(
            _experiment_campaign_spec
        )
        _experiment_campaign_spec.loader.exec_module(experiment_campaign)


SERVER_NAME = "orch-dork"


def _active_package_version() -> str:
    """Read the version from the exact source/installed package manifest."""

    manifest = Path(__file__).resolve().parents[3] / ".codex-plugin" / "plugin.json"
    try:
        if manifest.stat().st_size > 65_536 or manifest.is_symlink():
            raise ValueError("manifest boundary invalid")
        value = json.loads(manifest.read_text(encoding="utf-8"))
        version = value.get("version") if isinstance(value, dict) else None
        if value.get("name") != "orch-dork" or not isinstance(version, str) or not version.strip():
            raise ValueError("manifest identity invalid")
        return version
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        # Initialization must remain diagnosable if a development-only direct
        # module load omitted its package root. The runtime package validator
        # separately refuses such an incomplete install.
        return "0.1.0+manifest-unavailable"


SERVER_VERSION = _active_package_version()
PROTOCOL_VERSION = "2025-06-18"
PLAN_SCHEMA = "orch-dork/plan/v1"
TRACE_SCHEMA = "orch-dork/trace/v1"
REPORT_SCHEMA = "orch-dork/qualification/v1"
ADMISSION_SCHEMA = "orch-dork/admission/v1"
SPAWN_WAVE_SCHEMA = "orch-dork/spawn-wave/v1"
SPAWN_RESULT_ADAPTER_SCHEMA = "orch-dork/native-spawn-result-adapter/v1"
EVIDENCE_POLICY_OPERATIONS = (
    "produced_evidence",
    "failure_origin",
    "advisory_use",
    "evidence_reveal",
)
ROUTE_POLICY_OPERATIONS = (
    "independence_quorum",
    "serving_epoch",
    "task_spec_delivery",
)
CAMPAIGN_POLICY_OPERATIONS = (
    "series_authority",
    "evaluator_integrity",
    "batch_adjudication",
)
CLASSIFICATION_AUDIT_SCHEMA = "orch-dork/classification-audit/v1"
ADAPTIVE_CONTRACT_REGISTRY = {
    "ArtifactRefV1": {
        "validator": "validate_artifact_ref",
        "allowed_arguments": frozenset(),
        "required_arguments": frozenset(),
    },
    "ClaimLedgerV1": {
        "validator": "validate_claim_ledger",
        "allowed_arguments": frozenset({"task_spec"}),
        "required_arguments": frozenset(),
    },
    "HandoffPreflightV1": {
        "validator": "validate_handoff_preflight",
        "allowed_arguments": frozenset({"task_spec"}),
        "required_arguments": frozenset({"task_spec"}),
    },
    "HandoffPreflightCandidateV1": {
        "validator": "validate_handoff_preflight_candidate",
        "allowed_arguments": frozenset({"task_spec"}),
        "required_arguments": frozenset({"task_spec"}),
    },
    "HandoffReceiptV1": {
        "validator": "validate_handoff_receipt",
        "allowed_arguments": frozenset({"task_spec"}),
        "required_arguments": frozenset(),
    },
    "IncrementalClaimPacketV1": {
        "validator": "validate_incremental_claim_packet",
        "allowed_arguments": frozenset({"task_spec"}),
        "required_arguments": frozenset({"task_spec"}),
    },
    "TaskSpecV2": {
        "validator": "validate_task_spec",
        "allowed_arguments": frozenset({"authorized_write_scope"}),
        "required_arguments": frozenset(),
    },
    "VerificationReceiptV1": {
        "validator": "validate_verification_receipt",
        "allowed_arguments": frozenset({"task_spec", "handoff_receipt"}),
        "required_arguments": frozenset({"handoff_receipt"}),
    },
}
ADAPTIVE_CONTRACT_KINDS = tuple(ADAPTIVE_CONTRACT_REGISTRY)
# The current classification policy, owned by the fresh ticket-admission
# gate (orch_dork_ticket_admission.CLASSIFICATION_POLICY_VERSION).  The v1
# audit accepts a record bound to this known-newer policy version so one
# classification decision can satisfy both gates without per-gate dialects:
# under v2 the audit additionally admits a free-form descriptive
# decomposition basis and a pre-spawn execution state (the fields the v2
# gate already carries for the same judgment - see _check_decomposition_basis
# and _check_trace_status below).  Genuinely unknown or garbage version
# strings are still rejected by _check_policy_version; the fail-closed
# posture is unchanged.  Records bound to the v1 policy validate against the
# v1 closed sets only (DECOMPOSITION_BASES_V1, TRACE_STATUSES_V1), so
# archived v1 receipts keep validating exactly as before.
CLASSIFICATION_POLICY_VERSION_V2 = "classification-policy/v2"
# The v1 audit's own policy version.  Historical/advisory receipts bind this
# exact string and keep validating against the v1 closed enums; it must not
# be re-pointed at a newer vocabulary.
CLASSIFICATION_POLICY_VERSION = "classification-policy/v1"
# Policy versions the v1 audit accepts; everything else fails closed.
CLASSIFICATION_POLICY_VERSIONS = (
    CLASSIFICATION_POLICY_VERSION,
    CLASSIFICATION_POLICY_VERSION_V2,
)
# evidence.decomposition_basis values defined by the v1 policy.  A v1-bound
# record validates exactly against this closed set (archived v1 receipts are
# unchanged).  Policy v2 additionally admits a free-form descriptive basis
# (any non-empty string): the v2 ticket gate takes the same judgment as an
# attempted_decomposition/decomposition_basis string plus concrete lane
# evidence rather than a closed enum picked after the fact, so the same text
# qualifies on both gates.  Why each accepted value exists: the five v1
# categories (v1 records, or an explicit v2 record), or the v2 descriptive
# text (v2-bound records only).
DECOMPOSITION_BASES_V1 = frozenset(
    {
        "single_coherent_operation",
        "independent_deliverables",
        "worker_count",
        "token_ratio",
        "authority_or_ownership_gap",
    }
)
# execution.trace_status values defined by the v1 policy.  A v1-bound record
# validates exactly against this closed set (archived receipts are
# unchanged).  Policy v2 additionally admits TRACE_STATUS_SPAWN_PLANNED: the
# honest pre-spawn state for an orchestration decision the v2 gate has
# admitted (plan required) but whose workers have not yet been spawned - the
# state in which the gates are run, where the old closed enum had no value
# and forced a `submitted` trace that did not yet exist.  The existing
# atomic check (mode == "atomic" must carry not_applicable) deliberately
# keeps every other value, including the PLAN to spawn, a claimed
# orchestration trace: atomic work that planned, submitted, or observed a
# trace still flags ATOMIC_FABRICATED_ORCHESTRATION_TRACE.
TRACE_STATUSES_V1 = frozenset({"not_applicable", "submitted", "runtime_observed"})
TRACE_STATUS_SPAWN_PLANNED = "spawn_planned"
VALID_TRACE_STATUSES = TRACE_STATUSES_V1 | frozenset({TRACE_STATUS_SPAWN_PLANNED})


def _check_policy_version(value, issues):
    """Validate the record's declared policy version.

    Accepts CLASSIFICATION_POLICY_VERSION (v1, the historical boundary) or
    CLASSIFICATION_POLICY_VERSION_V2 (v2, the known-newer current policy).
    Returns True only for those two exact values so callers can enable the
    v2 vocabulary for v2-bound records only.  Any other value - unknown
    version, typo, garbage - fails closed with policy:version_invalid.
    """
    if value not in (
        CLASSIFICATION_POLICY_VERSION,
        CLASSIFICATION_POLICY_VERSION_V2,
    ):
        issues.append("policy:version_invalid")
        return False
    return True


def _check_decomposition_basis(value, is_v2, issues):
    """Validate evidence.decomposition_basis for the record's policy version.

    v1: the closed five-value enum.  v2: the same enum OR a free-form
    descriptive non-empty string, so a decision already expressed for the
    v2 gate passes this audit without inventing a second dialect.  Enum
    values are accepted under both versions because an operator may quote a
    v1 category verbatim in a v2 record.  Unknown category strings on v1
    records, non-string garbage, and empty strings fail closed.
    """
    if isinstance(value, str) and value in DECOMPOSITION_BASES_V1:
        return
    if is_v2 and isinstance(value, str) and value.strip():
        return
    issues.append("evidence:decomposition_basis_invalid")


def _check_trace_status(value, is_v2, issues):
    """Validate execution.trace_status for the record's policy version.

    v1: the closed three-value enum.  v2: the same enum OR spawn_planned
    (the honest pre-spawn state).  After this widening every execution state
    a v2-bound record can name -- none (not_applicable), planned but not yet
    spawned (spawn_planned), submitted, or runtime_observed -- exists in the
    vocabulary; no future or unknown state is silently accepted, and a
    spawn_planned value on a v1-bound record still fails closed.
    """
    if value in TRACE_STATUSES_V1:
        return
    if is_v2 and value == TRACE_STATUS_SPAWN_PLANNED:
        return
    issues.append("execution:trace_status_invalid")


def subagent_model():
    """The governed worker model, resolved when it is used.

    Resolving at call time rather than at import time is what makes the
    default swappable: a module-level constant would freeze whichever value
    happened to be configured when this file was first imported, so a pin or
    an environment override set later would be silently ignored.
    """

    return worker_default.configured_worker_model()


def subagent_effort():
    """The governed worker effort, resolved when it is used."""

    return worker_default.configured_worker_effort()


# Compatibility aliases for the v1 wire schema, which still uses `children`.
child_model = subagent_model
child_effort = subagent_effort
REASONING_EFFORTS = {"low", "medium", "high", "xhigh", "max", "ultra"}
MAX_STDIN_LINE_BYTES = 2_000_000

# Issue 84: on the V2 collaboration surface, a session whose root runs on a
# ChatGPT-native model encrypts every spawn task for the native backend. A
# routed worker (any provider-prefixed model such as qwen-local/qwen-smart)
# receives ciphertext and dies at its first turn with
# unreadable_encrypted_agent_task -- every lane, every time. The two working
# recipes are a routed root on V2, or a native root forced onto the classic
# V1 surface (profile sol-v1). Fail the pairing at freeze, not at spawn.
#
# "Routed" is detected by the provider prefix ("provider/model"); native
# ChatGPT models are bare slugs. Production MCP plan freeze supplies the exact
# runtime-observed surface from ``orch_dork_current_turn_route``. The environment
# variable remains only for pure archived-plan replay and provider-free legacy
# fixtures; it is not accepted as live current-turn evidence.
COLLABORATION_SURFACE_ENV = "ORCH_DORK_COLLABORATION_SURFACE"
NATIVE_ROOT_ROUTED_WORKER_ISSUE = (
    current_turn_route.NATIVE_ROOT_ROUTED_WORKER_ISSUE
    if current_turn_route is not None
    else "orchestrated:native_root_routed_worker_encrypted"
)


def _is_routed_model(value):
    return isinstance(value, str) and "/" in value


def _native_root_routed_worker_issue(root, children, collaboration_surface=None):
    """Return the Issue 84 pairing issue, or None when the plan is safe."""

    if collaboration_surface is None:
        collaboration_surface = os.environ.get(COLLABORATION_SURFACE_ENV)
    if collaboration_surface == "v1":
        return None
    if not isinstance(root, dict) or not isinstance(children, dict):
        return None
    root_model = root.get("model")
    worker_model = children.get("model", child_model())
    if not _is_nonempty_string(root_model) or not _is_nonempty_string(worker_model):
        return None
    if _is_routed_model(root_model) or not _is_routed_model(worker_model):
        return None
    return NATIVE_ROOT_ROUTED_WORKER_ISSUE

SPAWN_RESULT_FIELDS = {
    "lane_id",
    "worker_id",
    "status",
    "fresh",
    "parent_thread_id",
}
SPAWN_RESULT_STATUSES = {
    "created",
    "failed",
    "ambiguous",
    "unknown",
    "timed_out",
    "cancelled",
}

PLAN_KEYS = {
    "schema",
    "decision",
    "root",
    "children",
    "lanes",
    "integration",
    "protected_resources",
    "acceptance_criteria",
    "acceptance_resource_closure",
}
EVENT_FIELDS = {
    "root.started": {"root_thread_id", "model", "effort"},
    "root.tool": {"name", "category"},
    "child.spawned": {
        "lane_id",
        "child_thread_id",
        "parent_thread_id",
        "depth",
        "model",
        "effort",
        "context_policy",
    },
    "lane.verified": {"lane_id", "child_thread_id", "passed"},
    "lane.completed": {"lane_id", "child_thread_id", "status"},
    "integrator.started": {"child_thread_id"},
    "lane.released": {"lane_id", "owner_thread_id", "integrator_thread_id"},
    "integrator.validated": {"child_thread_id", "passed"},
    "integrator.completed": {"child_thread_id", "status"},
    "run.completed": {"root_thread_id"},
}


def audit_classification(record):
    """Audit one advisory or governed classification without launching work."""

    issues = []
    value = record if isinstance(record, dict) else {}
    _check_exact_keys(
        record,
        {
            "schema",
            "task_id",
            "substantive",
            "invocation",
            "classification",
            "evidence",
            "policy",
            "override",
            "authority",
            "execution",
        },
        "classification_record",
        issues,
    )
    if value.get("schema") != CLASSIFICATION_AUDIT_SCHEMA:
        issues.append("classification_record:schema_invalid")
    if not _is_nonempty_string(value.get("task_id")):
        issues.append("classification_record:task_id_invalid")
    if not isinstance(value.get("substantive"), bool):
        issues.append("classification_record:substantive_invalid")

    invocation = value.get("invocation")
    _check_exact_keys(
        invocation,
        {
            "status",
            "plugin_version",
            "mode",
            "global_instructions_sha256",
            "project_instructions_sha256",
            "source_pointer",
        },
        "invocation",
        issues,
    )
    invocation_value = invocation if isinstance(invocation, dict) else {}
    if invocation_value.get("status") not in {"loaded", "missing"}:
        issues.append("invocation:status_invalid")
    if invocation_value.get("mode") not in {"advisory", "governed"}:
        issues.append("invocation:mode_invalid")
    if invocation_value.get("status") == "loaded":
        if not _is_nonempty_string(invocation_value.get("plugin_version")):
            issues.append("invocation:plugin_version_invalid")
        for field in ("global_instructions_sha256", "project_instructions_sha256"):
            digest = invocation_value.get(field)
            if not isinstance(digest, str) or len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                issues.append("invocation:%s_invalid" % field)
    elif any(
        invocation_value.get(field) is not None
        for field in (
            "plugin_version",
            "global_instructions_sha256",
            "project_instructions_sha256",
        )
    ):
        issues.append("invocation:missing_has_identity")
    if not _is_nonempty_string(invocation_value.get("source_pointer")):
        issues.append("invocation:source_pointer_invalid")

    classification = value.get("classification")
    _check_exact_keys(
        classification,
        {"status", "mode", "reason", "confidence_bps", "source_pointer"},
        "classification",
        issues,
    )
    classification_value = classification if isinstance(classification, dict) else {}
    classification_status = classification_value.get("status")
    if classification_status not in {"recorded", "missing"}:
        issues.append("classification:status_invalid")
    mode = classification_value.get("mode")
    if classification_status == "recorded":
        if mode not in {"atomic", "orchestrated", "refused"}:
            issues.append("classification:mode_invalid")
        if not _is_nonempty_string(classification_value.get("reason")):
            issues.append("classification:reason_invalid")
        confidence = classification_value.get("confidence_bps")
        if type(confidence) is not int or not 0 <= confidence <= 10_000:
            issues.append("classification:confidence_bps_invalid")
    elif any(
        classification_value.get(field) is not None
        for field in ("mode", "reason", "confidence_bps")
    ):
        issues.append("classification:missing_has_decision")
    if not _is_nonempty_string(classification_value.get("source_pointer")):
        issues.append("classification:source_pointer_invalid")

    policy = value.get("policy")
    _check_exact_keys(policy, {"version", "source_pointer"}, "policy", issues)
    policy_value = policy if isinstance(policy, dict) else {}
    # A v2-bound record gets the v2 vocabulary documented next to the
    # CLASSIFICATION_POLICY_VERSION_V2 constant; a v1-bound record stays on
    # the v1 closed sets.  Unknown versions simply keep failing closed.
    policy_is_v2 = policy_value.get("version") == CLASSIFICATION_POLICY_VERSION_V2
    _check_policy_version(policy_value.get("version"), issues)
    if not _is_nonempty_string(policy_value.get("source_pointer")):
        issues.append("policy:source_pointer_invalid")
    evidence = value.get("evidence")
    _check_exact_keys(
        evidence,
        {
            "requested_deliverables",
            "independent_lane_count",
            "shared_mutation_seams",
            "coupling",
            "decomposition_basis",
            "required_authority_available",
            "safe_resource_ownership_available",
            "review_pointers",
        },
        "evidence",
        issues,
    )
    evidence_value = evidence if isinstance(evidence, dict) else {}
    deliverables = _check_string_list(
        evidence_value.get("requested_deliverables"),
        "evidence.requested_deliverables",
        issues,
        False,
    )
    lane_count = evidence_value.get("independent_lane_count")
    if type(lane_count) is not int or lane_count < 0:
        issues.append("evidence:independent_lane_count_invalid")
        lane_count = 0
    seams = _check_string_list(
        evidence_value.get("shared_mutation_seams"),
        "evidence.shared_mutation_seams",
        issues,
    )
    if evidence_value.get("coupling") not in {"none", "low", "high"}:
        issues.append("evidence:coupling_invalid")
    _check_decomposition_basis(
        evidence_value.get("decomposition_basis"), policy_is_v2, issues
    )
    for field in ("required_authority_available", "safe_resource_ownership_available"):
        if not isinstance(evidence_value.get(field), bool):
            issues.append("evidence:%s_invalid" % field)
    review_pointers = _check_string_list(
        evidence_value.get("review_pointers"),
        "evidence.review_pointers",
        issues,
        False,
    )

    authority = value.get("authority")
    _check_exact_keys(authority, {"authority_id", "scope_sha256", "source_pointer"}, "authority", issues)
    authority_value = authority if isinstance(authority, dict) else {}
    if not _is_nonempty_string(authority_value.get("authority_id")):
        issues.append("authority:authority_id_invalid")
    scope_sha = authority_value.get("scope_sha256")
    if not isinstance(scope_sha, str) or len(scope_sha) != 64 or any(
        char not in "0123456789abcdef" for char in scope_sha
    ):
        issues.append("authority:scope_sha256_invalid")
    if not _is_nonempty_string(authority_value.get("source_pointer")):
        issues.append("authority:source_pointer_invalid")

    override = value.get("override")
    _check_exact_keys(
        override,
        {
            "status",
            "source",
            "selected_mode",
            "reason",
            "authority_scope_sha256",
            "source_pointer",
        },
        "override",
        issues,
    )
    override_value = override if isinstance(override, dict) else {}
    override_status = override_value.get("status")
    if override_status not in {"none", "applied"}:
        issues.append("override:status_invalid")
    if override_status == "applied":
        if override_value.get("source") not in {"human", "project_policy"}:
            issues.append("override:source_invalid")
        if override_value.get("selected_mode") not in {"atomic", "orchestrated", "refused"}:
            issues.append("override:selected_mode_invalid")
        if not _is_nonempty_string(override_value.get("reason")):
            issues.append("override:reason_invalid")
        if override_value.get("authority_scope_sha256") != scope_sha:
            issues.append("override:authority_boundary_changed")
    elif any(
        override_value.get(field) is not None
        for field in ("source", "selected_mode", "reason", "authority_scope_sha256")
    ):
        issues.append("override:none_has_values")
    if not _is_nonempty_string(override_value.get("source_pointer")):
        issues.append("override:source_pointer_invalid")

    execution = value.get("execution")
    _check_exact_keys(
        execution,
        {"root_owner_id", "spawned_worker_ids", "trace_status", "source_pointer"},
        "execution",
        issues,
    )
    execution_value = execution if isinstance(execution, dict) else {}
    if not _is_nonempty_string(execution_value.get("root_owner_id")):
        issues.append("execution:root_owner_id_invalid")
    worker_ids = _check_string_list(
        execution_value.get("spawned_worker_ids"),
        "execution.spawned_worker_ids",
        issues,
    )
    _check_trace_status(execution_value.get("trace_status"), policy_is_v2, issues)
    if not _is_nonempty_string(execution_value.get("source_pointer")):
        issues.append("execution:source_pointer_invalid")

    review_signals = []
    if value.get("substantive") is True and invocation_value.get("status") == "missing":
        review_signals.append("MISSING_ORCH_DORK_INVOCATION")
    if value.get("substantive") is True and classification_status == "missing":
        review_signals.append("MISSING_CLASSIFICATION")
    if mode == "atomic" and lane_count >= 2 and len(deliverables) >= 2 and evidence_value.get("coupling") != "high":
        review_signals.append("ATOMIC_WITH_MULTIPLE_INDEPENDENT_DELIVERABLES")
    if mode == "orchestrated" and (
        evidence_value.get("coupling") == "high" or seams or lane_count < 2
    ):
        review_signals.append("ORCHESTRATED_TIGHTLY_COUPLED_OR_UNJUSTIFIED")
    if mode == "orchestrated" and evidence_value.get("decomposition_basis") in {
        "worker_count",
        "token_ratio",
    }:
        review_signals.append("ORCHESTRATED_SOLELY_FOR_COUNT_OR_TOKEN_RATIO")
    if mode == "orchestrated" and worker_ids and len(worker_ids) != lane_count:
        review_signals.append("ORCHESTRATED_WORKER_LANE_MISMATCH")
    if mode == "refused" and all(
        (
            evidence_value.get("required_authority_available") is True,
            evidence_value.get("safe_resource_ownership_available") is True,
        )
    ):
        review_signals.append("REFUSAL_WITHOUT_AUTHORITY_OR_OWNERSHIP_GAP")
    if mode != "refused" and evidence_value.get("required_authority_available") is False:
        review_signals.append("NON_REFUSAL_WITH_MISSING_AUTHORITY")
    if mode != "refused" and evidence_value.get("safe_resource_ownership_available") is False:
        review_signals.append("NON_REFUSAL_WITH_UNSAFE_OWNERSHIP")
    if mode == "atomic" and worker_ids:
        review_signals.append("ATOMIC_SPAWNED_WORKERS")
    if mode == "atomic" and execution_value.get("trace_status") != "not_applicable":
        review_signals.append("ATOMIC_FABRICATED_ORCHESTRATION_TRACE")

    recommended_mode = "refused" if (
        evidence_value.get("required_authority_available") is False
        or evidence_value.get("safe_resource_ownership_available") is False
    ) else (
        "orchestrated" if lane_count >= 2 and evidence_value.get("coupling") != "high" and not seams else "atomic"
    )
    effective_mode = override_value.get("selected_mode") if override_status == "applied" else mode
    if override_status == "applied" and effective_mode != recommended_mode:
        review_signals.append("RECORDED_OVERRIDE_DIFFERS_FROM_RECOMMENDATION")
    audit_status = "FAIL" if issues else (
        "REVIEW_REQUIRED" if review_signals else "PASS"
    )
    core = {
        "schema": CLASSIFICATION_AUDIT_SCHEMA,
        "status": audit_status,
        "task_id": value.get("task_id"),
        "substantive": value.get("substantive"),
        "invocation_status": invocation_value.get("status"),
        "classification_status": classification_status,
        "recorded_mode": mode,
        "recommended_mode": recommended_mode,
        "effective_mode": effective_mode,
        "confidence_bps": classification_value.get("confidence_bps"),
        "policy_version": policy_value.get("version"),
        "concrete_evidence": {
            "requested_deliverables": deliverables,
            "independent_lane_count": lane_count,
            "shared_mutation_seams": seams,
            "coupling": evidence_value.get("coupling"),
            "decomposition_basis": evidence_value.get("decomposition_basis"),
            "review_pointers": review_pointers,
        },
        "override_applied": override_status == "applied",
        "authority_scope_preserved": override_status != "applied" or override_value.get("authority_scope_sha256") == scope_sha,
        "root_owned": effective_mode == "atomic" and not worker_ids,
        "orchestration_trace_applicable": effective_mode == "orchestrated",
        "review_signals": sorted(set(review_signals)),
        "judgment_not_proof": True,
        "workers_launched": False,
        "issues": sorted(set(issues)),
        "evidence_tier": "submitted",
    }
    return {**core, "audit_sha256": json_sha256(core)}


def compact_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def json_sha256(value):
    return hashlib.sha256(compact_json(value).encode("utf-8")).hexdigest()


def _activation_preparation_unavailable(issue):
    core = {
        "schema": "orch-dork/governed-native-activation-preparation-report/v1",
        "policy_version": "governed-native-activation-preparation-policy/v1",
        "status": "BLOCKED",
        "decision": "REFUSED",
        "issues": [issue],
        "project_adapter_report_sha256": None,
        "project_ground_report_sha256": None,
        "provider_free": True,
        "hosted_calls": 0,
        "model_calls": 0,
        "native_calls": 0,
        "task_creations": 0,
        "worker_creations": 0,
        "credential_reads": 0,
        "authority_grants_minted": 0,
        "native_action_authorizations": 0,
    }
    return {**core, "report_sha256": json_sha256(core)}


_GOVERNED_NATIVE_REPORT_FIELDS = {
    "schema",
    "policy_version",
    "status",
    "decision",
    "controller_id",
    "issues",
    "cursor",
    "stage_report",
    "next_stage_action",
    "action",
    "controller_state",
    "hook_state_sha256",
    "provider_free",
    "hosted_calls",
    "model_calls",
    "native_calls",
    "task_creations",
    "worker_creations",
    "credential_reads",
    "authority_grants_minted",
    "native_action_authorizations",
    "report_sha256",
}
_GOVERNED_NATIVE_ZERO_COUNTERS = (
    "hosted_calls",
    "model_calls",
    "native_calls",
    "task_creations",
    "worker_creations",
    "credential_reads",
    "authority_grants_minted",
)


def _governed_native_controller_unavailable(program, issue):
    controller_id = (
        program.get("controller_id")
        if isinstance(program, dict)
        and isinstance(program.get("controller_id"), str)
        else None
    )
    core = {
        "schema": "orch-dork/governed-native-controller-report/v1",
        "policy_version": "governed-native-controller-policy/v1",
        "status": "BLOCKED",
        "decision": "HOST_ADAPTER_REFUSED",
        "controller_id": controller_id,
        "issues": [issue],
        "cursor": None,
        "stage_report": None,
        "next_stage_action": None,
        "action": None,
        "controller_state": {
            "terminal": False,
            "pending_intent": False,
            "action_outcome": None,
            "action_authorized": False,
            "grant_state": None,
            "cleanup_required": False,
        },
        "hook_state_sha256": None,
        "provider_free": True,
        "hosted_calls": 0,
        "model_calls": 0,
        "native_calls": 0,
        "task_creations": 0,
        "worker_creations": 0,
        "credential_reads": 0,
        "authority_grants_minted": 0,
        "native_action_authorizations": 0,
    }
    return {**core, "report_sha256": json_sha256(core)}


def _successor_first_action_unavailable(issue):
    core = {
        "schema": "orch-dork/qualification-successor-first-action/v1",
        "status": "BLOCKED",
        "decision": "REFUSED",
        "issues": [issue],
        "provider_free": True,
        "hosted_calls": 0,
        "model_calls": 0,
        "native_actions": 0,
        "task_creations": 0,
        "worker_creations": 0,
        "authority_grants_minted": 0,
    }
    return {**core, "report_sha256": json_sha256(core)}


def _successor_first_action_evaluation_issue(evaluator, error):
    stable_type = getattr(
        evaluator, "QualificationSuccessorError", None
    )
    issue = str(error)
    if (
        isinstance(stable_type, type)
        and issubclass(stable_type, Exception)
        and isinstance(error, stable_type)
        and 0 < len(issue) <= 160
        and issue.startswith(
            (
                "predecessor_settlement:",
                "successor_first_action:",
                "successor_first_action_preparation:",
                "successor_pre_turn:",
            )
        )
        and all(
            character.isalnum() or character in "_:-"
            for character in issue
        )
    ):
        return issue
    return "successor_first_action_host_bridge:evaluation_failed"


def _successor_action_advance_unavailable(issue):
    core = {
        "schema": "orch-dork/qualification-successor-action-advance/v2",
        "status": "BLOCKED",
        "decision": "REFUSED",
        "issues": [issue],
        "provider_free": True,
        "hosted_calls": 0,
        "model_calls": 0,
        "native_actions": 0,
        "task_creations": 0,
        "worker_creations": 0,
        "authority_grants_minted": 0,
    }
    return {**core, "report_sha256": json_sha256(core)}


def _successor_action_advance_evaluation_issue(
    evaluator, error, *, prefix="successor_action_advance:"
):
    stable_type = getattr(evaluator, "QualificationSuccessorError", None)
    issue = str(error)
    if (
        isinstance(stable_type, type)
        and issubclass(stable_type, Exception)
        and isinstance(error, stable_type)
        and 0 < len(issue) <= 160
        and issue.startswith(prefix)
        and all(character.isalnum() or character in "_:-" for character in issue)
    ):
        return issue
    return prefix[:-1] + "_host_bridge:evaluation_failed"


def _valid_governed_native_controller_report(report):
    if not isinstance(report, dict) or set(report) != _GOVERNED_NATIVE_REPORT_FIELDS:
        return False
    if (
        report.get("schema") != "orch-dork/governed-native-controller-report/v1"
        or report.get("policy_version") != "governed-native-controller-policy/v1"
        or report.get("status") not in {"PASS", "BLOCKED"}
        or not isinstance(report.get("decision"), str)
        or not report.get("decision")
        or not (
            report.get("controller_id") is None
            or isinstance(report.get("controller_id"), str)
        )
        or report.get("provider_free") is not True
    ):
        return False
    issues = report.get("issues")
    if (
        not isinstance(issues, list)
        or any(not isinstance(issue, str) or not issue for issue in issues)
        or issues != sorted(set(issues))
    ):
        return False
    for field in ("cursor", "stage_report", "action"):
        if report.get(field) is not None and not isinstance(report.get(field), dict):
            return False
    if report.get("next_stage_action") is not None and not isinstance(
        report.get("next_stage_action"), str
    ):
        return False
    controller_state = report.get("controller_state")
    if not isinstance(controller_state, dict) or set(controller_state) != {
        "terminal",
        "pending_intent",
        "action_outcome",
        "action_authorized",
        "grant_state",
        "cleanup_required",
    }:
        return False
    if any(
        type(controller_state.get(field)) is not bool
        for field in (
            "terminal",
            "pending_intent",
            "action_authorized",
            "cleanup_required",
        )
    ):
        return False
    action_count = report.get("native_action_authorizations")
    if (
        type(action_count) is not int
        or action_count not in {0, 1}
        or action_count != (1 if isinstance(report.get("action"), dict) else 0)
        or controller_state.get("action_authorized") != (action_count == 1)
        or any(type(report.get(field)) is not int or report.get(field) != 0 for field in _GOVERNED_NATIVE_ZERO_COUNTERS)
    ):
        return False
    hook_sha256 = report.get("hook_state_sha256")
    if hook_sha256 is not None and (
        not isinstance(hook_sha256, str)
        or len(hook_sha256) != 64
        or any(character not in "0123456789abcdef" for character in hook_sha256)
    ):
        return False
    declared_sha256 = report.get("report_sha256")
    try:
        observed_sha256 = json_sha256(
            {key: value for key, value in report.items() if key != "report_sha256"}
        )
    except (TypeError, ValueError):
        return False
    return declared_sha256 == observed_sha256


def _governed_native_plugin_data():
    configured = os.environ.get("CODEX_HOME")
    codex_home = Path(configured).expanduser() if configured else Path.home() / ".codex"
    if not codex_home.is_absolute() or codex_home.is_symlink():
        raise ValueError("CODEX_HOME must be an absolute non-symlink path")
    return codex_home / "plugins" / "data" / "orch-dork-orch-dork-local"


def _issue94_bootstrap_host_roots(raw_path):
    """Discover producer-sealed roots; the bootstrap reader revalidates them."""

    import orch_dork_owned_file as owned_file

    def read_owned_json(path, *, limit):
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path.is_symlink()
            or path.resolve(strict=True) != path
        ):
            raise ValueError("bootstrap artifact path invalid")
        return owned_file.read_owned_json(path, max_bytes=limit)

    path = Path(raw_path) if isinstance(raw_path, str) else None
    bootstrap = read_owned_json(path, limit=4_194_304)
    roots = bootstrap.get("source_roots") if isinstance(bootstrap, dict) else None
    if not isinstance(roots, dict) or set(roots) != {"source", "evidence"}:
        raise ValueError("bootstrap roots unavailable")
    resolved = _governed_native_source_roots(roots)
    if not path.is_relative_to(resolved["evidence"]):
        raise ValueError("bootstrap artifact outside evidence root")
    reference = bootstrap.get("pre_spawn_artifact")
    pre_path = (
        Path(reference.get("artifact_path"))
        if isinstance(reference, dict)
        else None
    )
    if pre_path is None or not pre_path.is_relative_to(resolved["evidence"]):
        raise ValueError("bootstrap pre-spawn reference invalid")
    pre_spawn = read_owned_json(pre_path, limit=4_194_304)
    enrollment = (
        pre_spawn.get("project_enrollment_report")
        if isinstance(pre_spawn, dict)
        else None
    )
    record_path = (
        Path(enrollment.get("record_path"))
        if isinstance(enrollment, dict)
        else None
    )
    if (
        record_path is None
        or not record_path.is_absolute()
        or record_path.parent.name != "records"
    ):
        raise ValueError("bootstrap enrollment root unavailable")
    registry = record_path.parent.parent
    if (
        registry.is_symlink()
        or registry.resolve(strict=True) != registry
        or not registry.is_dir()
    ):
        raise ValueError("bootstrap enrollment root invalid")
    return {**resolved, "enrollment_registry": registry}


def _valid_bootstrap_review_acknowledgement(
    report, *, arguments, request_meta, current_task_id
):
    try:
        from lifecycle_conformance.host_adapter import mcp_call_context

        context = mcp_call_context(request_meta)
        if not isinstance(report, dict) or set(report) != {
                "schema", "status", "decision", "controller_id", "subject_sha256",
                "submission_sha256", "native_call", "acknowledgement_sha256"
        }:
            return False
        if (
            not isinstance(report.get("controller_id"), str)
            or not report["controller_id"]
            or context["task_id"] != current_task_id
        ):
            return False
        submission = {
            "schema": "orch-dork/qualification-review-submission/v1",
            "subject_sha256": arguments["subject_sha256"],
            "verifications": arguments["verifications"],
        }
        expected = {
            "schema": "orch-dork/qualification-review-acknowledgement/v1",
            "status": "PASS",
            "decision": "REVIEW_SUBMITTED",
            "controller_id": report["controller_id"],
            "subject_sha256": arguments["subject_sha256"],
            "submission_sha256": json_sha256(submission),
            "native_call": context,
        }
        expected["acknowledgement_sha256"] = json_sha256(expected)
        return report == expected
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return False


def _governed_native_source_roots(value):
    if not isinstance(value, dict) or not value:
        raise ValueError("source_roots must be a non-empty object")
    roots = {}
    for name, raw_path in value.items():
        if not isinstance(name, str) or not name or not isinstance(raw_path, str):
            raise ValueError("source root entries must be named paths")
        path = Path(raw_path).expanduser()
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise ValueError("source roots must be absolute non-symlink directories")
        roots[name] = path.resolve(strict=True)
    return roots


def _adaptive_unavailable(schema, issue):
    return {
        "schema": schema,
        "status": "FAIL",
        "valid": False,
        "issues": [issue],
        "normalized": None,
        "digest": None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def evaluate_adaptive_finite_dag(program):
    """Export the provider-free adaptive finite-DAG controller."""

    if adaptive_finite_dag is None:
        return {
            "schema": "orch-dork/adaptive-finite-dag-report/v1",
            "status": "FAIL",
            "decision": "PROGRAM_REJECTED",
            "issues": ["adaptive_finite_dag:evaluator_unavailable"],
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    return adaptive_finite_dag.evaluate_adaptive_finite_dag(program)


def _policy_module_unavailable(schema, issue):
    return {
        "schema": schema,
        "status": "FAIL",
        "decision": "REJECTED",
        "operation": None,
        "issues": [issue],
        "result": None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def evaluate_evidence_policy(program):
    """Export the provider-free evidence-integrity evaluator."""

    if evidence_policy is None:
        return _policy_module_unavailable(
            "orch-dork/evidence-policy-report/v1",
            "evidence_policy:evaluator_unavailable",
        )
    return evidence_policy.evaluate_evidence_policy(program)


def evaluate_route_policy(program):
    """Export the provider-free route-integrity evaluator."""

    if route_policy is None:
        return _policy_module_unavailable(
            "orch-dork/route-policy-report/v1",
            "route_policy:evaluator_unavailable",
        )
    return route_policy.evaluate_route_policy(program)


def evaluate_campaign_policy(program):
    """Export the provider-free campaign-integrity evaluator."""

    if campaign_policy is None:
        return _policy_module_unavailable(
            "orch-dork/campaign-policy-report/v1",
            "campaign_policy:evaluator_unavailable",
        )
    return campaign_policy.evaluate_campaign_policy(program)


def evaluate_experiment_campaign(program):
    if experiment_campaign is None:
        return {
            "schema": "orch-dork/experiment-campaign-report/v1",
            "operation": "unknown",
            "status": "FAIL",
            "issues": ["experiment_campaign:evaluator_unavailable"],
            "result": None,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "runs_executed": 0,
            "default_changed": False,
        }
    return experiment_campaign.evaluate_experiment_campaign(program)


def validate_task_spec(value, *, authorized_write_scope=None):
    """Export the canonical provider-free ``TaskSpecV2`` validator."""

    if adaptive_contracts is None:
        return _adaptive_unavailable(
            "orch-dork/adaptive-contract-validation/v1",
            "task_spec:validator_unavailable",
        )
    return adaptive_contracts.validate_task_spec(
        value,
        authorized_write_scope=authorized_write_scope,
    )


def validate_artifact_ref(value):
    """Export the canonical provider-free ``ArtifactRefV1`` validator."""

    if adaptive_contracts is None:
        return _adaptive_unavailable(
            "orch-dork/adaptive-contract-validation/v1",
            "artifact_ref:validator_unavailable",
        )
    return adaptive_contracts.validate_artifact_ref(value)


def validate_handoff_receipt(value, *, task_spec=None):
    """Export the canonical provider-free ``HandoffReceiptV1`` validator."""

    if adaptive_contracts is None:
        return _adaptive_unavailable(
            "orch-dork/adaptive-contract-validation/v1",
            "handoff:validator_unavailable",
        )
    return adaptive_contracts.validate_handoff_receipt(value, task_spec=task_spec)


def validate_verification_receipt(
    value,
    *,
    task_spec=None,
    handoff_receipt=None,
):
    """Export the canonical provider-free ``VerificationReceiptV1`` validator."""

    if adaptive_contracts is None:
        return _adaptive_unavailable(
            "orch-dork/adaptive-contract-validation/v1",
            "verification:validator_unavailable",
        )
    return adaptive_contracts.validate_verification_receipt(
        value,
        task_spec=task_spec,
        handoff_receipt=handoff_receipt,
    )


def validate_claim_ledger(value, *, task_spec=None):
    """Export the canonical provider-free ``ClaimLedgerV1`` validator."""

    if adaptive_contracts is None:
        return _adaptive_unavailable(
            "orch-dork/adaptive-contract-validation/v1",
            "claim_ledger:validator_unavailable",
        )
    return adaptive_contracts.validate_claim_ledger(value, task_spec=task_spec)


def validate_incremental_claim_packet(value, *, task_spec=None):
    """Export the compact, budget-bound incremental evidence validator."""

    if adaptive_contracts is None:
        return _adaptive_unavailable(
            "orch-dork/adaptive-contract-validation/v1",
            "incremental:validator_unavailable",
        )
    return adaptive_contracts.validate_incremental_claim_packet(
        value,
        task_spec=task_spec,
    )


def validate_handoff_preflight(value, *, task_spec=None):
    """Export the runtime-observed typed-output canary gate."""

    if adaptive_contracts is None:
        report = _adaptive_unavailable(
            "orch-dork/adaptive-contract-validation/v1",
            "preflight:validator_unavailable",
        )
        report["spawn_permitted"] = False
        return report
    return adaptive_contracts.validate_handoff_preflight(
        value,
        task_spec=task_spec,
    )


def validate_handoff_preflight_candidate(value, *, task_spec=None):
    """Export the worker-authored, observer-enriched canary candidate gate."""

    if adaptive_contracts is None:
        report = _adaptive_unavailable(
            "orch-dork/adaptive-contract-validation/v1",
            "preflight_candidate:validator_unavailable",
        )
        report.update({"candidate_valid": False, "spawn_permitted": False})
        return report
    return adaptive_contracts.validate_handoff_preflight_candidate(
        value,
        task_spec=task_spec,
    )


def validate_adaptive_contract(
    contract_kind,
    value,
    *,
    task_spec=None,
    handoff_receipt=None,
    authorized_write_scope=None,
):
    """Route one closed contract kind to its canonical public validator."""

    route = ADAPTIVE_CONTRACT_REGISTRY.get(contract_kind)
    if route is None:
        raise ValueError("adaptive_contract:unknown_kind")
    supplied = {
        "task_spec": task_spec,
        "handoff_receipt": handoff_receipt,
        "authorized_write_scope": authorized_write_scope,
    }
    kwargs = {
        key: supplied[key]
        for key in route["allowed_arguments"]
        if supplied[key] is not None
    }
    validator = globals()[route["validator"]]
    return validator(value, **kwargs)


def _closed_status(value):
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if normalized in {
        "running", "completed", "errored", "interrupted", "shutdown",
        "pending_init", "not_found",
    } else None


def _reserve_shared_admission_authority(
    *,
    plan,
    plan_sha256,
    logical,
    root_thread_id,
    run_id,
    lane_ids,
    configured_cap,
    observed_free_slots,
    authority_state_reader,
    authority_state_committer,
):
    result = {
        "status": "NOT_CONFIGURED",
        "reason_codes": [],
        "run_id": run_id,
        "lane_ids": [],
        "queued_lane_ids": [],
        "historical_lane_ids": [],
        "authority_lane_ids": [],
        "state_sha256": None,
        "store_id": None,
    }
    if authority_state_reader is None and authority_state_committer is None:
        return result
    if (
        capacity_inventory is None
        or not callable(authority_state_reader)
        or not callable(authority_state_committer)
        or not _is_nonempty_string(run_id)
        or not _is_nonempty_string(root_thread_id)
    ):
        result.update(
            status="REFUSED",
            reason_codes=["authority:adapter_or_identity_invalid"],
        )
        return result
    shared = capacity_inventory.shared_capacity
    try:
        authority_read = authority_state_reader()
        if (
            not isinstance(authority_read, dict)
            or authority_read.get("status") != "VERIFIED"
            or authority_read.get("continuity_verified") is not True
        ):
            raise ValueError("authority:read_unverified")
        base_state = authority_read.get("state")
        authority = shared.validate_authority_state(base_state)
        if authority.get("status") != "RESOLVED":
            raise ValueError("authority:state_invalid")
        if (
            type(configured_cap) is not int
            or configured_cap < 1
            or configured_cap > shared.MAX_CONCURRENT_LANES
        ):
            raise ValueError("capacity:max_concurrent_lanes_reached")
        if type(observed_free_slots) is not int or observed_free_slots < 0:
            raise ValueError("capacity:observed_free_slots_invalid")
        ledger_bindings = authority.get("ledger", {}).get("bindings", {})
        historical_lane_ids = sorted(
            node_id
            for node_id in lane_ids
            if (
                str(run_id) + ":" + str(node_id) in ledger_bindings
                and ledger_bindings[str(run_id) + ":" + str(node_id)]
                == {"run_id": run_id, "route": "native_luna"}
            )
        ) if logical else []
        eligible_lane_ids = sorted(set(lane_ids) - set(historical_lane_ids))
        available_slots = min(
            observed_free_slots,
            configured_cap - len(authority["active_lane_ids"]),
        )
        selected_lane_ids = eligible_lane_ids[: max(0, available_slots)]
        queued_lane_ids = sorted(set(eligible_lane_ids) - set(selected_lane_ids))
        if eligible_lane_ids and not selected_lane_ids:
            result.update(
                status="QUEUED",
                reason_codes=["capacity:max_concurrent_lanes_reached"],
                queued_lane_ids=queued_lane_ids,
                historical_lane_ids=historical_lane_ids,
            )
            return result

        current_node_count = (
            plan.get("logical_worker_count")
            if logical and isinstance(plan, dict)
            else ((plan or {}).get("children") or {}).get("expected_count")
        )
        task_node_budget = (
            plan.get("task_node_budget", current_node_count)
            if logical and isinstance(plan, dict)
            else current_node_count
        )
        plan_revision = plan.get("revision") if logical else 1
        if (
            type(task_node_budget) is not int
            or type(current_node_count) is not int
            or task_node_budget < current_node_count
            or task_node_budget < len(selected_lane_ids)
            or type(plan_revision) is not int
            or plan_revision < 1
        ):
            raise ValueError("authority:plan_budget_invalid")

        state = base_state
        run = authority["runs"].get(run_id)
        if run is None:
            if plan_revision != 1:
                raise ValueError("authority:initial_revision_invalid")
            registered = shared.register_run_authority(
                state,
                run_id=run_id,
                root_thread_id=root_thread_id,
                task_node_budget=task_node_budget,
                plan_sha256=plan_sha256,
            )
            if registered.get("status") != "REGISTERED":
                raise ValueError("authority:run_registration_failed")
            state = registered["state"]
        else:
            if (
                run.get("root_thread_id") != root_thread_id
                or run.get("task_node_budget") != task_node_budget
            ):
                raise ValueError("authority:run_binding_mismatch")
            current_plan = run.get("plan_revisions", [])[-1]
            requested_plan = {
                "revision": plan_revision,
                "plan_sha256": plan_sha256,
            }
            if current_plan != requested_plan:
                predecessor = (
                    plan.get("predecessor_plan_sha256")
                    if logical and isinstance(plan, dict)
                    else None
                )
                if (
                    plan_revision != current_plan.get("revision", 0) + 1
                    or predecessor != current_plan.get("plan_sha256")
                ):
                    raise ValueError("authority:run_binding_mismatch")
                revised = shared.revise_run_authority(
                    state,
                    run_id=run_id,
                    predecessor_plan_sha256=current_plan["plan_sha256"],
                    successor_plan_sha256=plan_sha256,
                )
                if revised.get("status") != "REVISED":
                    raise ValueError("authority:run_revision_failed")
                state = revised["state"]

        authority_lane_ids = []
        for node_id in selected_lane_ids:
            lane_id = str(run_id) + ":" + str(node_id)
            reserved = shared.reserve_authority_lane(
                state,
                lane_id=lane_id,
                run_id=run_id,
                route="native_luna",
                plan_revision=plan_revision,
                plan_sha256=plan_sha256,
            )
            if reserved.get("status") != "RESERVED":
                reason = (reserved.get("reason_codes") or [
                    "authority:lane_reservation_failed"
                ])[0]
                raise ValueError(reason)
            state = reserved["state"]
            authority_lane_ids.append(lane_id)
        successor = shared.collapse_authority_transition(base_state, state)
        committed = authority_state_committer(successor)
        commit_ok = (
            isinstance(committed, dict)
            and committed.get("status") == "COMMITTED"
            and committed.get("state_sha256")
            == successor.get("state_sha256")
            and committed.get("reason_codes", []) == []
        )
        if not commit_ok:
            raise ValueError("authority:commit_conflict")
        authority_readback = authority_state_reader()
        readback = shared.validate_authority_state(
            authority_readback.get("state")
            if isinstance(authority_readback, dict)
            else None
        )
        if (
            not isinstance(authority_readback, dict)
            or authority_readback.get("status") != "VERIFIED"
            or authority_readback.get("continuity_verified") is not True
            or authority_readback.get("state_sha256")
            != successor.get("state_sha256")
            or readback.get("status") != "RESOLVED"
            or not set(authority_lane_ids)
            <= readback.get("active_lane_ids", set())
            or any(
                readback.get("ledger", {}).get("bindings", {}).get(lane_id)
                != {"run_id": run_id, "route": "native_luna"}
                for lane_id in authority_lane_ids
            )
        ):
            raise ValueError("authority:commit_readback_mismatch")
    except Exception as exc:
        reason = str(exc) or "authority:reservation_failed"
        result.update(status="REFUSED", reason_codes=[reason])
        return result
    result.update(
        status=("COMMITTED" if selected_lane_ids else "COMMITTED_NO_READY_LANES"),
        run_id=run_id,
        lane_ids=selected_lane_ids,
        queued_lane_ids=queued_lane_ids,
        historical_lane_ids=historical_lane_ids,
        authority_lane_ids=authority_lane_ids,
        state_sha256=successor["state_sha256"],
        store_id=authority_readback.get("store_id"),
    )
    return result


def validate_admission(
    plan,
    inventory,
    *,
    current_turn_route_report=None,
    run_id=None,
    authority_state_reader=None,
    authority_state_committer=None,
):
    """Admit a complete fresh wave before plan freeze or any spawn.

    The caller supplies the exact read-only inventory it observed. Terminal
    status alone never frees a lane: active-only accounting releases it only
    when the host-signed observation includes exact lane/run/route-bound
    cleanup proof.
    """

    logical = (
        isinstance(plan, dict)
        and plan.get("schema") == "orch-dork/logical-plan/v1"
    )
    if logical and efficiency_governor is not None:
        plan_report = efficiency_governor.validate_logical_plan(plan)
    else:
        plan_report = validate_plan(
            plan,
            current_turn_route_report=current_turn_route_report,
        )
    issues = ["plan:" + issue for issue in plan_report["issues"]]
    inventory_value = inventory if isinstance(inventory, dict) else {}
    if logical:
        expected_root = (
            (plan or {}).get("planner", {}).get("root_thread_id")
            if isinstance((plan or {}).get("planner"), dict)
            else None
        )
    else:
        expected_root = (
            (plan or {}).get("root", {}).get("thread_id")
            if isinstance(plan, dict) and isinstance((plan or {}).get("root"), dict)
            else None
        )
    if capacity_inventory is None:
        capacity_projection = evidence_core.capacity_authority_projection(None)
        inventory_report = {
            "issues": ["admission:capacity_inventory_unavailable"],
            "root_thread_id": inventory_value.get("root_thread_id"),
            "capacity": 0,
            "retirement_supported": False,
            "occupied_slots": 0,
            "free_slots": 0,
            "occupied_worker_ids": [],
            "released_terminal_worker_ids": [],
            "unreleased_terminal_worker_ids": [],
            **capacity_projection,
            "inventory_sha256": json_sha256(inventory_value),
            "input_schema": inventory_value.get("schema"),
        }
    else:
        inventory_report = capacity_inventory.evaluate_capacity_evidence(
            inventory,
            root_thread_id=expected_root,
            label="inventory",
        )
    capacity_projection = (
        capacity_inventory.capacity_authority_projection(inventory_report)
        if capacity_inventory is not None
        else capacity_projection
    )
    issues.extend(inventory_report.get("issues", []))
    root_thread_id = inventory_report.get("root_thread_id")
    capacity = inventory_report.get("capacity", 0)
    retirement_supported = inventory_report.get("retirement_supported", False)
    occupied = inventory_report.get("occupied_slots", 0)
    stale = inventory_report.get("occupied_worker_ids", [])
    released_terminals = inventory_report.get(
        "released_terminal_worker_ids", []
    )
    unreleased_terminals = inventory_report.get(
        "unreleased_terminal_worker_ids", []
    )
    free_slots = inventory_report.get("free_slots", max(0, capacity - occupied))
    ready_worker_ids = []
    queued_worker_ids = []
    if logical:
        ready_worker_ids = sorted(
            worker.get("id")
            for worker in (plan.get("workers") or [])
            if isinstance(worker, dict)
            and worker.get("executor") == "subagent"
            and not worker.get("dependencies")
            and isinstance(worker.get("id"), str)
        )
        reservable_lane_ids = ready_worker_ids
        expected = min(len(ready_worker_ids), max(0, free_slots))
    else:
        expected = (
            ((plan or {}).get("children") or {}).get("expected_count")
            if isinstance(plan, dict)
            else None
        )
    if not logical and type(expected) is int and free_slots < expected:
        issues.append("admission:insufficient_free_slots:%d<%d" % (free_slots, expected))
    reservable_lane_ids = (
        reservable_lane_ids
        if logical
        else sorted(
            lane.get("id")
            for lane in ((plan or {}).get("lanes") or [])
            if isinstance(lane, dict) and isinstance(lane.get("id"), str)
        )
    )
    authority_reservation = (
        {
            "status": "NOT_ATTEMPTED",
            "reason_codes": [],
            "run_id": run_id,
            "lane_ids": [],
            "queued_lane_ids": [],
            "historical_lane_ids": [],
            "authority_lane_ids": [],
            "state_sha256": None,
            "store_id": None,
        }
        if issues
        else _reserve_shared_admission_authority(
            plan=plan,
            plan_sha256=plan_report["plan_sha256"],
            logical=logical,
            root_thread_id=root_thread_id,
            run_id=run_id,
            lane_ids=reservable_lane_ids,
            configured_cap=capacity,
            observed_free_slots=free_slots,
            authority_state_reader=authority_state_reader,
            authority_state_committer=authority_state_committer,
        )
    )
    if authority_reservation["status"] == "REFUSED":
        issues.extend(
            "admission:" + code
            for code in authority_reservation["reason_codes"]
        )
    status = "PASS" if not issues else "FAIL"
    return {
        "schema": ADMISSION_SCHEMA,
        "kind": "admission",
        "status": status,
        "admitted": status == "PASS",
        "issues": sorted(set(issues)),
        "plan_sha256": plan_report["plan_sha256"],
        "inventory_sha256": inventory_report.get(
            "inventory_sha256", json_sha256(inventory_value)
        ),
        "root_thread_id": root_thread_id,
        "capacity": capacity,
        "max_concurrent_lanes": inventory_report.get(
            "max_concurrent_lanes", 32
        ),
        "capacity_basis": inventory_report.get(
            "capacity_basis", "instantaneous_occupancy"
        ),
        "cumulative_lane_limit": inventory_report.get(
            "cumulative_lane_limit"
        ),
        "root_counts_toward_lane_capacity": inventory_report.get(
            "root_counts_toward_lane_capacity", False
        ),
        "occupied_slots": occupied,
        "free_slots": free_slots,
        "required_slots": expected,
        "ready_worker_ids": ready_worker_ids if logical else [],
        "admitted_worker_ids": authority_reservation["lane_ids"] if logical else [],
        "queued_worker_ids": (
            sorted(
                set(ready_worker_ids)
                - set(authority_reservation.get("lane_ids", []))
                - set(authority_reservation.get("historical_lane_ids", []))
            )
            if logical
            else []
        ),
        "execution_profile": (
            plan_report.get("execution_profile") if logical else None
        ),
        "retirement_supported": retirement_supported,
        "occupied_worker_ids": sorted(stale),
        "released_terminal_worker_ids": sorted(released_terminals),
        "unreleased_terminal_worker_ids": sorted(unreleased_terminals),
        "inventory_schema": inventory_report.get("input_schema"),
        **capacity_projection,
        "admission_scope": (
            "authoritative"
            if inventory_report.get("capacity_authoritative") is True
            else "advisory"
        ),
        "worker_reuse_permitted": False,
        "authority_reservation_status": authority_reservation["status"],
        "authority_run_id": authority_reservation["run_id"],
        "authority_reserved_lane_ids": authority_reservation["lane_ids"],
        "authority_lane_ids": authority_reservation["authority_lane_ids"],
        "authority_state_sha256": authority_reservation["state_sha256"],
        "authority_store_id": authority_reservation["store_id"],
        "spawn_authority_permitted": (
            status == "PASS"
            and authority_reservation["status"] == "COMMITTED"
        ),
        "next_step": (
            "run_logical_worker_waves"
            if status == "PASS"
            and logical
            and authority_reservation["status"] == "COMMITTED"
            else "validate_spawn_wave"
            if status == "PASS"
            and authority_reservation["status"] == "COMMITTED"
            else "wait_for_dependency_ready_lane"
            if status == "PASS"
            and logical
            and authority_reservation["status"]
            == "COMMITTED_NO_READY_LANES"
            else "wait_for_capacity"
            if status == "PASS"
            and logical
            and authority_reservation["status"] == "QUEUED"
            else "commit_shared_capacity_reservation"
            if status == "PASS"
            else "abort_before_freeze"
        ),
        "evidence_tier": (
            "runtime-observed-inventory"
            if inventory_report.get("capacity_authoritative") is True
            else "submitted-inventory"
        ),
    }


def adapt_native_spawn_result(receipt):
    """Copy one explicit native creation receipt into the canonical wire shape.

    The adapter deliberately supplies no defaults.  Lane, worker, status,
    freshness, and parent identity must all be present in the observed input;
    a stringified object or incomplete receipt produces no result.
    """

    issues = []
    _check_exact_keys(receipt, SPAWN_RESULT_FIELDS, "receipt", issues)
    value = receipt if isinstance(receipt, dict) else {}
    for field in ("lane_id", "worker_id", "parent_thread_id"):
        if not _is_nonempty_string(value.get(field)):
            issues.append("receipt:%s_invalid" % field)
    if value.get("status") not in SPAWN_RESULT_STATUSES:
        issues.append("receipt:status_invalid")
    if type(value.get("fresh")) is not bool:
        issues.append("receipt:fresh_invalid")
    canonical = (
        {
            "lane_id": value["lane_id"],
            "worker_id": value["worker_id"],
            "status": value["status"],
            "fresh": value["fresh"],
            "parent_thread_id": value["parent_thread_id"],
        }
        if not issues
        else None
    )
    return {
        "schema": SPAWN_RESULT_ADAPTER_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "result": canonical,
        "result_sha256": json_sha256(canonical) if canonical is not None else None,
        "defaults_applied": False,
        "freshness_inferred": False,
        "parent_identity_synthesized": False,
    }


def validate_spawn_wave(
    plan,
    admission,
    results,
    *,
    current_turn_route_report=None,
    authority_state_reader=None,
    structural_replay=False,
):
    """Bind one fresh creation result to every lane or abort the attempt.

    ``structural_replay`` validates archived compatibility receipts without
    granting spawn authority or consulting/mutating the live capacity owner.
    It is not an execution admission path.
    """

    plan_report = validate_plan(
        plan,
        current_turn_route_report=current_turn_route_report,
    )
    issues = ["plan:" + issue for issue in plan_report["issues"]]
    admission_value = admission if isinstance(admission, dict) else {}
    if (
        admission_value.get("schema") != ADMISSION_SCHEMA
        or admission_value.get("status") != "PASS"
        or admission_value.get("admitted") is not True
        or admission_value.get("plan_sha256") != plan_report["plan_sha256"]
    ):
        issues.append("spawn_wave:admission_invalid")
    values = results if isinstance(results, list) else []
    if not isinstance(results, list):
        issues.append("spawn_wave:results_not_array")
    planned = {
        lane.get("id") for lane in (plan.get("lanes", []) if isinstance(plan, dict) else [])
        if isinstance(lane, dict)
    }
    authority_lane_ids = admission_value.get("authority_lane_ids")
    authority_run_id = admission_value.get("authority_run_id")
    if type(structural_replay) is not bool:
        issues.append("spawn_wave:structural_replay_invalid")
    elif not structural_replay:
        if (
            admission_value.get("authority_reservation_status") != "COMMITTED"
            or admission_value.get("spawn_authority_permitted") is not True
            or not isinstance(authority_lane_ids, list)
            or len(authority_lane_ids) != len(planned)
            or not callable(authority_state_reader)
        ):
            issues.append("spawn_wave:authority_reservation_missing")
        else:
            try:
                authority_read = authority_state_reader()
                shared = capacity_inventory.shared_capacity
                authority = shared.validate_authority_state(
                    authority_read.get("state")
                    if isinstance(authority_read, dict)
                    else None
                )
                bindings = authority.get("ledger", {}).get("bindings", {})
                active = authority.get("active_lane_ids", set())
                expected_authority_lanes = {
                    str(authority_run_id) + ":" + str(lane_id)
                    for lane_id in planned
                }
                if (
                    not isinstance(authority_read, dict)
                    or authority_read.get("status") != "VERIFIED"
                    or authority_read.get("continuity_verified") is not True
                    or authority.get("status") != "RESOLVED"
                    or set(authority_lane_ids) != expected_authority_lanes
                    or not expected_authority_lanes <= active
                    or any(
                        bindings.get(lane_id)
                        != {"run_id": authority_run_id, "route": "native_luna"}
                        for lane_id in expected_authority_lanes
                    )
                ):
                    raise ValueError
            except (AttributeError, KeyError, TypeError, ValueError):
                issues.append("spawn_wave:authority_reservation_invalid")
    lane_counts = {}
    worker_ids = set()
    members = []
    for index, result in enumerate(values):
        path = "results[%d]" % index
        _check_exact_keys(
            result,
            SPAWN_RESULT_FIELDS,
            path,
            issues,
        )
        if not isinstance(result, dict):
            continue
        lane_id = result.get("lane_id")
        worker_id = result.get("worker_id")
        if not _is_nonempty_string(lane_id):
            issues.append("%s:lane_id_invalid" % path)
        if result.get("status") not in SPAWN_RESULT_STATUSES:
            issues.append("%s:status_invalid" % path)
        if type(result.get("fresh")) is not bool:
            issues.append("%s:fresh_invalid" % path)
        if not _is_nonempty_string(result.get("parent_thread_id")):
            issues.append("%s:parent_thread_id_invalid" % path)
        lane_counts[lane_id] = lane_counts.get(lane_id, 0) + 1
        if lane_id not in planned:
            issues.append("spawn_wave:unknown_lane:%s" % lane_id)
        if not _is_nonempty_string(worker_id) or worker_id in worker_ids:
            issues.append("spawn_wave:worker_identity_invalid:%s" % lane_id)
        else:
            worker_ids.add(worker_id)
        if result.get("status") != "created":
            issues.append("spawn_wave:creation_not_confirmed:%s" % lane_id)
        if result.get("fresh") is not True:
            issues.append("spawn_wave:worker_not_fresh:%s" % lane_id)
        if result.get("parent_thread_id") != admission_value.get("root_thread_id"):
            issues.append("spawn_wave:parent_mismatch:%s" % lane_id)
        if (
            lane_id in planned
            and _is_nonempty_string(worker_id)
            and result.get("status") == "created"
            and result.get("fresh") is True
            and result.get("parent_thread_id") == admission_value.get("root_thread_id")
        ):
            members.append({"lane_id": lane_id, "worker_id": worker_id})
    for lane_id in sorted(planned):
        count = lane_counts.get(lane_id, 0)
        if count != 1:
            issues.append("spawn_wave:lane_result_count:%s:%d" % (lane_id, count))
    if len(values) != len(planned):
        issues.append("spawn_wave:result_count:%d!=%d" % (len(values), len(planned)))
    status = "PASS" if not issues else "FAIL"
    return {
        "schema": SPAWN_WAVE_SCHEMA,
        "kind": "spawn_wave",
        "status": status,
        "complete": status == "PASS",
        "attempt_state": "admitted" if status == "PASS" else "aborted_partial_wave",
        "issues": sorted(set(issues)),
        "plan_sha256": plan_report["plan_sha256"],
        "admission_sha256": json_sha256(admission_value),
        "results_sha256": json_sha256(values),
        "members": sorted(members, key=lambda item: item["lane_id"]) if status == "PASS" else [],
        "replacement_permitted": False,
        "reuse_permitted": False,
        "spawn_authority_permitted": status == "PASS" and not structural_replay,
        "replay_only": structural_replay is True,
        "evidence_tier": "submitted-collaboration-receipts",
    }


def _is_nonempty_string(value):
    return isinstance(value, str) and bool(value.strip())


def _check_exact_keys(value, required, path, issues):
    if not isinstance(value, dict):
        issues.append(path + ":not_object")
        return False
    missing = sorted(required - set(value))
    extra = sorted(set(value) - required)
    for key in missing:
        issues.append(path + ":missing:" + key)
    for key in extra:
        issues.append(path + ":unknown:" + str(key))
    return not missing and not extra


def _check_string_list(value, path, issues, allow_empty=True):
    if not isinstance(value, list):
        issues.append(path + ":not_array")
        return []
    if not allow_empty and not value:
        issues.append(path + ":empty")
    result = []
    for index, item in enumerate(value):
        if not _is_nonempty_string(item):
            issues.append("%s[%d]:not_nonempty_string" % (path, index))
        else:
            result.append(item.strip())
    if len(set(result)) != len(result):
        issues.append(path + ":duplicates")
    return result


def validate_plan(plan, *, current_turn_route_report=None):
    issues = []
    normalized_route = None
    if current_turn_route_report is not None:
        if current_turn_route is None:
            issues.append("routing:adapter_unavailable")
        else:
            route_validation = current_turn_route.validate_current_turn_route(
                current_turn_route_report
            )
            if route_validation.get("status") != "PASS":
                issues.append("routing:report_invalid")
                issues.extend(route_validation.get("issues", []))
            else:
                normalized_route = route_validation.get("normalized")
    if not _check_exact_keys(plan, PLAN_KEYS, "plan", issues):
        plan_value = plan if isinstance(plan, dict) else {}
    else:
        plan_value = plan

    if plan_value.get("schema") != PLAN_SCHEMA:
        issues.append("plan:schema_invalid")

    decision = plan_value.get("decision")
    _check_exact_keys(decision, {"mode", "reason"}, "decision", issues)
    mode = decision.get("mode") if isinstance(decision, dict) else None
    if mode not in {"atomic", "orchestrated", "refused"}:
        issues.append("decision:mode_invalid")
    if not isinstance(decision, dict) or not _is_nonempty_string(decision.get("reason")):
        issues.append("decision:reason_invalid")

    root = plan_value.get("root")
    _check_exact_keys(
        root,
        {"model", "effort", "coordination_only_after_freeze"},
        "root",
        issues,
    )
    if isinstance(root, dict):
        if not _is_nonempty_string(root.get("model")):
            issues.append("root:model_invalid")
        if root.get("effort") not in REASONING_EFFORTS:
            issues.append("root:effort_invalid")
        if not isinstance(root.get("coordination_only_after_freeze"), bool):
            issues.append("root:coordination_flag_invalid")

    if isinstance(normalized_route, dict) and isinstance(root, dict):
        observed_root = normalized_route.get("root")
        if isinstance(observed_root, dict):
            if root.get("model") != observed_root.get("model"):
                issues.append("root:model_not_current_turn")
            if root.get("effort") != observed_root.get("effort"):
                issues.append("root:effort_not_current_turn")

    children = plan_value.get("children")
    _check_exact_keys(
        children,
        {
            "expected_count",
            "max_concurrency",
            "max_depth",
            "context_policy",
            "model",
            "effort",
            "retries_allowed",
            "fallbacks_allowed",
        },
        "children",
        issues,
    )
    child_count = children.get("expected_count") if isinstance(children, dict) else None
    if isinstance(children, dict):
        for field in (
            "expected_count",
            "max_concurrency",
            "max_depth",
            "retries_allowed",
            "fallbacks_allowed",
        ):
            if type(children.get(field)) is not int:
                issues.append("children:%s_not_integer" % field)

    lanes = plan_value.get("lanes")
    if not isinstance(lanes, list):
        issues.append("lanes:not_array")
        lanes = []

    lane_ids = []
    resource_owners = {}
    for index, lane in enumerate(lanes):
        path = "lanes[%d]" % index
        _check_exact_keys(
            lane,
            {
                "id",
                "objective",
                "deliverables",
                "owned_resources",
                "excluded_resources",
                "dependencies",
                "verification",
            },
            path,
            issues,
        )
        if not isinstance(lane, dict):
            continue
        lane_id = lane.get("id")
        if not _is_nonempty_string(lane_id):
            issues.append(path + ":id_invalid")
            lane_id = "<invalid-%d>" % index
        else:
            lane_id = lane_id.strip()
            lane_ids.append(lane_id)
        if not _is_nonempty_string(lane.get("objective")):
            issues.append(path + ":objective_invalid")
        deliverables = _check_string_list(
            lane.get("deliverables"), path + ".deliverables", issues, False
        )
        owned = _check_string_list(
            lane.get("owned_resources"), path + ".owned_resources", issues, False
        )
        # A lane's declared deliverable must sit inside that lane's own
        # owned_resources. Custody derives lane scope from owned_resources
        # alone, so a deliverable declared outside it makes every required
        # write an out-of-scope access -- a contradiction that otherwise only
        # surfaces after the wave runs. The rule is shared with
        # efficiency_governor.validate_logical_plan so both plan schemas
        # judge the same plan identically; it originally landed only there,
        # which left this surface -- the one behind
        # validate_orchestration_plan -- ungated.
        if ownership is not None:
            for offset, reason in ownership.deliverables_outside_ownership(
                deliverables, owned
            ):
                issues.append("%s.deliverables[%d]:%s" % (path, offset, reason))
        _check_string_list(lane.get("excluded_resources"), path + ".excluded_resources", issues)
        _check_string_list(lane.get("dependencies"), path + ".dependencies", issues)
        _check_string_list(lane.get("verification"), path + ".verification", issues, False)
        for resource in owned:
            previous = resource_owners.get(resource)
            resource_mode = "read" if resource.startswith("read:") else "write"
            if previous is not None and previous[0] != lane_id:
                if not (previous[1] == resource_mode == "read"):
                    issues.append(
                        "lanes:resource_overlap:%s:%s:%s"
                        % (resource, previous[0], lane_id)
                    )
            resource_owners[resource] = (lane_id, resource_mode)

    if len(set(lane_ids)) != len(lane_ids):
        issues.append("lanes:duplicate_ids")
    known_ids = set(lane_ids)
    dependency_program_declared = False
    for index, lane in enumerate(lanes):
        if not isinstance(lane, dict):
            continue
        for dependency in lane.get("dependencies", []):
            dependency_program_declared = True
            if dependency not in known_ids:
                issues.append("lanes[%d]:unknown_dependency:%s" % (index, dependency))
            if dependency == lane.get("id"):
                issues.append("lanes[%d]:self_dependency" % index)
    # plan/v1 is the compatibility surface for the first-completed-worker
    # choreography.  It has no dependency scheduler, so accepting a sealed
    # edge here would turn that edge into decorative evidence: qualification
    # could still pass when the dependent lane completed first.  Dependency
    # programs belong to finite_dag/v1 under logical-plan/v1, where the wave
    # controller computes ready sets and preserves pending nodes on WAITING.
    if dependency_program_declared:
        issues.append(
            "orchestrated:dependencies_require_finite_dag_logical_plan"
        )

    integration = plan_value.get("integration")
    _check_exact_keys(
        integration,
        {"strategy", "release_required", "final_verification"},
        "integration",
        issues,
    )
    final_verification = []
    if isinstance(integration, dict):
        final_verification = _check_string_list(
            integration.get("final_verification"),
            "integration.final_verification",
            issues,
        )
        if not isinstance(integration.get("release_required"), bool):
            issues.append("integration:release_flag_invalid")

    _check_string_list(
        plan_value.get("protected_resources"), "protected_resources", issues
    )
    _check_string_list(
        plan_value.get("acceptance_criteria"), "acceptance_criteria", issues, False
    )

    if plan_closure is None:
        closure_report = {
            "status": "FAIL",
            "closed": False,
            "freeze_permitted": False,
            "spawn_permitted": False,
            "issues": ["closure:validator_unavailable"],
            "binding": {},
        }
    else:
        try:
            closure_report = plan_closure.validate_acceptance_resource_closure(
                plan_value
            )
        except Exception:
            closure_report = {
                "status": "FAIL",
                "closed": False,
                "freeze_permitted": False,
                "spawn_permitted": False,
                "issues": ["closure:analysis_failed"],
                "binding": {},
            }
    issues.extend(closure_report.get("issues", []))

    if ownership is None:
        issues.append("ownership:analyzer_unavailable")
    elif isinstance(plan_value, dict):
        try:
            ownership_report = ownership.analyze_ownership(plan_value)
        except Exception:
            issues.append("ownership:analysis_failed")
        else:
            issues.extend(ownership_report.get("issues", []))

    if mode == "atomic":
        if child_count != 0:
            issues.append("atomic:child_count_not_zero")
        if lanes:
            issues.append("atomic:lanes_not_empty")
        if isinstance(root, dict) and root.get("coordination_only_after_freeze") is not False:
            issues.append("atomic:root_coordination_only")
        if isinstance(children, dict):
            if children.get("max_concurrency") != 0:
                issues.append("atomic:max_concurrency_not_zero")
            if children.get("max_depth") != 0:
                issues.append("atomic:max_depth_not_zero")
        if isinstance(integration, dict):
            if integration.get("strategy") != "none":
                issues.append("atomic:integration_not_none")
            if integration.get("release_required") is not False:
                issues.append("atomic:release_required")
            if final_verification:
                issues.append("atomic:final_verification_not_empty")
    elif mode == "orchestrated":
        if isinstance(normalized_route, dict):
            issues.extend(normalized_route.get("issues", []))
        # Issue 114: one lane is a sanctioned degenerate wave (G10/FR49 —
        # the sizer must be free to answer N=1); the sole lane is its own
        # integrator. Two through four remain the ordinary band.
        if type(child_count) is not int or not 1 <= child_count <= 4:
            issues.append("orchestrated:child_count_out_of_range")
        if isinstance(children, dict):
            if children.get("max_concurrency") != child_count:
                issues.append("orchestrated:max_concurrency_mismatch")
            if children.get("max_depth") != 1:
                issues.append("orchestrated:max_depth_invalid")
            if children.get("context_policy") != "none":
                issues.append("orchestrated:context_policy_invalid")
            if children.get("model") != child_model():
                issues.append("orchestrated:child_model_invalid")
            if children.get("effort") != child_effort():
                issues.append("orchestrated:child_effort_invalid")
            if children.get("retries_allowed") != 0:
                issues.append("orchestrated:retries_not_zero")
            if children.get("fallbacks_allowed") != 0:
                issues.append("orchestrated:fallbacks_not_zero")
            if isinstance(normalized_route, dict):
                observed_worker = normalized_route.get("worker")
                if isinstance(observed_worker, dict):
                    if children.get("model") != observed_worker.get("model"):
                        issues.append("orchestrated:child_model_not_current_route")
                    if children.get("effort") != observed_worker.get("effort"):
                        issues.append("orchestrated:child_effort_not_current_route")
                collaboration_surface = normalized_route.get(
                    "collaboration_surface"
                )
            else:
                collaboration_surface = None
            pairing_issue = _native_root_routed_worker_issue(
                root, children, collaboration_surface
            )
            if pairing_issue is not None:
                issues.append(pairing_issue)
        integration_owner = closure_report.get("integration_owner", {})
        root_integrates = (
            isinstance(integration_owner, dict)
            and integration_owner.get("kind") == "root"
        )
        if isinstance(root, dict):
            expected_coordination_only = not root_integrates
            if (
                root.get("coordination_only_after_freeze")
                is not expected_coordination_only
            ):
                issues.append("orchestrated:root_coordination_mode_invalid")
        if len(lanes) != child_count:
            issues.append("orchestrated:lane_count_mismatch")
        if isinstance(integration, dict):
            expected_strategy = "root" if root_integrates else "first_completed_worker"
            if integration.get("strategy") != expected_strategy:
                issues.append("orchestrated:integration_strategy_invalid")
            if integration.get("release_required") is not True:
                issues.append("orchestrated:release_not_required")
            if not final_verification:
                issues.append("orchestrated:final_verification_empty")

    canonical = plan_value if isinstance(plan_value, dict) else {}
    return {
        "schema": REPORT_SCHEMA,
        "kind": "plan",
        "status": "PASS" if not issues else "FAIL",
        "qualified": not issues,
        "issues": sorted(set(issues)),
        "plan_sha256": json_sha256(canonical),
        "canonical_plan": canonical,
        "acceptance_resource_closure": closure_report,
        "ticket_admission_identity": closure_report.get("binding", {}),
        "freeze_permitted": not issues,
        "spawn_permitted": not issues,
        "evidence_tier": "submitted",
        "current_turn_route": normalized_route,
        "route_identity_sha256": (
            normalized_route.get("identity_sha256")
            if isinstance(normalized_route, dict)
            else None
        ),
        "root_route_evidence_tier": (
            "runtime-observed" if isinstance(normalized_route, dict) else "unknown"
        ),
        "root_route_verified": isinstance(normalized_route, dict),
        "worker_route_evidence_tier": "submitted",
        "worker_route_verified": False,
    }


def observe_current_orchestration_route(
    expected_identity_sha256=None,
    *,
    task_id=None,
    require_task_id=False,
):
    """Observe the exact live root route without accepting a session path.

    The task identity comes from Codex's per-call MCP metadata, with the shell
    environment retained for direct-launcher use. An optional prior identity
    rejects task, turn, model, effort, surface, or worker-route drift.
    """

    if current_turn_route is None:
        return {
            "schema": "orch-dork/current-turn-route/v1",
            "status": "FAIL",
            "disposition": "ROUTING_UNKNOWN",
            "issues": ["routing:adapter_unavailable"],
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "evidence_tier": "runtime-observed",
        }
    arguments = {}
    if expected_identity_sha256 is not None:
        arguments["expected_identity_sha256"] = expected_identity_sha256
    if task_id is not None:
        arguments["task_id"] = task_id
    if require_task_id:
        arguments["require_task_id"] = True
    return current_turn_route.observe_current_turn_route(**arguments)


def evaluate_live_route_handoff(
    program,
    *,
    task_id=None,
    require_task_id=False,
):
    """Prepare or bind a human-approved route transition for one live attempt."""

    if current_turn_route is None:
        return {
            "schema": "orch-dork/live-route-authorization/v1",
            "operation": None,
            "status": "FAIL",
            "disposition": "REFUSED",
            "issues": ["authorization:route_adapter_unavailable"],
            "dispatch_permitted": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "credential_reads": 0,
            "network_calls": 0,
        }
    route = observe_current_orchestration_route(
        task_id=task_id,
        require_task_id=require_task_id,
    )
    return current_turn_route.evaluate_live_route_authorization(
        program,
        route_report=route,
    )


def validate_plan_for_current_turn(plan, *, task_id=None, require_task_id=False):
    """Freeze compatibility plan/v1 against a fresh live route observation."""

    route = observe_current_orchestration_route(
        task_id=task_id,
        require_task_id=require_task_id,
    )
    return validate_plan(plan, current_turn_route_report=route)


def validate_logical_plan_for_current_turn(
    plan,
    *,
    task_id=None,
    require_task_id=False,
):
    """Freeze logical-plan/v1 against the same current-turn route contract."""

    if efficiency_governor is None:
        return {
            "schema": "orch-dork/logical-plan-report/v1",
            "status": "FAIL",
            "valid": False,
            "issues": ["logical_plan:validator_unavailable"],
            "current_turn_route": None,
            "route_identity_sha256": None,
            "root_route_evidence_tier": "unknown",
            "root_route_verified": False,
            "worker_route_evidence_tier": "submitted",
            "worker_route_verified": False,
        }
    report = dict(efficiency_governor.validate_logical_plan(plan))
    issues = list(report.get("issues", []))
    route = observe_current_orchestration_route(
        task_id=task_id,
        require_task_id=require_task_id,
    )
    normalized_route = None
    if current_turn_route is None:
        issues.append("routing:adapter_unavailable")
    else:
        validation = current_turn_route.validate_current_turn_route(route)
        if validation.get("status") != "PASS":
            issues.append("routing:report_invalid")
            issues.extend(validation.get("issues", []))
        else:
            normalized_route = validation.get("normalized")

    value = plan if isinstance(plan, dict) else {}
    planner = value.get("planner") if isinstance(value.get("planner"), dict) else {}
    execution = (
        value.get("execution") if isinstance(value.get("execution"), dict) else {}
    )
    if isinstance(normalized_route, dict):
        issues.extend(normalized_route.get("issues", []))
        observed_root = normalized_route.get("root")
        observed_worker = normalized_route.get("worker")
        if planner.get("root_thread_id") != normalized_route.get("session_id"):
            issues.append("planner:root_task_not_current_turn")
        if isinstance(observed_root, dict):
            if planner.get("model") != observed_root.get("model"):
                issues.append("planner:model_not_current_turn")
            if planner.get("effort") != observed_root.get("effort"):
                issues.append("planner:effort_not_current_turn")
        if isinstance(observed_worker, dict):
            if execution.get("worker_model") != observed_worker.get("model"):
                issues.append("execution:worker_model_not_current_route")
            if execution.get("worker_effort") != observed_worker.get("effort"):
                issues.append("execution:worker_effort_not_current_route")

    issues = sorted(set(issues))
    report.update(
        {
            "status": "PASS" if not issues else "FAIL",
            "valid": not issues,
            "issues": issues,
            "current_turn_route": normalized_route,
            "route_identity_sha256": (
                normalized_route.get("identity_sha256")
                if isinstance(normalized_route, dict)
                else None
            ),
            "root_route_evidence_tier": (
                "runtime-observed"
                if isinstance(normalized_route, dict)
                else "unknown"
            ),
            "root_route_verified": isinstance(normalized_route, dict),
            "worker_route_evidence_tier": "submitted",
            "worker_route_verified": False,
        }
    )
    return report


def _authorize_current_route(
    expected_identity_sha256,
    *,
    task_id=None,
    require_task_id=False,
):
    """Re-observe and authorize only the exact route frozen by validation."""

    route = observe_current_orchestration_route(
        expected_identity_sha256,
        task_id=task_id,
        require_task_id=require_task_id,
    )
    issues = []
    if current_turn_route is None:
        issues.append("routing:adapter_unavailable")
    else:
        validation = current_turn_route.validate_current_turn_route(route)
        if validation.get("status") != "PASS":
            issues.append("routing:report_invalid")
            issues.extend(validation.get("issues", []))
    if route.get("status") != "PASS" or route.get("disposition") != "SPAWN_COMPATIBLE":
        issues.extend(route.get("issues", []))
        if not route.get("issues"):
            issues.append("routing:spawn_not_compatible")
    return route, sorted(set(issues))


def validate_admission_for_current_turn(
    plan,
    inventory,
    expected_route_identity_sha256,
    *,
    task_id=None,
    require_task_id=False,
    run_id=None,
    authority_state_reader=None,
    authority_state_committer=None,
):
    """Bind capacity admission to the exact route frozen by plan validation."""

    route, route_issues = _authorize_current_route(
        expected_route_identity_sha256,
        task_id=task_id,
        require_task_id=require_task_id,
    )
    logical = (
        isinstance(plan, dict)
        and plan.get("schema") == "orch-dork/logical-plan/v1"
    )
    if logical:
        bound_plan = validate_logical_plan_for_current_turn(
            plan,
            task_id=task_id,
            require_task_id=require_task_id,
        )
    else:
        bound_plan = validate_plan(plan, current_turn_route_report=route)
    if bound_plan.get("status") != "PASS":
        route_issues.extend(
            "plan:" + issue for issue in bound_plan.get("issues", [])
        )
    if bound_plan.get("route_identity_sha256") != expected_route_identity_sha256:
        route_issues.append("routing:plan_identity_mismatch")

    report = dict(
        validate_admission(
            plan,
            inventory,
            current_turn_route_report=route,
            run_id=run_id,
            authority_state_reader=authority_state_reader,
            authority_state_committer=authority_state_committer,
        )
    )
    if route_issues:
        report.update(
            {
                "status": "FAIL",
                "admitted": False,
                "issues": sorted(
                    set(report.get("issues", [])) | set(route_issues)
                ),
                "next_step": "abort_before_freeze",
            }
        )
    report.update(
        {
            "current_turn_route": route,
            "route_identity_sha256": route.get("identity_sha256"),
            "root_route_evidence_tier": "runtime-observed",
            "root_route_verified": route.get("status") == "PASS",
            "worker_route_evidence_tier": "unobserved",
            "worker_route_verified": False,
        }
    )
    return report


def run_logical_worker_waves_for_current_turn(
    program,
    expected_route_identity_sha256,
    *,
    task_id=None,
    require_task_id=False,
):
    """Run no logical wave unless the frozen current route is unchanged."""

    route, route_issues = _authorize_current_route(
        expected_route_identity_sha256,
        task_id=task_id,
        require_task_id=require_task_id,
    )
    if efficiency_governor is None:
        route_issues.append("wave_program:controller_unavailable")
    if route_issues:
        value = program if isinstance(program, dict) else {}
        plan = (
            value.get("logical_plan")
            if isinstance(value.get("logical_plan"), dict)
            else {}
        )
        plan_report = (
            efficiency_governor.validate_logical_plan(plan)
            if efficiency_governor is not None
            else {"plan_sha256": None}
        )
        workers = plan.get("workers") if isinstance(plan.get("workers"), list) else []
        worker_ids = sorted(
            worker.get("id")
            for worker in workers
            if isinstance(worker, dict) and isinstance(worker.get("id"), str)
        )
        return {
            "schema": "orch-dork/wave-report/v1",
            "status": "FAILED",
            "program_id": value.get("program_id"),
            "plan_sha256": plan_report.get("plan_sha256"),
            "logical_worker_count": len(worker_ids),
            "wave_count": 0,
            "waves": [],
            "reconciliation": [
                {
                    "logical_worker_id": worker_id,
                    "status": "pending",
                    "wave_id": None,
                }
                for worker_id in worker_ids
            ],
            "pending_worker_ids": worker_ids,
            "failed_worker_ids": [],
            "issues": route_issues,
            "next_event": "current_route_required",
            "automatic_retries": 0,
            "automatic_replacements": 0,
            "model_poll_wakes": 0,
            "spawn_permitted": False,
            "current_turn_route": route,
            "route_identity_sha256": route.get("identity_sha256"),
            "root_route_evidence_tier": "runtime-observed",
            "root_route_verified": route.get("status") == "PASS",
            "worker_route_evidence_tier": "unobserved",
            "worker_route_verified": False,
            "evidence_tier": "runtime-observed-route",
        }
    report = dict(efficiency_governor.run_wave_program(program))
    report.update(
        {
            "current_turn_route": route,
            "route_identity_sha256": route.get("identity_sha256"),
            "root_route_evidence_tier": "runtime-observed",
            "root_route_verified": route.get("status") == "PASS",
            "worker_route_evidence_tier": report.get(
                "worker_route_evidence_tier", "unobserved"
            ),
            "worker_route_verified": report.get(
                "worker_route_verified", False
            ),
        }
    )
    return report


def validate_spawn_wave_for_current_turn(
    plan,
    admission,
    results,
    expected_route_identity_sha256,
    *,
    task_id=None,
    require_task_id=False,
    authority_state_reader=None,
):
    """Reject a submitted creation wave when its frozen root route drifted."""

    route, route_issues = _authorize_current_route(
        expected_route_identity_sha256,
        task_id=task_id,
        require_task_id=require_task_id,
    )
    admission_route_identity = (
        admission.get("route_identity_sha256")
        if isinstance(admission, dict)
        else None
    )
    if admission_route_identity != expected_route_identity_sha256:
        route_issues.append("routing:admission_identity_mismatch")
    report = dict(
        validate_spawn_wave(
            plan,
            admission,
            results,
            current_turn_route_report=route,
            authority_state_reader=authority_state_reader,
        )
    )
    if route_issues:
        report.update(
            {
                "status": "FAIL",
                "complete": False,
                "attempt_state": "aborted_route_changed",
                "issues": sorted(
                    set(report.get("issues", []))
                    | {"route:" + issue for issue in route_issues}
                ),
                "members": [],
            }
        )
    report.update(
        {
            "current_turn_route": route,
            "route_identity_sha256": route.get("identity_sha256"),
            "root_route_evidence_tier": "runtime-observed",
            "root_route_verified": route.get("status") == "PASS",
            "worker_route_evidence_tier": "unobserved",
            "worker_route_verified": False,
        }
    )
    return report


def _events_by_type(events):
    result = {}
    for event in events:
        result.setdefault(event.get("type"), []).append(event)
    return result


def qualify_trace(plan, trace, current_turn_route_report=None):
    plan_report = validate_plan(
        plan, current_turn_route_report=current_turn_route_report)
    issues = ["plan:" + issue for issue in plan_report["issues"]]
    if not isinstance(trace, dict):
        trace = {}
        issues.append("trace:not_object")
    else:
        _check_exact_keys(trace, {"schema", "plan_sha256", "counters", "events"}, "trace", issues)
    if trace.get("schema") != TRACE_SCHEMA:
        issues.append("trace:schema_invalid")
    if trace.get("plan_sha256") != plan_report["plan_sha256"]:
        issues.append("trace:plan_hash_mismatch")

    counters = trace.get("counters")
    _check_exact_keys(
        counters,
        {"retries", "fallbacks", "replacements", "nested_children"},
        "counters",
        issues,
    )
    if isinstance(counters, dict):
        for name in ("retries", "fallbacks", "replacements", "nested_children"):
            if counters.get(name) != 0:
                issues.append("counters:%s_not_zero" % name)

    events = trace.get("events")
    if not isinstance(events, list):
        events = []
        issues.append("events:not_array")
    previous_seq = 0
    for index, event in enumerate(events):
        path = "events[%d]" % index
        if not isinstance(event, dict):
            issues.append(path + ":not_object")
            continue
        event_type = event.get("type")
        required = EVENT_FIELDS.get(event_type)
        if required is None:
            issues.append(path + ":type_invalid")
            continue
        _check_exact_keys(event, {"seq", "type"} | required, path, issues)
        seq = event.get("seq")
        if type(seq) is not int or seq <= previous_seq:
            issues.append(path + ":seq_not_strictly_increasing")
        elif seq <= 0:
            issues.append(path + ":seq_not_positive")
        else:
            previous_seq = seq
        if event_type == "root.tool" and event.get("category") not in {
            "coordination",
            "implementation",
        }:
            issues.append(path + ":category_invalid")

    by_type = _events_by_type([event for event in events if isinstance(event, dict)])
    roots = by_type.get("root.started", [])
    completed_runs = by_type.get("run.completed", [])
    if len(roots) != 1:
        issues.append("lifecycle:root_started_count:%d" % len(roots))
    if len(completed_runs) != 1:
        issues.append("lifecycle:run_completed_count:%d" % len(completed_runs))
    root_id = roots[0].get("root_thread_id") if len(roots) == 1 else None
    if len(roots) == 1:
        planned_root = plan.get("root") if isinstance(plan, dict) else None
        planned_root = planned_root if isinstance(planned_root, dict) else {}
        if roots[0].get("model") != planned_root.get("model"):
            issues.append("lifecycle:root_model_invalid")
        if roots[0].get("effort") != planned_root.get("effort"):
            issues.append("lifecycle:root_effort_invalid")
    if len(completed_runs) == 1:
        if completed_runs[0].get("root_thread_id") != root_id:
            issues.append("lifecycle:root_completion_identity_mismatch")

    mode = (plan.get("decision") or {}).get("mode") if isinstance(plan, dict) else None
    child_event_types = {
        "child.spawned",
        "lane.verified",
        "lane.completed",
        "integrator.started",
        "lane.released",
        "integrator.validated",
        "integrator.completed",
    }
    if mode == "atomic":
        child_events = [event for event in events if event.get("type") in child_event_types]
        if child_events:
            issues.append("atomic:child_events_present")
    elif mode == "orchestrated":
        _qualify_orchestrated(plan, events, by_type, root_id, issues, plan_report)

    trace_value = trace if isinstance(trace, dict) else {}
    status = "PASS" if not issues else "FAIL"
    return {
        "schema": REPORT_SCHEMA,
        "kind": "trace",
        "status": status,
        # Compatibility: the MCP method and schema retain their historical
        # qualification names.  A model-authored trace can establish only
        # submitted structural conformance; it cannot observe the active
        # root's later persisted terminal record.
        "qualified": False,
        "conformant": not issues,
        "claim_permitted": False,
        "terminal_evidence": {
            "status": "declared_not_observed",
            "run_completed_event": "submitted_declaration",
            "required_next_step": "external_post_terminal_observation",
        },
        "issues": sorted(set(issues)),
        "plan_sha256": plan_report["plan_sha256"],
        "trace_sha256": json_sha256(trace_value),
        "evidence_tier": "submitted",
        "current_turn_route": plan_report.get("current_turn_route"),
        "route_identity_sha256": plan_report.get("route_identity_sha256"),
        "root_route_evidence_tier": plan_report.get(
            "root_route_evidence_tier", "unknown"
        ),
        "root_route_verified": plan_report.get("root_route_verified", False),
        "worker_route_evidence_tier": "unobserved",
        "worker_route_verified": False,
        "summary": {
            "events": len(events),
            "children": len(by_type.get("child.spawned", [])),
            "releases": len(by_type.get("lane.released", [])),
            "root_implementation_tools": sum(
                1
                for event in by_type.get("root.tool", [])
                if event.get("category") == "implementation"
            ),
        },
    }


def qualify_trace_for_current_turn(
    plan, trace, *, task_id=None, require_task_id=False
):
    """Qualify a submitted trace against a fresh live route observation."""

    route = observe_current_orchestration_route(
        task_id=task_id, require_task_id=require_task_id)
    return qualify_trace(
        plan, trace, current_turn_route_report=route)


READ_CUSTODY_QUALIFICATION_SCHEMA = "orch-dork/read-custody-qualification/v1"


def qualify_read_custody(audit_report, exceptions=None):
    """Issue 96 gate: a trace qualifies on the read axis only through this.

    Deterministic and fail-closed: the audit report must be a structurally
    intact orch-dork/read-custody-audit/v1 whose digest recomputes, and
    every violation it carries must be covered by a custody exception that
    validates under custody-exception/v1 with a non-blocking disposition
    (cured or superseded).  A recorded exception, an uncovered violation,
    a forged digest, or an unavailable auditor module refuses the claim.
    PASS here establishes the read-custody axis only; it never permits a
    terminal qualification or completion claim by itself.
    """
    issues = []
    covered = []
    if read_custody_audit is None:  # pragma: no cover - environment guard.
        issues.append("read_custody:auditor_unavailable")
        audit_report = {}
    if not isinstance(audit_report, dict):
        audit_report = {}
        issues.append("read_custody:report_not_object")
    expected_schema = "orch-dork/read-custody-audit/v1"
    if audit_report.get("schema") != expected_schema:
        issues.append("read_custody:report_schema_invalid")
    else:
        body = {
            key: audit_report[key]
            for key in audit_report
            if key != "report_sha256"
        }
        recomputed = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        if recomputed != audit_report.get("report_sha256"):
            issues.append("read_custody:report_digest_mismatch")
    violations = audit_report.get("violations")
    if not isinstance(violations, list):
        violations = []
        issues.append("read_custody:violations_not_array")
    validated_exceptions = []
    for index, record in enumerate(exceptions or []):
        try:
            validated = read_custody_audit.validate_custody_exception(record)
        except Exception as exc:
            issues.append("read_custody:exception_invalid:%d:%s" % (index, exc))
            continue
        validated_exceptions.append(validated)
    for violation in violations:
        if not isinstance(violation, dict):
            issues.append("read_custody:violation_not_object")
            continue
        path = violation.get("path")
        lane = violation.get("lane_id")
        match = next(
            (
                record
                for record in validated_exceptions
                if record["lane_id"] == lane
                and not record["qualification_blocking"]
                and any(
                    path == scope or str(path).startswith(scope + "/")
                    for scope in record["paths"]
                )
            ),
            None,
        )
        if match is None:
            issues.append(
                "read_custody:unresolved_violation:%s:%s" % (lane, path)
            )
        else:
            covered.append(
                {
                    "lane_id": lane,
                    "path": path,
                    "exception_sha256": match["exception_sha256"],
                }
            )
    if audit_report.get("status") == "PASS" and violations:
        issues.append("read_custody:pass_with_violations")
    if audit_report.get("status") not in ("PASS", "FAIL"):
        issues.append("read_custody:report_status_invalid")
    return {
        "schema": READ_CUSTODY_QUALIFICATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "covered_violations": covered,
        "exception_count": len(validated_exceptions),
        "audit_report_sha256": audit_report.get("report_sha256"),
        "claim_permitted": False,
        "axis": "read_custody",
    }


def _qualify_orchestrated(plan, events, by_type, root_id, issues, plan_report):
    lanes = plan.get("lanes", [])
    planned = {lane.get("id"): lane for lane in lanes if isinstance(lane, dict)}
    expected = (plan.get("children") or {}).get("expected_count")
    spawns = by_type.get("child.spawned", [])
    verifications = by_type.get("lane.verified", [])
    completions = by_type.get("lane.completed", [])
    integrator_starts = by_type.get("integrator.started", [])
    releases = by_type.get("lane.released", [])
    validations = by_type.get("integrator.validated", [])
    integrator_completions = by_type.get("integrator.completed", [])

    for tool in by_type.get("root.tool", []):
        if tool.get("category") == "implementation":
            issues.append("root:implementation_tool:%s" % tool.get("name"))

    if len(spawns) != expected:
        issues.append("graph:spawn_count:%d!=%s" % (len(spawns), expected))
    spawn_by_lane = {}
    child_ids = set()
    for spawn in spawns:
        lane_id = spawn.get("lane_id")
        if lane_id not in planned:
            issues.append("graph:spawn_unknown_lane:%s" % lane_id)
            continue
        if lane_id in spawn_by_lane:
            issues.append("graph:duplicate_spawn_lane:%s" % lane_id)
        spawn_by_lane[lane_id] = spawn
        child_id = spawn.get("child_thread_id")
        if not _is_nonempty_string(child_id) or child_id in child_ids:
            issues.append("graph:child_identity_invalid:%s" % lane_id)
        else:
            child_ids.add(child_id)
        if spawn.get("parent_thread_id") != root_id:
            issues.append("graph:parent_mismatch:%s" % lane_id)
        if spawn.get("depth") != 1:
            issues.append("graph:depth_invalid:%s" % lane_id)
        if spawn.get("model") != child_model():
            issues.append("graph:model_invalid:%s" % lane_id)
        if spawn.get("effort") != child_effort():
            issues.append("graph:effort_invalid:%s" % lane_id)
        if spawn.get("context_policy") != "none":
            issues.append("graph:context_invalid:%s" % lane_id)
    for lane_id in sorted(set(planned) - set(spawn_by_lane)):
        issues.append("graph:missing_spawn:%s" % lane_id)

    verified_by_lane = {}
    for event in verifications:
        verified_by_lane.setdefault(event.get("lane_id"), []).append(event)
    completed_by_lane = {}
    for event in completions:
        completed_by_lane.setdefault(event.get("lane_id"), []).append(event)

    for lane_id in sorted(planned):
        spawn = spawn_by_lane.get(lane_id)
        expected_child = spawn.get("child_thread_id") if spawn else None
        lane_verifications = verified_by_lane.get(lane_id, [])
        lane_completions = completed_by_lane.get(lane_id, [])
        if len(lane_verifications) != 1:
            issues.append("graph:verification_count:%s:%d" % (lane_id, len(lane_verifications)))
        elif (
            lane_verifications[0].get("child_thread_id") != expected_child
            or lane_verifications[0].get("passed") is not True
        ):
            issues.append("graph:verification_invalid:%s" % lane_id)
        if len(lane_completions) != 1:
            issues.append("graph:completion_count:%s:%d" % (lane_id, len(lane_completions)))
        elif (
            lane_completions[0].get("child_thread_id") != expected_child
            or lane_completions[0].get("status") != "completed"
        ):
            issues.append("graph:completion_invalid:%s" % lane_id)
        if len(lane_verifications) == 1 and len(lane_completions) == 1:
            if lane_verifications[0].get("seq", 0) >= lane_completions[0].get("seq", 0):
                issues.append("graph:verification_not_before_completion:%s" % lane_id)

    valid_completions = [
        values[0]
        for lane_id, values in completed_by_lane.items()
        if lane_id in planned and len(values) == 1
    ]
    if spawns and valid_completions:
        if max(event.get("seq", 0) for event in spawns) >= min(
            event.get("seq", 0) for event in valid_completions
        ):
            issues.append("graph:initial_wave_not_spawned_before_completion")

    if len(integrator_starts) != 1:
        issues.append("integration:start_count:%d" % len(integrator_starts))
        integrator_id = None
        integrator_start_seq = None
    else:
        integrator_id = integrator_starts[0].get("child_thread_id")
        integrator_start_seq = integrator_starts[0].get("seq")

    # The closure report carries the plan's declared integration owner. When
    # it names a specific lane, that lane is frozen into the plan at freeze
    # time and its release conditions are audited against it, so the trace
    # must be held to the same declaration: the named lane integrates, and
    # every other lane releases to it. Before this fix the qualifier forced
    # whoever finished first to integrate, so a plan naming any other lane
    # passed every pre-spawn gate and then became impossible to qualify no
    # matter how correctly the run proceeded. (TICKETS.md recorded such a
    # run as operator error; the contract, not the operator, was broken.)
    # When the plan does not name a lane -- root integration, an unknown or
    # incomplete owner, or a plan failing closure -- the historical
    # first-completed-worker behavior applies exactly as before.
    # The custody analyzer mirrors this resolution through
    # orch_dork_custody._declared_integrator_lane (issue 89) so both
    # validators hold one attempt to the same declared owner.
    # `validate_plan` computes the closure report in its own scope; the
    # same report travels out on the plan report as
    # `acceptance_resource_closure`, so read the declared owner there.
    first_completion = (
        min(
            valid_completions,
            key=lambda event: (event.get("seq", 0), str(event.get("child_thread_id", ""))),
        )
        if valid_completions
        else None
    )
    integration_owner = plan_report.get("acceptance_resource_closure", {}).get(
        "integration_owner", {}
    )
    designated_lane = None
    if (
        isinstance(integration_owner, dict)
        and integration_owner.get("kind") == "lane"
        and first_completion is not None
    ):
        declared_lane = str(integration_owner.get("id"))
        declared_completion = completed_by_lane.get(declared_lane, [])
        # A named-lane designation actually diverges from the historical
        # rule only when the named lane is a correctly completed lane that
        # is NOT the first completer. A plan that names the first completer
        # itself never desynchronized the pre-spawn gates from the trace
        # gates -- the run always had one conforming trace, which is exactly
        # how the stale TICKETS.md run was able to "select the wrong
        # integrator" -- so those runs keep the historical diagnostics and
        # roster semantics byte-for-byte.
        if len(declared_completion) == 1 and declared_completion[0] is not first_completion:
            designated_lane = declared_lane

    if first_completion is not None:
        if designated_lane is None:
            anchor_completion = first_completion
            if integrator_id != anchor_completion.get("child_thread_id"):
                issues.append("integration:not_first_completed_worker")
        else:
            # The designated owner is the authority for roster and identity:
            # it integrates, every other lane releases to it. Its completion
            # event anchors the "own work done first" rule below.
            anchor_completion = completed_by_lane[designated_lane][0]
            if integrator_id != anchor_completion.get("child_thread_id"):
                issues.append("integration:declared_integrator_not_designated")
                # The failed run is misidentifying the integrator the same
                # way the pre-declaration runs did, so the historical
                # diagnostic is emitted alongside when the attempted
                # integrator also is not the first completer. Diagnostic
                # only: it surfaces exclusively on failing traces.
                if integrator_id != first_completion.get("child_thread_id"):
                    issues.append("integration:not_first_completed_worker")
        if integrator_start_seq is not None and integrator_start_seq <= anchor_completion.get("seq", 0):
            issues.append("integration:started_before_owner_completed")
        # Deliberate scope decision: integration:no_overlap_with_initial_workers
        # is kept for the unnamed first-completer strategy only. Under that
        # strategy the integrator is a RUNTIME selection -- the first
        # completer -- so the check demands integration genuinely overlap
        # the lanes still running; it guards against an integrator that
        # idles while the remaining lanes finish. With a freeze-time
        # designated lane that argument does not hold: the lane
        # legitimately finishes its own survey work before integrating,
        # and whether it idles afterward says nothing about wasted root
        # time. The genuinely valuable guards still apply to a
        # designated integrator: each non-integrator lane still releases
        # exactly once, only after its own completion, to the actual
        # integrator; the integrator must not be released to itself; and
        # integration may not start before its own completion (the
        # anchored rule above).
        if (
            designated_lane is None
            and len(valid_completions) > 1
            and integrator_start_seq is not None
            and integrator_start_seq >= max(event.get("seq", 0) for event in valid_completions)
        ):
            issues.append("integration:no_overlap_with_initial_workers")

    if designated_lane is not None:
        integrator_lane = designated_lane
    else:
        integrator_lane = first_completion.get("lane_id") if first_completion else None
    release_by_lane = {}
    for release in releases:
        release_by_lane.setdefault(release.get("lane_id"), []).append(release)
    expected_release_lanes = set(planned) - ({integrator_lane} if integrator_lane else set())
    if len(releases) != max(0, len(planned) - 1):
        issues.append("integration:release_count:%d!=%d" % (len(releases), max(0, len(planned) - 1)))
    for lane_id in sorted(expected_release_lanes):
        lane_releases = release_by_lane.get(lane_id, [])
        lane_completion = completed_by_lane.get(lane_id, [])
        spawn = spawn_by_lane.get(lane_id)
        owner_id = spawn.get("child_thread_id") if spawn else None
        if len(lane_releases) != 1:
            issues.append("integration:release_lane_count:%s:%d" % (lane_id, len(lane_releases)))
            continue
        release = lane_releases[0]
        if release.get("owner_thread_id") != owner_id:
            issues.append("integration:release_owner_mismatch:%s" % lane_id)
        if release.get("integrator_thread_id") != integrator_id:
            issues.append("integration:release_target_mismatch:%s" % lane_id)
        if lane_completion and release.get("seq", 0) <= lane_completion[0].get("seq", 0):
            issues.append("integration:release_before_completion:%s" % lane_id)
        if integrator_start_seq is not None and release.get("seq", 0) <= integrator_start_seq:
            issues.append("integration:release_before_integrator_start:%s" % lane_id)
    if integrator_lane in release_by_lane:
        issues.append("integration:integrator_lane_released")
    for lane_id in sorted(set(release_by_lane) - expected_release_lanes):
        if lane_id != integrator_lane:
            issues.append("integration:release_unknown_lane:%s" % lane_id)

    if len(validations) != 1:
        issues.append("integration:validation_count:%d" % len(validations))
        validation_seq = None
    else:
        validation = validations[0]
        validation_seq = validation.get("seq")
        if validation.get("child_thread_id") != integrator_id:
            issues.append("integration:validation_target_mismatch")
        if validation.get("passed") is not True:
            issues.append("integration:validation_failed")
        preceding = [event.get("seq", 0) for event in valid_completions + releases]
        if preceding and validation_seq <= max(preceding):
            issues.append("integration:validation_before_all_releases_or_completions")

    if len(integrator_completions) != 1:
        issues.append("integration:completion_count:%d" % len(integrator_completions))
        integrator_complete_seq = None
    else:
        completion = integrator_completions[0]
        integrator_complete_seq = completion.get("seq")
        if completion.get("child_thread_id") != integrator_id:
            issues.append("integration:completion_target_mismatch")
        if completion.get("status") != "completed":
            issues.append("integration:completion_status_invalid")
        if validation_seq is not None and integrator_complete_seq <= validation_seq:
            issues.append("integration:completed_before_validation")

    run_completions = by_type.get("run.completed", [])
    if len(run_completions) == 1 and integrator_complete_seq is not None:
        if run_completions[0].get("seq", 0) <= integrator_complete_seq:
            issues.append("lifecycle:root_completed_before_integrator")


def _closed_program_schema(schema, fields, *, array_fields=(), object_fields=()):
    properties = {"schema": {"const": schema}}
    for field in fields:
        if field == "schema":
            continue
        if field in array_fields:
            properties[field] = {"type": "array", "items": {"type": "object"}}
        elif field in object_fields:
            properties[field] = {"type": "object"}
        else:
            properties[field] = {"type": "string", "minLength": 1}
    return {
        "type": "object",
        "properties": properties,
        "required": list(fields),
        "additionalProperties": False,
    }


def _wave_program_descriptor():
    base = (
        "schema",
        "program_id",
        "root_thread_id",
        "logical_plan",
        "observations",
    )
    variants = []
    for schema, extras in (
        ("orch-dork/wave-program/v1", ()),
        ("orch-dork/wave-program/v2", ("route_preflights",)),
        (
            "orch-dork/wave-program/v3",
            ("route_preflights", "task_specs", "completion_reserve"),
        ),
    ):
        fields = (*base, *extras)
        variants.append(
            _closed_program_schema(
                schema,
                fields,
                array_fields={"observations", "route_preflights", "task_specs"},
                object_fields={"logical_plan", "completion_reserve"},
            )
        )
    return {"oneOf": variants}


def _adaptive_program_descriptor():
    fields = (
        "schema",
        "controller_id",
        "current_plan",
        "decomposition_proposal",
        "proposal_approval",
        "limits",
        "consumption",
        "revision_history",
        "termination",
        "verification",
    )
    schema = _closed_program_schema(
        "orch-dork/adaptive-finite-dag-program/v1",
        fields,
        array_fields={"revision_history"},
        object_fields={
            "current_plan",
            "decomposition_proposal",
            "proposal_approval",
            "limits",
            "consumption",
            "termination",
            "verification",
        },
    )
    for nullable in ("decomposition_proposal", "proposal_approval"):
        schema["properties"][nullable] = {
            "type": ["object", "null"],
        }
    return schema


def _progress_program_descriptor():
    return _closed_program_schema(
        "orch-dork/wave-progress-program/v1",
        (
            "schema",
            "progress_id",
            "task_specs",
            "completion_reserve",
            "events",
        ),
        array_fields={"task_specs", "events"},
        object_fields={"completion_reserve"},
    )


def _routing_program_descriptor():
    variants = []
    for schema, bound in (
        ("orch-dork/wave-routing-program/v1", False),
        ("orch-dork/wave-routing-program/v2", True),
        ("orch-dork/wave-routing-program/v3", True),
    ):
        fields = (
            "schema",
            "plan_worker_model",
            "plan_worker_effort",
            "plan_root_model",
            "plan_root_effort",
            *(("expected_members",) if bound else ()),
            "lanes",
        )
        variants.append(
            _closed_program_schema(
                schema,
                fields,
                array_fields={"expected_members", "lanes"},
            )
        )
    return {"oneOf": variants}


def _model_combo_program_descriptor(schema, operations):
    return {
        "type": "object",
        "properties": {
            "schema": {"const": schema},
            "operation": {"type": "string", "enum": list(operations)},
            "payload": {"type": "object", "maxProperties": 256},
        },
        "required": ["schema", "operation", "payload"],
        "additionalProperties": False,
    }


def _contract_requirement_conditions():
    ordered = sorted(
        (
            (kind, route["required_arguments"])
            for kind, route in ADAPTIVE_CONTRACT_REGISTRY.items()
            if route["required_arguments"]
        ),
        key=lambda row: ("handoff_receipt" not in row[1], row[0]),
    )
    return [
        {
            "if": {
                "properties": {"contract_kind": {"const": kind}},
                "required": ["contract_kind"],
            },
            "then": {"required": sorted(required)},
        }
        for kind, required in ordered
    ]


# Every argument confirm_enrollment accepts; the tool's input schema lists the same.
_CONFIRM_ENROLLMENT_ARGUMENTS = frozenset({
    "draft_sha256", "second_model", "keep_local", "checks", "chat_model", "lineup_preset",
    "workers_max", "per_run_cost_usd", "daily_cost_usd", "allowed_workflow_profiles",
    "per_run_approval", "v1_opt_in",
})


def _governed_lane_schema() -> dict:
    return {
        "type": "array",
        "maxItems": 8,
        "items": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,31}$"},
                "goal": {"type": "string"},
                "checks": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4,
                    "items": {
                        "type": "object",
                        "properties": {
                            "check": {"type": "string"},
                            "selectors": {
                                "type": "array", "maxItems": 8, "items": {"type": "string"},
                            },
                        },
                        "required": ["check"],
                        "additionalProperties": False,
                    },
                },
                "writes": {"type": "array", "minItems": 1, "maxItems": 128, "items": {"type": "string"}},
            },
            "required": ["id", "goal", "checks"],
            "additionalProperties": False,
        },
    }


def _project_improvement_tools():
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    rows = (
        ("propose_project_improvements", "Compare this project's observed workflows, worker counts and role models. Production floors are twenty eligible runs and five comparable runs per choice. If no adopted default exists, select an observed baseline_run_id. Read the exact proposal and all supporting/contradicting runs before asking the user; this changes no defaults.",
         {"baseline_run_id": {"type": "string"}}, ["project_root"]),
        ("read_project_improvement", "Read this task's exact proposal, supporting and contradicting runs, missing promotion evidence, recorded decision and frozen canary cases.",
         {"proposal_sha256": digest}, ["project_root", "proposal_sha256"]),
        ("decide_project_improvement", "Only after the user explicitly approves or rejects the exact shown proposal, record that decision once using confirm_proposal_sha256. Standing run authority is not approval. This changes no defaults and refuses an active project.",
         {"confirm_proposal_sha256": digest, "decision": {"type": "string", "enum": ["approve", "reject"]}},
         ["project_root", "confirm_proposal_sha256", "decision"]),
        ("authorize_project_canary", "Only after showing the frozen canary cases and budget and receiving separate explicit user approval, confirm the returned canary intent hash. Offline and shadow originals must already pass. This grants one claim per frozen case, expires in one hour and changes no defaults. Ordinary governed admission still applies to each case.",
         {"proposal_sha256": digest, "confirm_canary_sha256": digest}, ["project_root", "proposal_sha256", "confirm_canary_sha256"]),
        ("adopt_project_improvement", "Only after the user explicitly confirms adoption, replay the complete offline, shadow and authorized canary promotion from retained host originals, consume this task's exact confirm_proposal_sha256 once and apply local defaults only between runs. Existing work remains frozen; omitted choices in future preparation use the new defaults. Missing cost or human review blocks promotion.",
         {"confirm_proposal_sha256": digest}, ["project_root", "confirm_proposal_sha256"]),
    )
    return [{"name": name, "title": name.replace("_", " ").capitalize(), "description": description,
             "inputSchema": {"type": "object", "properties": {"project_root": {"type": "string"}, **fields},
                             "required": required, "additionalProperties": False},
             "annotations": {"readOnlyHint": name == "read_project_improvement", "destructiveHint": False,
                             "openWorldHint": False, "idempotentHint": name == "read_project_improvement"}}
            for name, description, fields, required in rows]


def list_tools():
    return _project_improvement_tools() + [
        {
            "name": "audit_orchestration_classification",
            "title": "Audit an Orch Dork classification",
            "description": (
                "Record and review atomic, orchestrated, or refused judgment, "
                "confidence, invocation, authority, override, and execution evidence."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"record": {"type": "object"}},
                "required": ["record"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_ticket_admission",
            "title": "Evaluate advisory Orch Dork ticket classification",
            "description": (
                "Issue one non-authoritative provider-free classification-policy/v2 decision bound "
                "to the exact ticket, specification, acceptance criteria, authority, "
                "writable scope, root task, invocation, classification evidence, and "
                "candidate resources. This result never permits mutation; the "
                "AdmissionKernel is the sole hard admission seam."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_split_decision",
            "title": "Evaluate an Orch Dork split decision",
            "description": (
                "Apply the provider-free structural, marginal-value, scaling, "
                "and expansion gates before plan freeze. Accepted new "
                "orchestration defaults to finite_dag/v1; the bounded "
                "first_completed_worker/v1 choreography is explicit "
                "compatibility only. This evaluator neither consults capacity "
                "nor grants worker authority."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_deepening_policy",
            "title": "Evaluate an Orch Dork deepening proposal",
            "description": (
                "Apply the provider-free FR50 accept, deny, or defer economic "
                "gate to one typed decomposition proposal. The sealed decision "
                "records every FR47 marginal-value dimension, remaining budget, "
                "capacity, critical-path position, Issue 104 measurements, "
                "authorization preservation, and all gate constants. Dependency "
                "depth is evidence only; this evaluator cannot apply a revision, "
                "schedule workers, change capacity, or grant authority."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_learned_policy",
            "title": "Evaluate a learned Orch Dork sizing and stopping policy",
            "description": (
                "Apply one sealed, ledger-derived difficulty/family lookup "
                "policy to a declared task. The result is advisory input to "
                "the existing first-wave split and deepening economic gates; "
                "unknown families fall back to the standing defaults. This "
                "provider-free evaluator cannot train, promote, mutate a "
                "default, schedule workers, or grant authority."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "recommend_first_wave",
            "title": "Recommend an advisory Orch Dork first wave",
            "description": (
                "Apply the provider-free FR49 estimator to a declared touch set, "
                "sealed coupling prior, independently verifiable acceptance "
                "units, capability profile, and bounded typed scout deltas. "
                "The sealed recommendation is advisory input to the ordinary "
                "split gate and cannot freeze a plan, consult capacity, change "
                "a ceiling, permit workers, or grant authority."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_admission_kernel",
            "title": "Evaluate the integrity-checked admission kernel",
            "description": (
                "Re-read bounded local evidence and require one complete snapshot, "
                "candidate plan, and chained runtime-fact set before returning ADMIT, "
                "REVIEW_REQUIRED, or REFUSE. This is the sole hard admission seam."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "validate_semantic_plan_v2",
            "title": "Validate a semantic plan v2 contract",
            "description": (
                "Validate acceptance-to-deliverable-to-resource-to-owner closure, "
                "the complete evidence-backed dependency relation, integration "
                "ownership, risk, unknowns, and a fresh EvidenceSnapshot without "
                "launching work or granting authority."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_task_creation_intent",
            "title": "Evaluate an atomic task-creation intent",
            "description": (
                "Evaluate one provider-free, target-bound task-creation intent, "
                "exactly-once call receipt, delayed reconciliation inventory, "
                "and duplicate disposition without creating or mutating a task."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_governed_orchestration_run",
            "title": "Evaluate a controller-owned governed run",
            "description": (
                "Evaluate the staged hard-attempt contract for pre-spawn, "
                "TaskSpec delivery, continuous budget/tool authority, recovery, "
                "and typed terminal qualification. Legacy governed-run/v1 "
                "remains compatibility replay only. The evaluator is provider-"
                "free and never launches work."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "adapt_native_capacity_observation",
            "title": "Adapt an observed native capacity inventory",
            "description": (
                "Normalize one fresh host-signed capacity observation into "
                "collaboration-inventory/v2 using host-owned trust and replay "
                "state. The adapter never observes or invents capacity and "
                "emits no authoritative inventory for bare self-hashes, "
                "submitted keys, stale, dependent, or malformed evidence."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "observation": {"type": "object"},
                    "expected_root_thread_id": {
                        "type": "string",
                        "minLength": 1,
                    },
                },
                "required": ["observation"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_worker_lifecycle",
            "title": "Evaluate worker retirement or one-wave rollover",
            "description": (
                "Evaluate runtime-observed retirement capability, exact release "
                "proof, fresh capacity before freeze and spawn, or a pre-frozen "
                "one-wave root bound to atomic task creation and safe rollover, "
                "without retiring, creating, transferring, or launching work."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_execution_readiness",
            "title": "Evaluate pre-authority execution readiness",
            "description": (
                "Seal one provider-free readiness decision for the exact "
                "executor, controller, adapter, policy, descriptor, finalizer, "
                "evidence schema, environment, failure replay, lifecycle "
                "policy, and preserved regression fixtures before authority."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_coordinator_capsule",
            "title": "Evaluate a durable coordinator capsule",
            "description": (
                "Seal or validate one provider-free coordinator capsule, CAS "
                "update, post-compaction resume, cursor wait, efficiency budget, "
                "safe-rollover handoff, or historical replay without polling, "
                "messaging, task creation, lease transfer, or hosted work."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "project_orchestration_live_view",
            "title": "Project an Orch Dork live graph view",
            "description": (
                "Render a frozen plan beside append-only observed graph, "
                "telemetry, qualification, certainty, and navigation evidence."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "prepare_governed_native_activation",
            "title": "Prepare one governed native activation",
            "description": (
                "Bind one self-sealed permitting pre-implementation project-adapter "
                "report into the exact project-ground activation state, refresh its "
                "seal, and require a provider-free HEALTHY evaluation before returning "
                "a prepared payload. This read-only seam grants no authority and the "
                "unchanged controller and hard pre-spawn admission remain authoritative."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "authorize_issue94_successor_first_action",
            "title": "Authorize the exact Issue 94 successor first action",
            "description": (
                "Consume one sealed pre-turn successor report after the real "
                "startup SessionStart, atomically derive capacity admission "
                "and its exact spawn intent through repository constructors, "
                "and stop with READY_FOR_ONE_ATTEMPT before any native call."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pre_turn_report_path": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 4096,
                    },
                    "pre_turn_report_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                },
                "required": [
                    "pre_turn_report_path",
                    "pre_turn_report_sha256",
                ],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": False,
            },
        },
        {
            "name": "submit_issue94_semantic_review",
            "title": "Submit the Issue 94 root review",
            "description": (
                "Retain both raw VerificationReceipts for the controller's exact review subject. "
                "The host captures native call provenance and returns a submission acknowledgement. "
                "Semantic acceptance requires a subsequent independent owner observation."
            ),
            "inputSchema": {
                "type": "object", "properties": {
                    "pre_turn_report_path": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "pre_turn_report_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "subject_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "verifications": {"type": "array", "minItems": 2, "maxItems": 2,
                                      "items": {"type": "object", "properties": {
                                          "logical_worker_id": {"type": "string", "enum": ["spec", "standards"]},
                                          "verification_receipt": {"type": "object"}},
                                          "required": ["logical_worker_id", "verification_receipt"], "additionalProperties": False}},
                }, "required": ["pre_turn_report_path", "pre_turn_report_sha256", "subject_sha256", "verifications"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False, "idempotentHint": False},
        },
        {
            "name": "submit_issue94_bootstrapped_semantic_review",
            "title": "Submit the bootstrap-origin Issue 94 root review",
            "description": (
                "Retain both raw VerificationReceipts against the canonical bootstrap artifact. "
                "The host supplies source, evidence, enrollment, task, and native-call context."
            ),
            "inputSchema": {
                "type": "object", "properties": {
                    "bootstrap_artifact_path": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "bootstrap_report_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "subject_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "verifications": {"type": "array", "minItems": 2, "maxItems": 2,
                                      "items": {"type": "object", "properties": {
                                          "logical_worker_id": {"type": "string", "enum": ["spec", "standards"]},
                                          "verification_receipt": {"type": "object"}},
                                          "required": ["logical_worker_id", "verification_receipt"], "additionalProperties": False}},
                }, "required": ["bootstrap_artifact_path", "bootstrap_report_sha256", "subject_sha256", "verifications"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False, "idempotentHint": False},
        },
        {
            "name": "advance_issue94_successor_after_native_action",
            "title": "Advance the Issue 94 successor after one native action",
            "description": (
                "Consume the same sealed Issue 94 pre-turn report after the "
                "exact native action has been durably observed, construct the "
                "closed observation receipt from canonical hook evidence, and "
                "return the next exact action without caller field translation."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pre_turn_report_path": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 4096,
                    },
                    "pre_turn_report_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                },
                "required": [
                    "pre_turn_report_path",
                    "pre_turn_report_sha256",
                ],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": False,
            },
        },
        {
            "name": "advance_issue94_bootstrapped_after_native_action",
            "title": "Advance the bootstrap-origin Issue 94 controller",
            "description": (
                "Consume the canonical bootstrap artifact after one native action. "
                "The host supplies source, evidence, enrollment, task, and native-call context."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "bootstrap_artifact_path": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "bootstrap_report_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                },
                "required": ["bootstrap_artifact_path", "bootstrap_report_sha256"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False, "idempotentHint": False},
        },
        {
            "name": "advance_governed_native_controller",
            "title": "Advance one governed native controller transition",
            "description": (
                "Apply one closed provider-free transition through the canonical "
                "host-owned governed native controller. This is the explicit "
                "activation, stage, observation, and inspection bridge; it owns no "
                "provider, model, task, worker, credential, or native-action call."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": {
                        "type": "object",
                        "properties": {
                            "schema": {
                                "const": (
                                    "orch-dork/governed-native-controller-program/v1"
                                )
                            },
                            "controller_id": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 256,
                            },
                            "operation": {
                                "enum": ["activate", "stage", "observe", "inspect"]
                            },
                            "expected_cursor": {"type": ["object", "null"]},
                            "payload": {"type": "object"},
                        },
                        "required": [
                            "schema",
                            "controller_id",
                            "operation",
                            "expected_cursor",
                            "payload",
                        ],
                        "additionalProperties": False,
                    },
                    "source_roots": {
                        "type": "object",
                        "minProperties": 1,
                        "additionalProperties": {"type": "string"},
                    },
                },
                "required": ["program", "source_roots"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": False,
            },
        },
        {
            "name": "evaluate_project_ground_enforcement",
            "title": "Evaluate one project-ground mutation gate",
            "description": (
                "Compose trusted hook health, enrollment, immutable adapter, "
                "ticket admission, execution readiness, lease ownership, active "
                "controller, capsule, sandbox coverage, protected resources, and "
                "exact tool input into one provider-free read-only decision. The "
                "actual plugin hook or project-native gateway owns enforcement."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_project_ground_maintenance",
            "title": "Evaluate project-ground migration or recovery",
            "description": (
                "Preview one provider-free pinned compatibility, transactional "
                "migration, exact recovery, diagnostic, cache, or replay-bound "
                "maintenance decision. The MCP surface is read-only; explicit "
                "no-active-writer maintenance owns any later filesystem apply."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_project_enrollment",
            "title": "Evaluate Orch Dork project enrollment",
            "description": (
                "Read and validate one exact external enrollment record and "
                "repository binding generation without enrolling, repairing, "
                "removing, or mutating a project."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_orchestration_project_adapter",
            "title": "Evaluate an Orch Dork project adapter",
            "description": (
                "Validate a declarative project adapter, authority boundary, "
                "workspace observation, verification, and external checkpoints."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_orchestration_worker_port",
            "title": "Evaluate an Orch Dork worker port",
            "description": (
                "Validate the provider-free WorkerTransport, workspace, adapter, "
                "evidence, qualification, or activation boundary without making "
                "model, route, command, worktree, application, or promotion calls."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_orchestration_control_tower",
            "title": "Evaluate an Orch Dork Control Tower transition",
            "description": (
                "Prepare, advance, or inspect one provider-free typed finite-DAG "
                "Control Tower lifecycle through the canonical RunEngine and "
                "closed artifact, worker, and verification contracts. Intents "
                "never count as observed execution and this surface makes no "
                "model, hosted, credential, tool, repository, or release call."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": False,
            },
        },
        {
            "name": "observe_current_orchestration_route",
            "title": "Observe the current Orch Dork root route",
            "description": (
                "Read only the active Codex task's session_meta and final turn_context, "
                "seal its exact model, effort, multi-agent surface, and governed worker "
                "route, and reject unsupported or changed Sol/Opus launch profiles."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "expected_identity_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    }
                },
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_live_route_handoff",
            "title": "Evaluate a live route authorization handoff",
            "description": (
                "Prepare a sealed human-authorization checkpoint from the current "
                "task route, or bind the exact later authorization while permitting "
                "only the expected turn advance under an unchanged task, root, "
                "surface, and worker route. A successful authorization returns the "
                "new exact route identity for the ordinary immediate drift check; "
                "it makes no provider, model, credential, network, or live call."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "observe_current_local_task_runtime",
            "title": "Observe the current Local task owner",
            "description": (
                "Read only the explicitly injected Local app-server owner socket, "
                "prove that it owns and has loaded the current MCP task, and require "
                "zero direct descendants without guessing or falling back to a fixed "
                "desktop server."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "prepare_work_summary",
            "title": "Prepare work from a plain request or any ticket format",
            "description": "Codex interprets supplied input_text and drafts the goal, lanes or tickets. The host selects ready tickets with disjoint write ownership and resolves enrolled checks. Omitted models and efforts use active project defaults; without those defaults supply model and effort. Explicit choices win. Raw text is provenance only; show the returned summary in this task before start_governed_run using the returned start_arguments. This creates no run and makes no provider or GitHub call.",
            "inputSchema": {
                "type": "object", "properties": {
                    "project_root": {"type": "string"},
                    "input_text": {"type": "string", "minLength": 1, "maxLength": 262144},
                    "goal": {"type": "string", "minLength": 1, "maxLength": 16000},
                    "model": {"type": "string"}, "effort": {"type": "string"},
                    "lanes": _governed_lane_schema(),
                    "tickets": {"type": "array", "minItems": 1, "maxItems": 128, "items": {
                        "type": "object", "properties": {
                            "id": {"type": "string", "minLength": 1, "maxLength": 128},
                            "status": {"type": "string", "enum": ["ready", "complete", "blocked"]},
                            "depends_on": {"type": "array", "items": {"type": "string"}},
                            "writes": {"type": "array", "maxItems": 128, "items": {"type": "string"}},
                            "goal": {"type": "string", "minLength": 1, "maxLength": 16000},
                            "checks": _governed_lane_schema()["items"]["properties"]["checks"],
                        }, "required": ["id", "status", "depends_on", "writes", "goal", "checks"],
                        "additionalProperties": False,
                    }},
                    "ticket_file": {"type": "string"},
                    "worker_model": {"type": "string"}, "worker_effort": {"type": "string"},
                    "cost_budget_usd": {"type": ["number", "string"]},
                }, "required": ["project_root", "input_text", "goal"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "openWorldHint": False, "idempotentHint": True},
        },
        {
            "name": "propose_ticket_status_update",
            "title": "Propose status edits after a Verified ticket run",
            "description": "Propose exact literal before/after edits for tickets selected by this task's prepared intake, only after the host's Verified verdict. The optional enrolled-project ticket_file must be unchanged. Return the exact diff and ask the user to confirm it; no ticket status is written here. Supplied GitHub bodies are local text, never remote writes.",
            "inputSchema": {
                "type": "object", "properties": {
                    "run_id": {"type": "string"},
                    "edits": {"type": "array", "minItems": 1, "maxItems": 8, "items": {
                        "type": "object", "properties": {
                            "ticket_id": {"type": "string"},
                            "before": {"type": "string", "minLength": 1, "maxLength": 4096},
                            "after": {"type": "string", "minLength": 1, "maxLength": 4096},
                        }, "required": ["ticket_id", "before", "after"], "additionalProperties": False,
                    }},
                }, "required": ["run_id", "edits"], "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "openWorldHint": False, "idempotentHint": True},
        },
        {
            "name": "confirm_ticket_status_update",
            "title": "Apply the exact status proposal the user confirmed",
            "description": "Only after the user explicitly confirms the exact proposed diff in this requesting task, pass its proposal_sha256 as confirm_proposal_sha256. Standing run authority never supplies this confirmation. Recheck Verified and the unchanged file, consume confirmation once, and atomically apply only that proposal. Refuse active runs, stale files, other tasks, or used confirmations.",
            "inputSchema": {
                "type": "object", "properties": {
                    "confirm_proposal_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                }, "required": ["confirm_proposal_sha256"], "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "openWorldHint": False, "idempotentHint": False},
        },
        {
            "name": "start_governed_run",
            "title": "Start one governed task from this task",
            "description": (
                "Compare the run's frozen plan with the project's standing "
                "authority, then start one governed task in an enrolled project: "
                "omitted models and efforts use active project defaults; without "
                "those defaults supply model and effort. Explicit choices win. "
                "project_canary binds a frozen case only after the project-improvements "
                "journey's authorize_project_canary approval. "
                "with no lanes, a separate Codex task does the work under Orch "
                "Dork's hooks; with lanes (at most eight), that task spawns one "
                "worker per lane running worker_model, which writes the code, and "
                "model plans. Orch Dork runs each lane's checks (an enrolled check, "
                "optionally narrowed to the lane's test files by selectors) and the "
                "project's own checks itself, with one repair round if a check fails. "
                "Within the limits it starts at once with a notice and the plan "
                "diagram; beyond any limit it returns APPROVAL_REQUIRED naming "
                "each limit; after the user approves, the same call with "
                "approve_plan_sha256 starts exactly that plan one time, and the "
                "approval lapses after an hour or at the end of the day. Read the "
                "host-computed verdict with read_governed_run. A failed self-test "
                "or missing onboarding refuses with a named reason and an advisory "
                "offer that starts nothing without the user's confirmation; a "
                "repository with a running governed run, or a machine whose runs "
                "already hold eight lane workers, refuses at once."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project_root": {"type": "string"},
                    "goal": {"type": "string"},
                    "intake_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "model": {"type": "string"},
                    "effort": {"type": "string"},
                    "cost_budget_usd": {"type": ["number", "string"]},
                    "approve_plan_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "lanes": _governed_lane_schema(),
                    "worker_model": {"type": "string"},
                    "worker_effort": {"type": "string"},
                    "project_canary": {"type": "object", "properties": {
                        "proposal_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "intent_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "fixture_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "role": {"type": "string", "enum": ["champion", "challenger"]},
                    }, "required": ["proposal_sha256", "intent_sha256", "fixture_sha256", "role"], "additionalProperties": False},
                },
                "required": ["project_root", "goal"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": False,
            },
        },
        {
            "name": "read_governed_run",
            "title": "Read one governed run's status or verdict",
            "description": (
                "Wait up to wait_seconds (at most 50) for one governed run to "
                "end, then return its host-computed verdict, check results and "
                "record location, or its current state if it has not ended."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "run_id": {"type": "string"},
                    "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 50},
                },
                "required": ["run_id"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "steer_governed_run",
            "title": "Steer a running governed task",
            "description": (
                "Forward the user's exact words once from this run's requesting task. "
                "Direct typing in the governed task is also recorded. A steer keeps "
                "the frozen plan: an action outside it is refused and creates a "
                "revision offer visible through read_governed_run. Stop ends the run."
            ),
            "inputSchema": {
                "type": "object", "properties": {
                    "run_id": {"type": "string"}, "text": {"type": "string", "minLength": 1, "maxLength": 16000},
                }, "required": ["run_id", "text"], "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "openWorldHint": False, "idempotentHint": False},
        },
        {
            "name": "revise_governed_run",
            "title": "Accept or decline a specific plan revision offer",
            "description": (
                "Answer the offer read_governed_run showed. Declining keeps the original "
                "plan. Accepting supplies the revised goal and lanes (empty for zero "
                "workers); the watcher admits and freezes a new revision before "
                "activating it after old turns end. Beyond standing limits it returns "
                "APPROVAL_REQUIRED; only after the user approves, repeat with that "
                "exact approve_plan_sha256. No model or effort substitution, automatic "
                "retry, or extra repair is allowed."
            ),
            "inputSchema": {
                "type": "object", "properties": {
                    "run_id": {"type": "string"}, "offer_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "accept": {"type": "boolean"}, "goal": {"type": "string", "minLength": 1, "maxLength": 16000},
                    "lanes": _governed_lane_schema(),
                    "approve_plan_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                }, "required": ["run_id", "offer_sha256", "accept"], "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False,
                            "openWorldHint": False, "idempotentHint": False},
        },
        {
            "name": "stop_governed_run",
            "title": "Stop one governed run",
            "description": (
                "Stop a governed run at once: the watcher interrupts the governed "
                "task, ends its checks, cleans up, and records the verdict Stopped "
                "by you. A stop is never retried or replaced."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"run_id": {"type": "string"}},
                "required": ["run_id"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False,
                # Codex 0.160.0 asks before any tool marked destructive, and an
                # approval policy of never refuses it outright; stopping ends an
                # Orch Dork run and deletes nothing of the user's.
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "open_local_ui",
            "title": "Open Orch Dork's local setup and run views",
            "description": (
                "Return a private, expiring loopback link for packaged offline "
                "pages: project setup and standing limits, model onboarding, "
                "past runs, and read-only live plan diagrams; pass `view: \"tailnet\"` "
                "to open the same session from another of the user's own tailnet "
                "devices through an existing Tailscale Serve HTTPS mapping. Setup uses the "
                "same confirmation seams as chat. No page controls a run; "
                "Stop and run decisions stay in chat. Share the link only here."
            ),
            "inputSchema": {"type": "object", "properties": {
                "view": {"type": "string", "enum": ["local", "tailnet"]},
            }, "additionalProperties": False},
            "annotations": {
                "readOnlyHint": False, "destructiveHint": False,
                "openWorldHint": False, "idempotentHint": False,
            },
        },
        {
            "name": "onboard_model",
            "title": "Onboard or re-onboard a model named by the user",
            "description": (
                "Start onboarding for a model from Codex's list or any typed "
                "name, recording its family, privacy and V1 status. Before "
                "calling, explain that the short probe sends a trivial task "
                "using the user's login, spends a few thousand tokens and "
                "sends no project content. Use re_onboard only when asked "
                "to repeat a passed probe; follow with read_onboarding."
            ),
            "inputSchema": {
                "type": "object", "properties": {
                    "model": {"type": "string"}, "re_onboard": {"type": "boolean"},
                },
                "required": ["model"], "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False, "destructiveHint": False,
                "openWorldHint": True, "idempotentHint": False,
            },
        },
        {
            "name": "enroll_project",
            "title": "Propose enrolling a project for governed runs",
            "description": (
                "Inspect a project and propose its enrollment for governed runs: "
                "the check commands its own files declare (or a named question "
                "when they are ambiguous or missing), the model this task runs "
                "as Codex recorded it, the models Codex reports with a suggested "
                "second model, where governed runs reach V1, and default "
                "standing limits. Writes only a draft; nothing is enrolled until "
                "confirm_enrollment applies the user's answers."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"project_root": {"type": "string"}},
                "required": ["project_root"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": False,
            },
        },
        {
            "name": "confirm_enrollment",
            "title": "Confirm a project's enrollment and standing authority",
            "description": (
                "Apply the user's answers to an enrollment proposal: enroll the "
                "project through project ground, write its enrollment record and "
                "standing authority (workers, per-run and daily cost, allowed "
                "Workflow Profiles, role lineup, per-run approval, keep on this "
                "machine), and start onboarding for whichever of the chat model "
                "and the second model has not passed. Pass only what the user "
                "said; anything missing is returned as a named question."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "draft_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "second_model": {"type": "string"},
                    "keep_local": {"type": "boolean"},
                    "checks": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "argv": {"type": "array", "items": {"type": "string"}},
                                "timeout_seconds": {"type": "integer"},
                            },
                            "required": ["id", "argv", "timeout_seconds"],
                            "additionalProperties": False,
                        },
                    },
                    "chat_model": {"type": "string"},
                    "lineup_preset": {"type": "string", "enum": ["cheap", "balanced", "local"]},
                    "workers_max": {"type": "integer", "minimum": 1, "maximum": 8},
                    "per_run_cost_usd": {"type": ["number", "string"]},
                    "daily_cost_usd": {"type": ["number", "string"]},
                    "allowed_workflow_profiles": {"type": "array", "items": {"type": "string"}},
                    "per_run_approval": {"type": "boolean"},
                    "v1_opt_in": {"type": "string", "enum": ["accept", "decline"]},
                },
                "required": ["draft_sha256", "second_model", "keep_local"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": False,
            },
        },
        {
            "name": "read_onboarding",
            "title": "Read an onboarding job's progress",
            "description": (
                "Wait up to wait_seconds (at most 50) for an onboarding job to "
                "finish, then return each model's result and whether governed "
                "runs may start: two different models must pass onboarding."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": {"type": "string"},
                    "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 50},
                },
                "required": ["job_id"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "validate_logical_worker_program",
            "title": "Validate an Orch Dork logical worker program",
            "description": (
                "Validate any finite, justified logical worker program and bind it "
                "to the active task's runtime-observed root route without consulting "
                "or inferring live collaboration capacity."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"plan": {"type": "object"}},
                "required": ["plan"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "run_logical_worker_waves",
            "title": "Run an Orch Dork logical worker wave program",
            "description": (
                "Deterministically drain a finite logical program through "
                "fresh capacity-bound fixture/runtime observations without polling. "
                "Require and re-observe the route identity sealed at plan freeze. "
                "Substantive v3 programs require independently observed typed-output "
                "route preflights, exact native routing, live progress, completion "
                "reserve, and typed terminals; v1/v2 remain replay-compatible."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": _wave_program_descriptor(),
                    "expected_route_identity_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                },
                "required": ["expected_route_identity_sha256", "program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_wave_progress",
            "title": "Evaluate an Orch Dork live progress prefix",
            "description": (
                "Validate one append-only prefix of TaskSpec-bound incremental "
                "packets, reject duplicate or non-monotonic evidence, and stop "
                "continuation before completion reserve would be consumed."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": _progress_program_descriptor()},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_advisory_scan",
            "title": "Prepare or finalize a bounded advisory scan",
            "description": (
                "Build one finite read-only logical plan and typed TaskSpec per "
                "lane, or finalize exact native creation and terminal results. "
                "New v2 finalization also binds a sealed matching native observation "
                "or one typed unavailability; v1 remains replay-compatible. Completed "
                "handoffs remain reportable when qualification evidence is unknown, "
                "but this contract never permits a qualified runtime claim, worker "
                "creation, provider call, retry, or mutation."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": (
                        advisory_scan.program_descriptor()
                        if advisory_scan is not None
                        else {"type": "object"}
                    )
                },
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "observe_native_advisory_scan",
            "title": "Observe one bounded native advisory scan",
            "description": (
                "Read only the exact-hash root and child session files named by "
                "an attempt-observer manifest, compose the canonical graph and "
                "per-session route/terminal/usage observers, and return a compact "
                "path-free projection. Optional host signing uses the fixed "
                "provisioned observer authority. This tool never searches session "
                "storage or permits a runtime qualification claim."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": (
                        native_scan_observer.program_descriptor()
                        if native_scan_observer is not None
                        else {"type": "object"}
                    )
                },
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_sol_replan",
            "title": "Evaluate an Orch Dork Sol replan",
            "description": (
                "Validate a Sol-authored immutable plan revision, preserve failed "
                "history, and propagate failure only through declared dependencies."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_decomposition_proposal",
            "title": "Evaluate an Orch Dork decomposition proposal",
            "description": (
                "Stage-A mechanical validation of one typed worker split "
                "proposal: coverage of every parent acceptance criterion, "
                "acyclic children, frozen checkpoint, budget and per-node "
                "model channels, and root-only ownership. Optionally binds "
                "the implied successor revision with retained-node content "
                "hashes so later spec drift is visible."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "proposal": {"type": "object"},
                    "parent_plan": {"type": "object"},
                    "bind": {"type": "boolean"},
                },
                "required": ["proposal"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_adaptive_finite_dag",
            "title": "Evaluate an adaptive finite-DAG revision",
            "description": (
                "Validate one root-governed finite-DAG revision transaction, "
                "including the current plan, typed worker proposal, Sol "
                "approval, scope, graph, depth, revision, node, retry, and "
                "token limits, without launching workers or contacting a provider."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": _adaptive_program_descriptor()},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "validate_adaptive_contract",
            "title": "Validate an adaptive finite-DAG contract",
            "description": (
                "Route one explicit typed contract to the canonical provider-"
                "free validator. Inputs are closed records and may contain only "
                "bounded content-addressed evidence, never worker transcripts "
                "or tool history. Runtime preflight, observer-bound candidate, "
                "and incremental packets require their exact TaskSpecV2; "
                "VerificationReceiptV1 also "
                "requires the exact subject handoff it verifies."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "contract_kind": {
                        "type": "string",
                        "enum": list(ADAPTIVE_CONTRACT_KINDS),
                    },
                    "value": {"type": "object"},
                    "task_spec": {"type": "object"},
                    "handoff_receipt": {"type": "object"},
                    "authorized_write_scope": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 256,
                    },
                },
                "required": ["contract_kind", "value"],
                "allOf": _contract_requirement_conditions(),
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_evidence_policy",
            "title": "Evaluate bounded evidence-integrity contracts",
            "description": (
                "Validate produced-evidence identity, failure-origin quality evidence, "
                "advisory novelty versus actual use, or bounded Evidence Reveal without "
                "provider calls, transcript expansion, or filesystem access."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": _model_combo_program_descriptor(
                        "orch-dork/evidence-policy-program/v1",
                        EVIDENCE_POLICY_OPERATIONS,
                    )
                },
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_route_policy",
            "title": "Evaluate bounded route-integrity contracts",
            "description": (
                "Validate quorum over stable independence groups, serving-epoch causal "
                "comparability, or exact pre-work TaskSpec delivery acknowledgement."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": _model_combo_program_descriptor(
                        "orch-dork/route-policy-program/v1",
                        ROUTE_POLICY_OPERATIONS,
                    )
                },
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_campaign_policy",
            "title": "Evaluate bounded campaign-integrity contracts",
            "description": (
                "Validate permanently charged series authority, anti-Goodhart evaluator "
                "witnesses and probes, or deterministic risk-aware batch disposition."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": _model_combo_program_descriptor(
                        "orch-dork/campaign-policy-program/v1",
                        CAMPAIGN_POLICY_OPERATIONS,
                    )
                },
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_experiment_campaign",
            "title": "Seal or verify a preregistered experiment campaign",
            "description": (
                "Seal and verify closed campaign/v1 preregistration material or "
                "campaign-bound preregistered/exploratory result records. The "
                "provider-free contract executes no run and cannot change a default."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "validate_relay_manifest",
            "title": "Validate an Orch Dork relay manifest",
            "description": (
                "Validate one typed context-transfer contract between a "
                "producer and consumer node, or check a delivery against it: "
                "hash-pinned required inputs, fact freshness, forbidden-"
                "context fencing, and consumer acknowledgment routing."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest": {"type": "object"},
                    "delivery": {"type": "object"},
                },
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "verify_wave_routing",
            "title": "Verify observed wave routing against the frozen plan",
            "description": (
                "Compare each lane's observed session routing (model, effort, "
                "inherited history) against the plan-declared root and worker "
                "routing. The plan hash says declared; this says observed."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": _routing_program_descriptor()},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "run_active_orchestration_controller",
            "title": "Run the Orch Dork active controller",
            "description": (
                "Advance mechanical lifecycle rules from a closed runtime event "
                "stream and emit a compact Sol packet only for semantic decisions."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": {
                        "type": "object",
                        "properties": {
                            "schema": {
                                "const": "orch-dork/active-controller-program/v1"
                            }
                        },
                        "required": ["schema"],
                    }
                },
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_orchestration_limits",
            "title": "Evaluate Orch Dork limits and completion reserve",
            "description": (
                "Separate hard authority or safety ceilings, soft efficiency "
                "targets, and completion-only reserve using exact raw telemetry."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_orchestration_profile",
            "title": "Evaluate an Orch Dork profile lifecycle",
            "description": (
                "Derive exact profile activation, authority-required, running, "
                "or profile-local suspension state from immutable evidence."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_orchestration_efficiency",
            "title": "Evaluate Orch Dork coordination efficiency",
            "description": (
                "Automatically close a finite matched evaluation from exact "
                "sealed trial evidence without controlling safety activation."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_orchestration_budget",
            "title": "Evaluate an Orch Dork budget ledger",
            "description": (
                "Reconcile exact-or-unknown runtime consumption and reserve "
                "declared budget before downstream work starts."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_orchestration_recovery",
            "title": "Evaluate Orch Dork cancellation and recovery",
            "description": (
                "Preserve cancellation or timeout history, verify cleanup, and "
                "require a separate authorized identity for later recovery."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "qualify_orchestration_graph",
            "title": "Qualify an Orch Dork execution graph",
            "description": (
                "Validate a finite typed dependency graph and deterministically "
                "qualify joins, quorum, releases, bounds, and final verification."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "evaluate_root_rollover",
            "title": "Evaluate an Orch Dork root rollover",
            "description": (
                "Seal and verify a safe exactly-once no-history Sol successor "
                "handoff with single-owner lease transfer."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"program": {"type": "object"}},
                "required": ["program"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "validate_orchestration_custody",
            "title": "Validate Orch Dork attempt custody",
            "description": (
                "Bind admitted workers to lanes and reject non-member, protected, "
                "out-of-scope, or pre-release cross-lane resource access."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan": {"type": "object"},
                    "spawn_wave": {"type": "object"},
                    "events": {"type": "object"},
                },
                "required": ["plan", "spawn_wave", "events"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "validate_orchestration_ownership",
            "title": "Validate Orch Dork ownership",
            "description": (
                "Normalize lane resources and reject path, glob, semantic, symlink, "
                "protected-resource, and dirty-baseline conflicts before work begins."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan": {"type": "object"},
                    "workspace_root": {"type": "string"},
                    "baseline": {"type": "object"},
                },
                "required": ["plan"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "validate_orchestration_admission",
            "title": "Validate Orch Dork capacity admission",
            "description": (
                "Validate a native collaboration inventory before plan freeze. "
                "Require and re-observe the route identity sealed by plan validation. "
                "At most 32 non-root pending or running lanes occupy capacity; "
                "terminal lanes release only on exact host-signed lane, run, and "
                "native-route cleanup proof with zero owned descendants, without "
                "identity reuse. This read-only MCP projection cannot commit the "
                "root-owned CAS reservation and therefore grants no spawn authority."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan": {"type": "object"},
                    "inventory": {"type": "object"},
                    "expected_route_identity_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                },
                "required": [
                    "plan",
                    "inventory",
                    "expected_route_identity_sha256",
                ],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
        },
        {
            "name": "validate_orchestration_spawn_wave",
            "title": "Validate an Orch Dork spawn wave",
            "description": (
                "Require one fresh confirmed creation result for every admitted lane. "
                "Require and re-observe the route identity sealed at plan freeze. "
                "Partial, ambiguous, failed, duplicate, reused, or uncommitted-authority "
                "waves abort without replacement; the read-only MCP seam cannot supply "
                "the root-owned authority adapter."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan": {"type": "object"},
                    "admission": {"type": "object"},
                    "expected_route_identity_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "lane_id": {"type": "string", "minLength": 1},
                                "worker_id": {"type": "string", "minLength": 1},
                                "status": {
                                    "type": "string",
                                    "enum": sorted(SPAWN_RESULT_STATUSES),
                                },
                                "fresh": {"type": "boolean"},
                                "parent_thread_id": {"type": "string", "minLength": 1},
                            },
                            "required": sorted(SPAWN_RESULT_FIELDS),
                            "additionalProperties": False,
                        },
                    },
                },
                "required": [
                    "plan",
                    "admission",
                    "results",
                    "expected_route_identity_sha256",
                ],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False, "idempotentHint": True},
        },
        {
            "name": "validate_orchestration_plan",
            "title": "Validate an Orch Dork plan",
            "description": (
                "Validate and canonicalize a submitted orch-dork/plan/v1 against a fresh "
                "runtime observation of the active task's root route before implementation. "
                "It does not launch agents."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"plan": {"type": "object"}},
                "required": ["plan"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "qualify_orchestration_trace",
            "title": "Qualify an Orch Dork trace",
            "description": (
                "Check a normalized orch-dork/trace/v1 against its frozen plan. "
                "PASS establishes submitted structural conformance only; it never "
                "permits a terminal qualification or completion claim."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan": {"type": "object"},
                    "trace": {"type": "object"},
                },
                "required": ["plan", "trace"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
        {
            "name": "qualify_read_custody",
            "title": "Qualify the read-custody axis of a run",
            "description": (
                "Check an orch-dork/read-custody-audit/v1 report (digest "
                "recomputed) plus optional custody-exception/v1 records. "
                "Every violation must be covered by a cured or superseded "
                "exception; recorded exceptions and uncovered violations "
                "refuse the axis. PASS establishes the read-custody axis "
                "only; it never permits a terminal qualification or "
                "completion claim."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "audit_report": {"type": "object"},
                    "exceptions": {"type": "array", "items": {"type": "object"}},
                },
                "required": ["audit_report"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False,
                "idempotentHint": True,
            },
        },
    ]


def _tool_result(structured):
    rendered = compact_json(structured)
    if len(rendered.encode("utf-8")) > 32_768:
        projection = {
            "schema": "orch-dork/mcp-structured-content-projection/v1",
            "status": structured.get("status"),
            "decision": structured.get("decision"),
            "issues": structured.get("issues"),
            "action": structured.get("action"),
            "structured_content_sha256": hashlib.sha256(
                rendered.encode("utf-8")
            ).hexdigest(),
        }
        rendered = compact_json(projection)
        if len(rendered.encode("utf-8")) > 32_768:
            # A spawn batch carries each worker's sealed review corpus, which
            # quotes whole AGENTS.md sections, so the action alone can exceed
            # the frame's string bound (66 KB on 2026-09-30). The frame keeps
            # the action's digest; structuredContent still carries the action.
            projection["action"] = {
                "action_sha256": json_sha256(structured.get("action"))
            }
            rendered = compact_json(projection)
    return {
        "content": [{"type": "text", "text": rendered}],
        "structuredContent": structured,
        "isError": False,
    }


def _rpc_result(identifier, result):
    return {"jsonrpc": "2.0", "id": identifier, "result": result}


def _rpc_error(identifier, code, message):
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}}


def _owner_control_step_gate(evaluator, name, arguments, unavailable, issue):
    """Claim the qualification owner's open step before any controller read.

    Returns the bridge's no-effect refusal, an unavailable report when the
    step record cannot be read, or None to admit the call. An evaluator
    without the claim, or a flow whose owner opened no steps, is not gated.
    """

    claim = getattr(evaluator, "claim_owner_control_step", None)
    if not inspect.isfunction(claim):
        return None
    try:
        result = claim(
            pre_turn_report_path=arguments["pre_turn_report_path"],
            expected_report_sha256=arguments["pre_turn_report_sha256"],
            tool=name,
        )
    except Exception:
        return unavailable(issue)
    return result if result is None or isinstance(result, dict) else unavailable(issue)


def _action_advance_mcp_response_should_use_v2(evaluator, report):
    """Choose the v2 digest-only receipt for the validated current v5 schema.

    The "validated current v5" check is read off the passed-in pinned
    evaluator; policy never re-imports the sibling and never inspects the
    report beyond its declared schema. The v2 receipt keeps the create-only
    artifact as the sole location of the full action and report bytes; a v1
    receipt re-embeds the full action and reopens the same transport-stage
    truncation. Waiting / frontier / action-null v5 reports are not exempted:
    they ride the bounded frame just as safely through v2 because the v2
    receipt carries only the canonical action's declared digest.
    """
    if not isinstance(report, dict):
        return False
    v5_schema = getattr(evaluator, "ACTION_ADVANCE_REPORT_SCHEMA", None)
    if v5_schema is None or report.get("schema") != v5_schema:
        return False
    v2_schema = getattr(evaluator, "ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA", None)
    return isinstance(v2_schema, str) and bool(v2_schema)


_DEFAULT_ACTION_ADVANCE_MCP_RESPONSE_BUDGET = MCP_ACTION_ADVANCE_RESPONSE_BUDGET_BYTES


def _action_advance_mcp_response_budget(evaluator):
    """Resolve the conservative finite response budget from the pinned evaluator.

    Production uses the passed pinned evaluator's
    ``ACTION_ADVANCE_RESULT_ARTIFACT_RESPONSE_BUDGET`` without importing a
    different sibling. Older/test evaluators that omit a valid budget use
    policy's finite 8192-byte compatibility default. A present valid budget
    is honored; the compatibility default does not mask its value. Neither
    path permits an unbounded frame or a relaxed transport fallback.
    """
    budget = getattr(
        evaluator,
        "ACTION_ADVANCE_RESULT_ARTIFACT_RESPONSE_BUDGET",
        _DEFAULT_ACTION_ADVANCE_MCP_RESPONSE_BUDGET,
    )
    if not isinstance(budget, int) or budget <= 0:
        return _DEFAULT_ACTION_ADVANCE_MCP_RESPONSE_BUDGET
    return budget


def _action_advance_mcp_response(identifier, report, evaluator):
    """Keep complete generated reports in owned artifacts when a frame cannot fit.

    Behavior summary (issue 219 bounded result repair):
    * The serialised MCP response is bound by a conservative finite budget
      read from the pinned evaluator (8192 bytes by default). A serialised
      response that does not fit the budget refuses the tool call instead of
      letting the transport strip ``structuredContent`` or silently truncate
      the textual frame; the refuse never claims zero controller effects
      because the create-only artifact (when persisted) and the controller's
      previous tool outcome remain the durable record of advancement.
    * For every validated current v5 advance report the compact v2 receipt is
      used proactively before transport so that a v1 receipt with embedded
      full action never has to ride on the bounded MCP frame. The v2 persist
      is itself bound by the same finite budget; a v5 persist failure refuses
      without falling back to v1.
    * Tiny non-v5 reports and the historical v1 receipt's read contract remain
      bit-compatible: when the call passes through the legacy path the
      inline-render succeeds (no inline overflow) or the legacy v1 receipt is
      used and stays within budget; refusal-shaped inline reports keep their
      whole inline value.
    """
    import orch_dork_hostile_input as hostile_input

    budget = _action_advance_mcp_response_budget(evaluator)

    def _fits(payload):
        rendered = compact_json(payload).encode("utf-8")
        return len(rendered) <= budget

    use_v2 = _action_advance_mcp_response_should_use_v2(evaluator, report)
    persist_method = getattr(evaluator, "persist_issue94_action_advance_result", None)

    def persisted_response():
        if callable(persist_method):
            try:
                # Pre-v5 siblings expose only the original positional API.
                receipt = (
                    persist_method(
                        report,
                        receipt_schema=evaluator.ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA,
                    )
                    if use_v2 else persist_method(report)
                )
                response = _rpc_result(identifier, _tool_result(receipt))
                if _fits(response):
                    hostile_input.canonicalize_bounded_json(compact_json(response))
                    return response
            except Exception:
                # Advancement may already be durable. Refuse without a
                # substitute lifecycle report or an inline/full-action fallback.
                pass
        return _rpc_error(identifier, -32603, "Action result artifact unavailable")

    if use_v2:
        return persisted_response()

    inline = _rpc_result(identifier, _tool_result(report))
    try:
        bounded = hostile_input.canonicalize_bounded_json(compact_json(inline))
    except hostile_input.HostileInputError:
        bounded = None
    inline_fits = bounded is not None and _fits(inline)
    if inline_fits:
        return inline
    return persisted_response()


def dispatch(message, *, require_mcp_task_id=False):
    """Serve one MCP message, adding lifecycle resources and guidance.

    Lifecycle resources and the agent-next-invocation projection are
    navigation aids (Issue 164). The projection rides beside a tool result as
    one extra text content item; the canonical structuredContent and the first
    content item are exactly what the evaluator produced, and a projection is
    never accepted back as tool input.
    """

    if not isinstance(message, dict) or "id" not in message:
        return _dispatch_core(message, require_mcp_task_id=require_mcp_task_id)
    identifier = message.get("id")
    method = message.get("method")
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    if method == "resources/list":
        rows, issues = agent_lifecycle.list_resources(tool_catalog=list_tools())
        if rows is None:
            return _rpc_error(
                identifier, -32603, "agent_lifecycle:publication_refused:" + ",".join(issues[:4])
            )
        return _rpc_result(identifier, {"resources": rows})
    if method == "resources/read":
        contents, issues = agent_lifecycle.read_resource(
            params.get("uri"), tool_catalog=list_tools()
        )
        if contents is None:
            return _rpc_error(identifier, -32602, ",".join(issues[:4]))
        return _rpc_result(identifier, {"contents": contents})
    if method == "tools/call" and agent_lifecycle.contains_projection(params.get("arguments")):
        return _rpc_error(identifier, -32602, "agent_lifecycle:projection_not_input")
    response = _dispatch_core(message, require_mcp_task_id=require_mcp_task_id)
    result = response.get("result") if isinstance(response, dict) else None
    if (
        method == "tools/call"
        and isinstance(result, dict)
        and isinstance(result.get("structuredContent"), dict)
        and isinstance(result.get("content"), list)
    ):
        projection = agent_lifecycle.project_next_invocation(
            params.get("name"),
            result["structuredContent"],
            tool_catalog=list_tools(),
        )
        if projection is not None:
            result["content"] = [
                *result["content"],
                {"type": "text", "text": compact_json(projection)},
            ]
    return response


def _dispatch_core(message, *, require_mcp_task_id=False):
    if not isinstance(message, dict):
        return _rpc_error(None, -32600, "Invalid Request")
    identifier = message.get("id")
    method = message.get("method")
    if method in {"notifications/initialized", "notifications/cancelled"}:
        return None
    if "id" not in message:
        return None
    if method == "initialize":
        return _rpc_result(
            identifier,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"listChanged": False, "subscribe": False},
                },
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": (
                    "Validate Orch Dork plans before implementation and check normalized submitted "
                    "trace conformance. A submitted PASS never establishes terminal qualification; "
                    "external post-terminal observation is required."
                ),
            },
        )
    if method == "ping":
        return _rpc_result(identifier, {})
    if method == "tools/list":
        return _rpc_result(identifier, {"tools": list_tools()})
    if method == "resources/templates/list":
        return _rpc_result(identifier, {"resourceTemplates": []})
    if method == "tools/call":
        params = message.get("params")
        if not isinstance(params, dict):
            return _rpc_error(identifier, -32602, "Invalid params")
        request_meta = params.get("_meta")
        current_task_id = (
            request_meta.get("threadId")
            if isinstance(request_meta, dict)
            and isinstance(request_meta.get("threadId"), str)
            else None
        )
        name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            return _rpc_error(identifier, -32602, "Invalid arguments")
        if name == "audit_orchestration_classification" and set(arguments) == {"record"}:
            return _rpc_result(
                identifier,
                _tool_result(audit_classification(arguments["record"])),
            )
        if name == "evaluate_ticket_admission" and set(arguments) == {"program"}:
            if ticket_admission is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/ticket-admission/v2",
                            "policy_version": "classification-policy/v2",
                            "decision": "REFUSED",
                            "admitted": False,
                            "issues": ["ticket_admission:evaluator_unavailable"],
                            "provider_free": True,
                            "model_calls": 0,
                            "hosted_calls": 0,
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    ticket_admission.evaluate_ticket_admission(
                        arguments["program"]
                    )
                ),
            )
        if name == "evaluate_split_decision" and set(arguments) == {"program"}:
            if split_decision is None:
                report = {
                    "schema": "orch-dork/split-decision/v1",
                    "policy_version": "split-decision-policy/v1",
                    "status": "FAIL",
                    "decision": "REFUSE",
                    "split_approved": False,
                    "plan_required": False,
                    "execution_profile": None,
                    "issues": ["split_decision:evaluator_unavailable"],
                    "workers_permitted": False,
                    "authority_granted": False,
                    "capacity_consulted": False,
                    "capacity_ceiling_changed": False,
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                }
            else:
                report = split_decision.evaluate_split_decision(arguments["program"])
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_deepening_policy" and set(arguments) == {"program"}:
            if deepening_policy is None:
                report = {
                    "schema": "orch-dork/deepening-policy-report/v1",
                    "policy_version": "deepening-policy/v1",
                    "status": "FAIL",
                    "decision": "DENY",
                    "decision_record": None,
                    "reason_codes": ["contract_invalid"],
                    "issues": ["deepening_policy:evaluator_unavailable"],
                    "workers_can_spawn": False,
                    "workers_permitted": False,
                    "authority_granted": False,
                    "capacity_ceiling_changed": False,
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                }
            else:
                report = deepening_policy.evaluate_deepening_policy(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_learned_policy" and set(arguments) == {"program"}:
            if learned_policy is None:
                report = {
                    "schema": "orch-dork/learned-policy-inference/v1",
                    "status": "FAIL",
                    "issues": ["learned_policy:evaluator_unavailable"],
                    "learned_policy_applied": False,
                    "fallback_policy": "standing-defaults/v1",
                    "sizer_recommendation": None,
                    "stopping_signal": None,
                    "advisory_only": True,
                    "split_gate_required": True,
                    "deepening_gate_required": True,
                    "workers_permitted": False,
                    "authority_granted": False,
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                }
            else:
                report = learned_policy.evaluate_learned_policy(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "recommend_first_wave" and set(arguments) == {"program"}:
            if wave_recommendation is None:
                report = {
                    "schema": "orch-dork/wave-recommendation/v1",
                    "estimator_version": "first-wave-estimator/v0",
                    "status": "FAIL",
                    "issues": ["wave_recommendation:estimator_unavailable"],
                    "recommendation_id": None,
                    "task_id": None,
                    "disposition": "REFUSE",
                    "reason_codes": ["contract_invalid"],
                    "lane_count": None,
                    "candidate_cut": [],
                    "confidence_bps": None,
                    "evidence_basis": None,
                    "scout_allocation": None,
                    "estimator_input_sha256": None,
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
                    "recommendation_sha256": None,
                }
            else:
                report = wave_recommendation.recommend_first_wave(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_admission_kernel" and set(arguments) == {"program"}:
            if admission_kernel is None:
                report = {
                    "schema": "orch-dork/admission-decision/v1",
                    "kernel_version": "admission-kernel/v1",
                    "decision": "REFUSE",
                    "admitted": False,
                    "reasons": ["admission_kernel:unavailable"],
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                    "mutation_permitted": False,
                }
            else:
                report = admission_kernel.evaluate_admission_kernel(
                    arguments["program"],
                    source_roots={"plugin": Path(__file__).resolve().parents[3]},
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "validate_semantic_plan_v2" and set(arguments) == {"program"}:
            if semantic_plan_v2 is None:
                report = {
                    "schema": "orch-dork/semantic-plan-decision/v2",
                    "contract_version": "semantic-plan-v2",
                    "disposition": "REFUSE",
                    "admitted": False,
                    "reason_codes": ["semantic_plan:evaluator_unavailable"],
                    "mutation_permitted": False,
                    "authority_granted": False,
                    "workers_permitted": False,
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                }
            else:
                report = semantic_plan_v2.evaluate_semantic_plan_v2(arguments["program"])
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_task_creation_intent" and set(arguments) == {"program"}:
            if task_creation is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/task-creation-report/v1",
                            "status": "FAIL",
                            "outcome": "REFUSED",
                            "issues": ["task_creation:evaluator_unavailable"],
                            "provider_free": True,
                            "live_task_operations": 0,
                            "model_calls": 0,
                            "hosted_calls": 0,
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    task_creation.evaluate_task_creation(arguments["program"])
                ),
            )
        if name == "evaluate_governed_orchestration_run" and set(arguments) == {"program"}:
            if arguments["program"].get("schema") == "orch-dork/governed-attempt-program/v1":
                try:
                    import orch_dork_governed_attempt as governed_attempt
                except ImportError:
                    _attempt_path = Path(__file__).resolve().with_name(
                        "orch_dork_governed_attempt.py"
                    )
                    _attempt_spec = importlib.util.spec_from_file_location(
                        "orch_dork_governed_attempt", _attempt_path
                    )
                    if _attempt_spec is None or _attempt_spec.loader is None:
                        governed_attempt = None
                    else:
                        governed_attempt = importlib.util.module_from_spec(
                            _attempt_spec
                        )
                        sys.modules.setdefault(
                            "orch_dork_governed_attempt", governed_attempt
                        )
                        _attempt_spec.loader.exec_module(governed_attempt)
                if governed_attempt is None:
                    report = {
                        "schema": "orch-dork/governed-attempt-report/v1",
                        "status": "BLOCKED",
                        "disposition": "ENTRYPOINT_UNAVAILABLE",
                        "spawn_authorized": False,
                        "work_authorized": False,
                        "continuation_authorized": False,
                        "terminal_claim_permitted": False,
                        "issues": ["governed_attempt:evaluator_unavailable"],
                        "provider_free": True,
                        "live_task_operations": 0,
                        "model_calls": 0,
                        "hosted_calls": 0,
                    }
                else:
                    report = governed_attempt.evaluate_governed_attempt(
                        arguments["program"],
                        source_roots={
                            "plugin": Path(__file__).resolve().parents[3]
                        },
                    )
                return _rpc_result(identifier, _tool_result(report))
            try:
                import orch_dork_governed_run as governed_run
            except ImportError:
                _governed_run_path = Path(__file__).resolve().with_name(
                    "orch_dork_governed_run.py"
                )
                _governed_run_spec = importlib.util.spec_from_file_location(
                    "orch_dork_governed_run", _governed_run_path
                )
                if (
                    _governed_run_spec is None
                    or _governed_run_spec.loader is None
                ):
                    governed_run = None
                else:
                    governed_run = importlib.util.module_from_spec(
                        _governed_run_spec
                    )
                    _governed_run_spec.loader.exec_module(governed_run)
            if governed_run is None:
                report = {
                    "schema": "orch-dork/governed-run-report/v1",
                    "status": "BLOCKED",
                    "disposition": "ENTRYPOINT_UNAVAILABLE",
                    "issues": ["governed_run:evaluator_unavailable"],
                    "terminal_claim_permitted": False,
                    "provider_free": True,
                    "live_task_operations": 0,
                    "model_calls": 0,
                    "hosted_calls": 0,
                }
            else:
                report = governed_run.evaluate_governed_run(
                    arguments["program"],
                    policy_module=types.SimpleNamespace(
                        validate_plan=validate_plan,
                        validate_admission=validate_admission,
                        validate_spawn_wave=validate_spawn_wave,
                    ),
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "adapt_native_capacity_observation" and set(arguments) in (
            {"observation"},
            {"observation", "expected_root_thread_id"},
        ):
            if capacity_inventory is None:
                report = {
                    "schema": "orch-dork/native-capacity-adapter-report/v1",
                    "status": "FAIL",
                    "issues": ["capacity_inventory:adapter_unavailable"],
                    "capacity_authoritative": False,
                    "capacity_claim_permitted": False,
                    "inventory": None,
                    "signed_receipt_sha256": None,
                    "signing_key_id": None,
                    "trust_generation": None,
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                }
            else:
                report = capacity_inventory.adapt_native_capacity_observation(
                    arguments["observation"],
                    expected_root_thread_id=arguments.get(
                        "expected_root_thread_id"
                    ),
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_worker_lifecycle" and set(arguments) == {"program"}:
            if worker_lifecycle is None:
                report = {
                    "schema": "orch-dork/worker-lifecycle-report/v1",
                    "status": "FAIL",
                    "outcome": "REFUSED",
                    "issues": ["worker_lifecycle:evaluator_unavailable"],
                    "provider_free": True,
                    "live_worker_retirements": 0,
                    "live_task_operations": 0,
                    "workers_launched": 0,
                    "model_calls": 0,
                    "hosted_calls": 0,
                }
            else:
                report = worker_lifecycle.evaluate_worker_lifecycle(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_execution_readiness" and set(arguments) == {"program"}:
            if execution_readiness is None:
                report = {
                    "schema": "orch-dork/execution-readiness-receipt/v1",
                    "status": "NOT_READY",
                    "ready": False,
                    "authority_reservation_permitted": False,
                    "named_stop": "execution_readiness:evaluator_unavailable",
                    "issues": ["execution_readiness:evaluator_unavailable"],
                    "provider_free": True,
                    "credential_reads": 0,
                    "grant_reservations": 0,
                    "hosted_calls": 0,
                    "model_calls": 0,
                    "task_creations": 0,
                    "workers": 0,
                    "retries": 0,
                    "fallbacks": 0,
                }
            else:
                report = execution_readiness.evaluate_execution_readiness(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_coordinator_capsule" and set(arguments) == {"program"}:
            if coordinator_capsule is None:
                report = {
                    "schema": "orch-dork/coordinator-capsule-report/v1",
                    "status": "FAIL",
                    "decision": "STOPPED",
                    "next_action": {
                        "kind": "stop_unknown",
                        "reason": "coordinator capsule evaluator unavailable",
                        "source_pointer": "orch_dork_policy#dispatch",
                    },
                    "issues": ["coordinator_capsule:evaluator_unavailable"],
                    "provider_free": True,
                    "credential_reads": 0,
                    "grant_reservations": 0,
                    "hosted_calls": 0,
                    "model_calls": 0,
                    "task_creations": 0,
                    "worker_messages": 0,
                    "workers": 0,
                    "retries": 0,
                    "fallbacks": 0,
                    "replacements": 0,
                    "resampling": 0,
                }
            else:
                report = coordinator_capsule.evaluate_coordinator_capsule(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "project_orchestration_live_view" and set(arguments) == {"program"}:
            if live_view is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/live-view-report/v1",
                            "status": "FAIL",
                            "issues": ["live_view:projector_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(live_view.project_live_view(arguments["program"])),
            )
        if name == "prepare_governed_native_activation" and set(arguments) == {"program"}:
            try:
                evaluator = _load_optional_sibling(
                    "orch_dork_governed_native_controller", publish=True
                )
            except Exception:
                evaluator = None
            prepare = getattr(evaluator, "prepare_governed_native_activation", None)
            validate_report = getattr(
                evaluator, "validate_activation_preparation_report", None
            )
            if not callable(prepare) or not callable(validate_report):
                report = _activation_preparation_unavailable(
                    "preparation:evaluator_unavailable"
                )
            else:
                try:
                    report = prepare(arguments["program"])
                except Exception:
                    report = _activation_preparation_unavailable(
                        "preparation:evaluation_failed"
                    )
                else:
                    try:
                        validation = validate_report(report)
                    except Exception:
                        validation = {}
                    if not isinstance(validation, dict) or validation.get(
                        "valid"
                    ) is not True:
                        report = _activation_preparation_unavailable(
                            "preparation:evaluator_contract_invalid"
                        )
            return _rpc_result(identifier, _tool_result(report))
        if name == "authorize_issue94_successor_first_action" and set(
            arguments
        ) == {"pre_turn_report_path", "pre_turn_report_sha256"}:
            try:
                plugin_data = _governed_native_plugin_data()
                hook_definition = (
                    Path(__file__).resolve().parents[3]
                    / "hooks"
                    / "project_ground_hook.py"
                ).resolve(strict=True)
            except (OSError, TypeError, ValueError):
                report = _successor_first_action_unavailable(
                    "successor_first_action_host_bridge:input_invalid"
                )
            else:
                try:
                    evaluator = _load_optional_sibling(
                        "orch_dork_qualification_successor", publish=True
                    )
                except Exception:
                    evaluator = None
                authorize = getattr(
                    evaluator,
                    "authorize_issue94_successor_first_action",
                    None,
                )
                validate_report = getattr(
                    evaluator,
                    "validate_issue94_successor_first_action_report",
                    None,
                )
                if not callable(authorize) or not callable(validate_report):
                    report = _successor_first_action_unavailable(
                        "successor_first_action_host_bridge:evaluator_unavailable"
                    )
                elif require_mcp_task_id and not current_task_id:
                    report = _successor_first_action_unavailable(
                        "successor_first_action_host_bridge:task_identity_missing"
                    )
                elif (gated := _owner_control_step_gate(
                    evaluator, name, arguments, _successor_first_action_unavailable,
                    "successor_first_action_host_bridge:owner_step_invalid",
                )) is not None:
                    report = gated
                else:
                    try:
                        report = authorize(
                            pre_turn_report_path=arguments[
                                "pre_turn_report_path"
                            ],
                            expected_report_sha256=arguments[
                                "pre_turn_report_sha256"
                            ],
                            plugin_data=plugin_data,
                            hook_definition_path=hook_definition,
                            current_task_id=current_task_id,
                        )
                    except Exception as error:
                        report = _successor_first_action_unavailable(
                            _successor_first_action_evaluation_issue(
                                evaluator, error
                            )
                        )
                    else:
                        try:
                            validation = validate_report(report)
                        except Exception:
                            validation = {}
                        if (
                            not isinstance(validation, dict)
                            or validation.get("valid") is not True
                        ):
                            report = _successor_first_action_unavailable(
                                "successor_first_action_host_bridge:"
                                "evaluator_contract_invalid"
                            )
            return _rpc_result(identifier, _tool_result(report))
        if name == "submit_issue94_semantic_review" and set(arguments) == {
            "pre_turn_report_path", "pre_turn_report_sha256", "subject_sha256", "verifications",
        }:
            try:
                if not current_task_id:
                    raise ValueError("native task identity missing")
                evaluator = _load_optional_sibling("orch_dork_qualification_successor", publish=True)
                report = evaluator.submit_issue94_semantic_review(
                    pre_turn_report_path=arguments["pre_turn_report_path"], expected_report_sha256=arguments["pre_turn_report_sha256"],
                    subject_sha256=arguments["subject_sha256"], verifications=arguments["verifications"],
                    native_request_meta=request_meta, current_task_id=current_task_id,
                    plugin_data=_governed_native_plugin_data(),
                    hook_definition_path=(Path(__file__).resolve().parents[3] / "hooks" / "project_ground_hook.py").resolve(strict=True),
                )
                check = evaluator.validate_issue94_semantic_review_acknowledgement(
                    report, arguments=arguments, native_request_meta=request_meta, current_task_id=current_task_id)
                if not isinstance(check, dict) or check.get("valid") is not True:
                    raise ValueError("invalid acknowledgement")
            except Exception as error:
                # Keep the refusal's stable cause codes (bounded) so the
                # owner's preserved thread read names why it refused.
                causes = []
                cause = error
                while cause is not None and len(causes) < 4:
                    cause_text = str(cause)
                    if (
                        cause_text
                        and len(cause_text) <= 400
                        and ":" in cause_text
                        and all(character.isalnum() or character in "_:.,[]-" for character in cause_text)
                    ):
                        causes.append(cause_text)
                    cause = cause.__cause__
                report = {"schema": "orch-dork/qualification-review-submission-refusal/v1", "status": "BLOCKED",
                          "decision": "REVIEW_REFUSED",
                          "issues": ["successor_review_host_bridge:submission_refused", *causes]}
            return _rpc_result(identifier, _tool_result(report))
        if name == "submit_issue94_bootstrapped_semantic_review" and set(arguments) == {
            "bootstrap_artifact_path", "bootstrap_report_sha256", "subject_sha256", "verifications",
        }:
            try:
                if not current_task_id:
                    raise ValueError("native task identity missing")
                roots = _issue94_bootstrap_host_roots(arguments["bootstrap_artifact_path"])
                evaluator = _load_optional_sibling("orch_dork_qualification_successor", publish=True)
                report = evaluator.submit_issue94_bootstrapped_semantic_review(
                    bootstrap_artifact_path=arguments["bootstrap_artifact_path"],
                    expected_bootstrap_report_sha256=arguments["bootstrap_report_sha256"],
                    source_root=roots["source"], evidence_root=roots["evidence"],
                    enrollment_registry_root=roots["enrollment_registry"],
                    subject_sha256=arguments["subject_sha256"], verifications=arguments["verifications"],
                    native_request_meta=request_meta, current_task_id=current_task_id,
                    plugin_data=_governed_native_plugin_data(),
                    hook_definition_path=(Path(__file__).resolve().parents[3] / "hooks" / "project_ground_hook.py").resolve(strict=True),
                )
                if not _valid_bootstrap_review_acknowledgement(
                        report, arguments=arguments, request_meta=request_meta,
                        current_task_id=current_task_id):
                    raise ValueError("invalid acknowledgement")
            except Exception:
                report = {"schema": "orch-dork/qualification-review-submission-refusal/v1", "status": "BLOCKED",
                          "decision": "REVIEW_REFUSED", "issues": ["bootstrap_review_host_bridge:submission_refused"]}
            return _rpc_result(identifier, _tool_result(report))
        if name == "advance_issue94_successor_after_native_action" and set(
            arguments
        ) == {"pre_turn_report_path", "pre_turn_report_sha256"}:
            evaluator = None
            try:
                plugin_data = _governed_native_plugin_data()
                hook_definition = (
                    Path(__file__).resolve().parents[3]
                    / "hooks"
                    / "project_ground_hook.py"
                ).resolve(strict=True)
            except (OSError, TypeError, ValueError):
                report = _successor_action_advance_unavailable(
                    "successor_action_advance_host_bridge:input_invalid"
                )
            else:
                try:
                    evaluator = _load_optional_sibling(
                        "orch_dork_qualification_successor", publish=True
                    )
                except Exception:
                    evaluator = None
                advance = getattr(
                    evaluator,
                    "advance_issue94_successor_after_native_action",
                    None,
                )
                validate_report = getattr(
                    evaluator,
                    "validate_issue94_successor_action_advance_report",
                    None,
                )
                if not callable(advance) or not callable(validate_report):
                    report = _successor_action_advance_unavailable(
                        "successor_action_advance_host_bridge:evaluator_unavailable"
                    )
                elif require_mcp_task_id and not current_task_id:
                    report = _successor_action_advance_unavailable(
                        "successor_action_advance_host_bridge:task_identity_missing"
                    )
                elif (gated := _owner_control_step_gate(
                    evaluator, name, arguments, _successor_action_advance_unavailable,
                    "successor_action_advance_host_bridge:owner_step_invalid",
                )) is not None:
                    report = gated
                else:
                    try:
                        report = advance(
                            pre_turn_report_path=arguments[
                                "pre_turn_report_path"
                            ],
                            expected_report_sha256=arguments[
                                "pre_turn_report_sha256"
                            ],
                            plugin_data=plugin_data,
                            hook_definition_path=hook_definition,
                            current_task_id=current_task_id,
                            native_request_meta=request_meta,
                        )
                    except Exception as error:
                        report = _successor_action_advance_unavailable(
                            _successor_action_advance_evaluation_issue(
                                evaluator, error
                            )
                        )
                    else:
                        try:
                            validation = validate_report(report)
                        except Exception:
                            validation = {}
                        if (
                            not isinstance(validation, dict)
                            or validation.get("valid") is not True
                        ):
                            report = _successor_action_advance_unavailable(
                                "successor_action_advance_host_bridge:"
                                "evaluator_contract_invalid"
                            )
            return _action_advance_mcp_response(identifier, report, evaluator)
        if name == "advance_issue94_bootstrapped_after_native_action" and set(
            arguments
        ) == {"bootstrap_artifact_path", "bootstrap_report_sha256"}:
            evaluator = None
            try:
                roots = _issue94_bootstrap_host_roots(arguments["bootstrap_artifact_path"])
                plugin_data = _governed_native_plugin_data()
                hook_definition = (Path(__file__).resolve().parents[3]
                                   / "hooks" / "project_ground_hook.py").resolve(strict=True)
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                report = _successor_action_advance_unavailable(
                    "bootstrap_action_advance_host_bridge:input_invalid")
            else:
                try:
                    evaluator = _load_optional_sibling(
                        "orch_dork_qualification_successor", publish=True)
                except Exception:
                    evaluator = None
                advance = getattr(evaluator, "advance_issue94_bootstrapped_after_native_action", None)
                validate_report = getattr(evaluator, "validate_issue94_successor_action_advance_report", None)
                if not callable(advance) or not callable(validate_report):
                    report = _successor_action_advance_unavailable(
                        "bootstrap_action_advance_host_bridge:evaluator_unavailable")
                elif require_mcp_task_id and not current_task_id:
                    report = _successor_action_advance_unavailable(
                        "bootstrap_action_advance_host_bridge:task_identity_missing")
                else:
                    try:
                        report = advance(
                            bootstrap_artifact_path=arguments["bootstrap_artifact_path"],
                            expected_bootstrap_report_sha256=arguments["bootstrap_report_sha256"],
                            source_root=roots["source"], evidence_root=roots["evidence"],
                            enrollment_registry_root=roots["enrollment_registry"],
                            plugin_data=plugin_data, hook_definition_path=hook_definition,
                            current_task_id=current_task_id, native_request_meta=request_meta)
                    except Exception as error:
                        report = _successor_action_advance_unavailable(
                            _successor_action_advance_evaluation_issue(
                                evaluator, error, prefix="bootstrap_action_advance:"))
                    else:
                        try:
                            validation = validate_report(report)
                        except Exception:
                            validation = {}
                        if not isinstance(validation, dict) or validation.get("valid") is not True:
                            report = _successor_action_advance_unavailable(
                                "bootstrap_action_advance_host_bridge:evaluator_contract_invalid")
            return _action_advance_mcp_response(identifier, report, evaluator)
        if name == "advance_governed_native_controller" and set(arguments) == {
            "program",
            "source_roots",
        }:
            program = arguments["program"]
            try:
                plugin_data = _governed_native_plugin_data()
                hook_definition = (
                    Path(__file__).resolve().parents[3]
                    / "hooks"
                    / "project_ground_hook.py"
                ).resolve(strict=True)
                source_roots = _governed_native_source_roots(
                    arguments["source_roots"]
                )
            except (OSError, TypeError, ValueError):
                report = _governed_native_controller_unavailable(
                    program, "governed_native_host_bridge:input_invalid"
                )
            else:
                try:
                    evaluator = _load_optional_sibling(
                        "orch_dork_governed_native_controller", publish=True
                    )
                except Exception:
                    evaluator = None
                advance = getattr(
                    evaluator, "advance_governed_native_controller", None
                )
                if not callable(advance):
                    report = _governed_native_controller_unavailable(
                        program,
                        "governed_native_host_bridge:evaluator_unavailable",
                    )
                else:
                    try:
                        report = advance(
                            program,
                            plugin_data=plugin_data,
                            hook_definition_path=hook_definition,
                            source_roots=source_roots,
                        )
                    except Exception:
                        report = _governed_native_controller_unavailable(
                            program,
                            "governed_native_host_bridge:evaluation_failed",
                        )
                    else:
                        if not _valid_governed_native_controller_report(report):
                            report = _governed_native_controller_unavailable(
                                program,
                                "governed_native_host_bridge:evaluator_contract_invalid",
                            )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_project_ground_enforcement" and set(arguments) == {"program"}:
            if project_ground_enforcement is None:
                report = {
                    "schema": "orch-dork/project-ground-mutation-decision/v1",
                    "policy_version": "project-ground-enforcement-policy/v1",
                    "status": "BLOCKED",
                    "decision": "READ_ONLY",
                    "reason_codes": ["project_ground:enforcement_unavailable"],
                    "provider_free": True,
                    "hosted_calls": 0,
                    "model_calls": 0,
                    "credential_reads": 0,
                    "authority_grants_minted": 0,
                    "mutations_performed": 0,
                }
            else:
                report = project_ground_enforcement.evaluate_project_ground_enforcement(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_project_ground_maintenance" and set(arguments) == {"program"}:
            if project_ground_migration is None:
                report = {
                    "schema": "orch-dork/project-ground-maintenance-report/v1",
                    "policy_version": "project-ground-migration-policy/v1",
                    "status": "BLOCKED",
                    "decision": "READ_ONLY",
                    "issues": ["project_ground:maintenance_unavailable"],
                    "mutation_performed": False,
                    "previous_generation_preserved": True,
                    "provider_free": True,
                    "hosted_calls": 0,
                    "model_calls": 0,
                    "credential_reads": 0,
                    "task_creations": 0,
                    "authority_reservations": 0,
                }
            else:
                report = project_ground_migration.evaluate_project_ground_maintenance(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_project_enrollment" and set(arguments) == {"program"}:
            if project_ground is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/project-enrollment-report/v1",
                            "status": "FAIL",
                            "decision": "READ_ONLY",
                            "issues": ["project_ground:evaluator_unavailable"],
                            "provider_free": True,
                            "credential_reads": 0,
                            "authority_reservations": 0,
                            "hosted_calls": 0,
                            "model_calls": 0,
                            "task_creations": 0,
                            "worker_creations": 0,
                            "adapter_executions": 0,
                            "hook_changes": 0,
                            "sandbox_changes": 0,
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    project_ground.evaluate_project_enrollment(arguments["program"])
                ),
            )
        if name == "evaluate_orchestration_project_adapter" and set(arguments) == {"program"}:
            if project_adapter is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/project-adapter-report/v1",
                            "status": "FAIL",
                            "issues": ["project_adapter:evaluator_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    project_adapter.evaluate_project_adapter(arguments["program"])
                ),
            )
        if name == "evaluate_orchestration_worker_port" and set(arguments) == {"program"}:
            if worker_port is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/worker-port-report/v1",
                            "status": "FAIL",
                            "issues": ["worker_port:evaluator_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(worker_port.evaluate_worker_port(arguments["program"])),
            )
        if name == "evaluate_orchestration_control_tower" and set(arguments) == {"program"}:
            if control_tower is None:
                report = {
                    "schema": "orch-dork/control-tower-report/v1",
                    "program_id": None,
                    "operation": None,
                    "status": "FAIL",
                    "issues": ["control_tower:evaluator_unavailable"],
                    "result": None,
                }
                report["report_sha256"] = json_sha256(report)
            else:
                report = control_tower.evaluate_control_tower(arguments["program"])
            return _rpc_result(identifier, _tool_result(report))
        if name == "observe_current_orchestration_route" and set(arguments).issubset(
            {"expected_identity_sha256"}
        ):
            return _rpc_result(
                identifier,
                _tool_result(
                    observe_current_orchestration_route(
                        arguments.get("expected_identity_sha256"),
                        task_id=current_task_id,
                        require_task_id=require_mcp_task_id,
                    )
                ),
            )
        if name == "evaluate_live_route_handoff" and set(arguments) == {
            "program"
        }:
            return _rpc_result(
                identifier,
                _tool_result(
                    evaluate_live_route_handoff(
                        arguments["program"],
                        task_id=current_task_id,
                        require_task_id=require_mcp_task_id,
                    )
                ),
            )
        if name == "observe_current_local_task_runtime" and not arguments:
            if local_task_runtime is None:
                report = {
                    "schema": "orch-dork/current-local-task-runtime/v1",
                    "status": "FAIL",
                    "disposition": "TASK_OWNER_UNAVAILABLE",
                    "task_owner_verified": False,
                    "task_loaded": False,
                    "task_status": None,
                    "descendant_count": None,
                    "owner_identity_sha256": None,
                    "issues": ["task_owner:observer_unavailable"],
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                    "credential_reads": 0,
                    "network_calls": 0,
                    "task_creations": 0,
                    "native_calls": 0,
                }
                report["report_sha256"] = json_sha256(report)
            else:
                report = local_task_runtime.observe_current_local_task_runtime(
                    task_id=current_task_id,
                    require_task_id=require_mcp_task_id,
                )
            return _rpc_result(identifier, _tool_result(report))
        if name in {"prepare_work_summary", "propose_ticket_status_update", "confirm_ticket_status_update"}:
            import orch_dork_work_intake as work_intake

            handler = {"prepare_work_summary": work_intake.prepare,
                       "propose_ticket_status_update": work_intake.propose,
                       "confirm_ticket_status_update": work_intake.confirm}[name]
            return _rpc_result(identifier, _tool_result(handler(
                arguments, requesting_thread_id=current_task_id,
            )))
        if name in {"propose_project_improvements", "read_project_improvement", "decide_project_improvement",
                    "authorize_project_canary", "adopt_project_improvement"}:
            import orch_dork_project_improvements as improvements

            handler = {"propose_project_improvements": improvements.propose, "read_project_improvement": improvements.read,
                       "decide_project_improvement": improvements.decide, "authorize_project_canary": improvements.authorize_canary,
                       "adopt_project_improvement": improvements.adopt}[name]
            return _rpc_result(identifier, _tool_result(handler(arguments, requesting_thread_id=current_task_id)))
        if name == "start_governed_run" and {
            "project_root", "goal",
        } <= set(arguments) <= {
            "project_root", "goal", "model", "effort", "cost_budget_usd", "approve_plan_sha256",
            "lanes", "worker_model", "worker_effort", "intake_sha256", "project_canary",
        }:
            import orch_dork_governed_run_watcher as governed_run_watcher

            return _rpc_result(
                identifier,
                _tool_result(
                    governed_run_watcher.start_from_task(
                        arguments, requesting_thread_id=current_task_id
                    )
                ),
            )
        if name == "read_governed_run" and set(arguments) in (
            {"run_id"}, {"run_id", "wait_seconds"},
        ):
            import orch_dork_governed_run_watcher as governed_run_watcher

            return _rpc_result(
                identifier,
                _tool_result(governed_run_watcher.read_from_task(arguments)),
            )
        if (name == "steer_governed_run" and set(arguments) == {"run_id", "text"}) or (
            name == "revise_governed_run" and {"run_id", "offer_sha256", "accept"} <= set(arguments)
            <= {"run_id", "offer_sha256", "accept", "goal", "lanes", "approve_plan_sha256"}
        ):
            import orch_dork_governed_run_watcher as governed_run_watcher

            handler = (governed_run_watcher.steer_from_task if name == "steer_governed_run"
                       else governed_run_watcher.revise_from_task)
            turn_id = request_meta.get("turnId") if isinstance(request_meta, dict) else None
            return _rpc_result(identifier, _tool_result(handler(
                arguments, requesting_thread_id=current_task_id,
                requesting_turn_id=turn_id if isinstance(turn_id, str) else None,
            )))
        if name == "stop_governed_run" and set(arguments) == {"run_id"}:
            import orch_dork_governed_run_watcher as governed_run_watcher

            return _rpc_result(
                identifier,
                _tool_result(
                    governed_run_watcher.stop_from_task(
                        arguments, requesting_thread_id=current_task_id
                    )
                ),
            )
        if name == "open_local_ui":
            import orch_dork_local_ui as local_ui
            if set(arguments) == set() or (set(arguments) == {"view"} and arguments.get("view") in ("local", "tailnet")):
                return _rpc_result(identifier, _tool_result(
                    local_ui.start_from_task(arguments, requesting_thread_id=current_task_id)
                ))
            return _rpc_result(identifier, _tool_result(
                {"schema": local_ui.OPEN_SCHEMA, "status": "REFUSED", "reason": "request_invalid"}
            ))
        if name == "onboard_model" and set(arguments) in ({"model"}, {"model", "re_onboard"}):
            import orch_dork_guided_enrollment as guided_enrollment

            return _rpc_result(identifier, _tool_result(guided_enrollment.onboard_from_task(arguments)))
        if name == "enroll_project" and set(arguments) == {"project_root"}:
            import orch_dork_guided_enrollment as guided_enrollment

            return _rpc_result(
                identifier,
                _tool_result(
                    guided_enrollment.enroll_from_task(
                        arguments, requesting_thread_id=current_task_id
                    )
                ),
            )
        if name == "confirm_enrollment" and {
            "draft_sha256", "second_model", "keep_local",
        } <= set(arguments) <= _CONFIRM_ENROLLMENT_ARGUMENTS:
            import orch_dork_guided_enrollment as guided_enrollment

            return _rpc_result(
                identifier,
                _tool_result(
                    guided_enrollment.confirm_from_task(
                        arguments, requesting_thread_id=current_task_id
                    )
                ),
            )
        if name == "read_onboarding" and set(arguments) in (
            {"job_id"}, {"job_id", "wait_seconds"},
        ):
            import orch_dork_onboarding_probe as onboarding_probe

            return _rpc_result(
                identifier,
                _tool_result(onboarding_probe.read_from_task(arguments)),
            )
        if name == "validate_logical_worker_program" and set(arguments) == {"plan"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/logical-plan-report/v1",
                            "status": "FAIL",
                            "valid": False,
                            "issues": ["logical_plan:validator_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    validate_logical_plan_for_current_turn(
                        arguments["plan"],
                        task_id=current_task_id,
                        require_task_id=require_mcp_task_id,
                    )
                ),
            )
        if name == "run_logical_worker_waves" and set(arguments) == {
            "program",
            "expected_route_identity_sha256",
        }:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/wave-report/v1",
                            "status": "FAILED",
                            "issues": ["wave_program:controller_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    run_logical_worker_waves_for_current_turn(
                        arguments["program"],
                        arguments["expected_route_identity_sha256"],
                        task_id=current_task_id,
                        require_task_id=require_mcp_task_id,
                    )
                ),
            )
        if name == "evaluate_wave_progress" and set(arguments) == {"program"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/wave-progress-report/v1",
                            "status": "FAIL",
                            "issues": ["wave_progress:controller_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.evaluate_wave_progress(
                        arguments["program"]
                    )
                ),
            )
        if name == "evaluate_advisory_scan" and set(arguments) == {"program"}:
            if advisory_scan is None:
                report_schema = (
                    "orch-dork/advisory-scan-report/v2"
                    if arguments["program"].get("schema")
                    == "orch-dork/advisory-scan-program/v2"
                    else "orch-dork/advisory-scan-report/v1"
                )
                report = {
                    "schema": report_schema,
                    "operation": arguments["program"].get("operation"),
                    "status": "FAIL",
                    "decision": "REFUSED",
                    "scan_id": arguments["program"].get("scan_id"),
                    "issues": ["advisory_scan:evaluator_unavailable"],
                    "claim_permitted": False,
                    "workers_created": 0,
                    "model_calls": 0,
                    "hosted_calls": 0,
                    "provider_free": True,
                }
            else:
                report = advisory_scan.evaluate_advisory_scan(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "observe_native_advisory_scan" and set(arguments) == {"program"}:
            if native_scan_observer is None:
                report = {
                    "schema": "orch-dork/native-scan-observation/v1",
                    "status": "FAIL",
                    "decision": "REFUSED",
                    "graph_status": "UNBOUND",
                    "observation_status": "NOT_OBSERVED",
                    "qualification_evidence_status": "EVIDENCE_INCOMPLETE",
                    "claim_permitted": False,
                    "issues": ["native_scan_observer:unavailable"],
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                }
            else:
                report = native_scan_observer.observe_native_scan(
                    arguments["program"]
                )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_sol_replan" and set(arguments) == {"program"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/replan-report/v1",
                            "status": "FAIL",
                            "issues": ["replan:controller_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.evaluate_replan_program(arguments["program"])
                ),
            )
        if name == "evaluate_decomposition_proposal" and set(arguments) <= {
            "proposal",
            "parent_plan",
            "bind",
        } and "proposal" in arguments:
            if decomposition is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/decomposition-proposal-report/v1",
                            "status": "FAIL",
                            "issues": ["proposal:validator_unavailable"],
                        }
                    ),
                )
            report = decomposition.validate_decomposition_proposal(
                arguments["proposal"], parent_plan=arguments.get("parent_plan")
            )
            if arguments.get("bind") is True and report.get("status") == "PASS":
                binding = decomposition.bind_replan_revision(
                    arguments.get("parent_plan"), arguments["proposal"], report
                )
                report = dict(report)
                report["binding"] = binding
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_adaptive_finite_dag" and set(arguments) == {"program"}:
            return _rpc_result(
                identifier,
                _tool_result(evaluate_adaptive_finite_dag(arguments["program"])),
            )
        if name == "validate_adaptive_contract" and {
            "contract_kind",
            "value",
        } <= set(arguments):
            contract_kind = arguments.get("contract_kind")
            route = ADAPTIVE_CONTRACT_REGISTRY.get(contract_kind)
            if route is None:
                return _rpc_error(identifier, -32602, "Invalid tool or arguments")
            allowed = {
                "contract_kind",
                "value",
                *route["allowed_arguments"],
            }
            if not route["required_arguments"] <= set(arguments):
                return _rpc_error(
                    identifier,
                    -32602,
                    "Invalid tool or arguments",
                )
            if not set(arguments) <= allowed:
                return _rpc_error(identifier, -32602, "Invalid tool or arguments")
            report = validate_adaptive_contract(
                contract_kind,
                arguments["value"],
                task_spec=arguments.get("task_spec"),
                handoff_receipt=arguments.get("handoff_receipt"),
                authorized_write_scope=arguments.get("authorized_write_scope"),
            )
            return _rpc_result(identifier, _tool_result(report))
        if name == "evaluate_evidence_policy" and set(arguments) == {"program"}:
            return _rpc_result(
                identifier,
                _tool_result(evaluate_evidence_policy(arguments["program"])),
            )
        if name == "evaluate_route_policy" and set(arguments) == {"program"}:
            return _rpc_result(
                identifier,
                _tool_result(evaluate_route_policy(arguments["program"])),
            )
        if name == "evaluate_campaign_policy" and set(arguments) == {"program"}:
            return _rpc_result(
                identifier,
                _tool_result(evaluate_campaign_policy(arguments["program"])),
            )
        if name == "evaluate_experiment_campaign" and set(arguments) == {"program"}:
            return _rpc_result(
                identifier,
                _tool_result(evaluate_experiment_campaign(arguments["program"])),
            )
        if name == "validate_relay_manifest" and set(arguments) <= {"manifest", "delivery"} and arguments:
            if relay is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/relay-manifest-report/v1",
                            "status": "FAIL",
                            "issues": ["relay:validator_unavailable"],
                        }
                    ),
                )
            if "delivery" in arguments:
                return _rpc_result(
                    identifier,
                    _tool_result(relay.evaluate_relay_delivery(arguments["delivery"])),
                )
            return _rpc_result(
                identifier,
                _tool_result(relay.validate_relay_manifest(arguments["manifest"])),
            )
        if name == "verify_wave_routing" and set(arguments) == {"program"}:
            if routing_verify is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/wave-routing-report/v1",
                            "status": "FAIL",
                            "issues": ["routing:validator_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(routing_verify.verify_wave_routing(arguments["program"])),
            )
        if name == "run_active_orchestration_controller" and set(arguments) == {"program"}:
            if (
                isinstance(arguments["program"], dict)
                and arguments["program"].get("schema")
                == "orch-dork/governed-native-controller-program/v1"
            ):
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/active-controller-report/v1",
                            "status": "FAIL",
                            "issues": [
                                "active_controller:wrong_surface:"
                                "use_advance_governed_native_controller"
                            ],
                        }
                    ),
                )
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/active-controller-report/v1",
                            "status": "FAIL",
                            "issues": ["active_controller:unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.run_active_controller(arguments["program"])
                ),
            )
        if name == "evaluate_orchestration_limits" and set(arguments) == {"program"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/limit-policy-report/v1",
                            "status": "FAIL",
                            "issues": ["limit_policy:controller_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.evaluate_limit_policy(arguments["program"])
                ),
            )
        if name == "evaluate_orchestration_profile" and set(arguments) == {"program"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/profile-lifecycle-report/v1",
                            "status": "FAIL",
                            "issues": ["profile_lifecycle:controller_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.evaluate_profile_lifecycle(arguments["program"])
                ),
            )
        if name == "evaluate_orchestration_efficiency" and set(arguments) == {"program"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/efficiency-evaluation-report/v1",
                            "status": "FAIL",
                            "issues": ["efficiency_evaluator:unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.evaluate_efficiency_program(arguments["program"])
                ),
            )
        if name == "evaluate_orchestration_budget" and set(arguments) == {"program"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/budget-report/v1",
                            "status": "FAIL",
                            "issues": ["budget:controller_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.evaluate_budget_program(arguments["program"])
                ),
            )
        if name == "evaluate_orchestration_recovery" and set(arguments) == {"program"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/recovery-report/v1",
                            "status": "FAIL",
                            "issues": ["recovery:controller_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.evaluate_recovery_program(arguments["program"])
                ),
            )
        if name == "qualify_orchestration_graph" and set(arguments) == {"program"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/execution-graph-report/v1",
                            "status": "FAIL",
                            "issues": ["graph:controller_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.qualify_execution_graph(arguments["program"])
                ),
            )
        if name == "evaluate_root_rollover" and set(arguments) == {"program"}:
            if efficiency_governor is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/root-rollover-report/v1",
                            "status": "FAIL",
                            "issues": ["rollover:controller_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    efficiency_governor.evaluate_root_rollover(arguments["program"])
                ),
            )
        if name == "validate_orchestration_custody" and set(arguments) == {
            "plan", "spawn_wave", "events"
        }:
            if custody is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/custody/v1",
                            "status": "FAIL",
                            "custody_preserved": False,
                            "issues": ["custody:analyzer_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    custody.evaluate_custody(
                        arguments["plan"],
                        arguments["spawn_wave"],
                        arguments["events"],
                    )
                ),
            )
        if name == "validate_orchestration_ownership" and set(arguments).issubset(
            {"plan", "workspace_root", "baseline"}
        ) and "plan" in arguments:
            if ownership is None:
                return _rpc_result(
                    identifier,
                    _tool_result(
                        {
                            "schema": "orch-dork/ownership-analysis/v1",
                            "status": "FAIL",
                            "safe": False,
                            "issues": ["ownership:analyzer_unavailable"],
                        }
                    ),
                )
            return _rpc_result(
                identifier,
                _tool_result(
                    ownership.evaluate_ownership(
                        arguments["plan"],
                        workspace_root=arguments.get("workspace_root"),
                        baseline=arguments.get("baseline"),
                        task_id=current_task_id,
                        require_task_root=require_mcp_task_id,
                    )
                ),
            )
        if name == "validate_orchestration_admission" and set(arguments) == {
            "plan",
            "inventory",
            "expected_route_identity_sha256",
        }:
            return _rpc_result(
                identifier,
                _tool_result(
                    validate_admission_for_current_turn(
                        arguments["plan"],
                        arguments["inventory"],
                        arguments["expected_route_identity_sha256"],
                        task_id=current_task_id,
                        require_task_id=require_mcp_task_id,
                    )
                ),
            )
        if name == "validate_orchestration_spawn_wave" and set(arguments) == {
            "plan",
            "admission",
            "results",
            "expected_route_identity_sha256",
        }:
            return _rpc_result(
                identifier,
                _tool_result(
                    validate_spawn_wave_for_current_turn(
                        arguments["plan"],
                        arguments["admission"],
                        arguments["results"],
                        arguments["expected_route_identity_sha256"],
                        task_id=current_task_id,
                        require_task_id=require_mcp_task_id,
                    )
                ),
            )
        if name == "validate_orchestration_plan" and set(arguments) == {"plan"}:
            return _rpc_result(
                identifier,
                _tool_result(
                    validate_plan_for_current_turn(
                        arguments["plan"],
                        task_id=current_task_id,
                        require_task_id=require_mcp_task_id,
                    )
                ),
            )
        if name == "qualify_orchestration_trace" and set(arguments) == {"plan", "trace"}:
            return _rpc_result(
                identifier,
                _tool_result(
                    qualify_trace_for_current_turn(
                        arguments["plan"],
                        arguments["trace"],
                        task_id=current_task_id,
                        require_task_id=require_mcp_task_id,
                    )
                ),
            )
        if name == "qualify_read_custody" and set(arguments) in (
            {"audit_report"}, {"audit_report", "exceptions"}
        ):
            return _rpc_result(
                identifier,
                _tool_result(
                    qualify_read_custody(
                        arguments["audit_report"],
                        arguments.get("exceptions"),
                    )
                ),
            )
        return _rpc_error(identifier, -32602, "Invalid tool or arguments")
    return _rpc_error(identifier, -32601, "Method not found")


def serve():
    scripts_dir = Path(__file__).resolve().parents[3] / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        import orch_dork_mcp_server
    except ImportError:
        return 2
    methods = {
        "initialize",
        "ping",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "notifications/initialized",
        "notifications/cancelled",
    }
    return orch_dork_mcp_server.serve_stdio({method: dispatch for method in methods})


def _load_json(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    validate = sub.add_parser("validate-plan")
    validate.add_argument("plan")
    qualify = sub.add_parser("qualify")
    qualify.add_argument("plan")
    qualify.add_argument("trace")
    args = parser.parse_args(argv)
    if args.command == "serve":
        return serve()
    if args.command == "validate-plan":
        report = validate_plan(_load_json(args.plan))
    else:
        report = qualify_trace(_load_json(args.plan), _load_json(args.trace))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
