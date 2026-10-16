#!/usr/bin/env python3
"""Build and verify the allowlisted Orch Dork runtime package.

The development checkout is intentionally much larger than the installed
plugin.  This module is the one source of truth for the files that may cross
that boundary.  It does not discover files by extension and it never writes a
manifest containing source paths or file contents: the public result contains
only the package version and three content-addressed digests.

The implementation uses only the Python standard library so it can also be
used by a clean-machine preflight.  A staged directory is immutable from the
builder's point of view.  An existing non-identical stage is reported as
stale rather than silently cleaned or overwritten.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


PACKAGE_SCHEMA = "orch-dork/runtime-package/v1"
PROJECTION_PARITY_SCHEMA = "orch-dork/runtime-package-projection-parity/v1"
ISSUE156_REFUSAL_SHA256 = (
    "9fe0905f64f0f7b7b20809e499a2fe46bf63688724689d179c02e8d28afc1ed8"
)
MANIFEST_PATH = ".codex-plugin/plugin.json"
DESCRIPTOR_PATH = ".mcp.json"
DIRECT_ACTION_CONFIG_PATH = ".codex/config.toml"
DIRECT_ACTION_CONFIG_BYTES = (
    b"[features.code_mode]\n"
    b'direct_only_tool_namespaces = ["multi_agent_v1"]\n'
)

# These reviewed corpora contain opaque paths captured from owned temporary
# fixture roots. Replay never opens those paths. Only these exact bytes at
# these exact package paths may carry them; credential checks still apply.
_PINNED_PATH_FIXTURES = {
    "skills/orch-dork/runtime/lifecycle-conformance/activation-preparation.json":
        "6c0c5fe4533ba00d5497d620035be2505add762f582ba3a03434afb4666541aa",
    "skills/orch-dork/runtime/lifecycle-conformance/codex-linux-0.153.4.json":
        "c1cfedb20e570f219830832d6f014c57f431d9f14ac27f7a3ccb8effe684b9ed",
}

# This tuple is the package source of truth.  Keep it sorted and explicit:
# adding a runtime file is a deliberate source change, not an accidental
# consequence of a broad ``*.py`` or ``**/*`` glob.  The three paths used by
# the Issue 44 sibling lanes are listed up front as optional entries.  They
# become required as soon as they are present in the source checkout, while a
# first-lane build remains independent of unreleased sibling files.
RUNTIME_ALLOWLIST: tuple[str, ...] = (
    "skills/orch-dork/scripts/orch_dork_local_ui.py",
    "skills/orch-dork/scripts/orch_dork_local_ui_projection.py",
    "skills/orch-dork/ui/index.html",
    "skills/orch-dork/ui/app.js",
    "skills/orch-dork/ui/styles.css",
    ".codex/config.toml",
    ".codex-plugin/plugin.json",
    ".mcp.json",
    "LICENSE",
    "hooks/hooks.json",
    "hooks/project_ground_hook.py",
    "scripts/orch_dork_mcp_server.py",
    "skills/orch-dork/SKILL.md",
    "skills/orch-dork/agents/openai.yaml",
    "skills/orch-dork/references/contract-evaluation.md",
    "skills/orch-dork/references/execution.md",
    "skills/orch-dork/references/observability.md",
    "skills/orch-dork/references/policy.md",
    "skills/orch-dork/references/roles.md",
    "skills/orch-dork/references/project-ground.md",
    # Issue 170: portable conformance code and byte-pinned corpora.
    "skills/orch-dork/runtime/lifecycle-conformance/activation-preparation.json",
    "skills/orch-dork/runtime/lifecycle-conformance/codex-linux-0.153.4.json",
    "skills/orch-dork/runtime/lifecycle-conformance/cycles-01-36.json",
    "skills/orch-dork/runtime/lifecycle-conformance/mcp-context-extension-v1.json",
    "skills/orch-dork/runtime/lifecycle-conformance/source-scope-classifications-v1.json",
    "skills/orch-dork/scripts/lifecycle_conformance/__init__.py",
    "skills/orch-dork/scripts/lifecycle_conformance/action_authority.py",
    "skills/orch-dork/scripts/lifecycle_conformance/action_host.py",
    "skills/orch-dork/scripts/lifecycle_conformance/campaign.py",
    "skills/orch-dork/scripts/lifecycle_conformance/candidate_identity.py",
    "skills/orch-dork/scripts/lifecycle_conformance/cartesian.py",
    "skills/orch-dork/scripts/lifecycle_conformance/catalog.py",
    "skills/orch-dork/scripts/lifecycle_conformance/completion_gate.py",
    "skills/orch-dork/scripts/lifecycle_conformance/consumption.py",
    "skills/orch-dork/scripts/lifecycle_conformance/coverage_manifest.py",
    "skills/orch-dork/scripts/lifecycle_conformance/explorer.py",
    "skills/orch-dork/scripts/lifecycle_conformance/failure_injection.py",
    "skills/orch-dork/scripts/lifecycle_conformance/fragment.py",
    "skills/orch-dork/scripts/lifecycle_conformance/host_adapter.py",
    "skills/orch-dork/scripts/lifecycle_conformance/host_attestation.py",
    "skills/orch-dork/scripts/lifecycle_conformance/host_fixtures.py",
    "skills/orch-dork/scripts/lifecycle_conformance/host_mcp_fixtures.py",
    "skills/orch-dork/scripts/lifecycle_conformance/host_probes.py",
    "skills/orch-dork/scripts/lifecycle_conformance/injection_campaign.py",
    "skills/orch-dork/scripts/lifecycle_conformance/injection_oracle.py",
    "skills/orch-dork/scripts/lifecycle_conformance/injection_sites.py",
    "skills/orch-dork/scripts/lifecycle_conformance/live_attempt_consumption.py",
    "skills/orch-dork/scripts/lifecycle_conformance/live_qualification_execution.py",
    "skills/orch-dork/scripts/lifecycle_conformance/matrix_readback.py",
    "skills/orch-dork/scripts/lifecycle_conformance/matrix_runner.py",
    "skills/orch-dork/scripts/lifecycle_conformance/model.py",
    "skills/orch-dork/scripts/lifecycle_conformance/production_adapter.py",
    "skills/orch-dork/scripts/lifecycle_conformance/production_campaign.py",
    "skills/orch-dork/scripts/lifecycle_conformance/production_graph_evidence.py",
    "skills/orch-dork/scripts/lifecycle_conformance/production_readiness_execution.py",
    "skills/orch-dork/scripts/lifecycle_conformance/promotion_authentication.py",
    "skills/orch-dork/scripts/lifecycle_conformance/protocol.py",
    "skills/orch-dork/scripts/lifecycle_conformance/public_inventory.py",
    "skills/orch-dork/scripts/lifecycle_conformance/public_pair_evidence.py",
    "skills/orch-dork/scripts/lifecycle_conformance/public_pair_registry.py",
    "skills/orch-dork/scripts/lifecycle_conformance/reference_model.py",
    "skills/orch-dork/scripts/lifecycle_conformance/release_execution.py",
    "skills/orch-dork/scripts/lifecycle_conformance/reference_values.py",
    "skills/orch-dork/scripts/lifecycle_conformance/registries.py",
    "skills/orch-dork/scripts/lifecycle_conformance/replay_bindings.py",
    "skills/orch-dork/scripts/lifecycle_conformance/replays.py",
    "skills/orch-dork/scripts/lifecycle_conformance/scope_policy.py",
    "skills/orch-dork/scripts/lifecycle_conformance/source_coverage_backlog.py",
    "skills/orch-dork/scripts/lifecycle_conformance/source_scope_closure.py",
    "skills/orch-dork/scripts/lifecycle_conformance/values.py",
    "skills/orch-dork/scripts/orch_dork_governed_native_reports.py",
    # Adaptive finite-DAG controller and its typed communication contracts.
    "skills/orch-dork/scripts/orch_dork_adaptive_contracts.py",
    "skills/orch-dork/scripts/orch_dork_adaptive_finite_dag.py",
    "skills/orch-dork/scripts/orch_dork_advisory_scan.py",
    "skills/orch-dork/scripts/orch_dork_attempt_observer.py",
    "skills/orch-dork/scripts/orch_dork_codex_usage.py",
    "skills/orch-dork/scripts/orch_dork_coordinator_usage.py",
    "skills/orch-dork/scripts/orch_dork_qualification_budget.py",
    "skills/orch-dork/scripts/orch_dork_native_attempt_observer.py",
    "skills/orch-dork/scripts/orch_dork_native_checkpoint_attempt.py",
    "skills/orch-dork/scripts/orch_dork_native_worker_finals.py",
    # Issue 183: sealed model-profile registry resolved by plan validation.
    "skills/orch-dork/scripts/orch_dork_model_profile_registry.py",
    # Issue 184: two-stage architecture ingestion (digest and Owner seal).
    "skills/orch-dork/scripts/orch_dork_architecture_ingestion.py",
    # Issue 203: onboarded model profiles the onboarding probe writes (ADR 0012).
    "skills/orch-dork/scripts/orch_dork_onboarded_profiles.py",
    # Issue 225: canonical mission facts and trusted conditional local delivery.
    "skills/orch-dork/scripts/orch_dork_mission_authority.py",
    "skills/orch-dork/scripts/orch_dork_mission_host.py",
    "skills/orch-dork/scripts/orch_dork_mission_delivery.py",
    "skills/orch-dork/scripts/orch_dork_mission_candidate.py",
    "skills/orch-dork/scripts/orch_dork_mission_verification.py",
    "skills/orch-dork/scripts/orch_dork_mission_tracker.py",
    "skills/orch-dork/scripts/orch_dork_mission_publication.py",
    # Issue 226: canonical scope validation shared by claims and exact staging.
    "skills/orch-dork/scripts/orch_dork_mission_scope.py",
    # Issue 193: the governed-run watcher, its hook policy and the Codex
    # versions its startup self-test accepts.
    "skills/orch-dork/scripts/orch_dork_app_server_client.py",
    "skills/orch-dork/scripts/orch_dork_governed_run_cleanup.py",
    "skills/orch-dork/scripts/orch_dork_governed_run_controls.py",
    "skills/orch-dork/scripts/orch_dork_work_intake.py",
    "skills/orch-dork/scripts/orch_dork_governed_run_policy.py",
    "skills/orch-dork/scripts/orch_dork_governed_run_watcher.py",
    "skills/orch-dork/runtime/governed-mode/known-good-codex.json",
    # Issue 194: guided enrollment, standing authority and admission, and the
    # onboarding probe a chat starts.
    "skills/orch-dork/scripts/orch_dork_governed_admission.py",
    "skills/orch-dork/scripts/orch_dork_guided_enrollment.py",
    "skills/orch-dork/scripts/orch_dork_onboarding_probe.py",
    # Issue 195: the cost summary every governed run ends with.
    "skills/orch-dork/scripts/orch_dork_governed_run_cost.py",
    # Issue 164: agent lifecycle map publication and next-invocation projection.
    "skills/orch-dork/scripts/orch_dork_agent_lifecycle.py",
    "skills/orch-dork/runtime/agent-lifecycle-map-v1.json",
    "skills/orch-dork/scripts/orch_dork_admission_kernel.py",
    # Issue 50 release metadata and offline verification runtime.
    "skills/orch-dork/scripts/orch_dork_artifact_ledger.py",
    "skills/orch-dork/scripts/orch_dork_artifact_attestation.py",
    "skills/orch-dork/scripts/orch_dork_bundle.py",
    # Issue 97 process guard: exact worker-brief preamble renderer/linter.
    "skills/orch-dork/scripts/orch_dork_brief_lint.py",
    "skills/orch-dork/scripts/orch_dork_campaign_policy.py",
    "skills/orch-dork/scripts/orch_dork_campaign_power.py",
    "skills/orch-dork/scripts/orch_dork_campaign_prereg.py",
    "skills/orch-dork/scripts/orch_dork_capacity_inventory.py",
    # Issue 45 clean-machine install, adoption, and update acceptance seams.
    "skills/orch-dork/scripts/orch_dork_clean_adoption_acceptance.py",
    "skills/orch-dork/scripts/orch_dork_clean_machine_acceptance.py",
    "skills/orch-dork/scripts/orch_dork_clean_update_acceptance.py",
    "skills/orch-dork/scripts/orch_dork_coordinator_capsule.py",
    "skills/orch-dork/scripts/orch_dork_control_scheduler.py",
    "skills/orch-dork/scripts/orch_dork_control_tower.py",
    # Issue 153: authenticated, provider-free frontier credential admission.
    "skills/orch-dork/scripts/orch_dork_frontier_admission.py",
    "skills/orch-dork/scripts/orch_dork_frontier_admission_probe.ts",
    "skills/orch-dork/scripts/orch_dork_frontier_admission_qualification.py",
    "skills/orch-dork/scripts/orch_dork_frontier_campaign.py",
    "skills/orch-dork/scripts/orch_dork_frontier_qualification.py",
    "skills/orch-dork/scripts/orch_dork_workflow_profiles.py",
    "skills/orch-dork/scripts/orch_dork_custody.py",
    # Issue 97 host-local append-only custody-exception persistence.
    "skills/orch-dork/scripts/orch_dork_custody_exception_ledger.py",
    # North-star P1: typed decomposition proposals (split transactions).
    "skills/orch-dork/scripts/orch_dork_decomposition.py",
    # FR50: recorded economic gate over typed runtime deepening proposals.
    "skills/orch-dork/scripts/orch_dork_deepening_policy.py",
    # Optional durability-port pilot over an already-frozen finite DAG. DBOS
    # imports only when a live caller prepares the adapter.
    "skills/orch-dork/scripts/orch_dork_dbos_pilot.py",
    # Structural screening of worker terminal output; the wave controller
    # imports it, so an install missing it cannot evaluate a wave.
    "skills/orch-dork/scripts/orch_dork_degenerate_output.py",
    # Issue 127: seals a tranche dispatch packet and its decision sheet.
    "skills/orch-dork/scripts/orch_dork_dispatch_packet.py",
    # Issue 77 longitudinal outcome capture for real dogfood runs.
    "skills/orch-dork/scripts/orch_dork_dogfood_corpus.py",
    # Issue 131: exports blind evidence packets and imports provenance-typed
    # answers from any model without owning a model transport.
    "skills/orch-dork/scripts/orch_dork_dogfood_model_labeler.py",
    # Issue 128: renders one run as blind-verdict questions and writes the
    # answer through the corpus' own validation.
    "skills/orch-dork/scripts/orch_dork_dogfood_worksheet.py",
    # Issue 77 recovery: derive a run's mechanical spine from its session
    # record so an outcome survives a root that never reports.
    "skills/orch-dork/scripts/orch_dork_dogfood_recovery.py",
    "skills/orch-dork/scripts/orch_dork_efficiency_governor.py",
    "skills/orch-dork/scripts/orch_dork_evidence_core.py",
    # Issue 125: derives the sizing basis from sealed campaign ledgers.
    "skills/orch-dork/scripts/orch_dork_evidence_basis.py",
    "skills/orch-dork/scripts/orch_dork_evidence_policy.py",
    "skills/orch-dork/scripts/orch_dork_evidence_rate.py",
    "skills/orch-dork/scripts/orch_dork_evidence_snapshot.py",
    "skills/orch-dork/scripts/orch_dork_execution_readiness.py",
    # FR51: closed preregistration and campaign-result binding contracts.
    "skills/orch-dork/scripts/orch_dork_experiment_campaign.py",
    "skills/orch-dork/scripts/orch_dork_governed_completion.py",
    "skills/orch-dork/scripts/orch_dork_governed_attempt.py",
    "skills/orch-dork/scripts/orch_dork_governed_native_controller.py",
    "skills/orch-dork/scripts/orch_dork_native_grant_store.py",
    "skills/orch-dork/scripts/orch_dork_owned_file.py",
    "skills/orch-dork/scripts/orch_dork_native_result.py",
    "skills/orch-dork/scripts/orch_dork_governed_run.py",
    "skills/orch-dork/scripts/orch_dork_hostile_input.py",
    "skills/orch-dork/scripts/orch_dork_lane_workspace.py",
    # FR49-FR51: ledger-derived learned sizing/stopping and promotion records.
    "skills/orch-dork/scripts/orch_dork_learned_policy.py",
    # FR59: inactive Strategy cards and factored advisory route learning.
    "skills/orch-dork/scripts/orch_dork_route_learning.py",
    "skills/orch-dork/scripts/orch_dork_strategy_cards.py",
    # FR60: CPU-only topology search and inactive Champion/Challenger records.
    "skills/orch-dork/scripts/orch_dork_topology_lab.py",
    "skills/orch-dork/scripts/orch_dork_champion_challenger.py",
    # FR51 live half: bounded grant, family shards, and canonical ledger join.
    # Issues 134/139/140: failure-aware and transport-qualified successors.
    "skills/orch-dork/scripts/orch_dork_live_recovery.py",
    "skills/orch-dork/scripts/orch_dork_live_sweep.py",
    # Issue 142: standing authority for fully validated bounded run classes.
    "skills/orch-dork/scripts/orch_dork_standing_authority.py",
    # Issue 133: measurement-only, structurally tool-free Responses boundary.
    "skills/orch-dork/scripts/orch_dork_live_zero_tool.py",
    "skills/orch-dork/scripts/orch_dork_live_zero_tool_probe.ts",
    "skills/orch-dork/scripts/orch_dork_live_zero_tool_qualification.py",
    # Issue 163: projected provider-free qualification caller rehearsal.
    "skills/orch-dork/scripts/orch_dork_qualification_lifecycle_rehearsal.py",
    "skills/orch-dork/scripts/orch_dork_qualification_rehearsal.py",
    "skills/orch-dork/scripts/orch_dork_qualification_results.py",
    "skills/orch-dork/scripts/orch_dork_qualification_progress.py",
    "skills/orch-dork/scripts/orch_dork_qualification_review.py",
    "skills/orch-dork/scripts/orch_dork_qualification_verification.py",
    "skills/orch-dork/scripts/orch_dork_completion_process.py",
    "skills/orch-dork/scripts/orch_dork_completion_settlement.py",
    "skills/orch-dork/scripts/orch_dork_qualification_wave.py",
    "skills/orch-dork/scripts/orch_dork_qualification_final_metadata.py",
    "skills/orch-dork/scripts/orch_dork_qualification_final.py",
    "skills/orch-dork/scripts/orch_dork_qualification_owner.py",
    "skills/orch-dork/scripts/orch_dork_qualification_owner_rotation.py",
    "skills/orch-dork/scripts/orch_dork_qualification_closure.py",
    "skills/orch-dork/scripts/orch_dork_qualification_budget_failure.py",
    "skills/orch-dork/scripts/orch_dork_qualification_route_canary.py",
    "skills/orch-dork/scripts/orch_dork_qualification_governed_inputs.py",
    "skills/orch-dork/scripts/orch_dork_qualification_pre_spawn.py",
    "skills/orch-dork/scripts/orch_dork_qualification_activation.py",
    "skills/orch-dork/scripts/orch_dork_qualification_bootstrap.py",
    "skills/orch-dork/scripts/orch_dork_qualification_successor.py",
    "skills/orch-dork/scripts/orch_dork_activation_only_failure_recovery.py",
    "skills/orch-dork/scripts/orch_dork_partial_native_failure_recovery.py",
    "skills/orch-dork/scripts/orch_dork_post_spawn_failure_recovery.py",
    "skills/orch-dork/scripts/orch_dork_post_ack_bridge_failure_recovery.py",
    "skills/orch-dork/scripts/orch_dork_observed_spawn_stall_recovery.py",
    "skills/orch-dork/scripts/orch_dork_pre_native_failure_recovery.py",
    "skills/orch-dork/scripts/orch_dork_predecessor_readiness.py",
    "skills/orch-dork/scripts/orch_dork_qualification_host.py",
    "skills/orch-dork/scripts/orch_dork_issue170_qualification_owner.py",
    "skills/orch-dork/scripts/orch_dork_qualification_pricing.py",
    "skills/orch-dork/scripts/orch_dork_live_view.py",
    "skills/orch-dork/scripts/orch_dork_local_task_runtime.py",
    "skills/orch-dork/scripts/orch_dork_native_scan_observer.py",
    "skills/orch-dork/scripts/orch_dork_observability.py",
    "skills/orch-dork/scripts/orch_dork_observer_authority.py",
    "skills/orch-dork/scripts/orch_dork_observer_receipt.py",
    "skills/orch-dork/scripts/orch_dork_ownership.py",
    "skills/orch-dork/scripts/orch_dork_plan_closure.py",
    "skills/orch-dork/scripts/orch_dork_policy.py",
    "skills/orch-dork/scripts/orch_dork_provenance.py",
    "skills/orch-dork/scripts/orch_dork_process_containment.py",
    "skills/orch-dork/scripts/orch_dork_project_adapter.py",
    "skills/orch-dork/scripts/orch_dork_project_ground.py",
    "skills/orch-dork/scripts/orch_dork_project_ground_enforcement.py",
    "skills/orch-dork/scripts/orch_dork_project_ground_migration.py",
    # Optional model-boundary pilot; no third-party import occurs at module
    # load, and canonical Orch Dork validators retain acceptance authority.
    "skills/orch-dork/scripts/orch_dork_pydantic_ai_pilot.py",
    # North-star P2: event-driven scheduling evaluator.
    "skills/orch-dork/scripts/orch_dork_ready_queue.py",
    "skills/orch-dork/scripts/orch_dork_read_custody.py",
    # FR51 hash-keyed record/replay and ledger-derived holdout demotion. This
    # downstream adapter is not imported by policy, campaign, or trace core.
    "skills/orch-dork/scripts/orch_dork_record_replay.py",
    "skills/orch-dork/scripts/orch_dork_refusal_tiers.py",
    "skills/orch-dork/scripts/orch_dork_receipt.py",
    # North-star P3: declared write-set and versioned-state evaluators.
    # North-star seams: typed relay manifests for context transfer.
    "skills/orch-dork/scripts/orch_dork_relay.py",
    "skills/orch-dork/scripts/orch_dork_release_marketplace.py",
    "skills/orch-dork/scripts/orch_dork_research_manifest.py",
    "skills/orch-dork/scripts/orch_dork_repo_state.py",
    # North-star seams: runtime routing verification (observed vs declared).
    "skills/orch-dork/scripts/orch_dork_routing_verify.py",
    "skills/orch-dork/scripts/orch_dork_current_turn_route.py",
    "skills/orch-dork/scripts/orch_dork_route_policy.py",
    "skills/orch-dork/scripts/orch_dork_run_registry.py",
    "skills/orch-dork/scripts/orch_dork_run_engine.py",
    "skills/orch-dork/scripts/orch_dork_run_store.py",
    "skills/orch-dork/scripts/orch_dork_runtime_receipt_chain.py",
    "skills/orch-dork/scripts/orch_dork_runtime_package.py",
    "skills/orch-dork/scripts/orch_dork_sbom.py",
    "skills/orch-dork/scripts/orch_dork_semantic_plan_v2.py",
    "skills/orch-dork/scripts/orch_dork_semantic_delta.py",
    # FR62: shared concurrent-lane maximum imported by the Control Tower.
    "skills/orch-dork/scripts/orch_dork_shared_capacity.py",
    "skills/orch-dork/scripts/orch_dork_sol_benchmark.py",
    "skills/orch-dork/scripts/orch_dork_skill_contract.py",
    # Pre-freeze structural and marginal-value split policy. New accepted
    # orchestration selects finite_dag/v1 unless compatibility is explicit.
    "skills/orch-dork/scripts/orch_dork_split_decision.py",
    "skills/orch-dork/scripts/orch_dork_stateful_fuzz.py",
    # FR51 optional sweep adapter. It depends one-way on the campaign and
    # trace contracts; no policy or kernel module imports it.
    "skills/orch-dork/scripts/orch_dork_sweep_harness.py",
    "skills/orch-dork/scripts/orch_dork_task_creation.py",
    "skills/orch-dork/scripts/orch_dork_ticket_admission.py",
    # North-star P2: static coupling mapper and scout-delta validation.
    "skills/orch-dork/scripts/orch_dork_topology.py",
    "skills/orch-dork/scripts/orch_dork_topology_closure.py",
    # Issue 126: plans a campaign as a ladder of small tranches.
    "skills/orch-dork/scripts/orch_dork_tranche_ladder.py",
    # North-star P4: normalized run-trace instrumentation.
    "skills/orch-dork/scripts/orch_dork_trace.py",
    "skills/orch-dork/scripts/orch_dork_two_stage_ground_truth.py",
    "skills/orch-dork/scripts/orch_dork_usage.py",
    "skills/orch-dork/scripts/orch_dork_v1_observer.py",
    "skills/orch-dork/scripts/orch_dork_v2_observer.py",
    # FR49: provider-free first-wave recommendation and outcome records.
    "skills/orch-dork/scripts/orch_dork_wave_recommendation.py",
    "skills/orch-dork/scripts/orch_dork_worker_adapter.py",
    # The single source of truth for the governed worker model; every
    # validator imports it, so an install missing it cannot start.
    "skills/orch-dork/scripts/orch_dork_worker_default.py",
    "skills/orch-dork/scripts/orch_dork_worker_lifecycle.py",
    "skills/orch-dork/scripts/orch_dork_worker_port.py",
    "skills/orch-dork/scripts/orch_dork_worker_transport.py",
    "skills/orch-dork/scripts/orch_dork_worker_workspace.py",
    "skills/orch-dork/scripts/orch_dork_workspace_launch.py",
    "skills/orch-dork/scripts/orch_dork_workspace_sandbox.py",
    "skills/orch-dork/scripts/orch_dork_worktree_runner.py",
    # Portable-runtime lane outputs (optional until released).
    "scripts/orch_dork_mcp_launcher.py",
    "skills/orch-dork/runtime/frontier-regression-corpus-v1.json",
    "skills/orch-dork/runtime/execution-readiness-regressions-v1.json",
    "skills/orch-dork/runtime/qualification-rehearsal-replays-v1.json",
    "skills/orch-dork/runtime/issue111-v8-history-spec.json",
    "skills/orch-dork/runtime/observability-scenarios/budget-exhaustion.json",
    "skills/orch-dork/runtime/observability-scenarios/blocked-extra-work.json",
    "skills/orch-dork/runtime/observability-scenarios/cancellation.json",
    "skills/orch-dork/runtime/observability-scenarios/contradiction.json",
    "skills/orch-dork/runtime/observability-scenarios/issue17-timeout.json",
    "skills/orch-dork/runtime/observability-scenarios/missing-evidence.json",
    "skills/orch-dork/runtime/observability-scenarios/success.json",
    "skills/orch-dork/runtime/observability-scenarios/wrong-routing.json",
    # Local-marketplace lane output (optional until released).
    "skills/orch-dork/scripts/orch_dork_local_marketplace.py",
    # Issue 199: proposals and forward-only project adoption.
    "skills/orch-dork/references/project-improvements.md",
    "skills/orch-dork/scripts/orch_dork_project_improvements.py",
    "skills/orch-dork/scripts/orch_dork_project_promotion.py",
    "skills/orch-dork/scripts/orch_dork_project_proposals.py",
    # Issue 200: hosted online-diagram format and sanitizer, and the Site
    # origin file that stays null until the Owner publishes the Site.
    "skills/orch-dork/scripts/orch_dork_online_diagram.py",
    "skills/orch-dork/runtime/online-history-site.json",
    # Issue 201: TOML reading on Python 3.9 and 3.10 (the macOS system
    # python3) for the user's Codex config and a project's pyproject.toml.
    "skills/orch-dork/scripts/orch_dork_toml.py",
)

RUNTIME_ALLOWLIST = tuple(sorted(RUNTIME_ALLOWLIST))
RUNTIME_OPTIONAL_PATHS = frozenset(
    {
        "LICENSE",
        "scripts/orch_dork_mcp_launcher.py",
        # These references are owned by the portable-runtime lane.  They are
        # release-gated siblings: a package-only lane must be able to audit a
        # clean baseline before that lane has released them, while a final
        # integration build includes them whenever present.
        "skills/orch-dork/references/observability.md",
        "skills/orch-dork/references/policy.md",
        "skills/orch-dork/runtime/observability-scenarios/budget-exhaustion.json",
        "skills/orch-dork/runtime/observability-scenarios/blocked-extra-work.json",
        "skills/orch-dork/runtime/observability-scenarios/cancellation.json",
        "skills/orch-dork/runtime/observability-scenarios/contradiction.json",
        "skills/orch-dork/runtime/observability-scenarios/issue17-timeout.json",
        "skills/orch-dork/runtime/observability-scenarios/missing-evidence.json",
        "skills/orch-dork/runtime/observability-scenarios/success.json",
        "skills/orch-dork/runtime/observability-scenarios/wrong-routing.json",
        "skills/orch-dork/scripts/orch_dork_local_marketplace.py",
    }
)
RUNTIME_REQUIRED_PATHS = frozenset(RUNTIME_ALLOWLIST) - RUNTIME_OPTIONAL_PATHS
REPORT_FIELDS = ("version", "inventory_hash", "descriptor_hash", "package_digest")
PROJECTION_PARITY_MAX_REPORT_BYTES = 4096

_PROJECTION_EFFECTS = {
    "input_mutations": 0,
    "network_calls": 0,
    "credential_reads": 0,
    "provider_calls": 0,
    "model_calls": 0,
    "hosted_calls": 0,
    "campaign_calls": 0,
}

_DEVELOPMENT_PARTS = frozenset(
    {
        ".git",
        ".scratch",
        "SPEC.md",
        "TICKETS.md",
        "artifacts",
        "tests",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".coverage",
        "local-state",
        "state",
    }
)
_BYTECODE_SUFFIXES = (".pyc", ".pyo")
_CREDENTIAL_BASENAME = re.compile(
    r"^(?:\.env(?:\..*)?|credentials?|secrets?|private[_-]?key(?:\..*)?|"
    r"id_rsa(?:\..*)?|(?:api|access|refresh)[_-]?tokens?|(?:api|client)[_-]?keys?)(?:\..*)?$",
    re.IGNORECASE,
)
# A package may be copied to an unknown host, so source text must not carry a
# path rooted in a host-specific filesystem.  Keep the check lexical (rather
# than resolving anything from the source tree): references in documentation
# and descriptors are just as much a portability dependency as executable
# code.  The historical name is retained as an alias for callers that used
# the first implementation's private constant.
_ABSOLUTE_MACHINE_PATH = re.compile(
    rb"(?<![A-Za-z0-9_.\-/])/(?:Users|home|root|tmp|var|private(?:/var)?|"
    rb"opt(?:/homebrew)?|etc|usr|bin|sbin|Applications|Library|System|"
    rb"Volumes|dev|proc|run)(?=[/\\s\"'`()<>;,.:!?]|$)|"
    rb"(?<![A-Za-z0-9_.\-/])[A-Za-z]:[\\/](?:[^\\/\s\"'<>]|[\\/])*|"
    rb"(?<![A-Za-z0-9_.\-/])~/(?:[^\\/\s\"'<>]|[\\/])+"
)
_ABSOLUTE_USER_PATH = _ABSOLUTE_MACHINE_PATH
_PRIVATE_KEY = re.compile(rb"-----BEGIN [^-]{1,80}PRIVATE KEY-----")
_BEARER = re.compile(rb"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_TOKEN_VALUE = re.compile(
    rb"(?i)\b(?:sk|gh[pousr]|xox[baprs])[-_][A-Za-z0-9_-]{12,}|\bAKIA[0-9A-Z]{12,}"
)
_SECRET_ASSIGNMENT = re.compile(
    rb"(?i)\b(?:api[_-]?(?:key|token)|access[_-]?token|refresh[_-]?token|"
    rb"client[_-]?secret|password|passwd)\s*[:=]\s*[\"']?[A-Za-z0-9_./+=:-]{8,}"
)
_MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")
_GENERIC_FIXTURE_PATH = b'{"locator":"/tmp/link"}'


def _contains_absolute_machine_path(data: bytes) -> bool:
    """Return whether ``data`` embeds a host-rooted filesystem path.

    ``#!/usr/bin/env`` is the conventional portable Python shebang and is
    intentionally allowed.  Every other match remains a rejected machine
    path, including references in comments and Markdown.
    """

    # Issue 49's fixed hostile-input corpus intentionally contains the
    # generic ``{"locator":"/tmp/link"}`` token.  It is a deterministic
    # symlink-escape fixture, not a host/user path.  Allow only that exact
    # token; every other ``/tmp`` or rooted path remains rejected.
    fixture_offsets = {
        match.start() + _GENERIC_FIXTURE_PATH.index(b"/tmp")
        for match in re.finditer(re.escape(_GENERIC_FIXTURE_PATH), data)
    }
    def regex_literal_at(offset: int) -> bool:
        """Allow path fragments in a source regex declaration only.

        Issue 50 ships provider-free validators whose own source contains
        regular expressions matching host paths.  Those fragments are policy
        code, not portable-path dependencies.  The allowance is deliberately
        lexical and narrow: the matched line must be a raw/bytes string and a
        preceding line must open ``re.compile``.  User prose, JSON, and
        executable values remain rejected by the normal path check.
        """

        line_start = data.rfind(b"\n", 0, offset) + 1
        line_end = data.find(b"\n", offset)
        if line_end < 0:
            line_end = len(data)
        line = data[line_start:line_end]
        if not (b'r"' in line or b"r'" in line or b'rb"' in line or b"rb'" in line):
            return False
        context_start = max(0, line_start - 160)
        context = data[context_start:line_start]
        return b"re.compile" in context

    for match in _ABSOLUTE_MACHINE_PATH.finditer(data):
        token = match.group()
        if match.start() in fixture_offsets and token == b"/tmp":
            continue
        # ``/proc`` is the standard Linux process-telemetry namespace used by
        # the shipped containment helper, and ``/dev/null`` is the portable
        # sink used by the workspace adapter.  These exact non-user roots are
        # runtime contracts, not machine-specific checkout paths.  Keep all
        # other rooted paths (including arbitrary ``/tmp`` values) rejected.
        if token == b"/proc":
            continue
        if token == b"/dev" and data[match.start() : match.start() + len(b"/dev/null")] == b"/dev/null":
            continue
        if regex_literal_at(match.start()):
            continue
        line_start = data.rfind(b"\n", 0, match.start()) + 1
        prefix = data[line_start : match.start()].lstrip()
        if prefix.startswith(b"#!") and data[match.start() :].startswith(b"/usr/bin/env"):
            continue
        return True
    return False


class RuntimePackageError(ValueError):
    """Base error for a failed source, stage, or dependency check."""

    def __init__(self, issues: str | Iterable[str], *, message: str | None = None):
        if isinstance(issues, str):
            values = [issues]
        else:
            values = [str(value) for value in issues]
        self.issues = tuple(sorted(set(values)))
        if not self.issues:
            self.issues = ("runtime_package_invalid",)
        super().__init__(message or "runtime package rejected: " + ", ".join(self.issues))


class RuntimePackageValidationError(RuntimePackageError):
    """Raised when a stage is missing, stale, or differs from its source."""


class RuntimePackageBuildError(RuntimePackageError):
    """Raised when a source tree cannot be staged safely."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_relative(value: str, *, label: str = "path") -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise RuntimePackageError(f"{label}:not_canonical")
    if re.match(r"^[A-Za-z]:[\\/]", value):
        raise RuntimePackageError(f"{label}:absolute")
    path = PurePosixPath(value)
    normalized = path.as_posix()
    if path.is_absolute() or normalized != value or any(part in {"", ".", ".."} for part in path.parts):
        raise RuntimePackageError(f"{label}:not_canonical")
    return normalized


def _normalize_allowlist(allowlist: Sequence[str] | None) -> tuple[str, ...]:
    values = RUNTIME_ALLOWLIST if allowlist is None else tuple(allowlist)
    normalized = tuple(_canonical_relative(value, label="allowlist") for value in values)
    if len(set(normalized)) != len(normalized):
        raise RuntimePackageError("allowlist:duplicate")
    if normalized != tuple(sorted(normalized)):
        raise RuntimePackageError("allowlist:noncanonical_order")
    return normalized


def runtime_allowlist(*extra_paths: str) -> tuple[str, ...]:
    """Return the canonical allowlist, optionally extended explicitly.

    The extension is useful for a later release lane adding one named runtime
    asset.  It is still exact-path based and is validated/sorted before use.
    """

    return _normalize_allowlist(tuple(RUNTIME_ALLOWLIST) + tuple(extra_paths))


def _runtime_path_is_required(relative: str) -> bool:
    return (
        relative not in RUNTIME_OPTIONAL_PATHS
        or relative not in RUNTIME_ALLOWLIST
    )


def _relative(root: Path, path: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:  # pragma: no cover - defensive, callers bind roots
        raise RuntimePackageError("path_escape") from exc
    return _canonical_relative(relative.as_posix())


def _development_only(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    return any(part in _DEVELOPMENT_PARTS or part.endswith(_BYTECODE_SUFFIXES) for part in parts)


def _bytecode(relative: str) -> bool:
    return any(part == "__pycache__" or part.lower().endswith(_BYTECODE_SUFFIXES) for part in PurePosixPath(relative).parts)


def _credential_filename(relative: str) -> bool:
    stems = {
        "credential",
        "credentials",
        "secret",
        "secrets",
        "private_key",
        "id_rsa",
        "api_key",
        "api_keys",
        "api_token",
        "api_tokens",
        "access_token",
        "access_tokens",
        "refresh_token",
        "refresh_tokens",
    }
    return any(
        _CREDENTIAL_BASENAME.fullmatch(part)
        or part.lower().split(".", 1)[0] in stems
        for part in PurePosixPath(relative).parts
    )


def _check_root(root: Path, *, label: str) -> Path:
    root = Path(root)
    try:
        info = root.lstat()
    except FileNotFoundError as exc:
        raise RuntimePackageError(f"{label}:missing") from exc
    if stat.S_ISLNK(info.st_mode):
        raise RuntimePackageError(f"{label}:symlink")
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimePackageError(f"{label}:not_directory")
    return root


def _allowed_directories(allowlist: Sequence[str]) -> frozenset[str]:
    directories: set[str] = {""}
    for value in allowlist:
        parent = PurePosixPath(value).parent
        while str(parent) not in {"", "."}:
            directories.add(parent.as_posix())
            parent = parent.parent
    return frozenset(directories)


def _walk_nodes(root: Path) -> tuple[list[tuple[str, Path]], list[str]]:
    """Return regular files and structural issues without following links."""

    files: list[tuple[str, Path]] = []
    issues: list[str] = []
    for base, directories, names in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        directories.sort()
        names.sort()
        kept_directories: list[str] = []
        for name in directories:
            candidate = base_path / name
            relative = _relative(root, candidate)
            try:
                mode = candidate.lstat().st_mode
            except OSError:
                issues.append(f"unreadable:{relative}")
                continue
            if stat.S_ISLNK(mode):
                issues.append(f"symlink:{relative}")
                continue
            if not stat.S_ISDIR(mode):
                issues.append(f"special:{relative}")
                continue
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in names:
            candidate = base_path / name
            relative = _relative(root, candidate)
            try:
                mode = candidate.lstat().st_mode
            except OSError:
                issues.append(f"unreadable:{relative}")
                continue
            if stat.S_ISLNK(mode):
                issues.append(f"symlink:{relative}")
            elif not stat.S_ISREG(mode):
                issues.append(f"special:{relative}")
            else:
                files.append((relative, candidate))
    return files, issues


# One process often validates the same runtime bytes many times: every
# validation inventories both source and stage, and callers re-validate an
# unchanged installed runtime.  The path and credential scans are pure
# functions of the bytes and the path exemption, so their verdict is memoized
# by content digest.  A hit returns exactly the verdict this module computed
# for identical bytes.  The registry starts empty at import, so the action
# host binds only its type, and it is cleared rather than grown when full.
_CONTENT_VERDICTS: dict[tuple[str, bool], str | None] = {}
_CONTENT_VERDICT_LIMIT = 4096


def _content_issue(data: bytes, digest: str, *, path_exempt: bool) -> str | None:
    """Return the first content-policy issue for the bytes, or None."""

    key = (digest, path_exempt)
    if key in _CONTENT_VERDICTS:
        return _CONTENT_VERDICTS[key]
    if not path_exempt and _contains_absolute_machine_path(data):
        issue = "absolute_path"
    elif _PRIVATE_KEY.search(data) or _BEARER.search(data) or _TOKEN_VALUE.search(data) or _SECRET_ASSIGNMENT.search(data):
        issue = "credential"
    else:
        issue = None
    if len(_CONTENT_VERDICTS) >= _CONTENT_VERDICT_LIMIT:
        _CONTENT_VERDICTS.clear()
    _CONTENT_VERDICTS[key] = issue
    return issue


def _safe_file_bytes(path: Path, relative: str) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimePackageError(f"unreadable:{relative}") from exc
    # This module is the policy implementation for the path scanner itself.
    # Its source necessarily contains regular expressions and explanatory
    # examples of rooted paths; those literals are not host-specific runtime
    # dependencies.  Keep the exemption exact and continue credential checks.
    digest = _sha256(data)
    policy_source = relative == "skills/orch-dork/scripts/orch_dork_runtime_package.py"
    pinned_fixture = _PINNED_PATH_FIXTURES.get(relative) == digest
    issue = _content_issue(data, digest, path_exempt=policy_source or pinned_fixture)
    if issue is not None:
        raise RuntimePackageError(f"{issue}:{relative}")
    return data


def read_declared_runtime_allowlist(
    runtime_root: os.PathLike[str] | str,
) -> tuple[str, ...]:
    """Read one installed generation's literal runtime allowlist safely.

    Historical generations must be validated against the files they declared,
    not against the caller generation's later allowlist.  Parse only the
    module-level annotated literal; never import or execute historical code.
    """

    root = _check_root(Path(runtime_root), label="runtime_allowlist_source")
    relative = "skills/orch-dork/scripts/orch_dork_runtime_package.py"
    source_path = root / relative
    try:
        info = source_path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimePackageError("allowlist_source:not_regular")
        source = _safe_file_bytes(source_path, relative)
        if len(source) > 2_097_152:
            raise RuntimePackageError("allowlist_source:too_large")
        tree = ast.parse(source.decode("utf-8"), filename=relative)
    except RuntimePackageError:
        raise
    except (OSError, UnicodeError, SyntaxError) as error:
        raise RuntimePackageError("allowlist_source:unavailable") from error
    declarations = [
        node
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "RUNTIME_ALLOWLIST"
    ]
    if len(declarations) != 1 or declarations[0].value is None:
        raise RuntimePackageError("allowlist_source:declaration_invalid")
    try:
        declared = ast.literal_eval(declarations[0].value)
    except (TypeError, ValueError, SyntaxError) as error:
        raise RuntimePackageError(
            "allowlist_source:declaration_invalid"
        ) from error
    if not isinstance(declared, tuple) or not all(
        isinstance(value, str) for value in declared
    ):
        raise RuntimePackageError("allowlist_source:declaration_invalid")
    return _normalize_allowlist(tuple(sorted(declared)))


def _entry(relative: str, path: Path) -> dict[str, Any]:
    data = _safe_file_bytes(path, relative)
    mode = stat.S_IMODE(path.lstat().st_mode)
    return {"path": relative, "sha256": _sha256(data), "size": len(data), "mode": mode}


def _inventory_entries(root: Path, allowlist: tuple[str, ...], *, label: str) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    root = _check_root(root, label=label)
    files, structural = _walk_nodes(root)
    allowed = set(allowlist)
    allowed_dirs = _allowed_directories(allowlist)
    issues: list[str] = list(structural)
    entries: list[dict[str, Any]] = []
    actual: set[str] = set()
    for relative, path in files:
        actual.add(relative)
        if relative not in allowed:
            if _bytecode(relative):
                issues.append(f"bytecode:{relative}")
            elif _credential_filename(relative):
                issues.append(f"credential:{relative}")
            elif _development_only(relative):
                issues.append(f"development_only:{relative}")
            else:
                issues.append(f"unexpected:{relative}")
            continue
        if _bytecode(relative):
            issues.append(f"bytecode:{relative}")
            continue
        if _credential_filename(relative):
            issues.append(f"credential:{relative}")
            continue
        try:
            entries.append(_entry(relative, path))
        except RuntimePackageError as exc:
            issues.extend(exc.issues)
    for relative in sorted(set(allowlist) - actual):
        if _runtime_path_is_required(relative):
            issues.append(f"missing:{relative}")
    # Empty or undeclared directories are still package surfaces and must not
    # sneak into a stage simply because they contain no files.
    for base, directories, _ in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        for name in sorted(directories):
            candidate = base_path / name
            if candidate.is_symlink():
                continue
            relative = _relative(root, candidate)
            if relative not in allowed_dirs:
                if _bytecode(relative):
                    issues.append(f"bytecode:{relative}")
                elif _development_only(relative):
                    issues.append(f"development_only:{relative}")
                else:
                    issues.append(f"unexpected:{relative}")
    entries.sort(key=lambda value: value["path"])
    return entries, tuple(sorted(set(issues)))


def _require_json(root: Path, relative: str, entries: Mapping[str, dict[str, Any]]) -> Any:
    if relative not in entries:
        raise RuntimePackageError(f"missing_dependency:{relative}")
    try:
        return json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimePackageError(f"invalid_json:{relative}") from exc


def _dependency_target(source_relative: str, target: str) -> str:
    if not isinstance(target, str) or not target:
        raise RuntimePackageError(f"dependency:{source_relative}:invalid")
    target = target.split("#", 1)[0].split("?", 1)[0]
    if not target or target.lower().startswith(("http://", "https://", "mailto:")) or target.startswith("//"):
        return ""
    if target.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", target):
        raise RuntimePackageError(f"absolute_path:{source_relative}")
    parent = PurePosixPath(source_relative).parent.as_posix()
    candidate = os.path.normpath(os.path.join(parent, target))
    if candidate in {"", "."}:
        return ""
    if candidate.startswith("../") or candidate == "..":
        raise RuntimePackageError(f"path_escape:{source_relative}")
    return _canonical_relative(candidate)


def _validate_manifest_and_descriptor(root: Path, entries: Sequence[dict[str, Any]], allowlist: tuple[str, ...]) -> str:
    by_path = {entry["path"]: entry for entry in entries}
    if DIRECT_ACTION_CONFIG_PATH in allowlist:
        if DIRECT_ACTION_CONFIG_PATH not in by_path:
            raise RuntimePackageError(
                f"missing_dependency:{DIRECT_ACTION_CONFIG_PATH}"
            )
        try:
            direct_action_config = (root / DIRECT_ACTION_CONFIG_PATH).read_bytes()
        except OSError as exc:
            raise RuntimePackageError(
                f"unreadable:{DIRECT_ACTION_CONFIG_PATH}"
            ) from exc
        if direct_action_config != DIRECT_ACTION_CONFIG_BYTES:
            raise RuntimePackageError("direct_action_surface:config_mismatch")
    manifest = _require_json(root, MANIFEST_PATH, by_path)
    descriptor = _require_json(root, DESCRIPTOR_PATH, by_path)
    if not isinstance(manifest, Mapping):
        raise RuntimePackageError("manifest:not_object")
    version = manifest.get("version")
    if (
        not isinstance(version, str)
        or not version
        or len(version) > 128
        or any(char in version for char in "/\\\x00")
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in version)
    ):
        raise RuntimePackageError("manifest:version_invalid")
    # The plugin's two path-bearing fields must resolve inside this package.
    skills = manifest.get("skills")
    if not isinstance(skills, str):
        raise RuntimePackageError("missing_dependency:skills")
    skills_relative = skills[2:] if skills.startswith("./") else skills
    # Plugin manifests conventionally use ``./skills/``.  Remove exactly the
    # one conventional trailing slash, then validate the resulting relative
    # path so doubled slashes, dot segments, and escapes are not normalized
    # into an accepted dependency.
    if skills_relative.endswith("/"):
        skills_relative = skills_relative[:-1]
    try:
        skills_relative = _canonical_relative(skills_relative, label="manifest.skills")
    except RuntimePackageError as exc:
        raise RuntimePackageError("missing_dependency:manifest.skills") from exc
    if skills_relative not in _allowed_directories(allowlist):
        raise RuntimePackageError("missing_dependency:manifest.skills")
    mcp = manifest.get("mcpServers")
    if not isinstance(mcp, str):
        raise RuntimePackageError("missing_dependency:mcpServers")
    mcp_relative = mcp[2:] if mcp.startswith("./") else mcp
    mcp_relative = _canonical_relative(mcp_relative, label="manifest.mcpServers")
    if mcp_relative not in by_path:
        raise RuntimePackageError(f"missing_dependency:{mcp_relative}")
    if not isinstance(descriptor, Mapping):
        raise RuntimePackageError("descriptor:not_object")
    servers = descriptor.get("mcpServers")
    if not isinstance(servers, Mapping) or not servers:
        raise RuntimePackageError("descriptor:mcpServers_invalid")
    for name, server in sorted(servers.items(), key=lambda item: str(item[0])):
        if not isinstance(name, str) or not isinstance(server, Mapping):
            raise RuntimePackageError("descriptor:server_invalid")
        command = server.get("command")
        if not isinstance(command, str) or not command:
            raise RuntimePackageError(f"descriptor:command:{name}")
        if "\x00" in command or any(ord(char) < 0x20 or ord(char) == 0x7F for char in command):
            raise RuntimePackageError(f"descriptor:command:{name}")
        if command.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", command):
            raise RuntimePackageError(f"absolute_path:descriptor.command:{name}")
        # Bare interpreter names (for example ``python3``) are resolved by
        # the portable launcher.  If a descriptor names a relative command,
        # require that exact helper to be allowlisted; this closes ``../``
        # escapes that a string-only command check would otherwise permit.
        if "/" in command or "\\" in command or command in {".", ".."}:
            command_relative = command[2:] if command.startswith("./") else command
            command_relative = _canonical_relative(command_relative, label="descriptor.command")
            if command_relative not in by_path:
                raise RuntimePackageError(f"missing_dependency:{command_relative}")
        cwd = server.get("cwd", ".")
        if not isinstance(cwd, str) or cwd in {"", "."}:
            cwd = "."
        elif cwd.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", cwd):
            raise RuntimePackageError(f"absolute_path:descriptor.cwd:{name}")
        else:
            cwd = _canonical_relative(cwd, label="descriptor.cwd")
        if cwd != "." and cwd not in _allowed_directories(allowlist):
            raise RuntimePackageError(f"missing_dependency:{cwd}")
        args = server.get("args", [])
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            raise RuntimePackageError(f"descriptor:args:{name}")
        for arg in args:
            if arg.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", arg):
                raise RuntimePackageError(f"absolute_path:descriptor.args:{name}")
            if "\x00" in arg or any(ord(char) < 0x20 or ord(char) == 0x7F for char in arg):
                raise RuntimePackageError(f"descriptor:args:{name}")
            if (
                arg in {".", ".."}
                or arg.startswith(("./", "../"))
                or "/" in arg
                or "\\" in arg
                or arg.endswith((".py", ".json", ".yaml"))
            ):
                target = arg[2:] if arg.startswith("./") else arg
                target = _canonical_relative(target, label="descriptor.arg")
                if target not in by_path:
                    raise RuntimePackageError(f"missing_dependency:{target}")
    # Links are checked against the same allowlist.  External links and
    # fragment-only links are documentation, not package dependencies.
    for entry in entries:
        if not entry["path"].lower().endswith((".md", ".markdown")):
            continue
        try:
            text = (root / entry["path"]).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise RuntimePackageError(f"invalid_text:{entry['path']}") from exc
        for match in _MARKDOWN_LINK.finditer(text):
            target = _dependency_target(entry["path"], match.group(1))
            if not target:
                continue
            if target not in by_path:
                if _development_only(target):
                    raise RuntimePackageError(f"development_only:{target}")
                raise RuntimePackageError(f"missing_dependency:{target}")
    return version


def _inventory_hash(entries: Sequence[Mapping[str, Any]]) -> str:
    return _sha256(_canonical_json({"schema": PACKAGE_SCHEMA, "files": list(entries)}))


def _package_digest(version: str, entries: Sequence[Mapping[str, Any]], inventory_hash: str, descriptor_hash: str) -> str:
    payload = {
        "schema": PACKAGE_SCHEMA,
        "version": version,
        "inventory_hash": inventory_hash,
        "descriptor_hash": descriptor_hash,
        "files": list(entries),
    }
    return _sha256(_canonical_json(payload))


def _report(version: str, entries: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    inventory_hash = _inventory_hash(entries)
    descriptor = next((entry for entry in entries if entry["path"] == DESCRIPTOR_PATH), None)
    if descriptor is None:
        raise RuntimePackageError("missing_dependency:.mcp.json")
    descriptor_hash = str(descriptor["sha256"])
    return {
        "version": version,
        "inventory_hash": inventory_hash,
        "descriptor_hash": descriptor_hash,
        "package_digest": _package_digest(version, entries, inventory_hash, descriptor_hash),
    }


def inventory_runtime(root: os.PathLike[str] | str, *, allowlist: Sequence[str] | None = None) -> list[dict[str, Any]]:
    """Return a deterministic, sanitized inventory for a runtime tree."""

    paths = _normalize_allowlist(allowlist)
    entries, issues = _inventory_entries(Path(root), paths, label="source")
    if issues:
        raise RuntimePackageBuildError(issues)
    _validate_manifest_and_descriptor(Path(root), entries, paths)
    return entries


def _projectable_source_entries(
    root: Path,
    allowlist: tuple[str, ...],
) -> tuple[list[dict[str, Any]], str, dict[str, int]]:
    """Inventory only declared runtime files in a development checkout."""

    source = _check_root(root, label="source")
    entries: list[dict[str, Any]] = []
    source_modes: dict[str, int] = {}
    issues: list[str] = []
    for relative in allowlist:
        if _bytecode(relative):
            issues.append(f"bytecode:{relative}")
            continue
        if _credential_filename(relative):
            issues.append(f"credential:{relative}")
            continue
        parts = PurePosixPath(relative).parts
        candidate = source
        rejected = False
        for index, part in enumerate(parts):
            candidate = candidate / part
            partial = PurePosixPath(*parts[: index + 1]).as_posix()
            try:
                mode = candidate.lstat().st_mode
            except FileNotFoundError:
                if _runtime_path_is_required(relative):
                    issues.append(f"missing:{relative}")
                rejected = True
                break
            except OSError:
                issues.append(f"unreadable:{partial}")
                rejected = True
                break
            if stat.S_ISLNK(mode):
                issues.append(f"symlink:{partial}")
                rejected = True
                break
            if index < len(parts) - 1:
                if not stat.S_ISDIR(mode):
                    issues.append(f"special:{partial}")
                    rejected = True
                    break
            elif not stat.S_ISREG(mode):
                issues.append(f"special:{relative}")
                rejected = True
                break
        if rejected:
            continue
        try:
            entry = _entry(relative, candidate)
            source_modes[relative] = int(entry["mode"])
            # Group-shared Git checkouts commonly materialize tracked files as
            # 0664/0775 even though the same commit is 0644/0755 in a private
            # checkout.  Those umask-dependent write bits are not runtime
            # identity: remove them from every projected file while retaining
            # bytes, owner permissions and executable-bit distinctions.
            entry["mode"] = int(entry["mode"]) & ~0o022
            entries.append(entry)
        except RuntimePackageError as exc:
            issues.extend(exc.issues)
    if issues:
        raise RuntimePackageBuildError(issues)
    entries.sort(key=lambda value: value["path"])
    version = _validate_manifest_and_descriptor(source, entries, allowlist)
    return entries, version, source_modes


def _read_projected_source_file(
    source: Path,
    entry: Mapping[str, Any],
    *,
    source_mode: int,
) -> bytes:
    """Re-read one selected file without following a last-moment leaf link."""

    relative = str(entry["path"])
    path = source.joinpath(*PurePosixPath(relative).parts)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimePackageBuildError(f"source_changed:{relative}")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            data = handle.read()
    except RuntimePackageError:
        raise
    except OSError as exc:
        raise RuntimePackageBuildError(f"source_changed:{relative}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        len(data) != entry["size"]
        or _sha256(data) != entry["sha256"]
        or stat.S_IMODE(info.st_mode) != source_mode
    ):
        raise RuntimePackageBuildError(f"source_changed:{relative}")
    return data


def project_runtime_source(
    source_root: os.PathLike[str] | str,
    projection_root: os.PathLike[str] | str,
    *,
    allowlist: Sequence[str] | None = None,
) -> dict[str, str]:
    """Create one exact runtime-only projection of a development checkout.

    Files outside the normalized allowlist are deliberately not inventoried.
    Every selected path component is inspected with ``lstat`` before bytes are
    copied without following a leaf link.  The destination must not exist.
    """

    paths = _normalize_allowlist(allowlist)
    source = _check_root(Path(source_root), label="source")
    projection = Path(projection_root)
    if projection.exists() or projection.is_symlink():
        raise RuntimePackageBuildError("projection:exists")
    try:
        source_resolved = source.resolve()
        projection_resolved = projection.resolve(strict=False)
        if (
            projection_resolved == source_resolved
            or source_resolved in projection_resolved.parents
            or projection_resolved in source_resolved.parents
        ):
            raise RuntimePackageBuildError("projection:overlaps_source")
    except RuntimePackageError:
        raise
    except OSError as exc:
        raise RuntimePackageBuildError("path_escape") from exc

    source_entries, version, source_modes = _projectable_source_entries(source, paths)
    projection.mkdir()
    for entry in source_entries:
        relative = str(entry["path"])
        parts = PurePosixPath(relative).parts
        destination = projection.joinpath(*parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(
            _read_projected_source_file(
                source,
                entry,
                source_mode=source_modes[relative],
            )
        )
        os.chmod(destination, int(entry["mode"]))

    projected_entries, projected_issues = _inventory_entries(
        projection,
        paths,
        label="projection",
    )
    if projected_issues:
        raise RuntimePackageValidationError(projected_issues)
    projected_version = _validate_manifest_and_descriptor(
        projection,
        projected_entries,
        paths,
    )
    if version != projected_version or source_entries != projected_entries:
        raise RuntimePackageValidationError("projection:source_mismatch")
    return _report(version, source_entries)


def build_runtime_package(
    source_root: os.PathLike[str] | str,
    stage_root: os.PathLike[str] | str,
    *,
    allowlist: Sequence[str] | None = None,
) -> dict[str, str]:
    """Deterministically stage ``source_root`` into ``stage_root``.

    The operation is create-only with respect to the destination.  An empty
    destination directory is accepted; an existing non-empty destination must
    already be byte- and mode-identical to the source or ``stale_stage`` is
    raised.  No retry, cleanup, or fallback is performed for a stale stage.
    """

    paths = _normalize_allowlist(allowlist)
    source = _check_root(Path(source_root), label="source")
    stage = Path(stage_root)
    try:
        source_resolved = source.resolve()
        stage_resolved = stage.resolve(strict=False)
        if (
            stage_resolved == source_resolved
            or source_resolved in stage_resolved.parents
            or stage_resolved in source_resolved.parents
        ):
            raise RuntimePackageBuildError("stage_inside_source")
    except RuntimePackageError:
        raise
    except OSError as exc:
        raise RuntimePackageBuildError("path_escape") from exc
    source_entries, source_issues = _inventory_entries(source, paths, label="source")
    if source_issues:
        raise RuntimePackageBuildError(source_issues)
    version = _validate_manifest_and_descriptor(source, source_entries, paths)
    expected_report = _report(version, source_entries)
    stage_is_empty = False
    if stage.exists() or stage.is_symlink():
        if stage.is_symlink():
            raise RuntimePackageValidationError("stage:symlink")
        try:
            stage_info = stage.lstat()
        except OSError as exc:
            raise RuntimePackageValidationError("stage:unreadable") from exc
        if not stat.S_ISDIR(stage_info.st_mode):
            raise RuntimePackageValidationError("stage:not_directory")
        if any(stage.iterdir()):
            actual_entries, stage_issues = _inventory_entries(stage, paths, label="stage")
            mismatches = list(stage_issues)
            source_by_path = {entry["path"]: entry for entry in source_entries}
            stage_by_path = {entry["path"]: entry for entry in actual_entries}
            if set(source_by_path) != set(stage_by_path):
                mismatches.append("stale_stage:inventory")
            for relative in sorted(set(source_by_path) & set(stage_by_path)):
                if source_by_path[relative] != stage_by_path[relative]:
                    mismatches.append(f"stale_stage:{relative}")
            if mismatches:
                raise RuntimePackageValidationError(mismatches)
            return expected_report
        stage_is_empty = True
    else:
        stage.parent.mkdir(parents=True, exist_ok=True)
    temporary_parent = Path(tempfile.mkdtemp(prefix=".orch-dork-runtime-", dir=str(stage.parent)))
    temporary = temporary_parent / stage.name
    try:
        temporary.mkdir()
        for entry in source_entries:
            relative = entry["path"]
            destination = temporary / Path(*PurePosixPath(relative).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / Path(*PurePosixPath(relative).parts), destination, follow_symlinks=False)
            os.chmod(destination, int(entry["mode"]))
        if stage_is_empty:
            # ``os.replace`` cannot replace an existing directory, even when
            # it is empty.  Remove only that explicitly validated empty
            # destination; a concurrent mutation fails closed below.
            try:
                stage.rmdir()
            except OSError as exc:
                raise RuntimePackageValidationError("stale_stage:appeared") from exc
        try:
            os.replace(temporary, stage)
        except FileExistsError as exc:
            raise RuntimePackageValidationError("stale_stage:appeared") from exc
    finally:
        shutil.rmtree(temporary_parent, ignore_errors=True)
    verified = validate_runtime_package(source, stage, allowlist=paths)
    if verified != expected_report:
        raise RuntimePackageValidationError("stale_stage:post_copy")
    return verified


def validate_runtime_package(
    source_root: os.PathLike[str] | str,
    stage_root: os.PathLike[str] | str,
    *,
    allowlist: Sequence[str] | None = None,
) -> dict[str, str]:
    """Verify source/stage parity and return the sanitized package report."""

    paths = _normalize_allowlist(allowlist)
    source = _check_root(Path(source_root), label="source")
    stage = _check_root(Path(stage_root), label="stage")
    source_entries, source_issues = _inventory_entries(source, paths, label="source")
    stage_entries, stage_issues = _inventory_entries(stage, paths, label="stage")
    issues = list(source_issues) + list(stage_issues)
    if not issues:
        source_version = _validate_manifest_and_descriptor(source, source_entries, paths)
        stage_version = _validate_manifest_and_descriptor(stage, stage_entries, paths)
        if source_version != stage_version:
            issues.append("stale_stage:version")
        source_by_path = {entry["path"]: entry for entry in source_entries}
        stage_by_path = {entry["path"]: entry for entry in stage_entries}
        if set(source_by_path) != set(stage_by_path):
            issues.append("stale_stage:inventory")
        for relative in sorted(set(source_by_path) & set(stage_by_path)):
            if source_by_path[relative] != stage_by_path[relative]:
                issues.append(f"stale_stage:{relative}")
    if issues:
        raise RuntimePackageValidationError(issues)
    return _report(source_version, source_entries)


_PROJECTION_REASON_CLASS_PREFIXES = (
    ("bytecode:", "bytecode"),
    ("credential:", "credential"),
    ("development_only:", "development_only"),
    ("missing:", "missing"),
    ("stale_stage:", "changed_or_mode_drift"),
    ("symlink:", "symlink"),
    ("unexpected:", "unexpected"),
    ("absolute_path:", "unsafe_content"),
    ("special:", "special_file"),
    ("unreadable:", "unreadable"),
    ("manifest:", "metadata"),
    ("descriptor:", "metadata"),
    ("invalid_json:", "metadata"),
    ("missing_dependency:", "metadata"),
    ("dependency:", "metadata"),
    ("allowlist:", "allowlist"),
    ("source:", "source_root"),
    ("source_changed:", "source_changed"),
    ("installed:", "installed_root"),
    ("stage:", "installed_root"),
    ("projection:", "projection"),
    ("path_escape", "projection"),
)


def _projection_reason_classes(issues: Iterable[str]) -> list[str]:
    classes: set[str] = set()
    for issue in issues:
        classes.add(
            next(
                (
                    reason_class
                    for prefix, reason_class in _PROJECTION_REASON_CLASS_PREFIXES
                    if str(issue).startswith(prefix)
                ),
                "runtime_validation",
            )
        )
    return sorted(classes)


def _sealed_projection_parity_report(
    *,
    status: str,
    reason: str,
    reason_classes: Sequence[str],
    package: Mapping[str, str] | None,
    allowlist_sha256: str | None,
    file_count: int | None,
    cleanup_status: str,
    owned_temporary_removed: bool,
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": PROJECTION_PARITY_SCHEMA,
        "status": status,
        "reason": reason,
        "reason_classes": list(reason_classes),
        "package": dict(package) if package is not None else None,
        "projection": {
            "allowlist_sha256": allowlist_sha256,
            "file_count": file_count,
        },
        "cleanup": {
            "status": cleanup_status,
            "owned_temporary_removed": owned_temporary_removed,
        },
        "predecessor_refusal_sha256": ISSUE156_REFUSAL_SHA256,
        "provider_free": True,
        "effects": dict(_PROJECTION_EFFECTS),
    }
    report = {**core, "report_sha256": _sha256(_canonical_json(core))}
    if len(_canonical_json(report)) > PROJECTION_PARITY_MAX_REPORT_BYTES:
        fallback = {
            **core,
            "status": "BLOCKED",
            "reason": "report_bound_blocked",
            "reason_classes": ["report_bound"],
            "package": None,
            "projection": {
                "allowlist_sha256": allowlist_sha256,
                "file_count": None,
            },
        }
        report = {
            **fallback,
            "report_sha256": _sha256(_canonical_json(fallback)),
        }
    return report


def validate_projected_runtime_package(
    source_root: os.PathLike[str] | str,
    installed_root: os.PathLike[str] | str,
    *,
    allowlist: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Validate a normal checkout against one exact installed runtime.

    The development checkout is reduced to the normalized runtime allowlist in
    one owned temporary directory.  Exact parity is then delegated to
    :func:`validate_runtime_package`.  All failures become a bounded,
    path-free v1 report, and success is impossible until temporary cleanup has
    been independently observed.
    """

    try:
        paths = _normalize_allowlist(allowlist)
    except RuntimePackageError as exc:
        return _sealed_projection_parity_report(
            status="BLOCKED",
            reason="allowlist_blocked",
            reason_classes=_projection_reason_classes(exc.issues),
            package=None,
            allowlist_sha256=None,
            file_count=None,
            cleanup_status="NOT_CREATED",
            owned_temporary_removed=True,
        )

    allowlist_sha256 = _sha256(
        _canonical_json({"schema": PACKAGE_SCHEMA, "allowlist": list(paths)})
    )
    package: dict[str, str] | None = None
    file_count: int | None = None
    temporary_parent: Path | None = None
    cleanup_status = "NOT_CREATED"
    owned_temporary_removed = True
    status = "BLOCKED"
    reason = "projection_setup_blocked"
    reason_classes: list[str] = []
    phase = "source_root"
    try:
        source = _check_root(Path(source_root), label="source")
        phase = "installed_root"
        installed = _check_root(Path(installed_root), label="installed")
        phase = "projection"
        temporary_parent = Path(
            tempfile.mkdtemp(prefix=".orch-dork-runtime-parity-")
        )
        cleanup_status = "UNKNOWN"
        owned_temporary_removed = False
        temporary_resolved = temporary_parent.resolve()
        for input_root in (source, installed):
            input_resolved = input_root.resolve()
            if (
                temporary_resolved == input_resolved
                or temporary_resolved in input_resolved.parents
                or input_resolved in temporary_resolved.parents
            ):
                raise RuntimePackageBuildError(
                    "projection:temporary_overlaps_input"
                )
        projection = temporary_parent / "runtime"
        projected_package = project_runtime_source(
            source,
            projection,
            allowlist=paths,
        )
        projected_entries = inventory_runtime(projection, allowlist=paths)
        file_count = len(projected_entries)
        phase = "installed_runtime"
        package = validate_runtime_package(
            projection,
            installed,
            allowlist=paths,
        )
        if package != projected_package:
            raise RuntimePackageValidationError(
                "projection:package_digest_mismatch"
            )
        status = "PASS"
        reason = "projected_runtime_parity"
    except RuntimePackageError as exc:
        reason = (
            "installed_runtime_blocked"
            if phase in {"installed_root", "installed_runtime"}
            else "source_projection_blocked"
        )
        reason_classes = _projection_reason_classes(exc.issues)
    except (OSError, TypeError, ValueError):
        reason = "projection_setup_blocked"
        reason_classes = ["projection"]
    finally:
        if temporary_parent is not None:
            try:
                shutil.rmtree(temporary_parent)
            except OSError:
                pass
            try:
                temporary_parent.lstat()
            except FileNotFoundError:
                cleanup_status = "PASS"
                owned_temporary_removed = True
            except OSError:
                cleanup_status = "UNKNOWN"
                owned_temporary_removed = False
            else:
                cleanup_status = "BLOCKED"
                owned_temporary_removed = False
    if cleanup_status not in {"PASS", "NOT_CREATED"}:
        status = "BLOCKED"
        reason = "cleanup_blocked"
        reason_classes = sorted(set(reason_classes) | {"cleanup"})
    return _sealed_projection_parity_report(
        status=status,
        reason=reason,
        reason_classes=reason_classes,
        package=package,
        allowlist_sha256=allowlist_sha256,
        file_count=file_count,
        cleanup_status=cleanup_status,
        owned_temporary_removed=owned_temporary_removed,
    )


# Small compatibility aliases make the seam convenient for callers while
# retaining one implementation and one allowlist.
build_package = build_runtime_package
stage_package = build_runtime_package
validate_package = validate_runtime_package
inventory = inventory_runtime


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or verify an allowlisted Orch Dork runtime package")
    parser.add_argument("source", type=Path)
    parser.add_argument("stage", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--verify", action="store_true", help="verify an existing stage instead of building it")
    modes.add_argument(
        "--projected-verify",
        action="store_true",
        help="project a development checkout and verify one installed runtime",
    )
    args = parser.parse_args(argv)
    if args.projected_verify:
        report = validate_projected_runtime_package(args.source, args.stage)
        print(
            json.dumps(
                report,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0 if report["status"] == "PASS" else 2
    try:
        report = validate_runtime_package(args.source, args.stage) if args.verify else build_runtime_package(args.source, args.stage)
    except RuntimePackageError as exc:
        print(json.dumps({"status": "BLOCKED", "issues": list(exc.issues)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - command-line convenience
    raise SystemExit(_main())
