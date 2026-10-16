#!/usr/bin/env python3
"""Repository-owned construction for governed Issue 94 qualification inputs.

The module consumes the strict qualification artifact instead of importing
test fixtures or accepting caller-translated fields. It owns the complete
closed logical plan and exhaustive Markdown manifest used by the governed
pre-spawn program, and persists them together for unchanged typed handoff.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping

import orch_dork_adaptive_contracts as contracts
import orch_dork_efficiency_governor as governor
import orch_dork_live_zero_tool as zero_tool
import orch_dork_plan_closure as plan_closure
import orch_dork_qualification_rehearsal as rehearsal
import orch_dork_research_manifest as research_manifest


GOVERNED_INPUTS_REPORT_SCHEMA = (
    "orch-dork/qualification-governed-inputs-report/v1"
)
GOVERNED_INPUTS_RECEIPT_SCHEMA = (
    "orch-dork/qualification-governed-inputs-receipt/v1"
)
_EXPECTED_LANES = ("spec", "standards")
_COUNTER_NAMES = (
    "credential_reads",
    "network_calls",
    "provider_calls",
    "model_calls",
    "hosted_calls",
    "controller_activations",
    "capacity_reservations",
    "authority_grants",
    "native_actions",
    "workers",
)


class QualificationGovernedInputsError(ValueError):
    """Stable refusal before controller, capacity, or native action."""


@contextmanager
def _artifact_plan_route(
    value: Any,
    *,
    case_id: Any,
) -> Iterator[None]:
    """Bind an allowlisted artifact to its own recorded worker route."""

    plan = value if isinstance(value, Mapping) else {}
    execution = plan.get("execution")
    if (
        case_id in rehearsal.HISTORICAL_REPLAY_CASE_IDS
        and isinstance(execution, Mapping)
        and isinstance(execution.get("worker_model"), str)
        and bool(execution.get("worker_model"))
        and isinstance(execution.get("worker_effort"), str)
        and bool(execution.get("worker_effort"))
    ):
        model = execution["worker_model"]
        effort = execution["worker_effort"]
        with governor.worker_default.pinned(
            model=model,
            effort=effort,
        ), zero_tool.pinned_route(model=model, effort=effort):
            yield
        return
    yield


def _validate_artifact_plan(
    value: Any,
    *,
    case_id: Any,
) -> dict[str, Any]:
    """Revalidate a plan under its current or exact completed worker route."""

    with _artifact_plan_route(value, case_id=case_id):
        return governor.validate_logical_plan(value)


def rebind_artifact_plan(
    value: Any,
    *,
    case_id: Any,
) -> Any:
    """Freeze a re-stamped plan's routing policy again, when it carries one.

    A plan whose lanes name profiles (Issue 203's reviewer lane) binds the
    sealed routing policy over its whole core, so a plan the qualification
    re-stamps with its project, generation, closure or attempt root binds
    the policy again.  A plan that names no profile carries no binding and
    is returned unchanged, as every earlier attempt froze.
    """

    if not isinstance(value, Mapping) or governor.ROUTING_POLICY_FIELD not in value:
        return value
    with _artifact_plan_route(value, case_id=case_id):
        return governor.bind_routing_policy(value)


def _source_root(value: str | Path) -> Path:
    root = Path(value)
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise QualificationGovernedInputsError(
            "governed_inputs:source_root_unavailable"
        ) from error
    if root.is_symlink() or not resolved.is_dir():
        raise QualificationGovernedInputsError(
            "governed_inputs:source_root_invalid"
        )
    return resolved


def _is_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _task_specs(
    artifact: rehearsal.QualificationArtifact,
) -> tuple[dict[str, Any], ...]:
    raw = artifact.report.get("qualification_payload", {}).get("task_specs")
    if not isinstance(raw, list) or len(raw) != len(_EXPECTED_LANES):
        raise QualificationGovernedInputsError(
            "governed_inputs:task_specs_invalid"
        )
    rows: list[dict[str, Any]] = []
    lane_ids: list[str] = []
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != {
            "logical_worker_id",
            "task_spec_sha256",
            "task_spec",
        }:
            raise QualificationGovernedInputsError(
                "governed_inputs:task_spec_binding_invalid"
            )
        lane_id = item.get("logical_worker_id")
        validation = contracts.validate_task_spec(item.get("task_spec"))
        normalized = validation.get("normalized")
        if (
            lane_id not in _EXPECTED_LANES
            or validation.get("status") != "PASS"
            or validation.get("valid") is not True
            or validation.get("issues") != []
            or not isinstance(normalized, Mapping)
            or normalized.get("id") != lane_id
            or item.get("task_spec_sha256")
            != validation.get("digest")
        ):
            raise QualificationGovernedInputsError(
                "governed_inputs:task_spec_binding_invalid"
            )
        lane_ids.append(str(lane_id))
        rows.append(deepcopy(dict(normalized)))
    if sorted(lane_ids) != list(_EXPECTED_LANES):
        raise QualificationGovernedInputsError(
            "governed_inputs:task_spec_lane_set_invalid"
        )
    return tuple(sorted(rows, key=lambda row: row["id"]))


def _read_scope_paths(
    task_spec: Mapping[str, Any],
    source_root: Path,
) -> tuple[str, ...]:
    raw = task_spec.get("read_scope")
    if not isinstance(raw, list) or not raw:
        raise QualificationGovernedInputsError(
            "governed_inputs:research_read_scope_invalid"
        )
    paths: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise QualificationGovernedInputsError(
                "governed_inputs:research_source_invalid"
            )
        candidate = PurePosixPath(item)
        if (
            candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or candidate.suffix.casefold() != ".md"
        ):
            raise QualificationGovernedInputsError(
                "governed_inputs:research_source_invalid"
            )
        resolved = (source_root / candidate.as_posix()).resolve(strict=True)
        try:
            resolved.relative_to(source_root)
        except ValueError as error:
            raise QualificationGovernedInputsError(
                "governed_inputs:research_source_escape"
            ) from error
        if resolved.is_symlink() or not resolved.is_file():
            raise QualificationGovernedInputsError(
                "governed_inputs:research_source_invalid"
            )
        paths.append(candidate.as_posix())
    if len(paths) != len(set(paths)):
        raise QualificationGovernedInputsError(
            "governed_inputs:research_source_duplicate"
        )
    return tuple(sorted(paths))


@dataclass(frozen=True, slots=True)
class Issue94ResearchEnvelope:
    """Typed whole-manifest envelope derived from frozen TaskSpecs."""

    manifest: dict[str, Any]
    manifest_sha256: str
    source_paths: tuple[str, ...]
    claim_ids: tuple[str, ...]

    @classmethod
    def from_artifact(
        cls,
        artifact: Any,
        source_root: str | Path,
    ) -> "Issue94ResearchEnvelope":
        if not isinstance(artifact, rehearsal.QualificationArtifact):
            raise QualificationGovernedInputsError(
                "governed_inputs:qualification_artifact_type_invalid"
            )
        resolved_root = _source_root(source_root)

        claims: list[dict[str, Any]] = []
        all_paths: set[str] = set()
        for task_spec in _task_specs(artifact):
            paths = _read_scope_paths(task_spec, resolved_root)
            lane_id = str(task_spec["id"])
            claim_id = "issue94-" + lane_id + "-research-scope"
            claims.append(
                {
                    "claim_id": claim_id,
                    "statement_sha256": contracts.json_sha256(
                        {
                            "lane_id": lane_id,
                            "goal": task_spec["goal"],
                            "source_paths": list(paths),
                        }
                    ),
                    "source_paths": list(paths),
                }
            )
            all_paths.update(paths)

        manifest = research_manifest.build_markdown_manifest(
            resolved_root,
            manifest_id=(
                str(artifact.report["case_id"])
                + "-issue94-research"
            ),
            claims=claims,
            used_claim_ids=[row["claim_id"] for row in claims],
            source_pointer=(
                "qualification-artifact://"
                + artifact.report_sha256
                + "#task-spec-read-scope"
            ),
        )
        validation = research_manifest.validate_markdown_manifest(
            manifest,
            resolved_root,
        )
        if (
            validation.get("status") != "PASS"
            or validation.get("issues") != []
            or validation.get("manifest_sha256")
            != manifest.get("manifest_sha256")
        ):
            raise QualificationGovernedInputsError(
                "governed_inputs:research_manifest_invalid"
            )
        return cls(
            manifest=deepcopy(manifest),
            manifest_sha256=str(manifest["manifest_sha256"]),
            source_paths=tuple(sorted(all_paths)),
            claim_ids=tuple(sorted(row["claim_id"] for row in claims)),
        )


def _project_identity(
    artifact: rehearsal.QualificationArtifact,
    source_root: Path,
) -> dict[str, Any]:
    binding_path = source_root / ".orch-dork/binding.json"
    try:
        binding = json.loads(binding_path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationGovernedInputsError(
            "governed_inputs:project_binding_unavailable"
        ) from error
    required = {
        "schema",
        "project_id",
        "protocol",
        "required",
        "binding_generation",
        "enrollment_identity_sha256",
        "adapter_command",
        "adapter_sha256",
    }
    payload = artifact.report.get("qualification_payload", {})
    prepared = payload.get("prepared_activation_payload")
    identity = (
        prepared.get("identity")
        if isinstance(prepared, Mapping)
        else None
    )
    if (
        not isinstance(binding, Mapping)
        or set(binding) != required
        or binding.get("schema") != "orch-dork/project-binding/v1"
        or binding.get("required") is not True
        or not isinstance(identity, Mapping)
        or binding.get("project_id") != identity.get("project_id")
        or binding.get("binding_generation")
        != identity.get("enrollment_generation")
    ):
        raise QualificationGovernedInputsError(
            "governed_inputs:project_binding_invalid"
        )
    root_text = str(source_root)
    return {
        "project_id": binding["project_id"],
        "protocol": binding["protocol"],
        "binding_generation": binding["binding_generation"],
        "binding_manifest_sha256": contracts.json_sha256(binding),
        "workspace_root": root_text,
        "workspace_root_sha256": hashlib.sha256(
            root_text.encode("utf-8")
        ).hexdigest(),
        "required_resource_surfaces": ["install"],
        "research_manifest_required": True,
        "source_pointer": "source:.orch-dork/binding.json",
    }


def _generation_identity(
    artifact: rehearsal.QualificationArtifact,
) -> dict[str, Any]:
    payload = artifact.report.get("qualification_payload", {})
    prepared = payload.get("prepared_activation_payload")
    identity = (
        prepared.get("identity")
        if isinstance(prepared, Mapping)
        else None
    )
    attempt = payload.get("attempt")
    if not isinstance(identity, Mapping) or not isinstance(attempt, Mapping):
        raise QualificationGovernedInputsError(
            "governed_inputs:generation_identity_invalid"
        )
    generation = {
        "source_version": identity.get("source_version"),
        "installed_version": identity.get("installed_plugin_version"),
        "task_loaded_version": identity.get("task_loaded_version"),
        "fresh_task": identity.get("fresh_task"),
    }
    if (
        len(
            {
                generation["source_version"],
                generation["installed_version"],
                generation["task_loaded_version"],
                attempt.get("installed_plugin_version"),
            }
        )
        != 1
        or generation["fresh_task"] is not True
    ):
        raise QualificationGovernedInputsError(
            "governed_inputs:generation_identity_invalid"
        )
    return generation


def _criterion_index(
    lane_id: str,
    criteria: list[Any],
) -> int:
    prefix = lane_id.casefold() + " "
    matches = [
        index
        for index, criterion in enumerate(criteria)
        if isinstance(criterion, str)
        and criterion.casefold().startswith(prefix)
    ]
    if len(matches) != 1:
        raise QualificationGovernedInputsError(
            "governed_inputs:criterion_lane_binding_invalid"
        )
    return matches[0]


def _closure_projection(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "lanes": deepcopy(plan["workers"]),
        "acceptance_criteria": deepcopy(plan["acceptance_criteria"]),
        "protected_resources": deepcopy(plan["protected_resources"]),
        "decision": {"mode": "orchestrated"},
        "root": {"coordination_only_after_freeze": False},
        "integration": {
            "strategy": "root",
            "final_verification": deepcopy(
                plan["integration"]["final_verification"]
            ),
        },
        "acceptance_resource_closure": deepcopy(
            plan["acceptance_resource_closure"]
        ),
    }


@dataclass(frozen=True, slots=True)
class Issue94LogicalPlanEnvelope:
    """Typed closed plan built from one complete qualification artifact."""

    logical_plan: dict[str, Any]
    plan_sha256: str
    closure_report: dict[str, Any]
    closure_sha256: str

    @classmethod
    def from_artifact(
        cls,
        artifact: Any,
        source_root: str | Path,
    ) -> "Issue94LogicalPlanEnvelope":
        if not isinstance(artifact, rehearsal.QualificationArtifact):
            raise QualificationGovernedInputsError(
                "governed_inputs:qualification_artifact_type_invalid"
            )
        root = _source_root(source_root)
        payload = artifact.report.get("qualification_payload", {})
        raw_plan = payload.get("logical_plan")
        initial = _validate_artifact_plan(
            raw_plan,
            case_id=artifact.report.get("case_id"),
        )
        if (
            initial.get("status") != "PASS"
            or initial.get("valid") is not True
            or initial.get("issues") != []
            or not isinstance(raw_plan, Mapping)
            or raw_plan.get("acceptance_resource_closure") is not None
        ):
            raise QualificationGovernedInputsError(
                "governed_inputs:logical_plan_invalid"
            )
        plan = deepcopy(dict(raw_plan))
        plan["project"] = _project_identity(artifact, root)
        plan["generation"] = _generation_identity(artifact)
        plan["task_node_budget"] = len(plan["workers"])

        criteria = plan["acceptance_criteria"]
        requirements: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []
        for worker in plan["workers"]:
            lane_id = worker.get("id")
            resources = worker.get("owned_resources")
            if (
                not isinstance(lane_id, str)
                or not isinstance(resources, list)
                or len(resources) != 1
                or not isinstance(resources[0], str)
            ):
                raise QualificationGovernedInputsError(
                    "governed_inputs:lane_resource_invalid"
                )
            requirement_id = "lane-" + lane_id
            requirements.append(
                {
                    "id": requirement_id,
                    "criterion": _criterion_index(lane_id, criteria),
                    "resource": resources[0],
                    "phase": "implementation",
                    "surface": "path",
                    "generated": False,
                }
            )
            assignments.append(
                {
                    "requirement_id": requirement_id,
                    "owner": {"kind": "lane", "id": lane_id},
                }
            )
        requirements.extend(
            [
                {
                    "id": "installed-generation",
                    "criterion": 0,
                    "resource": "install/orch-dork/**",
                    "phase": "integration",
                    "surface": "install",
                    "generated": False,
                },
                {
                    "id": "terminal-verification",
                    "criterion": 0,
                    "resource": "semantic:terminal-verification",
                    "phase": "final_verification",
                    "surface": "semantic",
                    "generated": False,
                },
            ]
        )
        assignments.extend(
            [
                {
                    "requirement_id": "installed-generation",
                    "owner": {"kind": "root", "id": "root"},
                },
                {
                    "requirement_id": "terminal-verification",
                    "owner": {"kind": "root", "id": "root"},
                },
            ]
        )
        plan["acceptance_resource_closure"] = {
            "schema": plan_closure.CLOSURE_SCHEMA,
            "workspace_root": str(root),
            "binding": {
                "acceptance_criteria_sha256": "0" * 64,
                "writable_scope_sha256": "0" * 64,
                "integration_resources_sha256": "0" * 64,
                "final_verification_sha256": "0" * 64,
            },
            "requirements": requirements,
            "assignments": assignments,
            "integration_owner": {
                "kind": "root",
                "id": "root",
                "release_conditions": ["all delegated nodes verified"],
            },
        }
        sealed = plan_closure.bind_closure(_closure_projection(plan))
        plan["acceptance_resource_closure"] = sealed[
            "acceptance_resource_closure"
        ]
        plan = rebind_artifact_plan(plan, case_id=artifact.report.get("case_id"))
        validation = _validate_artifact_plan(
            plan,
            case_id=artifact.report.get("case_id"),
        )
        closure_report = validation.get("acceptance_resource_closure")
        if (
            validation.get("status") != "PASS"
            or validation.get("valid") is not True
            or validation.get("issues") != []
            or not isinstance(closure_report, Mapping)
            or closure_report.get("status") != "PASS"
            or closure_report.get("closed") is not True
            or closure_report.get("spawn_permitted") is not True
            or closure_report.get("issues") != []
        ):
            raise QualificationGovernedInputsError(
                "governed_inputs:logical_plan_closure_invalid"
            )
        return cls(
            logical_plan=deepcopy(plan),
            plan_sha256=str(validation["plan_sha256"]),
            closure_report=deepcopy(dict(closure_report)),
            closure_sha256=str(closure_report["closure_sha256"]),
        )


def build_issue94_research_manifest(
    artifact: Any,
    source_root: str | Path,
) -> dict[str, Any]:
    """Return one complete sealed manifest; callers translate no fields."""

    return Issue94ResearchEnvelope.from_artifact(
        artifact,
        source_root,
    ).manifest


@dataclass(frozen=True, slots=True)
class Issue94GovernedInputsArtifact:
    """Strict accessor for one persisted closed-plan/research pair."""

    report: dict[str, Any]
    report_sha256: str
    qualification_report_sha256: str
    logical_plan: dict[str, Any]
    logical_plan_sha256: str
    closure_report: dict[str, Any]
    closure_sha256: str
    research_manifest: dict[str, Any]
    research_manifest_sha256: str
    source_paths: tuple[str, ...]
    claim_ids: tuple[str, ...]

    @classmethod
    def from_report(
        cls,
        report: Any,
        source_root: str | Path,
    ) -> "Issue94GovernedInputsArtifact":
        required = {
            "schema",
            "status",
            "issues",
            "case_id",
            "qualification_report_sha256",
            "logical_plan",
            "logical_plan_sha256",
            "closure_report",
            "closure_sha256",
            "research_manifest",
            "research_manifest_sha256",
            "source_paths",
            "claim_ids",
            "counters",
            "report_sha256",
        }
        if not isinstance(report, Mapping) or set(report) != required:
            raise QualificationGovernedInputsError(
                "governed_inputs:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        core = {
            key: deepcopy(item)
            for key, item in value.items()
            if key != "report_sha256"
        }
        counters = value.get("counters")
        source_paths = value.get("source_paths")
        claim_ids = value.get("claim_ids")
        manifest = value.get("research_manifest")
        manifest_validation = research_manifest.validate_markdown_manifest(
            manifest,
            _source_root(source_root),
        )
        plan_validation = _validate_artifact_plan(
            value.get("logical_plan"),
            case_id=value.get("case_id"),
        )
        closure_report = plan_validation.get(
            "acceptance_resource_closure"
        )
        qualification_sha = value.get("qualification_report_sha256")
        if (
            value.get("schema") != GOVERNED_INPUTS_REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("issues") != []
            or not isinstance(value.get("case_id"), str)
            or not value["case_id"]
            or not _is_sha(qualification_sha)
            or plan_validation.get("status") != "PASS"
            or plan_validation.get("valid") is not True
            or plan_validation.get("issues") != []
            or plan_validation.get("plan_sha256")
            != value.get("logical_plan_sha256")
            or not isinstance(closure_report, Mapping)
            or dict(closure_report) != value.get("closure_report")
            or closure_report.get("status") != "PASS"
            or closure_report.get("closed") is not True
            or closure_report.get("spawn_permitted") is not True
            or closure_report.get("issues") != []
            or closure_report.get("closure_sha256")
            != value.get("closure_sha256")
            or not isinstance(source_paths, list)
            or source_paths != sorted(set(source_paths))
            or not isinstance(claim_ids, list)
            or claim_ids != sorted(set(claim_ids))
            or not isinstance(counters, Mapping)
            or set(counters) != set(_COUNTER_NAMES)
            or any(counters.get(name) != 0 for name in _COUNTER_NAMES)
            or not isinstance(manifest, Mapping)
            or manifest_validation.get("status") != "PASS"
            or manifest_validation.get("issues") != []
            or manifest_validation.get("manifest_sha256")
            != value.get("research_manifest_sha256")
            or sorted(
                {
                    path
                    for claim in manifest.get("claims", [])
                    for path in claim.get("source_paths", [])
                }
            )
            != source_paths
            or sorted(manifest.get("used_claim_ids", [])) != claim_ids
            or value.get("report_sha256")
            != contracts.json_sha256(core)
        ):
            raise QualificationGovernedInputsError(
                "governed_inputs:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            qualification_report_sha256=str(qualification_sha),
            logical_plan=deepcopy(dict(value["logical_plan"])),
            logical_plan_sha256=str(value["logical_plan_sha256"]),
            closure_report=deepcopy(dict(closure_report)),
            closure_sha256=str(value["closure_sha256"]),
            research_manifest=deepcopy(dict(manifest)),
            research_manifest_sha256=str(
                value["research_manifest_sha256"]
            ),
            source_paths=tuple(source_paths),
            claim_ids=tuple(claim_ids),
        )


def build_issue94_governed_inputs_report(
    artifact: Any,
    source_root: str | Path,
) -> dict[str, Any]:
    """Build and seal the complete closed-plan and research input pair."""

    if not isinstance(artifact, rehearsal.QualificationArtifact):
        raise QualificationGovernedInputsError(
            "governed_inputs:qualification_artifact_type_invalid"
        )
    plan = Issue94LogicalPlanEnvelope.from_artifact(
        artifact,
        source_root,
    )
    research = Issue94ResearchEnvelope.from_artifact(
        artifact,
        source_root,
    )
    core = {
        "schema": GOVERNED_INPUTS_REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "case_id": artifact.report["case_id"],
        "qualification_report_sha256": artifact.report_sha256,
        "logical_plan": plan.logical_plan,
        "logical_plan_sha256": plan.plan_sha256,
        "closure_report": plan.closure_report,
        "closure_sha256": plan.closure_sha256,
        "research_manifest": research.manifest,
        "research_manifest_sha256": research.manifest_sha256,
        "source_paths": list(research.source_paths),
        "claim_ids": list(research.claim_ids),
        "counters": {name: 0 for name in _COUNTER_NAMES},
    }
    report = {**core, "report_sha256": contracts.json_sha256(core)}
    Issue94GovernedInputsArtifact.from_report(report, source_root)
    return report


def read_issue94_governed_inputs_artifact(
    path: str | Path,
    source_root: str | Path,
) -> Issue94GovernedInputsArtifact:
    """Load one private artifact with the shared bounded safe reader."""

    payload = rehearsal._artifact_bytes(Path(path))
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationGovernedInputsError(
            "governed_inputs:artifact_json_invalid"
        ) from error
    return Issue94GovernedInputsArtifact.from_report(value, source_root)


def persist_issue94_governed_inputs_artifact(
    report: Any,
    output_path: str | Path,
    source_root: str | Path,
) -> dict[str, Any]:
    """Create and revalidate one owner-only artifact; return a receipt."""

    artifact = Issue94GovernedInputsArtifact.from_report(
        report,
        source_root,
    )
    output = Path(output_path)
    payload = (
        json.dumps(
            artifact.report,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    rehearsal._write_create_only(output, payload)
    persisted = read_issue94_governed_inputs_artifact(
        output,
        source_root,
    )
    if persisted.report != artifact.report:
        raise QualificationGovernedInputsError(
            "governed_inputs:artifact_readback_mismatch"
        )
    core = {
        "schema": GOVERNED_INPUTS_RECEIPT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "case_id": persisted.report["case_id"],
        "qualification_report_sha256": (
            persisted.qualification_report_sha256
        ),
        "artifact_path": str(output),
        "artifact_size_bytes": len(payload),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": persisted.report_sha256,
        "logical_plan_sha256": persisted.logical_plan_sha256,
        "closure_sha256": persisted.closure_sha256,
        "research_manifest_sha256": (
            persisted.research_manifest_sha256
        ),
        "source_paths": list(persisted.source_paths),
        "claim_ids": list(persisted.claim_ids),
        "counters": deepcopy(persisted.report["counters"]),
    }
    return {**core, "receipt_sha256": contracts.json_sha256(core)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qualification-artifact", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        qualification = rehearsal.read_qualification_artifact(
            args.qualification_artifact
        )
        report = build_issue94_governed_inputs_report(
            qualification,
            args.source_root,
        )
        receipt = persist_issue94_governed_inputs_artifact(
            report,
            args.output,
            args.source_root,
        )
    except (OSError, QualificationGovernedInputsError, ValueError) as error:
        print(
            json.dumps(
                {
                    "schema": GOVERNED_INPUTS_RECEIPT_SCHEMA,
                    "status": "FAIL",
                    "issues": [str(error)],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


__all__ = [
    "GOVERNED_INPUTS_RECEIPT_SCHEMA",
    "GOVERNED_INPUTS_REPORT_SCHEMA",
    "Issue94GovernedInputsArtifact",
    "Issue94LogicalPlanEnvelope",
    "Issue94ResearchEnvelope",
    "QualificationGovernedInputsError",
    "build_issue94_governed_inputs_report",
    "build_issue94_research_manifest",
    "persist_issue94_governed_inputs_artifact",
    "read_issue94_governed_inputs_artifact",
]


if __name__ == "__main__":
    raise SystemExit(main())
