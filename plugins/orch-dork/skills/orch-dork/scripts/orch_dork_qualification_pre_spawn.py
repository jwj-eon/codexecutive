#!/usr/bin/env python3
"""Own the complete post-canary Issue 94 pre-spawn assembly boundary.

Callers pass three whole typed artifacts, one canonical external enrollment
registry, and one root-task identity.  This driver constructs every legacy
stage program through repository-owned constructors, evaluates the complete
provider-free chain, persists one sealed artifact, and stops before capacity
admission, activation, or worker creation.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_admission_kernel as admission_kernel  # noqa: E402
import orch_dork_coordinator_capsule as coordinator_capsule  # noqa: E402
import orch_dork_efficiency_governor as governor  # noqa: E402
import orch_dork_execution_readiness as execution_readiness  # noqa: E402
import orch_dork_governed_attempt as governed_attempt  # noqa: E402
import orch_dork_governed_native_controller as native_controller  # noqa: E402
import orch_dork_project_adapter as project_adapter  # noqa: E402
import orch_dork_project_ground as project_ground  # noqa: E402
import orch_dork_project_ground_enforcement as ground_enforcement  # noqa: E402
import orch_dork_qualification_governed_inputs as governed_inputs  # noqa: E402
import orch_dork_qualification_rehearsal as rehearsal  # noqa: E402
import orch_dork_qualification_route_canary as route_canary  # noqa: E402
import orch_dork_ticket_admission as ticket_admission  # noqa: E402


REPORT_SCHEMA = "orch-dork/qualification-pre-spawn-report/v2"
RECEIPT_SCHEMA = "orch-dork/qualification-pre-spawn-artifact-receipt/v2"
CHECKPOINT_REPORT_SCHEMA = "orch-dork/qualification-pre-spawn-report/v3"
CHECKPOINT_RECEIPT_SCHEMA = "orch-dork/qualification-pre-spawn-artifact-receipt/v3"
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_COUNTER_NAMES = (
    "authority_grants",
    "capacity_reservations",
    "controller_activations",
    "credential_reads",
    "hosted_calls",
    "model_calls",
    "native_actions",
    "network_calls",
    "provider_calls",
    "workers",
)
_ENROLLMENT_COUNTER_NAMES = (
    "adapter_executions",
    "authority_reservations",
    "credential_reads",
    "hook_changes",
    "hosted_calls",
    "model_calls",
    "sandbox_changes",
    "task_creations",
    "worker_creations",
)
_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "case_id",
        "evaluation_time",
        "qualification_report_sha256",
        "governed_inputs_report_sha256",
        "canary_report_sha256",
        "qualification_report",
        "governed_inputs_report",
        "canary_report",
        "evidence_manifest",
        "ticket_admission_program",
        "ticket_admission",
        "hard_admission_program",
        "hard_admission_report",
        "execution_readiness_program",
        "execution_readiness_report",
        "project_adapter_program",
        "project_adapter_report",
        "project_enrollment_program",
        "project_enrollment_report",
        "activation_preparation_report",
        "pre_spawn_program",
        "pre_spawn_report",
        "counters",
        "report_sha256",
    }
)


class QualificationPreSpawnError(ValueError):
    """Stable refusal raised before capacity or activation authority."""


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


def unmaterialized_hook_trust_sha256(
    hook_definition_sha256: Any,
    hook_registration_sha256: Any,
) -> str:
    """Seal the explicit pre-live placeholder, never a trust receipt."""

    if not _is_sha(hook_definition_sha256) or not _is_sha(
        hook_registration_sha256
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:hook_identity_invalid"
        )
    return _sha(
        {
            "hook_definition_sha256": hook_definition_sha256,
            "hook_registration_sha256": hook_registration_sha256,
        }
    )


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise QualificationPreSpawnError(
            "pre_spawn:evaluation_time_timezone_required"
        )
    return value.astimezone(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise QualificationPreSpawnError(
            "pre_spawn:evaluation_time_invalid"
        )
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise QualificationPreSpawnError(
            "pre_spawn:evaluation_time_invalid"
        ) from error


def _source_root(value: str | Path) -> Path:
    try:
        root = Path(value).resolve(strict=True)
    except (OSError, ValueError) as error:
        raise QualificationPreSpawnError(
            "pre_spawn:source_root_unavailable"
        ) from error
    if not root.is_dir():
        raise QualificationPreSpawnError(
            "pre_spawn:source_root_invalid"
        )
    return root


def _evidence_root(value: str | Path) -> Path:
    try:
        candidate = Path(value)
        if candidate.is_symlink():
            raise ValueError("symlink evidence root")
        root = candidate.resolve(strict=True)
        details = root.stat()
    except (OSError, ValueError) as error:
        raise QualificationPreSpawnError(
            "pre_spawn:evidence_root_unavailable"
        ) from error
    if (
        not root.is_dir()
        or stat.S_ISLNK(details.st_mode)
        or details.st_mode & 0o077
        or (hasattr(os, "getuid") and details.st_uid != os.getuid())
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:evidence_root_unsafe"
        )
    return root


def _enrollment_registry_root(value: str | Path) -> Path:
    candidate = Path(value)
    try:
        if not candidate.is_absolute() or candidate.is_symlink():
            raise ValueError("non-canonical registry root")
        root = candidate.resolve(strict=True)
        details = root.stat()
        records = root / "records"
        record_details = records.stat()
    except (OSError, ValueError) as error:
        raise QualificationPreSpawnError(
            "pre_spawn:enrollment_registry_unavailable"
        ) from error
    # Project enrollment creates these directories under the caller's umask;
    # mode 0775 is therefore a supported owner-controlled host layout.  The
    # directory must be owned by this uid and not world-writable, while the
    # manifest and record themselves are descriptor-checked and the record is
    # required to be owner-only by the project-ground constructor.
    if (
        candidate != root
        or not root.is_dir()
        or not records.is_dir()
        or records.is_symlink()
        or details.st_mode & 0o002
        or record_details.st_mode & 0o002
        or (
            hasattr(os, "getuid")
            and (
                details.st_uid != os.getuid()
                or record_details.st_uid != os.getuid()
            )
        )
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:enrollment_registry_unsafe"
        )
    return root


@dataclass(frozen=True, slots=True)
class ActiveProjectEnrollmentArtifact:
    """Strict whole-program/report access to current read-only enrollment."""

    program: dict[str, Any]
    program_sha256: str
    report: dict[str, Any]
    report_sha256: str
    manifest_sha256: str
    record_sha256: str
    identity_key: str

    @classmethod
    def from_roots(
        cls,
        source_root: str | Path,
        enrollment_registry_root: str | Path,
    ) -> "ActiveProjectEnrollmentArtifact":
        root = _source_root(source_root)
        registry = _enrollment_registry_root(enrollment_registry_root)
        try:
            program = project_ground.build_active_inspection_program(
                root,
                registry,
                maintenance_reason=(
                    "read-only qualification enrollment inspection"
                ),
                source_pointer=(
                    "qualification-pre-spawn#active-enrollment"
                ),
            )
        except project_ground.ProjectEnrollmentInspectionError as error:
            if "registry:record:missing" in error.issues:
                raise QualificationPreSpawnError(
                    "pre_spawn:project_enrollment_record_unavailable"
                ) from error
            raise QualificationPreSpawnError(
                "pre_spawn:project_enrollment_invalid:" + str(error)
            ) from error
        report = project_ground.evaluate_project_enrollment(program)
        manifest = report.get("current_manifest")
        record = report.get("current_record")
        identity_key = report.get("identity_key")
        expected_manifest_sha256 = report.get("manifest_sha256")
        report_core = {
            key: deepcopy(child)
            for key, child in report.items()
            if key != "report_sha256"
        }
        if (
            report.get("status") != "PASS"
            or report.get("decision") != "ACTIVE"
            or report.get("issues") != []
            or report.get("provider_free") is not True
            or report.get("mutation_performed") is not False
            or not _is_sha(identity_key)
            or not _is_sha(expected_manifest_sha256)
            or not isinstance(manifest, Mapping)
            or not isinstance(record, Mapping)
            or not _is_sha(record.get("record_sha256"))
            or report.get("record_sha256") != record.get("record_sha256")
            or report.get("record_path")
            != str(registry / "records" / (str(identity_key) + ".json"))
            or report.get("binding_path")
            != str(root / ".orch-dork/binding.json")
            or any(report.get(name) != 0 for name in _ENROLLMENT_COUNTER_NAMES)
            or report.get("report_sha256") != _sha(report_core)
        ):
            raise QualificationPreSpawnError(
                "pre_spawn:project_enrollment_not_active:"
                + ";".join(report.get("issues", []))
            )
        return cls(
            program=deepcopy(program),
            program_sha256=_sha(program),
            report=deepcopy(report),
            report_sha256=str(report["report_sha256"]),
            manifest_sha256=str(expected_manifest_sha256),
            record_sha256=str(record["record_sha256"]),
            identity_key=str(identity_key),
        )


def _require_input_artifacts(
    qualification: Any,
    inputs: Any,
    canary: Any,
) -> tuple[
    rehearsal.QualificationArtifact,
    governed_inputs.Issue94GovernedInputsArtifact,
    route_canary.RouteCanaryArtifact,
]:
    if not isinstance(qualification, rehearsal.QualificationArtifact):
        raise QualificationPreSpawnError(
            "pre_spawn:qualification_artifact_type_invalid"
        )
    if not isinstance(
        inputs,
        governed_inputs.Issue94GovernedInputsArtifact,
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:governed_inputs_artifact_type_invalid"
        )
    if not isinstance(canary, route_canary.RouteCanaryArtifact):
        raise QualificationPreSpawnError(
            "pre_spawn:canary_artifact_type_invalid"
        )
    case_id = qualification.report.get("case_id")
    if (
        inputs.report.get("case_id") != case_id
        or canary.report.get("case_id") != case_id
        or inputs.qualification_report_sha256
        != qualification.report_sha256
        or canary.report.get("qualification_report_sha256")
        != qualification.report_sha256
        or canary.report.get("status") != "PASS"
        or canary.candidate is None
        or canary.runtime_observation is None
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:input_artifact_binding_invalid"
        )
    return qualification, inputs, canary


def _ticket_program(
    qualification: rehearsal.QualificationArtifact,
    inputs: governed_inputs.Issue94GovernedInputsArtifact,
    canary: route_canary.RouteCanaryArtifact,
    *,
    root_task_id: str,
    run_id: str,
    attempt_id: str,
) -> dict[str, Any]:
    plan = inputs.logical_plan
    workers = plan["workers"]
    writable_scope = sorted(
        {
            str(resource)
            for worker in workers
            for resource in worker["owned_resources"]
        }
    )
    ticket_spec = {
        "ticket_id": "issue-94",
        "qualification_target": qualification.report[
            "qualification_payload"
        ]["attempt"]["qualification_target"],
        "qualification_report_sha256": qualification.report_sha256,
        "governed_inputs_report_sha256": inputs.report_sha256,
        "canary_report_sha256": canary.report_sha256,
    }
    authority_scope = {
        "available": True,
        "provider_free": True,
        "writable_scope": list(writable_scope),
        "hosted_calls": 0,
        "model_calls": 0,
    }
    invocation_identity = {
        "surface": "fresh-local-task",
        "run_id": run_id,
        "attempt_id": attempt_id,
        "qualification_attempt_sha256": qualification.report[
            "qualification_payload"
        ]["attempt_sha256"],
        "route_canary_report_sha256": canary.report_sha256,
    }
    classification = {
        "mode": "orchestrated",
        "evidence": {
            "attempted_decomposition": (
                "Standards and Spec are disjoint read-only review lanes"
            ),
            "authority_available": True,
            "ownership_available": True,
        },
    }
    candidate_lanes = [
        {
            "lane_id": worker["id"],
            "objective": worker["objective"],
            "owned_resources": list(worker["owned_resources"]),
        }
        for worker in workers
    ]
    return ticket_admission.build_ticket_admission_program(
        ticket_id="issue-94",
        ticket_spec=ticket_spec,
        acceptance_criteria=list(plan["acceptance_criteria"]),
        authority_scope=authority_scope,
        writable_scope=writable_scope,
        root_task_id=root_task_id,
        invocation_identity=invocation_identity,
        classification=classification,
        candidate_lanes=candidate_lanes,
    )


def _sealed_stage_report(kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        "schema": "orch-dork/qualification-pre-spawn-stage-evidence/v1",
        "kind": kind,
        "status": "PASS",
        "closed": True,
        "payload": deepcopy(dict(payload)),
    }
    return {**core, "report_sha256": _sha(core)}


def _persist_stage_evidence(
    evidence_root: Path,
    *,
    case_id: str,
    attempt_id: str,
    reports: Mapping[str, Mapping[str, Any]],
    worker_ids: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    prefix = _sha(
        {"case_id": case_id, "attempt_id": attempt_id}
    )[:20]
    component_rows: list[dict[str, Any]] = []
    manifest_rows: list[dict[str, Any]] = []
    worker_kinds = {"spawn", "custody", "graph"}
    for kind in admission_kernel.COMPONENT_ORDER:
        report = reports.get(kind)
        if not isinstance(report, Mapping):
            raise QualificationPreSpawnError(
                "pre_spawn:evidence_missing:" + kind
            )
        value = deepcopy(dict(report))
        if (
            value.get("schema")
            != "orch-dork/qualification-pre-spawn-stage-evidence/v1"
            or value.get("kind") != kind
            or value.get("status") != "PASS"
            or value.get("closed") is not True
            or value.get("report_sha256")
            != _sha(
                {
                    key: deepcopy(child)
                    for key, child in value.items()
                    if key != "report_sha256"
                }
            )
        ):
            raise QualificationPreSpawnError(
                "pre_spawn:evidence_invalid:" + kind
            )
        filename = "pre-spawn-" + prefix + "-" + kind + ".json"
        path = evidence_root / filename
        payload = _canonical(value) + b"\n"
        rehearsal._write_create_only(path, payload)
        persisted = rehearsal._artifact_bytes(path)
        if persisted != payload:
            raise QualificationPreSpawnError(
                "pre_spawn:evidence_readback_mismatch:" + kind
            )
        source_sha256 = hashlib.sha256(payload).hexdigest()
        component_payload: dict[str, Any] = {
            "evidence_report_sha256": value["report_sha256"],
            "worker_ids": (
                list(worker_ids) if kind in worker_kinds else []
            ),
        }
        if kind == "spawn":
            component_payload["terminal_worker_ids"] = []
        component_rows.append(
            {
                "kind": kind,
                "producer": "qualification-pre-spawn-" + kind,
                "source_locator": "evidence:" + filename,
                "source_sha256": source_sha256,
                "evidence_tier": "runtime-observed-sanitized",
                "status": "PASS",
                "payload": component_payload,
            }
        )
        manifest_rows.append(
            {
                "kind": kind,
                "path": filename,
                "source_sha256": source_sha256,
                "report_sha256": value["report_sha256"],
            }
        )
    core = {
        "schema": "orch-dork/qualification-pre-spawn-evidence-manifest/v1",
        "case_id": case_id,
        "attempt_id": attempt_id,
        "components": manifest_rows,
    }
    return component_rows, {**core, "manifest_sha256": _sha(core)}


def _component_evidence_from_manifest(
    manifest: Mapping[str, Any],
    *,
    worker_ids: list[str],
) -> list[dict[str, Any]]:
    components = manifest.get("components")
    if not isinstance(components, list):
        raise QualificationPreSpawnError(
            "pre_spawn_artifact:evidence_manifest_invalid"
        )
    by_kind = {
        str(row.get("kind")): row
        for row in components
        if isinstance(row, Mapping)
    }
    rows: list[dict[str, Any]] = []
    worker_kinds = {"spawn", "custody", "graph"}
    for kind in admission_kernel.COMPONENT_ORDER:
        row = by_kind.get(kind)
        if not isinstance(row, Mapping):
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:evidence_manifest_invalid"
            )
        payload: dict[str, Any] = {
            "evidence_report_sha256": row["report_sha256"],
            "worker_ids": list(worker_ids) if kind in worker_kinds else [],
        }
        if kind == "spawn":
            payload["terminal_worker_ids"] = []
        rows.append(
            {
                "kind": kind,
                "producer": "qualification-pre-spawn-" + kind,
                "source_locator": "evidence:" + str(row["path"]),
                "source_sha256": row["source_sha256"],
                "evidence_tier": "runtime-observed-sanitized",
                "status": "PASS",
                "payload": payload,
            }
        )
    return rows


def _read_stage_evidence(
    manifest: Any,
    evidence_root: Path,
    *,
    case_id: str,
    attempt_id: str,
) -> dict[str, dict[str, Any]]:
    manifest_fields = {
        "schema",
        "case_id",
        "attempt_id",
        "components",
        "manifest_sha256",
    }
    if not isinstance(manifest, Mapping) or set(manifest) != manifest_fields:
        raise QualificationPreSpawnError(
            "pre_spawn_artifact:evidence_manifest_invalid"
        )
    value = deepcopy(dict(manifest))
    components = value.get("components")
    core = {
        key: deepcopy(child)
        for key, child in value.items()
        if key != "manifest_sha256"
    }
    if (
        value.get("schema")
        != "orch-dork/qualification-pre-spawn-evidence-manifest/v1"
        or value.get("case_id") != case_id
        or value.get("attempt_id") != attempt_id
        or not isinstance(components, list)
        or len(components) != len(admission_kernel.COMPONENT_ORDER)
        or value.get("manifest_sha256") != _sha(core)
    ):
        raise QualificationPreSpawnError(
            "pre_spawn_artifact:evidence_manifest_invalid"
        )
    reports: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    row_fields = {"kind", "path", "source_sha256", "report_sha256"}
    prefix = _sha(
        {"case_id": case_id, "attempt_id": attempt_id}
    )[:20]
    for expected_kind, raw in zip(
        admission_kernel.COMPONENT_ORDER,
        components,
    ):
        if not isinstance(raw, Mapping) or set(raw) != row_fields:
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:evidence_manifest_invalid"
            )
        row = dict(raw)
        relative = row.get("path")
        if (
            row.get("kind") != expected_kind
            or not isinstance(relative, str)
            or relative
            != "pre-spawn-" + prefix + "-" + expected_kind + ".json"
            or Path(relative).name != relative
            or relative in seen_paths
            or not _is_sha(row.get("source_sha256"))
            or not _is_sha(row.get("report_sha256"))
        ):
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:evidence_manifest_invalid"
            )
        seen_paths.add(relative)
        try:
            payload = rehearsal._artifact_bytes(evidence_root / relative)
            report = json.loads(payload)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:evidence_unavailable:" + expected_kind
            ) from error
        report_core = (
            {
                key: deepcopy(child)
                for key, child in report.items()
                if key != "report_sha256"
            }
            if isinstance(report, Mapping)
            else {}
        )
        if (
            hashlib.sha256(payload).hexdigest() != row["source_sha256"]
            or not isinstance(report, Mapping)
            or set(report)
            != {"schema", "kind", "status", "closed", "payload", "report_sha256"}
            or report.get("schema")
            != "orch-dork/qualification-pre-spawn-stage-evidence/v1"
            or report.get("kind") != expected_kind
            or report.get("status") != "PASS"
            or report.get("closed") is not True
            or report.get("report_sha256") != row["report_sha256"]
            or report.get("report_sha256") != _sha(report_core)
        ):
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:evidence_invalid:" + expected_kind
            )
        reports[expected_kind] = deepcopy(dict(report))
    return reports


def _semantic_evidence(
    ticket: Mapping[str, Any],
    plan_report: Mapping[str, Any],
    closure_report: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        closure_report.get("status") != "PASS"
        or closure_report.get("closed") is not True
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:semantic_evidence_invalid"
        )
    core = {
        "schema": "orch-dork/qualification-pre-spawn-semantic-evidence/v1",
        "status": "PASS",
        "closed": True,
        "ticket_admission_sha256": ticket["admission_sha256"],
        "logical_plan_report": deepcopy(dict(plan_report)),
        "closure_report": deepcopy(dict(closure_report)),
    }
    return {**core, "report_sha256": _sha(core)}


def _stage_reports(
    qualification: rehearsal.QualificationArtifact,
    inputs: governed_inputs.Issue94GovernedInputsArtifact,
    canary: route_canary.RouteCanaryArtifact,
    *,
    wave_program: Mapping[str, Any],
    wave_report: Mapping[str, Any],
    semantic_evidence: Mapping[str, Any],
    readiness_report: Mapping[str, Any],
    activation_preparation_report: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    return {
        "inventory": _sealed_stage_report(
            "inventory",
            {
                "runtime_module_root": qualification.report[
                    "runtime_module_root"
                ],
                "runtime_projected": qualification.report[
                    "runtime_projected"
                ],
                "structural_qualification_report": deepcopy(
                    qualification.structural_qualification_report
                ),
            },
        ),
        "native_receipt": _sealed_stage_report(
            "native_receipt",
            {
                "canary_report": deepcopy(canary.report),
                "runtime_observation": deepcopy(canary.runtime_observation),
            },
        ),
        "spawn": _sealed_stage_report(
            "spawn",
            {
                "wave_program": deepcopy(dict(wave_program)),
                "wave_report": deepcopy(dict(wave_report)),
            },
        ),
        "custody": _sealed_stage_report(
            "custody",
            {
                "governed_inputs_report": deepcopy(inputs.report),
                "closure_report": deepcopy(inputs.closure_report),
            },
        ),
        "graph": _sealed_stage_report(
            "graph",
            {
                "semantic_evidence": deepcopy(dict(semantic_evidence)),
                "logical_plan": deepcopy(wave_program["logical_plan"]),
            },
        ),
        "capability": _sealed_stage_report(
            "capability",
            {
                "execution_readiness_report": deepcopy(
                    dict(readiness_report)
                ),
                "activation_preparation_report": deepcopy(
                    dict(activation_preparation_report)
                ),
            },
        ),
    }


def _workspace_observation(
    source_root: Path,
    source_paths: tuple[str, ...],
) -> tuple[dict[str, Any], str]:
    def git_output(*arguments: str) -> bytes:
        completed = subprocess.run(
            ["git", "-C", str(source_root), *arguments],
            env={"PATH": os.environ.get("PATH", "")},
            capture_output=True,
            timeout=5,
            check=False,
        )
        if (
            completed.returncode != 0
            or completed.stderr
            or len(completed.stdout) > 1_048_576
        ):
            raise QualificationPreSpawnError(
                "pre_spawn:workspace_observation_failed"
            )
        return completed.stdout

    def nul_paths(*arguments: str) -> set[str]:
        try:
            return {
                value.decode("utf-8")
                for value in git_output(*arguments).split(b"\0")
                if value
            }
        except UnicodeError as error:
            raise QualificationPreSpawnError(
                "pre_spawn:workspace_path_invalid"
            ) from error

    dirty_paths = sorted(
        nul_paths("diff", "--name-only", "-z", "--")
        | nul_paths("diff", "--cached", "--name-only", "-z", "--")
        | nul_paths(
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
        )
    )
    try:
        head = git_output("rev-parse", "--verify", "HEAD").decode(
            "ascii"
        ).strip()
    except UnicodeError as error:
        raise QualificationPreSpawnError(
            "pre_spawn:workspace_head_invalid"
        ) from error
    if not re.fullmatch(r"[0-9a-f]{40,64}", head):
        raise QualificationPreSpawnError(
            "pre_spawn:workspace_head_invalid"
        )
    rows = []
    for relative in sorted(set(source_paths) | {
        ".orch-dork/binding.json",
        "hooks/hooks.json",
        "hooks/project_ground_hook.py",
        "scripts/orch_dork_self_project_adapter.py",
    }):
        path = (source_root / relative).resolve(strict=True)
        try:
            path.relative_to(source_root)
        except ValueError as error:
            raise QualificationPreSpawnError(
                "pre_spawn:workspace_path_escape"
            ) from error
        rows.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    baseline = _sha({"git_head": head, "observed_files": rows})
    return (
        {
            "status": "known",
            "workspace_root": str(source_root),
            "baseline_sha256": baseline,
            "dirty_paths": dirty_paths,
            "source_pointer": "git:HEAD+index+worktree+untracked",
        },
        baseline,
    )


def _build_project_ground(
    qualification: rehearsal.QualificationArtifact,
    inputs: governed_inputs.Issue94GovernedInputsArtifact,
    source_root: Path,
    *,
    enrollment: ActiveProjectEnrollmentArtifact,
    ticket_program: Mapping[str, Any],
    ticket: Mapping[str, Any],
    plan_report: Mapping[str, Any],
    readiness_report: Mapping[str, Any],
    capsule_report: Mapping[str, Any],
    identity: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    source_activation = qualification.report["stages"][
        "activation_preparation"
    ]["report"]
    if native_controller.validate_activation_preparation_report(
        source_activation
    ) != {"valid": True, "issues": []}:
        raise QualificationPreSpawnError(
            "pre_spawn:source_activation_invalid"
        )
    payload = deepcopy(source_activation["prepared_activation_payload"])
    plan = inputs.logical_plan
    version = str(plan["generation"]["installed_version"])
    workspace, workspace_sha256 = _workspace_observation(
        source_root,
        inputs.source_paths,
    )
    adapter_path = source_root / "scripts/orch_dork_self_project_adapter.py"
    hook_path = source_root / "hooks/project_ground_hook.py"
    registration_path = source_root / "hooks/hooks.json"
    binding_sha256 = enrollment.manifest_sha256
    adapter_sha256 = hashlib.sha256(adapter_path.read_bytes()).hexdigest()
    hook_sha256 = hashlib.sha256(hook_path.read_bytes()).hexdigest()
    registration_sha256 = hashlib.sha256(
        registration_path.read_bytes()
    ).hexdigest()
    binding = deepcopy(enrollment.report["current_manifest"])
    if (
        binding.get("project_id") != plan["project"]["project_id"]
        or binding.get("binding_generation")
        != plan["project"]["binding_generation"]
        or binding.get("adapter_sha256") != adapter_sha256
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:project_binding_invalid"
        )

    authority_scope_sha256 = ticket["identity"][
        "authority_scope_sha256"
    ]
    writable_scope_sha256 = ticket["identity"][
        "writable_scope_sha256"
    ]
    configuration = {
        "binding_manifest_sha256": binding_sha256,
        "native_adapter_sha256": adapter_sha256,
        "plan_sha256": plan_report["plan_sha256"],
        "readiness_receipt_sha256": readiness_report["receipt_sha256"],
    }
    adapter_definition = {
        "schema": project_adapter.ADAPTER_SCHEMA,
        "adapter_id": "orch-dork-source-adapter",
        "version": "binding-" + str(binding["binding_generation"]),
        "project_kind": "coding",
        "configuration": configuration,
        "configuration_sha256": project_adapter._sha256(configuration),
        "workspace_root": str(source_root),
        "focused_verification": [
            {
                "verification_id": "qualification-rehearsal",
                "kind": "command",
                "argv": [
                    "python3",
                    "-B",
                    "-m",
                    "unittest",
                    "tests.test_orch_dork_qualification_rehearsal",
                ],
                "target_pointer": "workspace",
                "source_pointer": "AGENTS.md#required-sync-loop",
            }
        ],
        "final_verification": [
            {
                "verification_id": "full-suite",
                "kind": "command",
                "argv": [
                    "python3",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tests",
                ],
                "target_pointer": "workspace",
                "source_pointer": "AGENTS.md#push-only-when-green",
            }
        ],
        "protected_resources": [
            ".orch-dork/binding.json",
            "hooks/hooks.json",
            "hooks/project_ground_hook.py",
        ],
        "workspace_baseline": {
            "required": True,
            "algorithm": "sha256",
            "dirty_policy": "preserve",
            "source_pointer": "qualification-pre-spawn#workspace-policy",
        },
        "external_systems": [],
        "approval_checkpoints": [],
        "source_pointer": ".orch-dork/binding.json#adapter",
    }
    boundary = {
        "sandbox_scope_sha256": writable_scope_sha256,
        "approval_policy": "never",
        "external_action_grants": [],
        "source_pointer": "qualification-pre-spawn#authority-boundary",
    }
    admission_events = [
        {
            "type": "ticket.claimed",
            "ticket_id": ticket["ticket_id"],
            "admission_sha256": ticket["admission_sha256"],
            "source_pointer": "qualification-pre-spawn#ticket-claimed",
        }
    ]
    adapter_program = project_adapter.build_pre_implementation_program(
        evaluation_id=str(qualification.report["case_id"])
        + "-project-adapter",
        adapter_definition=adapter_definition,
        authority_boundary={
            "root": boundary,
            "delegated": deepcopy(boundary),
            "source_pointer": "qualification-pre-spawn#boundary-comparison",
        },
        workspace_observation=workspace,
        ticket_program=ticket_program,
        ticket_admission=ticket,
        admission_events=admission_events,
    )
    adapter_report = project_adapter.evaluate_project_adapter(adapter_program)
    if (
        adapter_report.get("status") != "PASS"
        or adapter_report.get("implementation_permitted") is not True
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:project_adapter_invalid:"
            + ";".join(
                adapter_report.get("blockers", [])
                + adapter_report.get("issues", [])
            )
        )

    task_specs = deepcopy(
        qualification.report["qualification_payload"]["task_specs"]
    )
    ground_identity = payload["identity"]
    ground_identity.update(
        {
            "project_id": plan["project"]["project_id"],
            "enrollment_generation": plan["project"][
                "binding_generation"
            ],
            "installed_plugin_version": version,
            "ticket_id": ticket["ticket_id"],
            "admission_sha256": ticket["admission_sha256"],
            "authority_scope_sha256": authority_scope_sha256,
            "root_thread_id": identity["root_task_id"],
            # A Local app-server task's startup hook session is the thread id.
            # Keep that observed identity intact so the post-start controller
            # binding matches the successor's first real tool event.
            "root_session_id": identity["root_task_id"],
            "run_id": identity["run_id"],
            "attempt_id": identity["attempt_id"],
            "root_model": identity["root_model"],
            "root_effort": identity["root_effort"],
            "source_version": version,
            "task_loaded_version": version,
            "fresh_task": True,
            "plan_sha256": plan_report["plan_sha256"],
            "task_specs_sha256": (
                native_controller.task_specs_identity_sha256(task_specs)
            ),
            "hook_definition_sha256": hook_sha256,
            "hook_registration_sha256": registration_sha256,
            "native_adapter_sha256": (
                native_controller.CLOSED_NATIVE_ACTION_ADAPTER_SHA256
            ),
        }
    )
    payload["enrollment_program"] = deepcopy(enrollment.program)
    payload["hook_trust_receipt_sha256"] = (
        unmaterialized_hook_trust_sha256(
            hook_sha256,
            registration_sha256,
        )
    )
    payload["task_specs"] = task_specs
    ground_record = payload["project_ground_state"]
    program = ground_record["program"]
    program["event"].update(
        {
            "session_id": ground_identity["root_session_id"],
            "cwd": str(source_root),
            "model": identity["root_model"],
            "source": "startup",
        }
    )
    program["state"]["lifecycle"]["resumed"] = False
    program["state"]["hook"].update(
        {
            "expected_sha256": hook_sha256,
            "observed_sha256": hook_sha256,
        }
    )
    prerequisites = program["state"]["prerequisites"]
    prerequisites["ticket_admission"].update(
        {
            "status": "PASS",
            "decision": ticket["decision"],
            "ticket_id": ticket["ticket_id"],
            "admission_sha256": ticket["admission_sha256"],
            "implementation_permitted": False,
            "plan_sha256": plan_report["plan_sha256"],
        }
    )
    prerequisites["enrollment"].update(
        {
            "status": "PASS",
            "decision": "ACTIVE",
            "project_id": plan["project"]["project_id"],
            "generation": plan["project"]["binding_generation"],
            "manifest_sha256": enrollment.manifest_sha256,
            "record_sha256": enrollment.record_sha256,
        }
    )
    prerequisites["adapter"] = {
        "status": "BLOCKED",
        "decision": "DENY",
        "snapshot_sha256": None,
        "report_sha256": None,
    }
    prerequisites["execution_readiness"] = {
        "status": "PASS",
        "report_sha256": readiness_report["receipt_sha256"],
    }
    prerequisites["lease"].update(
        {
            "status": "active_successor",
            "version": 1,
            "owner_thread_id": identity["root_task_id"],
            "current_thread_id": identity["root_task_id"],
            "checkpoint_sha256": _sha(
                {
                    "root_task_id": identity["root_task_id"],
                    "plan_sha256": plan_report["plan_sha256"],
                }
            ),
            "cas_valid": True,
        }
    )
    prerequisites["active_controller"] = {
        "status": "PASS",
        "report_sha256": hashlib.sha256(
            Path(native_controller.__file__).read_bytes()
        ).hexdigest(),
    }
    prerequisites["capsule"] = {
        "status": "PASS",
        "capsule_sha256": capsule_report["capsule_sha256"],
    }
    prerequisites["authority"] = {
        "scope_sha256": authority_scope_sha256,
        "writable_scope_sha256": writable_scope_sha256,
        "grants_sha256": _sha([]),
        "narrowed": True,
    }
    prerequisites["workspace"] = {
        "baseline_sha256": workspace_sha256,
        "current_sha256": workspace_sha256,
        "baseline_valid": True,
    }
    program["state"]["sandbox"].update(
        {
            "status": "PASS",
            "profile": "narrow-local",
            "writable_roots": [str(source_root)],
            "source_pointer": "qualification-pre-spawn#sandbox",
        }
    )
    ground_record["program_sha256"] = ground_enforcement._sha(program)
    preparation_program = (
        native_controller
        .build_governed_native_activation_preparation_program(
            activation_payload=payload,
            project_adapter_report=adapter_report,
        )
    )
    preparation_report = native_controller.prepare_governed_native_activation(
        preparation_program
    )
    if (
        native_controller.validate_activation_preparation_report(
            preparation_report
        )
        != {"valid": True, "issues": []}
        or preparation_report.get("decision") != "READY_FOR_ACTIVATION"
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:activation_preparation_invalid:"
            + ";".join(preparation_report.get("issues", []))
        )
    prepared_ground = preparation_report["prepared_activation_payload"][
        "project_ground_state"
    ]["program"]
    return (
        adapter_program,
        adapter_report,
        preparation_report,
        deepcopy(prepared_ground),
    )


def _attempt_reservation(plan, case_id, *, checkpoint_lifecycle):
    """Freeze one declared lifecycle without inferring live consumption or dollars."""
    limits = {"max_sol_ingress_tokens": 8_000, "max_total_tokens": 40_000,
              "max_tool_calls": 10 if checkpoint_lifecycle else 8}
    if not checkpoint_lifecycle:
        return limits, governor.build_budget_reservation_program(
            plan, program_id=case_id + "-budget", max_total_tokens=limits["max_total_tokens"]), {}
    import orch_dork_qualification_progress as progress
    import orch_dork_qualification_budget as accounting
    # Eight native actions and the checkpoint/review MCP calls comprise the
    # closed trace. One response per call plus two root turn completions gives
    # a separate response ceiling; token weights are expressly non-monetary.
    policy = accounting.build_checkpoint_accounting_policy(
        max_root_responses=limits["max_tool_calls"] + 2, root_model=plan["planner"]["model"])
    budget = progress.build_checkpoint_reservation_program(
        plan, program_id=case_id + "-budget", max_total_tokens=limits["max_total_tokens"],
        root_token_reserve=20_000, accounting_policy=policy,
    )
    return limits, budget, {"require_worker_checkpoint": True,
        "checkpoint_reservation_profile": progress.RESERVATION_PROFILE,
        "checkpoint_accounting_policy": policy}


def _attempt_bound_plan(
    inputs: governed_inputs.Issue94GovernedInputsArtifact,
    *,
    root_task_id: str,
    case_id: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a validated plan rebound to the fresh attempt root."""
    plan = deepcopy(inputs.logical_plan)
    plan["planner"]["root_thread_id"] = root_task_id
    plan = governed_inputs.rebind_artifact_plan(plan, case_id=case_id)
    plan_report = governed_inputs._validate_artifact_plan(
        plan,
        case_id=case_id,
    )
    if plan_report.get("status") != "PASS":
        raise QualificationPreSpawnError("pre_spawn:logical_plan_invalid")
    return plan, plan_report


def _build_report(
    qualification: rehearsal.QualificationArtifact,
    inputs: governed_inputs.Issue94GovernedInputsArtifact,
    canary: route_canary.RouteCanaryArtifact,
    source_root: Path,
    evidence_root: Path,
    enrollment_registry_root: Path,
    *,
    root_task_id: str,
    now: datetime,
    checkpoint_lifecycle: bool = False,
) -> dict[str, Any]:
    enrollment = ActiveProjectEnrollmentArtifact.from_roots(
        source_root,
        enrollment_registry_root,
    )
    plan, plan_report = _attempt_bound_plan(
        inputs,
        root_task_id=root_task_id,
        case_id=qualification.report.get("case_id"),
    )
    case_id = str(qualification.report["case_id"])
    run_id = root_task_id + "-issue94-run"
    attempt_id = root_task_id + "-issue94-attempt"
    version = str(plan["generation"]["installed_version"])
    identity = {
        "run_id": run_id,
        "attempt_id": attempt_id,
        "root_task_id": root_task_id,
        "root_model": plan["planner"]["model"],
        "root_effort": plan["planner"]["effort"],
        "source_version": version,
        "installed_version": version,
        "task_loaded_version": version,
        "fresh_task": True,
    }

    ticket_program = _ticket_program(
        qualification,
        inputs,
        canary,
        root_task_id=root_task_id,
        run_id=run_id,
        attempt_id=attempt_id,
    )
    ticket = ticket_admission.evaluate_ticket_admission(ticket_program)
    ticket_validation = ticket_admission.validate_decision(ticket)
    if (
        not ticket_validation.get("valid")
        or ticket.get("decision")
        != ticket_admission.ORCHESTRATION_PLAN_REQUIRED
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:ticket_admission_invalid"
        )

    acceptance_sha256 = ticket["identity"][
        "acceptance_criteria_sha256"
    ]
    capsule_program = coordinator_capsule.build_initialization_program(
        capsule_id=case_id + "-coordinator-capsule",
        ticket_id=str(ticket["ticket_id"]),
        acceptance_sha256=str(acceptance_sha256),
        admission_sha256=str(ticket["admission_sha256"]),
        plan_sha256=str(plan_report["plan_sha256"]),
        root_task_id=root_task_id,
        source_version=version,
        installed_version=version,
        worker_ids=[str(row["id"]) for row in plan["workers"]],
    )
    capsule_report = coordinator_capsule.evaluate_coordinator_capsule(
        capsule_program
    )
    if (
        capsule_report.get("status") != "PASS"
        or not _is_sha(capsule_report.get("capsule_sha256"))
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:coordinator_capsule_invalid"
        )

    readiness_root = evidence_root / (
        "readiness-" + _sha({"attempt_id": attempt_id})[:20]
    )
    readiness_program = (
        execution_readiness.run_provider_free_readiness_program(
            source_root=Path(__file__).resolve().parents[3],
            temporary_root=readiness_root,
            readiness_id=case_id + "-execution-readiness",
            attempt_id=attempt_id,
            plan_sha256=plan_report["plan_sha256"],
            authority_scope_sha256=ticket["identity"][
                "authority_scope_sha256"
            ],
        )
    )
    readiness_report = execution_readiness.evaluate_execution_readiness(
        readiness_program
    )
    if readiness_report.get("status") != "READY_FOR_AUTHORITY":
        raise QualificationPreSpawnError(
            "pre_spawn:execution_readiness_invalid:"
            + ";".join(readiness_report.get("issues", []))
        )

    (
        adapter_program,
        adapter_report,
        activation_preparation_report,
        ground_program,
    ) = _build_project_ground(
        qualification,
        inputs,
        source_root,
        enrollment=enrollment,
        ticket_program=ticket_program,
        ticket=ticket,
        plan_report=plan_report,
        readiness_report=readiness_report,
        capsule_report=capsule_report,
        identity=identity,
    )
    attempt_limits, budget_program, checkpoint_options = _attempt_reservation(
        plan, case_id, checkpoint_lifecycle=checkpoint_lifecycle,
    )
    wave_program = governor.build_wave_v3_preflight_program(
        plan,
        program_id=case_id + "-wave",
        task_specs=qualification.report["qualification_payload"][
            "task_specs"
        ],
        canary_task_spec=qualification.report["qualification_payload"][
            "canary_task_spec"
        ],
        candidate=canary.candidate,
        runtime_observation=canary.runtime_observation,
    )
    wave_report = governor.run_wave_program(wave_program)
    if (
        wave_report.get("status") != "WAITING"
        or wave_report.get("spawn_permitted") is not True
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:wave_preflight_invalid:"
            + ";".join(wave_report.get("issues", []))
        )
    semantic_evidence = _semantic_evidence(
        ticket,
        plan_report,
        inputs.closure_report,
    )
    stage_reports = _stage_reports(
        qualification,
        inputs,
        canary,
        wave_program=wave_program,
        wave_report=wave_report,
        semantic_evidence=semantic_evidence,
        readiness_report=readiness_report,
        activation_preparation_report=activation_preparation_report,
    )
    worker_ids = [str(row["id"]) for row in plan["workers"]]
    component_evidence, evidence_manifest = _persist_stage_evidence(
        evidence_root,
        case_id=case_id,
        attempt_id=attempt_id,
        reports=stage_reports,
        worker_ids=worker_ids,
    )
    projection = governed_attempt.build_admission_plan_projection(plan)
    hard_program = admission_kernel.build_observed_admission_program(
        attempt_id=attempt_id,
        root_task_id=root_task_id,
        ticket_id=str(ticket["ticket_id"]),
        ticket_spec=ticket_program["ticket_spec"],
        acceptance_criteria=ticket_program["acceptance_criteria"],
        authority_scope=ticket_program["authority_scope"],
        writable_scope=ticket_program["writable_scope"],
        installed_identity={
            "generation": deepcopy(plan["generation"]),
            "runtime_module_root": qualification.report[
                "runtime_module_root"
            ],
            "runtime_projected": qualification.report[
                "runtime_projected"
            ],
            "installed_version": version,
        },
        instructions={
            "boundary": deepcopy(qualification.report["boundary"]),
            "approval_preflight_report": deepcopy(
                qualification.approval_preflight_report
            ),
        },
        invocation_identity=ticket_program["invocation_identity"],
        repository_inventory={
            "source_paths": list(inputs.source_paths),
            "research_manifest_sha256": inputs.research_manifest_sha256,
        },
        source_identity={
            "workspace_root": str(source_root),
            "workspace_root_sha256": plan["project"][
                "workspace_root_sha256"
            ],
        },
        plan=projection,
        component_evidence=component_evidence,
        source_roots={"evidence": evidence_root},
        semantic_evidence=semantic_evidence,
        observed_at=now,
    )
    hard_report = admission_kernel.evaluate_admission_kernel(
        hard_program,
        source_roots={"evidence": evidence_root},
        now=now,
    )
    if hard_report.get("decision") != admission_kernel.ADMIT:
        raise QualificationPreSpawnError(
            "pre_spawn:hard_admission_invalid:"
            + ";".join(hard_report.get("reasons", []))
        )
    pre_spawn_program = governed_attempt.build_pre_spawn_program(
        identity,
        ticket_admission=ticket,
        hard_admission=hard_program,
        logical_plan=plan,
        wave_preflight=wave_program,
        budget_program=budget_program,
        execution_readiness=readiness_program,
        project_ground=ground_program,
        coordinator_capsule=capsule_program,
        research_manifest=inputs.research_manifest,
        attempt_limits=attempt_limits,
        **checkpoint_options,
    )
    pre_spawn_report = governed_attempt.evaluate_governed_attempt(
        pre_spawn_program,
        source_roots={"evidence": evidence_root},
        now=now,
    )
    if (
        pre_spawn_report.get("status") != "PASS"
        or pre_spawn_report.get("disposition")
        != "SHARED_CAPACITY_ADMISSION_REQUIRED"
        or len(pre_spawn_report.get("stages", [])) != 12
        or any(
            row.get("status") != "PASS"
            for row in pre_spawn_report.get("stages", [])
        )
    ):
        raise QualificationPreSpawnError(
            "pre_spawn:governed_attempt_refused:"
            + ";".join(pre_spawn_report.get("issues", []))
        )

    core = {
        "schema": CHECKPOINT_REPORT_SCHEMA if checkpoint_lifecycle else REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "case_id": case_id,
        "evaluation_time": _timestamp(now),
        "qualification_report_sha256": qualification.report_sha256,
        "governed_inputs_report_sha256": inputs.report_sha256,
        "canary_report_sha256": canary.report_sha256,
        "qualification_report": deepcopy(qualification.report),
        "governed_inputs_report": deepcopy(inputs.report),
        "canary_report": deepcopy(canary.report),
        "evidence_manifest": evidence_manifest,
        "ticket_admission_program": ticket_program,
        "ticket_admission": deepcopy(dict(ticket)),
        "hard_admission_program": hard_program,
        "hard_admission_report": hard_report,
        "execution_readiness_program": readiness_program,
        "execution_readiness_report": readiness_report,
        "project_adapter_program": adapter_program,
        "project_adapter_report": adapter_report,
        "project_enrollment_program": deepcopy(enrollment.program),
        "project_enrollment_report": deepcopy(enrollment.report),
        "activation_preparation_report": activation_preparation_report,
        "pre_spawn_program": pre_spawn_program,
        "pre_spawn_report": pre_spawn_report,
        "counters": {name: 0 for name in _COUNTER_NAMES},
    }
    return {**core, "report_sha256": _sha(core)}


@dataclass(frozen=True, slots=True)
class Issue94PreSpawnArtifact:
    """Strict whole-report access to one provider-free pre-spawn result."""

    report: dict[str, Any]
    report_sha256: str
    status: str
    qualification_report: dict[str, Any]
    governed_inputs_report: dict[str, Any]
    canary_report: dict[str, Any]
    evidence_manifest: dict[str, Any]
    ticket_admission_program: dict[str, Any]
    ticket_admission: dict[str, Any]
    hard_admission_program: dict[str, Any]
    hard_admission_report: dict[str, Any]
    execution_readiness_program: dict[str, Any]
    execution_readiness_report: dict[str, Any]
    project_adapter_program: dict[str, Any]
    project_adapter_report: dict[str, Any]
    project_enrollment_program: dict[str, Any]
    project_enrollment_report: dict[str, Any]
    activation_preparation_report: dict[str, Any]
    pre_spawn_program: dict[str, Any]
    pre_spawn_report: dict[str, Any]
    counters: dict[str, int]

    @classmethod
    def from_report(
        cls,
        report: Any,
        source_root: str | Path,
        evidence_root: str | Path,
        enrollment_registry_root: str | Path,
    ) -> "Issue94PreSpawnArtifact":
        report_value = report if isinstance(report, Mapping) else {}
        inputs_value = report_value.get("governed_inputs_report")
        plan = (
            inputs_value.get("logical_plan")
            if isinstance(inputs_value, Mapping)
            else None
        )
        with governed_inputs._artifact_plan_route(
            plan,
            case_id=report_value.get("case_id"),
        ):
            return cls._from_report_under_bound_route(
                report,
                source_root,
                evidence_root,
                enrollment_registry_root,
            )

    @classmethod
    def _from_report_under_bound_route(
        cls,
        report: Any,
        source_root: str | Path,
        evidence_root: str | Path,
        enrollment_registry_root: str | Path,
    ) -> "Issue94PreSpawnArtifact":
        if not isinstance(report, Mapping) or set(report) != _REPORT_FIELDS:
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        root = _source_root(source_root)
        evidence = _evidence_root(evidence_root)
        enrollment = ActiveProjectEnrollmentArtifact.from_roots(
            root,
            enrollment_registry_root,
        )
        if (
            value.get("schema") not in (REPORT_SCHEMA, CHECKPOINT_REPORT_SCHEMA)
            or value.get("status") != "PASS"
            or value.get("issues") != []
            or not isinstance(value.get("case_id"), str)
            or any(
                not _is_sha(value.get(name))
                for name in (
                    "qualification_report_sha256",
                    "governed_inputs_report_sha256",
                    "canary_report_sha256",
                    "report_sha256",
                )
            )
            or not isinstance(value.get("counters"), Mapping)
            or set(value["counters"]) != set(_COUNTER_NAMES)
            or any(value["counters"].get(name) != 0 for name in _COUNTER_NAMES)
        ):
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:report_invalid"
            )
        now = _parse_timestamp(value["evaluation_time"])
        try:
            qualification = rehearsal.QualificationArtifact.from_report(
                value["qualification_report"]
            )
            inputs = governed_inputs.Issue94GovernedInputsArtifact.from_report(
                value["governed_inputs_report"],
                root,
            )
            canary = route_canary.RouteCanaryArtifact.from_report(
                value["canary_report"]
            )
            _require_input_artifacts(qualification, inputs, canary)
        except (KeyError, TypeError, ValueError) as error:
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:input_binding_invalid"
            ) from error
        if (
            value["qualification_report_sha256"]
            != qualification.report_sha256
            or value["governed_inputs_report_sha256"]
            != inputs.report_sha256
            or value["canary_report_sha256"] != canary.report_sha256
            or value["case_id"] != qualification.report["case_id"]
            or value["case_id"] != inputs.report["case_id"]
            or value["case_id"] != canary.report["case_id"]
        ):
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:input_binding_invalid"
            )
        ticket_program = value.get("ticket_admission_program")
        ticket = value.get("ticket_admission")
        hard_program = value.get("hard_admission_program")
        hard_report = value.get("hard_admission_report")
        readiness_program = value.get("execution_readiness_program")
        readiness_report = value.get("execution_readiness_report")
        adapter_program = value.get("project_adapter_program")
        adapter_report = value.get("project_adapter_report")
        enrollment_program = value.get("project_enrollment_program")
        enrollment_report = value.get("project_enrollment_report")
        activation_report = value.get("activation_preparation_report")
        pre_spawn_program = value.get("pre_spawn_program")
        pre_spawn_report = value.get("pre_spawn_report")
        if not all(
            isinstance(item, Mapping)
            for item in (
                ticket_program,
                ticket,
                hard_program,
                hard_report,
                readiness_program,
                readiness_report,
                adapter_program,
                adapter_report,
                enrollment_program,
                enrollment_report,
                activation_report,
                pre_spawn_program,
                pre_spawn_report,
            )
        ):
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:stage_shape_invalid"
            )
        root_task_id = ticket_program.get("root_task_id")
        if not isinstance(root_task_id, str) or not root_task_id:
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:stage_binding_invalid"
            )
        run_id = root_task_id + "-issue94-run"
        attempt_id = root_task_id + "-issue94-attempt"
        plan, plan_report = _attempt_bound_plan(
            inputs,
            root_task_id=root_task_id,
            case_id=value.get("case_id"),
        )
        version = str(plan["generation"]["installed_version"])
        identity = {
            "run_id": run_id,
            "attempt_id": attempt_id,
            "root_task_id": root_task_id,
            "root_model": plan["planner"]["model"],
            "root_effort": plan["planner"]["effort"],
            "source_version": version,
            "installed_version": version,
            "task_loaded_version": version,
            "fresh_task": True,
        }
        expected_ticket_program = _ticket_program(
            qualification,
            inputs,
            canary,
            root_task_id=root_task_id,
            run_id=run_id,
            attempt_id=attempt_id,
        )
        expected_ticket = ticket_admission.evaluate_ticket_admission(
            expected_ticket_program
        )
        ticket_validation = ticket_admission.validate_decision(ticket)
        acceptance_sha256 = expected_ticket["identity"][
            "acceptance_criteria_sha256"
        ]
        capsule_program = coordinator_capsule.build_initialization_program(
            capsule_id=str(value["case_id"]) + "-coordinator-capsule",
            ticket_id=str(expected_ticket["ticket_id"]),
            acceptance_sha256=str(acceptance_sha256),
            admission_sha256=str(expected_ticket["admission_sha256"]),
            plan_sha256=str(plan_report["plan_sha256"]),
            root_task_id=root_task_id,
            source_version=version,
            installed_version=version,
            worker_ids=[str(row["id"]) for row in plan["workers"]],
        )
        capsule_report = coordinator_capsule.evaluate_coordinator_capsule(
            capsule_program
        )
        expected_readiness = execution_readiness.evaluate_execution_readiness(
            readiness_program
        )
        (
            expected_adapter_program,
            expected_adapter_report,
            expected_activation_report,
            ground_program,
        ) = _build_project_ground(
            qualification,
            inputs,
            root,
            enrollment=enrollment,
            ticket_program=expected_ticket_program,
            ticket=expected_ticket,
            plan_report=plan_report,
            readiness_report=expected_readiness,
            capsule_report=capsule_report,
            identity=identity,
        )
        attempt_limits, budget_program, checkpoint_options = _attempt_reservation(
            plan, str(value["case_id"]), checkpoint_lifecycle=value["schema"] == CHECKPOINT_REPORT_SCHEMA,
        )
        wave_program = governor.build_wave_v3_preflight_program(
            plan,
            program_id=str(value["case_id"]) + "-wave",
            task_specs=qualification.report["qualification_payload"][
                "task_specs"
            ],
            canary_task_spec=qualification.report[
                "qualification_payload"
            ]["canary_task_spec"],
            candidate=canary.candidate,
            runtime_observation=canary.runtime_observation,
        )
        wave_report = governor.run_wave_program(wave_program)
        semantic_evidence = _semantic_evidence(
            expected_ticket,
            plan_report,
            inputs.closure_report,
        )
        expected_stage_reports = _stage_reports(
            qualification,
            inputs,
            canary,
            wave_program=wave_program,
            wave_report=wave_report,
            semantic_evidence=semantic_evidence,
            readiness_report=expected_readiness,
            activation_preparation_report=expected_activation_report,
        )
        observed_stage_reports = _read_stage_evidence(
            value["evidence_manifest"],
            evidence,
            case_id=str(value["case_id"]),
            attempt_id=attempt_id,
        )
        worker_ids = [str(row["id"]) for row in plan["workers"]]
        component_evidence = _component_evidence_from_manifest(
            value["evidence_manifest"],
            worker_ids=worker_ids,
        )
        expected_hard_program = (
            admission_kernel.build_observed_admission_program(
                attempt_id=attempt_id,
                root_task_id=root_task_id,
                ticket_id=str(expected_ticket["ticket_id"]),
                ticket_spec=expected_ticket_program["ticket_spec"],
                acceptance_criteria=expected_ticket_program[
                    "acceptance_criteria"
                ],
                authority_scope=expected_ticket_program["authority_scope"],
                writable_scope=expected_ticket_program["writable_scope"],
                installed_identity={
                    "generation": deepcopy(plan["generation"]),
                    "runtime_module_root": qualification.report[
                        "runtime_module_root"
                    ],
                    "runtime_projected": qualification.report[
                        "runtime_projected"
                    ],
                    "installed_version": version,
                },
                instructions={
                    "boundary": deepcopy(qualification.report["boundary"]),
                    "approval_preflight_report": deepcopy(
                        qualification.approval_preflight_report
                    ),
                },
                invocation_identity=expected_ticket_program[
                    "invocation_identity"
                ],
                repository_inventory={
                    "source_paths": list(inputs.source_paths),
                    "research_manifest_sha256": (
                        inputs.research_manifest_sha256
                    ),
                },
                source_identity={
                    "workspace_root": str(root),
                    "workspace_root_sha256": plan["project"][
                        "workspace_root_sha256"
                    ],
                },
                plan=governed_attempt.build_admission_plan_projection(plan),
                component_evidence=component_evidence,
                source_roots={"evidence": evidence},
                semantic_evidence=semantic_evidence,
                observed_at=now,
            )
        )
        expected_hard_report = admission_kernel.evaluate_admission_kernel(
            expected_hard_program,
            source_roots={"evidence": evidence},
            now=now,
        )
        expected_pre_spawn_program = governed_attempt.build_pre_spawn_program(
            identity,
            ticket_admission=expected_ticket,
            hard_admission=expected_hard_program,
            logical_plan=plan,
            wave_preflight=wave_program,
            budget_program=budget_program,
            execution_readiness=readiness_program,
            project_ground=ground_program,
            coordinator_capsule=capsule_program,
            research_manifest=inputs.research_manifest,
            attempt_limits=attempt_limits,
            **checkpoint_options,
        )
        expected_pre_spawn_report = governed_attempt.evaluate_governed_attempt(
            expected_pre_spawn_program,
            source_roots={"evidence": evidence},
            now=now,
        )
        checks = {
            "ticket_program_schema": (
                ticket_program.get("schema")
                == ticket_admission.PROGRAM_SCHEMA
            ),
            "ticket_program": dict(ticket_program)
            == expected_ticket_program,
            "ticket_report": dict(expected_ticket) == dict(ticket),
            "ticket_validation": bool(ticket_validation.get("valid")),
            "ticket_decision": (
                expected_ticket.get("decision")
                == ticket_admission.ORCHESTRATION_PLAN_REQUIRED
            ),
            "readiness_report": expected_readiness == readiness_report,
            "readiness_status": (
                readiness_report.get("status") == "READY_FOR_AUTHORITY"
            ),
            "adapter_program": dict(adapter_program)
            == expected_adapter_program,
            "adapter_report": dict(adapter_report)
            == expected_adapter_report,
            "enrollment_program": dict(enrollment_program)
            == enrollment.program,
            "enrollment_report": dict(enrollment_report)
            == enrollment.report,
            "activation_report": dict(activation_report)
            == expected_activation_report,
            "activation_validation": (
                native_controller.validate_activation_preparation_report(
                    activation_report
                )
                == {"valid": True, "issues": []}
            ),
            "stage_evidence": observed_stage_reports
            == expected_stage_reports,
            "hard_program": dict(hard_program) == expected_hard_program,
            "hard_report": dict(hard_report) == expected_hard_report,
            "hard_decision": (
                hard_report.get("decision") == admission_kernel.ADMIT
            ),
            "pre_spawn_program": dict(pre_spawn_program)
            == expected_pre_spawn_program,
            "pre_spawn_report": dict(pre_spawn_report)
            == expected_pre_spawn_report,
            "pre_spawn_status": pre_spawn_report.get("status") == "PASS",
            "pre_spawn_disposition": (
                pre_spawn_report.get("disposition")
                == "SHARED_CAPACITY_ADMISSION_REQUIRED"
            ),
            "pre_spawn_stages": (
                len(pre_spawn_report.get("stages", [])) == 12
                and all(
                    row.get("status") == "PASS"
                    for row in pre_spawn_report.get("stages", [])
                )
            ),
            "report_seal": value["report_sha256"]
            == _sha(
                {
                    key: deepcopy(child)
                    for key, child in value.items()
                    if key != "report_sha256"
                }
            ),
        }
        failed_checks = sorted(
            name for name, passed in checks.items() if not passed
        )
        if failed_checks:
            raise QualificationPreSpawnError(
                "pre_spawn_artifact:stage_binding_invalid:"
                + ",".join(failed_checks)
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            status=str(value["status"]),
            qualification_report=deepcopy(qualification.report),
            governed_inputs_report=deepcopy(inputs.report),
            canary_report=deepcopy(canary.report),
            evidence_manifest=deepcopy(dict(value["evidence_manifest"])),
            ticket_admission_program=deepcopy(dict(ticket_program)),
            ticket_admission=deepcopy(dict(ticket)),
            hard_admission_program=deepcopy(dict(hard_program)),
            hard_admission_report=deepcopy(dict(hard_report)),
            execution_readiness_program=deepcopy(dict(readiness_program)),
            execution_readiness_report=deepcopy(dict(readiness_report)),
            project_adapter_program=deepcopy(dict(adapter_program)),
            project_adapter_report=deepcopy(dict(adapter_report)),
            project_enrollment_program=deepcopy(
                dict(enrollment_program)
            ),
            project_enrollment_report=deepcopy(dict(enrollment_report)),
            activation_preparation_report=deepcopy(dict(activation_report)),
            pre_spawn_program=deepcopy(dict(pre_spawn_program)),
            pre_spawn_report=deepcopy(dict(pre_spawn_report)),
            counters={
                str(key): int(child)
                for key, child in value["counters"].items()
            },
        )


def build_issue94_pre_spawn_report(
    qualification: Any,
    inputs: Any,
    canary: Any,
    source_root: str | Path,
    *,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
    root_task_id: str,
    now: datetime | None = None,
    checkpoint_lifecycle: bool = False,
) -> dict[str, Any]:
    """Construct, evaluate, and seal the complete provider-free chain."""

    if type(checkpoint_lifecycle) is not bool:
        raise QualificationPreSpawnError("pre_spawn:checkpoint_profile_invalid")
    qualification, inputs, canary = _require_input_artifacts(
        qualification,
        inputs,
        canary,
    )
    root = _source_root(source_root)
    evidence = _evidence_root(evidence_root)
    registry = _enrollment_registry_root(enrollment_registry_root)
    evaluation_time = _parse_timestamp(
        _timestamp(now or datetime.now(timezone.utc))
    )
    with governed_inputs._artifact_plan_route(
        inputs.logical_plan,
        case_id=qualification.report.get("case_id"),
    ):
        report = _build_report(
            qualification,
            inputs,
            canary,
            root,
            evidence,
            registry,
            root_task_id=root_task_id,
            now=evaluation_time,
            checkpoint_lifecycle=checkpoint_lifecycle,
        )
        Issue94PreSpawnArtifact.from_report(
            report,
            root,
            evidence,
            registry,
        )
    return report


def read_issue94_pre_spawn_artifact(
    path: str | Path,
    source_root: str | Path,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
) -> Issue94PreSpawnArtifact:
    payload = rehearsal._artifact_bytes(Path(path))
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationPreSpawnError(
            "pre_spawn_artifact:json_invalid"
        ) from error
    return Issue94PreSpawnArtifact.from_report(
        value,
        source_root,
        evidence_root,
        enrollment_registry_root,
    )


def persist_issue94_pre_spawn_artifact(
    report: Any,
    output_path: str | Path,
    source_root: str | Path,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
) -> dict[str, Any]:
    artifact = Issue94PreSpawnArtifact.from_report(
        report,
        source_root,
        evidence_root,
        enrollment_registry_root,
    )
    output = Path(output_path)
    payload = _canonical(artifact.report) + b"\n"
    rehearsal._write_create_only(output, payload)
    persisted = read_issue94_pre_spawn_artifact(
        output,
        source_root,
        evidence_root,
        enrollment_registry_root,
    )
    if persisted.report != artifact.report:
        raise QualificationPreSpawnError(
            "pre_spawn_artifact:readback_mismatch"
        )
    core = {
        "schema": CHECKPOINT_RECEIPT_SCHEMA if persisted.report["schema"] == CHECKPOINT_REPORT_SCHEMA else RECEIPT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "case_id": persisted.report["case_id"],
        "artifact_path": str(output),
        "artifact_size_bytes": len(payload),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": persisted.report_sha256,
        "qualification_report_sha256": persisted.report[
            "qualification_report_sha256"
        ],
        "governed_inputs_report_sha256": persisted.report[
            "governed_inputs_report_sha256"
        ],
        "canary_report_sha256": persisted.report[
            "canary_report_sha256"
        ],
        "project_enrollment_program_sha256": _sha(
            persisted.project_enrollment_program
        ),
        "project_enrollment_report_sha256": (
            persisted.project_enrollment_report["report_sha256"]
        ),
        "ticket_admission_sha256": persisted.ticket_admission[
            "admission_sha256"
        ],
        "hard_admission_sha256": persisted.hard_admission_report[
            "admission_digest"
        ],
        "pre_spawn_receipt_sha256": persisted.pre_spawn_report[
            "receipt"
        ]["receipt_sha256"],
        "disposition": persisted.pre_spawn_report["disposition"],
        "counters": deepcopy(persisted.counters),
    }
    return {**core, "receipt_sha256": _sha(core)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build and persist the provider-free Issue 94 pre-spawn envelope."
        ),
        epilog=(
            "--source-root binds project and research ground; execution "
            "readiness observes this driver's own installed or projected "
            "package root. --evidence-root must already be private mode 0700."
        ),
    )
    parser.add_argument("--qualification-artifact", type=Path, required=True)
    parser.add_argument("--governed-inputs-artifact", type=Path, required=True)
    parser.add_argument("--canary-artifact", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--enrollment-registry-root",
        type=Path,
        required=True,
    )
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--root-task-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkpoint-lifecycle", action="store_true")
    args = parser.parse_args(argv)
    try:
        qualification = rehearsal.read_qualification_artifact(
            args.qualification_artifact
        )
        inputs = governed_inputs.read_issue94_governed_inputs_artifact(
            args.governed_inputs_artifact,
            args.source_root,
        )
        canary = route_canary.read_route_canary_artifact(
            args.canary_artifact
        )
        report = build_issue94_pre_spawn_report(
            qualification,
            inputs,
            canary,
            args.source_root,
            evidence_root=args.evidence_root,
            enrollment_registry_root=args.enrollment_registry_root,
            root_task_id=args.root_task_id,
            checkpoint_lifecycle=args.checkpoint_lifecycle,
        )
        receipt = persist_issue94_pre_spawn_artifact(
            report,
            args.output,
            args.source_root,
            args.evidence_root,
            args.enrollment_registry_root,
        )
    except (
        KeyError,
        OSError,
        QualificationPreSpawnError,
        TypeError,
        ValueError,
    ) as error:
        print(
            json.dumps(
                {
                    "schema": CHECKPOINT_RECEIPT_SCHEMA if args.checkpoint_lifecycle else RECEIPT_SCHEMA,
                    "status": "FAIL",
                    "issues": [str(error)],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


__all__ = [
    "CHECKPOINT_REPORT_SCHEMA",
    "CHECKPOINT_RECEIPT_SCHEMA",
    "RECEIPT_SCHEMA",
    "REPORT_SCHEMA",
    "ActiveProjectEnrollmentArtifact",
    "Issue94PreSpawnArtifact",
    "QualificationPreSpawnError",
    "build_issue94_pre_spawn_report",
    "persist_issue94_pre_spawn_artifact",
    "read_issue94_pre_spawn_artifact",
    "unmaterialized_hook_trust_sha256",
]


if __name__ == "__main__":
    raise SystemExit(main())
