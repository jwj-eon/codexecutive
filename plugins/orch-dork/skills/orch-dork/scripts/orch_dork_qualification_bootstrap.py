#!/usr/bin/env python3
"""Atomically bootstrap Issue 94 from fresh pre-spawn evidence to capacity.

The caller supplies the three whole post-canary artifacts and output paths.
This provider-free driver builds and persists pre-spawn evidence, issues the
owner-attested activation handoff, advances the canonical controller through
activation and its first pre-spawn stage, and stops before capacity admission
or any network, model, worker, or native action.
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
import sys
from typing import Any


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_governed_native_controller as native_controller  # noqa: E402
import orch_dork_owned_file as owned_file  # noqa: E402
import orch_dork_qualification_activation as activation  # noqa: E402
import orch_dork_qualification_governed_inputs as governed_inputs  # noqa: E402
import orch_dork_qualification_pre_spawn as pre_spawn  # noqa: E402
import orch_dork_qualification_rehearsal as rehearsal  # noqa: E402
import orch_dork_qualification_route_canary as route_canary  # noqa: E402
import orch_dork_qualification_owner_rotation as owner_rotation  # noqa: E402
from orch_dork_governed_native_reports import completion_waiting_authority  # noqa: E402


REPORT_SCHEMA = "orch-dork/qualification-controller-bootstrap/v2"
RECEIPT_SCHEMA = "orch-dork/qualification-controller-bootstrap-receipt/v2"
REFERENCE_SCHEMA = "orch-dork/sealed-artifact-reference/v1"
OWNER_DISPOSITION_SCHEMA = "orch-dork/bootstrap-owner-disposition/v1"
MAX_ARTIFACT_BYTES = 4_194_304
MAX_INPUT_ARTIFACT_BYTES = 1_048_576
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_COUNTERS = {
    "authority_grants": 0,
    "capacity_reservations": 0,
    "controller_activations": 1,
    "controller_stages": 1,
    "credential_reads": 2,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "network_calls": 0,
    "provider_calls": 0,
    "workers": 0,
}
_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "case_id",
        "controller_id",
        "evaluation_time",
        "source_roots",
        "pre_spawn_artifact",
        "pre_spawn_artifact_receipt",
        "activation_handoff_artifact",
        "activation_handoff_artifact_receipt",
        "activation_report",
        "owner_disposition_artifact",
        "pre_spawn_stage_program",
        "pre_spawn_stage_report",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_CONTROLLER_REPORT_FIELDS = frozenset(
    {
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
)
_CONTROLLER_ZERO_COUNTERS = (
    "hosted_calls",
    "model_calls",
    "native_calls",
    "task_creations",
    "worker_creations",
    "credential_reads",
    "authority_grants_minted",
    "native_action_authorizations",
)


class QualificationBootstrapError(ValueError):
    """Stable fail-closed controller-bootstrap refusal."""


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


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _sealed(value: Mapping[str, Any], field: str = "report_sha256") -> bool:
    return _is_sha(value.get(field)) and value.get(field) == _sha(
        {key: child for key, child in value.items() if key != field}
    )


def _owned_evidence_root(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise QualificationBootstrapError("bootstrap:evidence_root_unsafe")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except OSError as error:
        raise QualificationBootstrapError(
            "bootstrap:evidence_root_unavailable"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QualificationBootstrapError("bootstrap:evidence_root_unsafe")
    return resolved


def _output_path(value: str | Path, evidence_root: Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or os.path.lexists(path):
        raise QualificationBootstrapError("bootstrap:output_path_unsafe")
    try:
        parent = path.parent.resolve(strict=True)
        info = parent.lstat()
    except OSError as error:
        raise QualificationBootstrapError(
            "bootstrap:output_parent_unavailable"
        ) from error
    if (
        not parent.is_relative_to(evidence_root)
        or parent.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QualificationBootstrapError("bootstrap:output_parent_unsafe")
    return path


def _reference(
    path: Path,
    report_sha256: str,
    *,
    max_bytes: int = MAX_INPUT_ARTIFACT_BYTES,
) -> dict[str, Any]:
    try:
        raw = owned_file.read_owned_bytes(
            path,
            max_bytes=max_bytes,
            required_mode=0o600,
        )
    except (OSError, ValueError) as error:
        raise QualificationBootstrapError(
            "bootstrap:referenced_artifact_unavailable"
        ) from error
    return {
        "schema": REFERENCE_SCHEMA,
        "artifact_path": str(path),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "report_sha256": report_sha256,
    }


def _controller_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CONTROLLER_REPORT_FIELDS:
        raise QualificationBootstrapError(
            "bootstrap:controller_report_shape_invalid"
        )
    report = deepcopy(dict(value))
    state = report.get("controller_state")
    if (
        report.get("schema") != native_controller.REPORT_SCHEMA
        or report.get("status") not in {"PASS", "BLOCKED"}
        or not isinstance(report.get("decision"), str)
        or report.get("provider_free") is not True
        or not isinstance(report.get("issues"), list)
        or report["issues"] != sorted(set(report["issues"]))
        or not isinstance(state, Mapping)
        or set(state)
        != {
            "terminal",
            "pending_intent",
            "action_outcome",
            "action_authorized",
            "grant_state",
            "cleanup_required",
        }
        or any(report.get(name) != 0 for name in _CONTROLLER_ZERO_COUNTERS)
        or not _sealed(report)
    ):
        raise QualificationBootstrapError(
            "bootstrap:controller_report_invalid"
        )
    return report


def _read_reference(
    value: Any,
    *,
    expected_path: Path,
    expected_report_sha256: str,
    max_bytes: int = MAX_INPUT_ARTIFACT_BYTES,
) -> bytes:
    try:
        raw = owned_file.read_owned_bytes(
            expected_path, max_bytes=max_bytes, required_mode=0o600,
        )
    except (OSError, ValueError) as error:
        raise QualificationBootstrapError(
            "bootstrap:referenced_artifact_unavailable"
        ) from error
    expected = {
        "schema": REFERENCE_SCHEMA,
        "artifact_path": str(expected_path),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "report_sha256": expected_report_sha256,
    }
    if _canonical(value) != _canonical(expected):
        raise QualificationBootstrapError(
            "bootstrap:artifact_reference_invalid"
        )
    return raw


def _require_artifact_receipts(value, pre, handoff, pre_bytes, handoff_bytes):
    """Reconstruct receipts independently from validated artifacts and read bytes.

    A self-consistent seal alone cannot bind schema, paths, counters or lineage.
    Keep this consumer independent of the production receipt constructors.
    """
    # Bind the bytes observed by reference verification to the report already
    # validated above. This also refuses replacement between those two reads.
    if (pre_bytes != pre_spawn._canonical(pre.report) + b"\n"
            or handoff_bytes != activation._canonical(handoff.report) + b"\n"):
        raise QualificationBootstrapError("bootstrap_artifact:receipt_bytes_invalid")
    pre_core = {
        "schema": pre_spawn.CHECKPOINT_RECEIPT_SCHEMA
        if pre.report["schema"] == pre_spawn.CHECKPOINT_REPORT_SCHEMA else pre_spawn.RECEIPT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "case_id": pre.report["case_id"],
        "artifact_path": value["pre_spawn_artifact"]["artifact_path"],
        "artifact_size_bytes": len(pre_bytes),
        "artifact_sha256": hashlib.sha256(pre_bytes).hexdigest(),
        "report_sha256": pre.report_sha256,
        "qualification_report_sha256": pre.report["qualification_report_sha256"],
        "governed_inputs_report_sha256": pre.report["governed_inputs_report_sha256"],
        "canary_report_sha256": pre.report["canary_report_sha256"],
        "project_enrollment_program_sha256": _sha(pre.project_enrollment_program),
        "project_enrollment_report_sha256": pre.project_enrollment_report["report_sha256"],
        "ticket_admission_sha256": pre.ticket_admission["admission_sha256"],
        "hard_admission_sha256": pre.hard_admission_report["admission_digest"],
        "pre_spawn_receipt_sha256": pre.pre_spawn_report["receipt"]["receipt_sha256"],
        "disposition": pre.pre_spawn_report["disposition"],
        "counters": pre.counters,
    }
    handoff_core = {
        "schema": activation.RECEIPT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "artifact_path": value["activation_handoff_artifact"]["artifact_path"],
        "artifact_size_bytes": len(handoff_bytes),
        "artifact_sha256": hashlib.sha256(handoff_bytes).hexdigest(),
        "report_sha256": handoff.report_sha256,
        "pre_spawn_report_sha256": handoff.pre_spawn_artifact.report_sha256,
        "hook_trust_receipt_sha256": handoff.hook_trust_receipt_sha256,
        "controller_program_sha256": _sha(handoff.controller_program),
        "disposition": "READY_FOR_CONTROLLER_ACTIVATION",
        "counters": handoff.counters,
    }
    for name, core in (("pre_spawn_artifact_receipt", pre_core),
                       ("activation_handoff_artifact_receipt", handoff_core)):
        expected = {**core, "receipt_sha256": _sha(core)}
        # JSON byte comparison distinguishes bool/int and int/float aliases.
        if _canonical(value[name]) != _canonical(expected):
            raise QualificationBootstrapError("bootstrap_artifact:receipt_binding_invalid")


def _owner_disposition_report(snapshot, activation_report_sha256, activation_program_sha256, issues):
    core = {
        "schema": OWNER_DISPOSITION_SCHEMA,
        "status": "REFUSED" if issues else "OBSERVED",
        "issues": issues,
        "scope": "bootstrap_predecessor_disposition",
        "activation_report_sha256": activation_report_sha256,
        "activation_program_sha256": activation_program_sha256,
        "snapshot": snapshot,
        "owner_released": bool(snapshot and snapshot["predecessor_observation"] is not None),
        "continuation_permitted": False,
        "terminal_claim_permitted": False,
        "provider_free": True,
        "model_calls": 0,
        "native_calls": 0,
        "rotation_calls": 0,
    }
    return {**core, "report_sha256": _sha(core)}


def _owner_activation_context(activation_report, activation_program):
    if (
        native_controller.validate_governed_native_controller_report(activation_report).get("valid") is not True
        or activation_report["status"] != "PASS"
        or activation_report["decision"] != "ACTIVATED_READ_ONLY"
        or activation_report["action"] is not None
        or activation_report["stage_report"] is not None
        or activation_report["controller_state"] != {
            "terminal": False, "pending_intent": False, "action_outcome": None,
            "action_authorized": False, "grant_state": None, "cleanup_required": False,
        }
        or activation_report["cursor"]["seq"] != 1
        or not isinstance(activation_program, Mapping)
        or set(activation_program) != {"schema", "operation", "controller_id", "expected_cursor", "payload"}
        or activation_program["schema"] != native_controller.PROGRAM_SCHEMA
        or activation_program["operation"] != "activate"
        or activation_program["expected_cursor"] is not None
        or activation_program["controller_id"] != activation_report["controller_id"]
        or not isinstance(activation_program["payload"], Mapping)
        or set(activation_program["payload"]) != {
            "identity", "enrollment_program", "project_ground_state", "hook_trust_receipt_sha256", "task_specs"
        }
    ):
        raise QualificationBootstrapError("bootstrap:owner_activation_invalid")


def validate_bootstrap_owner_disposition(report: Any, *, activation_report: Any, activation_program: Any) -> dict:
    """Validate transport bound to the exact activation, without asserting authority."""
    try:
        _owner_activation_context(activation_report, activation_program)
        if len(_canonical(report)) > MAX_ARTIFACT_BYTES:
            raise ValueError("owner disposition exceeds bounds")
        if report["status"] == "OBSERVED":
            snapshot = report["snapshot"]
            if not isinstance(snapshot, Mapping) or set(snapshot) != {
                "authority", "activation", "activation_event", "marker", "predecessor_observation"
            }:
                raise ValueError("invalid owner snapshot")
            authority, marker = snapshot["authority"], snapshot["marker"]
            completion_waiting_authority(authority)
            owner_rotation._marker(marker, authority["owner"])
            event = snapshot["activation_event"]
            if not isinstance(event, Mapping) or set(event) != {
                "run_id", "seq", "kind", "actor_key", "payload", "note", "prev_hash", "event_hash", "origin"
            } or native_controller.run_engine.verify_event_chain([event]) != [1]:
                raise ValueError("activation event invalid")
            origin = json.loads(event["payload"])["plan"]["origin"]
            submitted = activation_program["payload"]
            admitted = snapshot["activation"]
            # Admission records evaluated enrollment/trust and normalized TaskSpecs.
            # Preserve the entire submitted-program digest, then compare its
            # semantic inputs with the actual hash-bound admitted facts.
            if (
                authority["tip"] != activation_report["cursor"]
                or native_controller._cursor([event]) != authority["tip"]
                or authority["owner"]["controller_id"] != activation_report["controller_id"]
                or admitted["identity"] != submitted["identity"]
                or admitted["project_ground_state"] != submitted["project_ground_state"]
                or admitted["task_specs"] != native_controller.normalized_task_specs(submitted["task_specs"])
                or admitted["hook_trust"]["signed_receipt_sha256"] != submitted["hook_trust_receipt_sha256"]
                or _sha(snapshot["activation"]) != authority["owner"]["activation_sha256"]
                or native_controller._controller_events([event])[0]["payload"] != snapshot["activation"]
                or origin.get("controller_id") != authority["owner"]["controller_id"]
                or origin.get("store_identity_sha256") != authority["store_identity_sha256"]
                or origin.get("controller_run_marker_sha256") != marker["marker_sha256"]
                or origin.get("previous_controller_run_id") != marker["previous_controller_run_id"]
                or origin.get("previous_controller_run_marker_sha256") != marker["previous_marker_sha256"]
            ):
                raise ValueError("owner activation changed")
            prior = snapshot["predecessor_observation"]
            if marker["previous_controller_run_id"] is None:
                if prior is not None:
                    raise ValueError("initial owner has a predecessor")
            elif (
                owner_rotation.validate_owner_rotation_observation(prior).get("valid") is not True
                or prior["status"] != "OBSERVED"
                or prior["snapshot"]["successor"]["authority"] != authority
                or prior["snapshot"]["successor"]["marker"] != marker
                or prior["snapshot"]["successor"]["activation"] != snapshot["activation"]
            ):
                raise ValueError("predecessor disposition unverified")
            expected = _owner_disposition_report(snapshot, activation_report["report_sha256"], _sha(activation_program), [])
        else:
            expected = _owner_disposition_report(
                None, activation_report["report_sha256"], _sha(activation_program), ["bootstrap:owner_disposition_unverified"]
            )
        if _canonical(report) != _canonical(expected):
            raise ValueError("owner report changed")
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, native_controller.run_engine.RunKernelError):
        return {"valid": False, "issues": ["bootstrap:owner_disposition_transport_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def _observe_bootstrap_owner_disposition(controller, activation_report, activation_program):
    """Read an already admitted owner before its first stage, without rotation."""
    _owner_activation_context(activation_report, activation_program)
    try:
        authority = controller.grants.canonical_authority()
        completion_waiting_authority(authority)
        state, rows = controller._state(authority["owner"]["controller_run_id"], recover_provisional=False)
        if (
            native_controller._cursor(rows) != activation_report["cursor"]
            or len(native_controller._controller_events(rows)) != 1
            or not controller._hook_runtime_matches(state["activation"]["identity"])
            or not controller._retained_hook_evidence_valid(state)
        ):
            raise ValueError("successor already advanced or changed")
        marker = controller.grants.controller_run_marker(authority["owner"]["controller_run_id"])
        prior = None
        if marker["previous_controller_run_id"] is not None:
            previous = controller.grants.controller_run_marker(marker["previous_controller_run_id"])
            previous_owner = {
                "schema": native_controller.native_grant_store.OWNER_SCHEMA,
                **{key: previous[key] for key in ("controller_id", "controller_run_id", "activation_sha256", "store_identity_sha256")},
            }
            previous_rows = controller._rows(previous_owner["controller_run_id"])
            prior = owner_rotation.observe_predecessor_owner_disposition(
                controller, predecessor_owner=previous_owner,
                predecessor_cursor=native_controller._cursor(previous_rows),
            )
        snapshot = {"authority": authority, "activation": state["activation"], "activation_event": rows[0], "marker": marker,
                    "predecessor_observation": prior}
        report = _owner_disposition_report(snapshot, activation_report["report_sha256"], _sha(activation_program), [])
        if (
            validate_bootstrap_owner_disposition(report, activation_report=activation_report,
                                                 activation_program=activation_program)["valid"] is not True
            or controller.grants.canonical_authority() != authority
            or controller.grants.controller_run_marker(authority["owner"]["controller_run_id"]) != marker
        ):
            raise ValueError("owner changed during observation")
        return report
    except Exception:
        return _owner_disposition_report(
            None, activation_report["report_sha256"], _sha(activation_program), ["bootstrap:owner_disposition_unverified"]
        )


def _read_bootstrap_owner_disposition(reference, *, evidence_root, activation_report, activation_program):
    try:
        path = Path(reference["artifact_path"])
        if not path.is_absolute() or path.is_symlink() or not path.resolve(strict=True).is_relative_to(evidence_root):
            raise ValueError("owner evidence outside its root")
        raw = owned_file.read_owned_bytes(path, max_bytes=MAX_ARTIFACT_BYTES, required_mode=0o600)
        report = json.loads(raw)
        if (
            raw != _canonical(report) + b"\n"
            or validate_bootstrap_owner_disposition(report, activation_report=activation_report,
                                                    activation_program=activation_program)["valid"] is not True
            or report["status"] != "OBSERVED"
        ):
            raise ValueError("owner observation unverified")
        expected = {"schema": REFERENCE_SCHEMA, "artifact_path": str(path),
                    "artifact_sha256": hashlib.sha256(raw).hexdigest(), "report_sha256": report["report_sha256"]}
        if reference != expected or _reference(path, report["report_sha256"], max_bytes=MAX_ARTIFACT_BYTES) != expected:
            raise ValueError("owner reference changed")
        return report
    except (OSError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
        raise QualificationBootstrapError("bootstrap:owner_disposition_artifact_invalid") from error


def _advance_bootstrap_controller(handoff, *, plugin_data, hook_definition, owner_output, evidence_root):
    """Keep activation, its read-only owner proof and first stage in one host lifetime."""
    owner_output = _output_path(owner_output, _owned_evidence_root(evidence_root))
    with native_controller.open_governed_native_controller(
        plugin_data=plugin_data,
        hook_definition_path=hook_definition,
        source_roots=handoff.controller_source_roots,
    ) as controller:
        activation_report = _controller_report(controller.advance(handoff.controller_program))
        if activation_report.get("status") != "PASS" or activation_report.get("decision") != "ACTIVATED_READ_ONLY":
            raise QualificationBootstrapError(
                "bootstrap:activation_refused:" + str(activation_report.get("report_sha256"))
                + ":" + ",".join(activation_report.get("issues", []))
            )
        owner_report = _observe_bootstrap_owner_disposition(controller, activation_report, handoff.controller_program)
        rehearsal._write_create_only(owner_output, _canonical(owner_report) + b"\n")
        owner_reference = _reference(owner_output, owner_report["report_sha256"], max_bytes=MAX_ARTIFACT_BYTES)
        # Preserve the exact observation even when it refuses or the next stage
        # fails. It describes the already completed activation, not new work.
        _read_bootstrap_owner_disposition(
            owner_reference, evidence_root=evidence_root,
            activation_report=activation_report, activation_program=handoff.controller_program,
        )
        stage_program = native_controller.build_governed_native_stage_program(
            controller_id=activation_report["controller_id"], expected_cursor=activation_report["cursor"],
            stage_program=handoff.pre_spawn_artifact.pre_spawn_program, proposed_action=None,
        )
        stage_report = _controller_report(controller.advance(stage_program))
        if (
            stage_report.get("status") != "PASS" or stage_report.get("decision") != "STAGE_ADVANCED"
            or stage_report.get("next_stage_action") != "capacity_admission" or stage_report.get("action") is not None
        ):
            raise QualificationBootstrapError("bootstrap:pre_spawn_stage_refused:" + str(stage_report.get("report_sha256")))
        return activation_report, stage_program, stage_report, owner_reference


@dataclass(frozen=True, slots=True)
class Issue94ControllerBootstrapArtifact:
    """Strict whole-report handoff at the capacity-admission boundary."""

    report: dict[str, Any]
    report_sha256: str
    source_roots: dict[str, str]
    pre_spawn_artifact: pre_spawn.Issue94PreSpawnArtifact
    activation_handoff_artifact: activation.Issue94ActivationHandoffArtifact
    activation_report: dict[str, Any]
    owner_disposition_observation: dict[str, Any]
    pre_spawn_stage_program: dict[str, Any]
    pre_spawn_stage_report: dict[str, Any]
    counters: dict[str, int]

    @classmethod
    def from_report(
        cls,
        report: Any,
        source_root: str | Path,
        evidence_root: str | Path,
        enrollment_registry_root: str | Path,
    ) -> "Issue94ControllerBootstrapArtifact":
        if not isinstance(report, Mapping) or set(report) != _REPORT_FIELDS:
            raise QualificationBootstrapError(
                "bootstrap_artifact:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        expected_roots = {
            "evidence": str(Path(evidence_root).resolve(strict=True)),
            "source": str(Path(source_root).resolve(strict=True)),
        }
        if (
            value.get("schema") != REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("issues") != []
            or value.get("source_roots") != expected_roots
            or value.get("provider_free") is not True
            or value.get("counters") != _COUNTERS
            or not _sealed(value)
        ):
            raise QualificationBootstrapError(
                "bootstrap_artifact:report_invalid"
            )
        pre_reference = value.get("pre_spawn_artifact")
        activation_reference = value.get("activation_handoff_artifact")
        if not isinstance(pre_reference, Mapping) or not isinstance(
            activation_reference, Mapping
        ):
            raise QualificationBootstrapError(
                "bootstrap_artifact:reference_invalid"
            )
        pre_path = Path(str(pre_reference.get("artifact_path")))
        activation_path = Path(
            str(activation_reference.get("artifact_path"))
        )
        pre = pre_spawn.read_issue94_pre_spawn_artifact(
            pre_path,
            source_root,
            evidence_root,
            enrollment_registry_root,
        )
        handoff = activation.read_issue94_activation_handoff_artifact(
            activation_path,
            source_root,
            evidence_root,
            enrollment_registry_root,
        )
        pre_bytes = _read_reference(
            pre_reference,
            expected_path=pre_path,
            expected_report_sha256=pre.report_sha256,
        )
        handoff_bytes = _read_reference(
            activation_reference,
            expected_path=activation_path,
            expected_report_sha256=handoff.report_sha256,
        )
        _require_artifact_receipts(value, pre, handoff, pre_bytes, handoff_bytes)
        activation_report = _controller_report(
            value.get("activation_report")
        )
        stage_report = _controller_report(
            value.get("pre_spawn_stage_report")
        )
        owner_observation = _read_bootstrap_owner_disposition(
            value.get("owner_disposition_artifact"), evidence_root=Path(evidence_root).resolve(strict=True),
            activation_report=activation_report, activation_program=handoff.controller_program,
        )
        expected_stage = native_controller.build_governed_native_stage_program(
            controller_id=str(value.get("controller_id")),
            expected_cursor=activation_report.get("cursor"),
            stage_program=pre.pre_spawn_program,
            proposed_action=None,
        )
        if (
            value.get("case_id") != pre.report.get("case_id")
            or value.get("controller_id")
            != handoff.report.get("controller_id")
            or handoff.controller_source_roots != expected_roots
            or activation_report.get("controller_id")
            != value.get("controller_id")
            or activation_report.get("decision")
            != "ACTIVATED_READ_ONLY"
            or activation_report.get("action") is not None
            or stage_report.get("controller_id") != value.get("controller_id")
            or stage_report.get("decision") != "STAGE_ADVANCED"
            or stage_report.get("next_stage_action")
            != "capacity_admission"
            or stage_report.get("action") is not None
            or stage_report.get("stage_report", {}).get("status") != "PASS"
            or stage_report.get("stage_report", {}).get("disposition")
            != "SHARED_CAPACITY_ADMISSION_REQUIRED"
            or value.get("pre_spawn_stage_program") != expected_stage
        ):
            raise QualificationBootstrapError(
                "bootstrap_artifact:stage_binding_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            source_roots=deepcopy(expected_roots),
            pre_spawn_artifact=pre,
            activation_handoff_artifact=handoff,
            activation_report=activation_report,
            owner_disposition_observation=owner_observation,
            pre_spawn_stage_program=deepcopy(expected_stage),
            pre_spawn_stage_report=stage_report,
            counters={
                str(key): int(child)
                for key, child in value["counters"].items()
            },
        )


def read_issue94_controller_bootstrap_artifact(
    path: str | Path,
    source_root: str | Path,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
) -> Issue94ControllerBootstrapArtifact:
    try:
        raw = owned_file.read_owned_bytes(
            path,
            max_bytes=MAX_ARTIFACT_BYTES,
            required_mode=0o600,
        )
        report = json.loads(raw.decode("utf-8"))
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        raise QualificationBootstrapError(
            "bootstrap_artifact:unavailable"
        ) from error
    return Issue94ControllerBootstrapArtifact.from_report(
        report,
        source_root,
        evidence_root,
        enrollment_registry_root,
    )


def materialize_issue94_controller_bootstrap(
    qualification_artifact_path: str | Path,
    governed_inputs_artifact_path: str | Path,
    canary_artifact_path: str | Path,
    source_root: str | Path,
    *,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
    root_task_id: str,
    controller_id: str,
    pre_spawn_output_path: str | Path,
    activation_output_path: str | Path,
    output_path: str | Path,
    now: datetime | None = None,
    runtime_plugin_root: str | Path | None = None,
    pre_turn: bool = False,
    checkpoint_lifecycle: bool = False,
) -> dict[str, Any]:
    """Build fresh evidence and atomically reach capacity-admission readiness."""

    if type(checkpoint_lifecycle) is not bool:
        raise QualificationBootstrapError("bootstrap:checkpoint_profile_invalid")
    evidence = _owned_evidence_root(evidence_root)
    outputs = (
        _output_path(pre_spawn_output_path, evidence),
        _output_path(activation_output_path, evidence),
        _output_path(output_path, evidence),
    )
    owner_output = _output_path(outputs[2].with_name(outputs[2].name + ".owner-disposition.json"), evidence)
    if len({str(path) for path in (*outputs, owner_output)}) != len(outputs) + 1:
        raise QualificationBootstrapError("bootstrap:output_paths_reused")
    pre_output, handoff_output, output = outputs
    evaluation_time = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    qualification = rehearsal.read_qualification_artifact(
        qualification_artifact_path
    )
    inputs = governed_inputs.read_issue94_governed_inputs_artifact(
        governed_inputs_artifact_path,
        source_root,
    )
    canary = route_canary.read_route_canary_artifact(canary_artifact_path)
    pre_report = pre_spawn.build_issue94_pre_spawn_report(
        qualification,
        inputs,
        canary,
        source_root,
        evidence_root=evidence,
        enrollment_registry_root=enrollment_registry_root,
        root_task_id=root_task_id,
        now=evaluation_time,
        checkpoint_lifecycle=checkpoint_lifecycle,
    )
    pre_receipt = pre_spawn.persist_issue94_pre_spawn_artifact(
        pre_report,
        pre_output,
        source_root,
        evidence,
        enrollment_registry_root,
    )
    handoff_receipt = activation.materialize_issue94_activation_handoff(
        pre_output,
        handoff_output,
        source_root,
        evidence_root=evidence,
        enrollment_registry_root=enrollment_registry_root,
        controller_id=controller_id,
        now=evaluation_time,
        pre_turn=pre_turn,
    )
    handoff = activation.read_issue94_activation_handoff_artifact(
        handoff_output,
        source_root,
        evidence,
        enrollment_registry_root,
    )
    plugin_data = activation._canonical_plugin_data(create=True)
    selected_plugin_root = (
        Path(runtime_plugin_root)
        if runtime_plugin_root is not None
        else Path(__file__).resolve().parents[3]
    )
    if not selected_plugin_root.is_absolute() or selected_plugin_root.is_symlink():
        raise QualificationBootstrapError(
            "bootstrap:runtime_plugin_root_unsafe"
        )
    try:
        hook_definition = (
            selected_plugin_root / "hooks" / "project_ground_hook.py"
        ).resolve(strict=True)
    except OSError as error:
        raise QualificationBootstrapError(
            "bootstrap:runtime_hook_unavailable"
        ) from error
    activation_report, stage_program, stage_report, owner_reference = _advance_bootstrap_controller(
        handoff, plugin_data=plugin_data, hook_definition=hook_definition,
        owner_output=owner_output, evidence_root=evidence,
    )
    core = {
        "schema": REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "case_id": handoff.pre_spawn_artifact.report["case_id"],
        "controller_id": controller_id,
        "evaluation_time": evaluation_time.isoformat(),
        "source_roots": deepcopy(handoff.controller_source_roots),
        "pre_spawn_artifact": _reference(
            pre_output,
            handoff.pre_spawn_artifact.report_sha256,
        ),
        "pre_spawn_artifact_receipt": deepcopy(pre_receipt),
        "activation_handoff_artifact": _reference(
            handoff_output,
            handoff.report_sha256,
        ),
        "activation_handoff_artifact_receipt": deepcopy(handoff_receipt),
        "activation_report": activation_report,
        "owner_disposition_artifact": owner_reference,
        "pre_spawn_stage_program": stage_program,
        "pre_spawn_stage_report": stage_report,
        "provider_free": True,
        "counters": deepcopy(_COUNTERS),
    }
    report = {**core, "report_sha256": _sha(core)}
    Issue94ControllerBootstrapArtifact.from_report(
        report,
        source_root,
        evidence,
        enrollment_registry_root,
    )
    payload = _canonical(report) + b"\n"
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise QualificationBootstrapError("bootstrap_artifact:too_large")
    rehearsal._write_create_only(output, payload)
    persisted = read_issue94_controller_bootstrap_artifact(
        output,
        source_root,
        evidence,
        enrollment_registry_root,
    )
    if persisted.report != report:
        raise QualificationBootstrapError(
            "bootstrap_artifact:readback_mismatch"
        )
    receipt_core = {
        "schema": RECEIPT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "artifact_path": str(output),
        "artifact_size_bytes": len(payload),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": persisted.report_sha256,
        "pre_spawn_report_sha256": (
            persisted.pre_spawn_artifact.report_sha256
        ),
        "activation_handoff_report_sha256": (
            persisted.activation_handoff_artifact.report_sha256
        ),
        "activation_report_sha256": persisted.activation_report[
            "report_sha256"
        ],
        "owner_disposition_report_sha256": persisted.owner_disposition_observation["report_sha256"],
        "pre_spawn_stage_report_sha256": (
            persisted.pre_spawn_stage_report["report_sha256"]
        ),
        "disposition": "READY_FOR_CAPACITY_ADMISSION",
        "counters": deepcopy(persisted.counters),
    }
    return {**receipt_core, "receipt_sha256": _sha(receipt_core)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification-artifact", type=Path, required=True)
    parser.add_argument("--governed-inputs-artifact", type=Path, required=True)
    parser.add_argument("--canary-artifact", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument(
        "--enrollment-registry-root",
        type=Path,
        required=True,
    )
    parser.add_argument("--root-task-id", required=True)
    parser.add_argument("--controller-id", required=True)
    parser.add_argument("--pre-spawn-output", type=Path, required=True)
    parser.add_argument("--activation-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-plugin-root", type=Path)
    parser.add_argument("--pre-turn", action="store_true")
    parser.add_argument("--checkpoint-lifecycle", action="store_true")
    args = parser.parse_args(argv)
    try:
        receipt = materialize_issue94_controller_bootstrap(
            args.qualification_artifact,
            args.governed_inputs_artifact,
            args.canary_artifact,
            args.source_root,
            evidence_root=args.evidence_root,
            enrollment_registry_root=args.enrollment_registry_root,
            root_task_id=args.root_task_id,
            controller_id=args.controller_id,
            pre_spawn_output_path=args.pre_spawn_output,
            activation_output_path=args.activation_output,
            output_path=args.output,
            runtime_plugin_root=args.runtime_plugin_root,
            pre_turn=args.pre_turn,
            checkpoint_lifecycle=args.checkpoint_lifecycle,
        )
    except Exception as error:
        issue = (
            str(error)
            if isinstance(
                error,
                (
                    KeyError,
                    OSError,
                    TypeError,
                    ValueError,
                ),
            )
            else "bootstrap:unexpected_failure:" + type(error).__name__
        )
        result = {
            "schema": RECEIPT_SCHEMA,
            "status": "FAIL",
            "issues": [issue],
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


__all__ = [
    "Issue94ControllerBootstrapArtifact",
    "QualificationBootstrapError",
    "materialize_issue94_controller_bootstrap",
    "read_issue94_controller_bootstrap_artifact",
    "validate_bootstrap_owner_disposition",
]


if __name__ == "__main__":
    raise SystemExit(main())
