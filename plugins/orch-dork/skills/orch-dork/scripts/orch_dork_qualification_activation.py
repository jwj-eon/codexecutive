#!/usr/bin/env python3
"""Materialize one owner-attested Issue 94 activation handoff.

The input is one whole sealed pre-spawn artifact.  This driver verifies the
exact task-owning Local app-server invocation, issues one host-signed hook
trust receipt, persists it create-only in the canonical plugin data store,
reruns the real activation preparer, and seals the exact controller program.
It never activates the controller or performs a network, model, or native
action.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
import orch_dork_local_task_runtime as local_task_runtime  # noqa: E402
import orch_dork_observer_authority as observer_authority  # noqa: E402
import orch_dork_observer_receipt as observer_receipt  # noqa: E402
import orch_dork_owned_file as owned_file  # noqa: E402
import orch_dork_qualification_pre_spawn as pre_spawn  # noqa: E402
import orch_dork_qualification_rehearsal as rehearsal  # noqa: E402


REPORT_SCHEMA = "orch-dork/qualification-activation-handoff/v1"
RECEIPT_SCHEMA = "orch-dork/qualification-activation-handoff-receipt/v1"
EMIT_SCHEMA = "orch-dork/qualification-controller-program-handoff/v1"
MAX_ARTIFACT_BYTES = 1_048_576
MAX_RECEIPT_BYTES = native_controller.MAX_DURABLE_FILE_BYTES
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_COUNTERS = {
    "capacity_reservations": 0,
    "controller_activations": 0,
    "credential_reads": 2,
    "evidence_files_created": 1,
    "hook_trust_files_created": 1,
    "hook_trust_receipts_issued": 1,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "network_calls": 0,
    "provider_calls": 0,
    "workers": 0,
}
_RUNTIME_FIELDS = frozenset(
    {
        "schema",
        "status",
        "disposition",
        "task_id",
        "task_runtime_report",
        "hook_inventory_report",
        "mode",
        "invocation_id",
        "app_server_argv_sha256",
        "issues",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "credential_reads",
        "network_calls",
        "task_creations",
        "native_calls",
        "report_sha256",
    }
)
_CURRENT_RUNTIME_FIELDS = frozenset(
    {
        "schema",
        "status",
        "disposition",
        "task_owner_verified",
        "task_loaded",
        "task_status",
        "descendant_count",
        "owner_identity_sha256",
        "issues",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "credential_reads",
        "network_calls",
        "task_creations",
        "native_calls",
        "report_sha256",
    }
)
_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "case_id",
        "controller_id",
        "evaluation_time",
        "pre_spawn_artifact",
        "task_runtime_report",
        "signing_authority",
        "hook_trust_receipt_sha256",
        "hook_trust_verification_report",
        "activation_preparation_report",
        "controller_program",
        "controller_source_roots",
        "provider_free",
        "counters",
        "report_sha256",
    }
)


class QualificationActivationError(ValueError):
    """Stable fail-closed activation-handoff refusal."""


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


def _instant(value: Any) -> datetime:
    if isinstance(value, datetime):
        selected = value
    elif isinstance(value, str):
        try:
            selected = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise QualificationActivationError(
                "activation_handoff:evaluation_time_invalid"
            ) from error
    else:
        raise QualificationActivationError(
            "activation_handoff:evaluation_time_invalid"
        )
    if selected.tzinfo is None:
        raise QualificationActivationError(
            "activation_handoff:evaluation_time_timezone_required"
        )
    return selected.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _sealed(value: Mapping[str, Any], field: str = "report_sha256") -> bool:
    return _is_sha(value.get(field)) and value.get(field) == _sha(
        {key: child for key, child in value.items() if key != field}
    )


def _owned_directory(path: Path, *, create: bool) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise QualificationActivationError(
            "activation_handoff:state_directory_unsafe"
        )
    try:
        if create and not path.exists():
            path.mkdir(parents=True, mode=0o700)
        info = path.lstat()
    except OSError as error:
        raise QualificationActivationError(
            "activation_handoff:state_directory_unsafe"
            if create
            else "activation_handoff:state_directory_unavailable"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QualificationActivationError(
            "activation_handoff:state_directory_unsafe"
        )
    return path


def _canonical_plugin_data(*, create: bool) -> Path:
    configured = os.environ.get("CODEX_HOME")
    codex_home = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".codex"
    )
    _owned_directory(codex_home, create=False)
    plugin_data = (
        codex_home
        / "plugins"
        / "data"
        / "orch-dork-orch-dork-local"
    )
    return _owned_directory(plugin_data, create=create)


def _ensure_hook_trust_root(plugin_data: Path) -> Path:
    state_root = _owned_directory(
        plugin_data / "governed-native",
        create=True,
    )
    return _owned_directory(state_root / "hook-trust", create=True)


def _authority_paths() -> tuple[Path, Path, Path]:
    trust_raw = os.environ.get(observer_receipt.TRUST_STORE_ENV)
    replay_raw = os.environ.get(observer_receipt.REPLAY_DB_ENV)
    if not trust_raw or not replay_raw:
        raise QualificationActivationError(
            "activation_handoff:observer_authority_unavailable"
        )
    trust_path = Path(trust_raw)
    replay_path = Path(replay_raw)
    state_dir = trust_path.parent
    if (
        not trust_path.is_absolute()
        or not replay_path.is_absolute()
        or trust_path != state_dir / observer_authority.TRUST_STORE_FILENAME
        or replay_path != state_dir / observer_authority.REPLAY_DB_FILENAME
    ):
        raise QualificationActivationError(
            "activation_handoff:observer_authority_mismatch"
        )
    return state_dir, trust_path, replay_path


def _trust_store() -> observer_receipt.ObserverTrustStore:
    _state_dir, trust_path, _replay_path = _authority_paths()
    try:
        return observer_receipt.ObserverTrustStore.from_host_file(trust_path)
    except observer_receipt.ObserverReceiptError as error:
        raise QualificationActivationError(
            "activation_handoff:observer_authority_invalid"
        ) from error


def _authority() -> tuple[
    dict[str, Any],
    observer_receipt.FileHostSigner,
    observer_receipt.ObserverTrustStore,
]:
    state_dir, trust_path, _replay_path = _authority_paths()
    try:
        identity = observer_authority.inspect_authority(state_dir=state_dir)
        signer = observer_receipt.FileHostSigner.from_host_file(
            state_dir / observer_authority.SEED_FILENAME,
            key_id=str(identity["key_id"]),
            host_id=str(identity["host_id"]),
        )
        trust_store = observer_receipt.ObserverTrustStore.from_host_file(
            trust_path
        )
    except (
        KeyError,
        OSError,
        observer_authority.ObserverAuthorityError,
        observer_receipt.ObserverReceiptError,
    ) as error:
        raise QualificationActivationError(
            "activation_handoff:observer_authority_invalid"
        ) from error
    return identity, signer, trust_store


def _output_path(path: str | Path, evidence_root: Path) -> Path:
    output = Path(path)
    if not output.is_absolute() or output.is_symlink():
        raise QualificationActivationError(
            "activation_handoff_artifact:path_unsafe"
        )
    if os.path.lexists(output):
        raise QualificationActivationError(
            "activation_handoff_artifact:already_exists"
        )
    try:
        parent = output.parent.resolve(strict=True)
        evidence = evidence_root.resolve(strict=True)
        info = parent.lstat()
    except OSError as error:
        raise QualificationActivationError(
            "activation_handoff_artifact:parent_unavailable"
        ) from error
    if (
        not parent.is_relative_to(evidence)
        or parent.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QualificationActivationError(
            "activation_handoff_artifact:parent_unsafe"
        )
    return output


def _pre_spawn_reference(path: Path, artifact: Any) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink():
        raise QualificationActivationError(
            "activation_handoff:pre_spawn_path_unsafe"
        )
    try:
        payload = owned_file.read_owned_bytes(
            path,
            max_bytes=MAX_ARTIFACT_BYTES,
            required_mode=0o600,
        )
    except (OSError, ValueError) as error:
        raise QualificationActivationError(
            "activation_handoff:pre_spawn_artifact_unavailable"
        ) from error
    return {
        "schema": "orch-dork/sealed-artifact-reference/v1",
        "artifact_path": str(path),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": artifact.report_sha256,
    }


@dataclass(frozen=True, slots=True)
class CurrentTaskHookTrustArtifact:
    """Strict access to one owner-bound hook-trust observation."""

    report: dict[str, Any]
    report_sha256: str
    task_id: str
    mode: str
    invocation_id: str
    app_server_argv_sha256: str
    hook_inventory_report_sha256: str

    @classmethod
    def from_report(
        cls,
        report: Any,
        *,
        expected_task_id: str,
    ) -> "CurrentTaskHookTrustArtifact":
        if not isinstance(report, Mapping) or set(report) != _RUNTIME_FIELDS:
            raise QualificationActivationError(
                "activation_handoff:runtime_report_shape_invalid"
            )
        value = deepcopy(dict(report))
        runtime = value.get("task_runtime_report")
        try:
            inventory = local_task_runtime.OwnerHookInventoryArtifact.from_report(
                value.get("hook_inventory_report")
            )
        except local_task_runtime.LocalTaskRuntimeError as error:
            raise QualificationActivationError(
                "activation_handoff:hook_inventory_invalid"
            ) from error
        if (
            value.get("schema") != local_task_runtime.HOOK_TRUST_SCHEMA
            or value.get("status") != "PASS"
            or value.get("disposition")
            != "ONE_INVOCATION_BYPASS_ATTESTED"
            or value.get("task_id") != expected_task_id
            or value.get("mode") != "one_invocation_bypass"
            or not isinstance(value.get("invocation_id"), str)
            or _IDENTIFIER.fullmatch(value["invocation_id"]) is None
            or not _is_sha(value.get("app_server_argv_sha256"))
            or value.get("issues") != []
            or value.get("provider_free") is not True
            or any(
                value.get(name) != 0
                for name in (
                    "model_calls",
                    "hosted_calls",
                    "credential_reads",
                    "network_calls",
                    "task_creations",
                    "native_calls",
                )
            )
            or not _sealed(value)
            or not isinstance(runtime, Mapping)
            or set(runtime) != _CURRENT_RUNTIME_FIELDS
            or runtime.get("schema") != local_task_runtime.SCHEMA
            or runtime.get("status") != "PASS"
            or runtime.get("task_owner_verified") is not True
            or runtime.get("task_loaded") is not True
            or runtime.get("task_status") not in {"active", "idle"}
            or runtime.get("descendant_count") != 0
            or runtime.get("issues") != []
            or not _sealed(runtime)
        ):
            raise QualificationActivationError(
                "activation_handoff:runtime_report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            task_id=str(value["task_id"]),
            mode=str(value["mode"]),
            invocation_id=str(value["invocation_id"]),
            app_server_argv_sha256=str(
                value["app_server_argv_sha256"]
            ),
            hook_inventory_report_sha256=inventory.report_sha256,
        )


def _expected_trust_payload(
    *,
    controller_id: str,
    identity: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": native_controller.HOOK_TRUST_PAYLOAD_SCHEMA,
        "status": "PASS",
        "controller_id": controller_id,
        "project_id": identity.get("project_id"),
        "root_session_id": identity.get("root_session_id"),
        "hook_definition_sha256": identity.get(
            "hook_definition_sha256"
        ),
        "hook_registration_sha256": identity.get(
            "hook_registration_sha256"
        ),
    }


def _prepared_activation(
    artifact: pre_spawn.Issue94PreSpawnArtifact,
    receipt_sha256: str,
) -> dict[str, Any]:
    source = artifact.activation_preparation_report.get(
        "prepared_activation_payload"
    )
    if not isinstance(source, Mapping):
        raise QualificationActivationError(
            "activation_handoff:prepared_payload_unavailable"
        )
    payload = deepcopy(dict(source))
    identity = payload.get("identity")
    if not isinstance(identity, Mapping):
        raise QualificationActivationError(
            "activation_handoff:activation_identity_invalid"
        )
    expected_placeholder = pre_spawn.unmaterialized_hook_trust_sha256(
        identity.get("hook_definition_sha256"),
        identity.get("hook_registration_sha256"),
    )
    if payload.get("hook_trust_receipt_sha256") != expected_placeholder:
        raise QualificationActivationError(
            "activation_handoff:hook_trust_placeholder_invalid"
        )
    payload["hook_trust_receipt_sha256"] = receipt_sha256
    program = (
        native_controller
        .build_governed_native_activation_preparation_program(
            activation_payload=payload,
            project_adapter_report=artifact.project_adapter_report,
        )
    )
    report = native_controller.prepare_governed_native_activation(program)
    if (
        native_controller.validate_activation_preparation_report(report)
        != {"valid": True, "issues": []}
        or report.get("decision") != "READY_FOR_ACTIVATION"
        or report.get("prepared_activation_payload") != payload
    ):
        raise QualificationActivationError(
            "activation_handoff:activation_preparation_refused"
        )
    return report


def _controller_program(
    *,
    controller_id: str,
    activation_report: Mapping[str, Any],
) -> dict[str, Any]:
    payload = activation_report.get("prepared_activation_payload")
    if not isinstance(payload, Mapping):
        raise QualificationActivationError(
            "activation_handoff:prepared_payload_unavailable"
        )
    return native_controller.build_governed_native_activation_program(
        controller_id=controller_id,
        prepared_activation_payload=payload,
    )


def _verify_receipt(
    envelope: Mapping[str, Any],
    *,
    expected: Mapping[str, Any],
    runtime: CurrentTaskHookTrustArtifact,
    evaluation_time: datetime,
    trust_store: observer_receipt.ObserverTrustStore,
) -> dict[str, Any]:
    report = observer_receipt.verify_signed_receipt(
        envelope,
        expected_kind=native_controller.HOOK_TRUST_RECEIPT_KIND,
        expected_payload=expected,
        evaluation_time=evaluation_time,
        trust_store=trust_store,
        replay_guard=observer_receipt.MemoryReplayGuard(),
    )
    payload = report.get("payload")
    if (
        report.get("status") != "PASS"
        or not isinstance(payload, Mapping)
        or set(payload)
        != set(expected)
        | {"mode", "invocation_id", "hook_inventory_report_sha256"}
        or payload.get("mode") != runtime.mode
        or payload.get("invocation_id") != runtime.invocation_id
        or payload.get("hook_inventory_report_sha256")
        != runtime.hook_inventory_report_sha256
    ):
        raise QualificationActivationError(
            "activation_handoff:hook_trust_receipt_invalid"
        )
    return report


@dataclass(frozen=True, slots=True)
class Issue94ActivationHandoffArtifact:
    """Strict whole-report handoff to the governed controller bridge."""

    report: dict[str, Any]
    report_sha256: str
    pre_spawn_artifact: pre_spawn.Issue94PreSpawnArtifact
    task_runtime_report: dict[str, Any]
    hook_trust_receipt_sha256: str
    hook_trust_verification_report: dict[str, Any]
    activation_preparation_report: dict[str, Any]
    controller_program: dict[str, Any]
    controller_source_roots: dict[str, str]
    counters: dict[str, int]

    @classmethod
    def from_report(
        cls,
        report: Any,
        source_root: str | Path,
        evidence_root: str | Path,
        enrollment_registry_root: str | Path,
    ) -> "Issue94ActivationHandoffArtifact":
        if not isinstance(report, Mapping) or set(report) != _REPORT_FIELDS:
            raise QualificationActivationError(
                "activation_handoff_artifact:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        if (
            value.get("schema") != REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("issues") != []
            or value.get("provider_free") is not True
            or not isinstance(value.get("case_id"), str)
            or not isinstance(value.get("controller_id"), str)
            or _IDENTIFIER.fullmatch(value["controller_id"]) is None
            or value.get("counters") != _COUNTERS
            or not _sealed(value)
        ):
            raise QualificationActivationError(
                "activation_handoff_artifact:report_invalid"
            )
        now = _instant(value.get("evaluation_time"))
        reference = value.get("pre_spawn_artifact")
        if (
            not isinstance(reference, Mapping)
            or set(reference)
            != {
                "schema",
                "artifact_path",
                "artifact_sha256",
                "report_sha256",
            }
            or reference.get("schema")
            != "orch-dork/sealed-artifact-reference/v1"
            or not _is_sha(reference.get("artifact_sha256"))
            or not _is_sha(reference.get("report_sha256"))
        ):
            raise QualificationActivationError(
                "activation_handoff_artifact:pre_spawn_reference_invalid"
            )
        pre_spawn_path = Path(str(reference["artifact_path"]))
        try:
            pre_spawn_bytes = owned_file.read_owned_bytes(
                pre_spawn_path,
                max_bytes=MAX_ARTIFACT_BYTES,
                required_mode=0o600,
            )
            input_artifact = pre_spawn.read_issue94_pre_spawn_artifact(
                pre_spawn_path,
                source_root,
                evidence_root,
                enrollment_registry_root,
            )
        except (OSError, ValueError) as error:
            raise QualificationActivationError(
                "activation_handoff_artifact:pre_spawn_unavailable"
            ) from error
        if (
            hashlib.sha256(pre_spawn_bytes).hexdigest()
            != reference["artifact_sha256"]
            or input_artifact.report_sha256 != reference["report_sha256"]
            or input_artifact.report.get("case_id") != value["case_id"]
        ):
            raise QualificationActivationError(
                "activation_handoff_artifact:pre_spawn_binding_invalid"
            )
        source_payload = input_artifact.activation_preparation_report.get(
            "prepared_activation_payload"
        )
        identity = (
            source_payload.get("identity")
            if isinstance(source_payload, Mapping)
            else None
        )
        if not isinstance(identity, Mapping):
            raise QualificationActivationError(
                "activation_handoff_artifact:activation_identity_invalid"
            )
        runtime = CurrentTaskHookTrustArtifact.from_report(
            value.get("task_runtime_report"),
            expected_task_id=str(identity.get("root_thread_id")),
        )
        receipt_sha256 = value.get("hook_trust_receipt_sha256")
        if not _is_sha(receipt_sha256):
            raise QualificationActivationError(
                "activation_handoff_artifact:receipt_digest_invalid"
            )
        plugin_data = _canonical_plugin_data(create=False)
        receipt_path = (
            plugin_data
            / "governed-native"
            / "hook-trust"
            / (str(receipt_sha256) + ".json")
        )
        try:
            raw = owned_file.read_owned_bytes(
                receipt_path,
                max_bytes=MAX_RECEIPT_BYTES,
                required_mode=0o600,
            )
            envelope = json.loads(raw.decode("utf-8"))
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as error:
            raise QualificationActivationError(
                "activation_handoff_artifact:receipt_unavailable"
            ) from error
        if (
            hashlib.sha256(raw).hexdigest() != receipt_sha256
            or not isinstance(envelope, Mapping)
            or raw != _canonical(envelope)
        ):
            raise QualificationActivationError(
                "activation_handoff_artifact:receipt_binding_invalid"
            )
        trust_store = _trust_store()
        expected = _expected_trust_payload(
            controller_id=str(value["controller_id"]),
            identity=identity,
        )
        verification = _verify_receipt(
            envelope,
            expected=expected,
            runtime=runtime,
            evaluation_time=now,
            trust_store=trust_store,
        )
        expected_activation = _prepared_activation(
            input_artifact,
            str(receipt_sha256),
        )
        expected_controller = _controller_program(
            controller_id=str(value["controller_id"]),
            activation_report=expected_activation,
        )
        expected_source_roots = {
            "evidence": str(Path(evidence_root).resolve(strict=True)),
            "source": str(Path(source_root).resolve(strict=True)),
        }
        if (
            value.get("hook_trust_verification_report") != verification
            or value.get("activation_preparation_report")
            != expected_activation
            or value.get("controller_program") != expected_controller
            or value.get("controller_source_roots")
            != expected_source_roots
        ):
            raise QualificationActivationError(
                "activation_handoff_artifact:stage_binding_invalid"
            )
        authority = value.get("signing_authority")
        if (
            not isinstance(authority, Mapping)
            or set(authority)
            != {"host_id", "generation", "key_id", "fingerprint"}
            or authority.get("host_id") != verification.get("host_id")
            or authority.get("key_id") != verification.get("key_id")
            or authority.get("generation")
            != verification.get("trust_generation")
            or not _is_sha(authority.get("fingerprint"))
            or authority.get("fingerprint")
            != trust_store.keys.get(str(authority.get("key_id")), {}).get(
                "fingerprint"
            )
        ):
            raise QualificationActivationError(
                "activation_handoff_artifact:signing_authority_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            pre_spawn_artifact=input_artifact,
            task_runtime_report=deepcopy(runtime.report),
            hook_trust_receipt_sha256=str(receipt_sha256),
            hook_trust_verification_report=deepcopy(verification),
            activation_preparation_report=deepcopy(expected_activation),
            controller_program=deepcopy(expected_controller),
            controller_source_roots=deepcopy(expected_source_roots),
            counters={
                str(key): int(child)
                for key, child in value["counters"].items()
            },
        )


def read_issue94_activation_handoff_artifact(
    path: str | Path,
    source_root: str | Path,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
) -> Issue94ActivationHandoffArtifact:
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
        raise QualificationActivationError(
            "activation_handoff_artifact:unavailable"
        ) from error
    return Issue94ActivationHandoffArtifact.from_report(
        report,
        source_root,
        evidence_root,
        enrollment_registry_root,
    )


def materialize_issue94_activation_handoff(
    pre_spawn_artifact_path: str | Path,
    output_path: str | Path,
    source_root: str | Path,
    *,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
    controller_id: str,
    now: datetime | None = None,
    pre_turn: bool = False,
) -> dict[str, Any]:
    """Issue, persist, prepare, and seal one exact pre-activation handoff."""

    if not isinstance(controller_id, str) or _IDENTIFIER.fullmatch(
        controller_id
    ) is None:
        raise QualificationActivationError(
            "activation_handoff:controller_id_invalid"
        )
    evidence = _owned_directory(Path(evidence_root), create=False)
    output = _output_path(output_path, evidence)
    pre_spawn_path = Path(pre_spawn_artifact_path)
    input_artifact = pre_spawn.read_issue94_pre_spawn_artifact(
        pre_spawn_path,
        source_root,
        evidence,
        enrollment_registry_root,
    )
    reference = _pre_spawn_reference(pre_spawn_path, input_artifact)
    source_payload = input_artifact.activation_preparation_report.get(
        "prepared_activation_payload"
    )
    identity = (
        source_payload.get("identity")
        if isinstance(source_payload, Mapping)
        else None
    )
    if not isinstance(identity, Mapping):
        raise QualificationActivationError(
            "activation_handoff:activation_identity_invalid"
        )
    task_id = identity.get("root_thread_id")
    runtime = CurrentTaskHookTrustArtifact.from_report(
        local_task_runtime.observe_current_local_task_hook_trust(
            task_id=str(task_id),
            allow_pre_turn_idle=pre_turn,
        ),
        expected_task_id=str(task_id),
    )
    authority, signer, trust_store = _authority()
    evaluation_time = _instant(now or datetime.now(timezone.utc))
    expected = _expected_trust_payload(
        controller_id=controller_id,
        identity=identity,
    )
    trust_payload = {
        **expected,
        "mode": runtime.mode,
        "invocation_id": runtime.invocation_id,
        "hook_inventory_report_sha256": (
            runtime.hook_inventory_report_sha256
        ),
    }
    nonce = "hook-trust-" + _sha(
        {
            "controller_id": controller_id,
            "pre_spawn_report_sha256": input_artifact.report_sha256,
            "invocation_id": runtime.invocation_id,
        }
    )
    envelope = signer.issue(
        native_controller.HOOK_TRUST_RECEIPT_KIND,
        trust_payload,
        issued_at=_timestamp(evaluation_time - timedelta(seconds=1)),
        valid_until=_timestamp(evaluation_time + timedelta(minutes=4)),
        nonce=nonce,
    )
    encoded = _canonical(envelope)
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise QualificationActivationError(
            "activation_handoff:hook_trust_receipt_too_large"
        )
    receipt_sha256 = hashlib.sha256(encoded).hexdigest()
    plugin_data = _canonical_plugin_data(create=True)
    trust_root = _ensure_hook_trust_root(plugin_data)
    receipt_path = trust_root / (receipt_sha256 + ".json")
    created_receipt = False
    created_output = False
    try:
        rehearsal._write_create_only(receipt_path, encoded)
        created_receipt = True
        readback = owned_file.read_owned_bytes(
            receipt_path,
            max_bytes=MAX_RECEIPT_BYTES,
            required_mode=0o600,
        )
        if readback != encoded:
            raise QualificationActivationError(
                "activation_handoff:hook_trust_readback_mismatch"
            )
        verification = _verify_receipt(
            envelope,
            expected=expected,
            runtime=runtime,
            evaluation_time=evaluation_time,
            trust_store=trust_store,
        )
        activation_report = _prepared_activation(
            input_artifact,
            receipt_sha256,
        )
        controller_program = _controller_program(
            controller_id=controller_id,
            activation_report=activation_report,
        )
        core = {
            "schema": REPORT_SCHEMA,
            "status": "PASS",
            "issues": [],
            "case_id": input_artifact.report["case_id"],
            "controller_id": controller_id,
            "evaluation_time": _timestamp(evaluation_time),
            "pre_spawn_artifact": reference,
            "task_runtime_report": deepcopy(runtime.report),
            "signing_authority": {
                "host_id": authority["host_id"],
                "generation": authority["generation"],
                "key_id": authority["key_id"],
                "fingerprint": authority["fingerprint"],
            },
            "hook_trust_receipt_sha256": receipt_sha256,
            "hook_trust_verification_report": verification,
            "activation_preparation_report": activation_report,
            "controller_program": controller_program,
            "controller_source_roots": {
                "evidence": str(evidence.resolve(strict=True)),
                "source": str(Path(source_root).resolve(strict=True)),
            },
            "provider_free": True,
            "counters": deepcopy(_COUNTERS),
        }
        report = {**core, "report_sha256": _sha(core)}
        Issue94ActivationHandoffArtifact.from_report(
            report,
            source_root,
            evidence,
            enrollment_registry_root,
        )
        artifact_bytes = _canonical(report) + b"\n"
        rehearsal._write_create_only(output, artifact_bytes)
        created_output = True
        persisted = read_issue94_activation_handoff_artifact(
            output,
            source_root,
            evidence,
            enrollment_registry_root,
        )
        if persisted.report != report:
            raise QualificationActivationError(
                "activation_handoff_artifact:readback_mismatch"
            )
    except Exception:
        if created_output:
            try:
                output.unlink()
            except OSError:
                pass
        if created_receipt:
            try:
                receipt_path.unlink()
            except OSError:
                pass
        raise
    receipt_core = {
        "schema": RECEIPT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "artifact_path": str(output),
        "artifact_size_bytes": len(artifact_bytes),
        "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "report_sha256": persisted.report_sha256,
        "pre_spawn_report_sha256": input_artifact.report_sha256,
        "hook_trust_receipt_sha256": receipt_sha256,
        "controller_program_sha256": _sha(persisted.controller_program),
        "disposition": "READY_FOR_CONTROLLER_ACTIVATION",
        "counters": deepcopy(persisted.counters),
    }
    return {**receipt_core, "receipt_sha256": _sha(receipt_core)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pre-spawn-artifact", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument(
        "--enrollment-registry-root",
        type=Path,
        required=True,
    )
    parser.add_argument("--controller-id", required=True)
    parser.add_argument("--pre-turn", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--emit-controller-program", action="store_true")
    args = parser.parse_args(argv)
    try:
        receipt = materialize_issue94_activation_handoff(
            args.pre_spawn_artifact,
            args.output,
            args.source_root,
            evidence_root=args.evidence_root,
            enrollment_registry_root=args.enrollment_registry_root,
            controller_id=args.controller_id,
            pre_turn=args.pre_turn,
        )
        if args.emit_controller_program:
            artifact = read_issue94_activation_handoff_artifact(
                args.output,
                args.source_root,
                args.evidence_root,
                args.enrollment_registry_root,
            )
            emit_core = {
                "schema": EMIT_SCHEMA,
                "status": "PASS",
                "artifact_receipt": receipt,
                "controller_program": artifact.controller_program,
            }
            result = {**emit_core, "report_sha256": _sha(emit_core)}
        else:
            result = receipt
    except (
        KeyError,
        OSError,
        QualificationActivationError,
        TypeError,
        ValueError,
        observer_receipt.ObserverReceiptError,
        rehearsal.QualificationRehearsalError,
    ) as error:
        result = {
            "schema": RECEIPT_SCHEMA,
            "status": "FAIL",
            "issues": [str(error)],
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 1
    except Exception as error:
        result = {
            "schema": RECEIPT_SCHEMA,
            "status": "FAIL",
            "issues": [
                "activation_handoff:unexpected_failure:"
                + type(error).__name__
            ],
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


__all__ = [
    "EMIT_SCHEMA",
    "Issue94ActivationHandoffArtifact",
    "QualificationActivationError",
    "RECEIPT_SCHEMA",
    "REPORT_SCHEMA",
    "materialize_issue94_activation_handoff",
    "read_issue94_activation_handoff_artifact",
]


if __name__ == "__main__":
    raise SystemExit(main())
