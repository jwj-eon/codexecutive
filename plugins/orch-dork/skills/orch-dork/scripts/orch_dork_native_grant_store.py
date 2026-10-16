#!/usr/bin/env python3
"""Plugin-data-wide owner and single-use native-grant authority.

The RunStore event stream remains the controller and shared-capacity ledger.
This module adds only the host-wide facts that cannot safely live in an
attempt-local projection: the sole active controller identity and consumption
state for each exact native action.  It never stores occupancy or executes an
action.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Mapping, NamedTuple

import orch_dork_run_engine as run_engine
import orch_dork_run_store as run_store
import orch_dork_native_result as native_result
import orch_dork_owned_file as owned_file
import orch_dork_shared_capacity as shared_capacity


OWNER_SCHEMA = "orch-dork/governed-native-owner/v1"
GRANT_SCHEMA = "orch-dork/governed-native-grant/v1"
GRANT_HISTORY_SCHEMA = "orch-dork/governed-native-grant-history/v1"
HOOK_PROJECTION_HISTORY_SCHEMA = (
    "orch-dork/governed-native-hook-projection-history/v1"
)
AUTHORITY_MARKER_SCHEMA = "orch-dork/governed-native-authority-marker/v1"
AUTHORITY_MARKER_NAME = "authority-initialized.json"
AUTHORITY_TOMBSTONE_SCHEMA = (
    "orch-dork/governed-native-authority-tombstone/v1"
)
AUTHORITY_TOMBSTONE_RELATIVE = (
    Path("project-ground") / "native-authority-initialized.json"
)
CONTROLLER_RUN_MARKER_SCHEMA = (
    "orch-dork/governed-native-controller-run-marker/v1"
)
CONTROLLER_RUN_MARKER_RELATIVE = (
    Path("project-ground") / "native-controller-runs"
)
GRANT_TRANSITION_WITNESS_SCHEMA = (
    "orch-dork/governed-native-grant-transition-witness/v1"
)
GRANT_TRANSITION_COMMIT_SCHEMA = (
    "orch-dork/governed-native-grant-transition-commit/v1"
)
NATIVE_WITNESS_ROOT_ENV = "ORCH_DORK_NATIVE_WITNESS_ROOT"
NATIVE_WITNESS_MANIFEST_SCHEMA = (
    "orch-dork/governed-native-external-witness-manifest/v1"
)
CONTROLLER_RUN_WITNESS_SCHEMA = (
    "orch-dork/governed-native-controller-run-witness/v1"
)
DATABASE_RELATIVE = Path("governed-native") / "controller.sqlite3"

_GRANT_FIELDS = {
    "action_sha256",
    "action_kind",
    "controller_id",
    "controller_run_id",
    "controller_seq",
    "controller_event_hash",
    "action_id",
    "tool_name",
    "tool_input_sha256",
}
_CAPACITY_FIELDS = {
    "capacity_run_id",
    "capacity_seq",
    "capacity_event_hash",
}
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_OUTCOMES = frozenset({"completed", "failed", "cancelled", "timed_out", "unknown"})
_CONTROLLER_EVENT_SCHEMA = "orch-dork/governed-native-controller-event/v1"
_CONTROLLER_ACTION_SCHEMA = "orch-dork/governed-native-action/v1"
_PARTIAL_NATIVE_FAILURE_STAGE_SCHEMA = (
    "orch-dork/partial-native-failure-terminalization-stage/v1"
)
_POST_ACK_BRIDGE_FAILURE_STAGE_SCHEMA = (
    "orch-dork/post-ack-bridge-failure-terminalization-stage/v1"
)
_OBSERVED_SPAWN_STALL_STAGE_SCHEMA = (
    "orch-dork/observed-spawn-stall-terminalization-stage/v1"
)
_DURABLE_HOOK_EVENT_SCHEMA = "orch-dork/project-ground-durable-event/v1"
_RETAINED_OWNER_OBSERVATION_SCHEMA = (
    "orch-dork/retained-owner-native-observation/v1"
)
_RETAINED_OWNER_ACTION_EVIDENCE_SCHEMA = (
    "orch-dork/retained-owner-native-action-evidence/v1"
)
_NATIVE_ACTION_RECEIPT_SCHEMA = "orch-dork/native-action-receipt/v1"
_HOOK_EVIDENCE_FIELDS = {
    "action",
    "pretool_report_sha256",
    "pretool_durable_record_sha256",
    "posttool_report_sha256",
    "posttool_durable_record_sha256",
    "result_binding",
}
_HOOK_BINDING_SCHEMA = "orch-dork/governed-native-hook-binding/v1"
_HOOK_BINDING_FIELDS = frozenset(
    {
        "schema",
        "controller_id",
        "controller_run_id",
        "controller_seq",
        "controller_event_hash",
        "root_thread_id",
        "root_session_id",
        "root_model",
        "hook_definition_sha256",
        "hook_registration_sha256",
        "store_identity_sha256",
        "ground_state_sha256",
        "status",
        "action",
        "binding_sha256",
    }
)
_MAX_DURABLE_HOOK_RECORD_BYTES = 131_072
_MAX_CONTROLLER_RUN_MARKER_BYTES = 4096
_MAX_CONTROLLER_RUN_MARKERS = 4096
_MAX_GRANT_TRANSITION_WITNESS_BYTES = 4096
_MAX_GRANT_TRANSITION_WITNESSES = 32_768
_MAX_EXTERNAL_WITNESS_MANIFEST_BYTES = 4096
_DISPATCH_STATES = frozenset({"AUTHORIZED", "DISPATCHED", "POST_OBSERVED"})
_GRANT_COLUMNS = (
    "action_sha256",
    "schema",
    "controller_id",
    "controller_run_id",
    "controller_seq",
    "controller_event_hash",
    "action_id",
    "action_kind",
    "tool_name",
    "tool_input_sha256",
    "capacity_run_id",
    "capacity_seq",
    "capacity_event_hash",
    "state",
    "pretool_event_sha256",
    "pretool_report_sha256",
    "tool_use_id",
    "outcome",
    "result_sha256",
    "result_binding_sha256",
    "posttool_report_sha256",
)


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 256


class OwnerClosedAckCut(NamedTuple):
    """One closed producer/receiver shape; evidence validation stays independent."""

    program_schema: str
    failure_cut: str
    artifact_key: str
    completed_continuations: int
    owner_terminal_issue: str
    receipt_fields: frozenset[str]
    digest_fields: frozenset[str]

    worker_terminal_observed: bool
    control_result_unreadable: bool
    # The root advanced the controller itself inside the turn that asked for
    # one native call, so the continuation it authorized was never sent.
    root_extra_advance: bool = False

    @property
    def control_proof(self) -> bool:
        """The cut proves a control call rather than a hook denial: nothing was dispatched."""
        return self.control_result_unreadable or self.root_extra_advance


_OWNER_CLOSED_ACK_RECEIPT_FIELDS = frozenset(['abandoned_action_id', 'abandoned_action_sha256', 'abandoned_task_id', 'authorized_input_sha256', 'capacity_authority_state_sha256', 'created_lanes', 'created_logical_lane_id', 'created_worker_id', 'failure_artifacts', 'failure_cut', 'failure_evidence_sha256', 'historical_package_digest', 'historical_runtime_report_sha256', 'never_started_logical_lane_ids', 'owner_process_group_cleaned', 'owner_process_match_count', 'worker_process_match_count', 'worker_terminal_receipt_observed'])
_OWNER_CLOSED_ACK_DIGEST_FIELDS = frozenset(['abandoned_action_sha256', 'authorized_input_sha256', 'capacity_authority_state_sha256', 'failure_evidence_sha256', 'historical_package_digest', 'historical_runtime_report_sha256'])
_OWNER_CLOSED_ACK_DENIAL_FIELDS = frozenset({"denied_input_sha256", "pretool_denial_report_sha256"})
_OWNER_CLOSED_ACK_CONTROL_FIELDS = frozenset({"control_call_id", "control_result_sha256", "pre_turn_report_sha256"})
OWNER_CLOSED_ACK_DENIED_FIRST = OwnerClosedAckCut(
    "orch-dork/owner-closed-ack-stall-program/v1", "owner_closed_after_denied_first_continuation",
    "pretool_denial", 0, "issue170_owner:native_action_count_invalid",
    _OWNER_CLOSED_ACK_RECEIPT_FIELDS | _OWNER_CLOSED_ACK_DENIAL_FIELDS,
    _OWNER_CLOSED_ACK_DIGEST_FIELDS | _OWNER_CLOSED_ACK_DENIAL_FIELDS,
    worker_terminal_observed=False, control_result_unreadable=False,
)
OWNER_CLOSED_ACK_DENIED_SECOND = OWNER_CLOSED_ACK_DENIED_FIRST._replace(
    program_schema="orch-dork/owner-closed-ack-stall-program/v2",
    failure_cut="owner_closed_after_denied_second_continuation", completed_continuations=1,
    worker_terminal_observed=True,
)
OWNER_CLOSED_ACK_UNREADABLE = OwnerClosedAckCut(
    "orch-dork/owner-closed-ack-stall-program/v3", "owner_closed_after_unreadable_control_result",
    "pre_turn", 0, "issue170_owner:control_attribution_invalid",
    _OWNER_CLOSED_ACK_RECEIPT_FIELDS | _OWNER_CLOSED_ACK_CONTROL_FIELDS,
    _OWNER_CLOSED_ACK_DIGEST_FIELDS | (_OWNER_CLOSED_ACK_CONTROL_FIELDS - {"control_call_id"}),
    worker_terminal_observed=False, control_result_unreadable=True,
)
OWNER_CLOSED_ACK_ROOT_EXTRA_ADVANCE = OwnerClosedAckCut(
    "orch-dork/owner-closed-ack-stall-program/v4", "owner_closed_after_root_extra_advance",
    "pre_turn", 0, "issue170_owner:native_action_count_invalid",
    _OWNER_CLOSED_ACK_RECEIPT_FIELDS | _OWNER_CLOSED_ACK_CONTROL_FIELDS,
    _OWNER_CLOSED_ACK_DIGEST_FIELDS | (_OWNER_CLOSED_ACK_CONTROL_FIELDS - {"control_call_id"}),
    worker_terminal_observed=False, control_result_unreadable=False, root_extra_advance=True,
)
OWNER_CLOSED_ACK_CUTS = (
    OWNER_CLOSED_ACK_DENIED_FIRST, OWNER_CLOSED_ACK_DENIED_SECOND, OWNER_CLOSED_ACK_UNREADABLE,
    OWNER_CLOSED_ACK_ROOT_EXTRA_ADVANCE,
)


def owner_closed_ack_cut_for_program(schema: Any) -> OwnerClosedAckCut | None:
    return next((cut for cut in OWNER_CLOSED_ACK_CUTS if cut.program_schema == schema), None)


def owner_closed_ack_cut_for_failure(failure_cut: Any) -> OwnerClosedAckCut | None:
    return next((cut for cut in OWNER_CLOSED_ACK_CUTS if cut.failure_cut == failure_cut), None)


def _owner_closed_ack_terminal_valid(
    intent_event: Mapping[str, Any],
    terminal_event: Mapping[str, Any],
    intent_cursor: Mapping[str, Any],
    grant: Mapping[str, Any],
    binding: Mapping[str, Any],
    capacity_state_sha256: str,
) -> bool:
    """Recognize the sealed closed-owner cuts without inventing an outcome."""

    intent = intent_event.get("payload")
    terminal = terminal_event.get("payload")
    stage = terminal.get("stage_report") if isinstance(terminal, Mapping) else None
    receipt = stage.get("receipt") if isinstance(stage, Mapping) else None
    if not all(isinstance(value, Mapping) for value in (intent, terminal, stage, receipt)):
        return False
    cut = owner_closed_ack_cut_for_failure(receipt.get("failure_cut"))
    if cut is None:
        return False
    control = cut.control_proof
    receipt_fields = cut.receipt_fields
    digest_fields = cut.digest_fields
    lanes = receipt.get("created_lanes")
    artifacts = receipt.get("failure_artifacts")
    if not (
        set(receipt) == receipt_fields
        and all(_digest(receipt.get(field)) for field in digest_fields)
        and isinstance(lanes, list) and len(lanes) == 2
        and all(isinstance(lane, Mapping) and set(lane) == {"lane_id", "agent_id"}
                and _text(lane.get("agent_id")) and _text(lane.get("lane_id")) for lane in lanes)
        and len({lane["lane_id"] for lane in lanes}) == 2
        and len({lane["agent_id"] for lane in lanes}) == 2
        and isinstance(artifacts, Mapping)
        and set(artifacts) == {"owner_terminal", cut.artifact_key, "root_rollout"} | {lane["lane_id"] for lane in lanes}
        and all(isinstance(ref, Mapping) and set(ref) == {"path", "sha256"}
                and isinstance(ref.get("path"), str) and Path(ref["path"]).is_absolute()
                and _digest(ref.get("sha256")) for ref in artifacts.values())
    ):
        return False
    operation = "observed_spawn_stall_terminalization"
    return bool(
        intent_event.get("event_type") == "stage_intent"
        and set(intent) == {"operation", "failure_evidence_sha256", "evaluation_time", "proposed_action_sha256"}
        and intent.get("operation") == operation
        and intent.get("failure_evidence_sha256") == receipt["failure_evidence_sha256"]
        and _text(intent.get("evaluation_time")) and intent.get("proposed_action_sha256") is None
        and terminal_event.get("event_type") == "stage_result"
        and set(terminal) == {"intent_cursor", "stage_report", "action", "capacity_guard", "terminal", "cleanup_required", "terminal_evidence_sha256", "issues"}
        and terminal.get("intent_cursor") == dict(intent_cursor)
        and terminal.get("action") is None and terminal.get("capacity_guard") is None
        and terminal.get("terminal") is True and terminal.get("cleanup_required") is False
        and terminal.get("issues") == []
        and set(stage) == {"schema", "operation", "status", "disposition", "issues", "receipt", "next_action"}
        and stage.get("schema") == _OBSERVED_SPAWN_STALL_STAGE_SCHEMA
        and stage.get("operation") == operation and stage.get("status") == "PASS"
        and stage.get("disposition") == "OBSERVED_SPAWN_STALL_TERMINALIZED"
        and stage.get("issues") == [] and stage.get("next_action") == "terminal_capacity_settlement"
        and terminal.get("terminal_evidence_sha256") == NativeGrantStore._sha(stage)
        and receipt["abandoned_action_id"] == grant.get("action_id")
        and receipt["abandoned_action_sha256"] == grant.get("action_sha256")
        and receipt["abandoned_task_id"] == binding.get("root_thread_id")
        and receipt["authorized_input_sha256"] == grant.get("tool_input_sha256")
        and (_text(receipt["control_call_id"]) if control else receipt["denied_input_sha256"] != receipt["authorized_input_sha256"])
        and {"lane_id": receipt["created_logical_lane_id"], "agent_id": receipt["created_worker_id"]} == lanes[-1]
        and receipt["never_started_logical_lane_ids"] == []
        and receipt["worker_terminal_receipt_observed"] is cut.worker_terminal_observed
        and type(receipt["worker_process_match_count"]) is int and receipt["worker_process_match_count"] == 0
        and type(receipt["owner_process_match_count"]) is int and receipt["owner_process_match_count"] == 0
        and receipt["owner_process_group_cleaned"] is True
        and receipt["capacity_authority_state_sha256"] != capacity_state_sha256
    )


# Historical callers and instrumentation retain this compatibility name.
_owner_closed_ack_denial_terminal_valid = _owner_closed_ack_terminal_valid


def canonical_database_path(plugin_data: str | os.PathLike[str]) -> Path:
    return Path(plugin_data).resolve() / DATABASE_RELATIVE


def physical_store_sha256(path: str | os.PathLike[str]) -> str:
    resolved = str(Path(path).resolve())
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()


def canonical_witness_root() -> Path:
    configured = os.environ.get(NATIVE_WITNESS_ROOT_ENV)
    if configured:
        provided = Path(configured).expanduser()
    else:
        state_home = os.environ.get("XDG_STATE_HOME")
        provided = (
            Path(state_home).expanduser()
            if state_home
            else Path.home() / ".local" / "state"
        ) / "orch-dork" / "native-controller-witnesses"
    if not provided.is_absolute() or provided.is_symlink():
        raise ValueError("native witness root requires an absolute non-symlink path")
    return provided.resolve()


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


class NativeGrantStore:
    """Closed SQLite authority shared by the controller and synchronous hook."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        provided = Path(path)
        if not provided.is_absolute() or provided.is_symlink():
            raise ValueError("native grant store requires an absolute non-symlink path")
        self.path = provided.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            owned_file.verify_owned_regular_file(self.path)
        except FileNotFoundError:
            descriptor = os.open(
                self.path,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
        self.store_identity_sha256 = physical_store_sha256(self.path)
        self.authority_marker_path = self.path.parent / AUTHORITY_MARKER_NAME
        self.authority_tombstone_path = (
            self.path.parent.parent / AUTHORITY_TOMBSTONE_RELATIVE
        )
        self.controller_run_marker_root = (
            self.path.parent.parent / CONTROLLER_RUN_MARKER_RELATIVE
        )
        witness_base = canonical_witness_root()
        self.external_witness_root = (
            witness_base / self.store_identity_sha256
        )
        self.external_witness_manifest_path = (
            self.external_witness_root / "manifest.json"
        )
        self.external_controller_run_witness_root = (
            self.external_witness_root / "controller-runs"
        )
        self.grant_transition_witness_root = (
            self.external_witness_root / "grant-transitions"
        )
        self.initialize()
        owned_file.verify_owned_regular_file(self.path)

    def _connect(self) -> sqlite3.Connection:
        before = owned_file.verify_owned_regular_file(self.path)
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        try:
            after = owned_file.verify_owned_regular_file(self.path)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError("native grant store changed while opening")
        except Exception:
            connection.close()
            raise
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _authority_marker_payload(self) -> bytes:
        core = {
            "schema": AUTHORITY_MARKER_SCHEMA,
            "store_identity_sha256": self.store_identity_sha256,
        }
        marker = {**core, "marker_sha256": self._sha(core)}
        return self._canonical(marker) + b"\n"

    def _authority_tombstone_payload(self) -> bytes:
        core = {
            "schema": AUTHORITY_TOMBSTONE_SCHEMA,
            "store_identity_sha256": self.store_identity_sha256,
        }
        tombstone = {**core, "tombstone_sha256": self._sha(core)}
        return self._canonical(tombstone) + b"\n"

    @staticmethod
    def _authority_file_status(path: Path, expected_payload: bytes) -> str:
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return "ABSENT"
        except OSError:
            return "INVALID"
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > 4096
                or metadata.st_mode & 0o022
                or (
                    hasattr(os, "getuid")
                    and metadata.st_uid != os.getuid()
                )
            ):
                return "INVALID"
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                payload = handle.read(4097)
        finally:
            os.close(descriptor)
        return (
            "VALID"
            if payload == expected_payload
            else "INVALID"
        )

    def _authority_marker_status(self) -> str:
        return self._authority_file_status(
            self.authority_marker_path, self._authority_marker_payload()
        )

    def _authority_tombstone_status(self) -> str:
        return self._authority_file_status(
            self.authority_tombstone_path,
            self._authority_tombstone_payload(),
        )

    def _authority_files_valid(self) -> bool:
        return (
            self._authority_marker_status() == "VALID"
            and self._authority_tombstone_status() == "VALID"
        )

    def _ensure_authority_file(self, path: Path, payload: bytes) -> bool:
        status = self._authority_file_status(path, payload)
        if status != "ABSENT":
            return status == "VALID"
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                os.close(descriptor)
            directory = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except FileExistsError:
            pass
        except OSError:
            return False
        return self._authority_file_status(path, payload) == "VALID"

    def _ensure_authority_files(self) -> bool:
        return bool(
            self._ensure_authority_file(
                self.authority_marker_path, self._authority_marker_payload()
            )
            and self._ensure_authority_file(
                self.authority_tombstone_path,
                self._authority_tombstone_payload(),
            )
            and self._authority_files_valid()
        )

    @staticmethod
    def _ensure_read_only_file(path: Path, payload: bytes) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            parent = path.parent.lstat()
            if (
                not stat.S_ISDIR(parent.st_mode)
                or path.parent.is_symlink()
                or parent.st_mode & 0o022
                or (
                    hasattr(os, "getuid")
                    and parent.st_uid != os.getuid()
                )
            ):
                return False
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o400,
            )
        except FileExistsError:
            try:
                return (
                    owned_file.read_owned_bytes(
                        path,
                        max_bytes=max(len(payload), 1),
                        required_mode=0o400,
                    )
                    == payload
                )
            except (OSError, ValueError):
                return False
        except OSError:
            return False
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            return False
        finally:
            os.close(descriptor)
        try:
            directory = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return (
                owned_file.read_owned_bytes(
                    path,
                    max_bytes=max(len(payload), 1),
                    required_mode=0o400,
                )
                == payload
            )
        except (OSError, ValueError):
            return False

    @staticmethod
    def _owned_directory_valid(path: Path) -> bool:
        try:
            metadata = path.lstat()
        except OSError:
            return False
        return bool(
            stat.S_ISDIR(metadata.st_mode)
            and not path.is_symlink()
            and not metadata.st_mode & 0o022
            and (
                not hasattr(os, "getuid")
                or metadata.st_uid == os.getuid()
            )
        )

    def _external_witness_manifest(self) -> dict[str, Any]:
        core = {
            "schema": NATIVE_WITNESS_MANIFEST_SCHEMA,
            "store_identity_sha256": self.store_identity_sha256,
            "store_path": str(self.path),
        }
        return {**core, "manifest_sha256": self._sha(core)}

    def _external_witness_manifest_status(self) -> str:
        try:
            manifest = owned_file.read_owned_json(
                self.external_witness_manifest_path,
                max_bytes=_MAX_EXTERNAL_WITNESS_MANIFEST_BYTES,
                required_mode=0o400,
            )
        except FileNotFoundError:
            return "ABSENT"
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return "INVALID"
        return (
            "VALID"
            if manifest == self._external_witness_manifest()
            and self._owned_directory_valid(self.external_witness_root)
            else "INVALID"
        )

    def _ensure_external_witness_manifest(self) -> bool:
        status = self._external_witness_manifest_status()
        if status != "ABSENT":
            return status == "VALID"
        try:
            self.external_witness_root.mkdir(
                parents=True, exist_ok=True, mode=0o700
            )
        except OSError:
            return False
        if not self._owned_directory_valid(self.external_witness_root):
            return False
        payload = self._canonical(self._external_witness_manifest()) + b"\n"
        return bool(
            self._ensure_read_only_file(
                self.external_witness_manifest_path, payload
            )
            and self._external_witness_manifest_status() == "VALID"
        )

    def _controller_run_witness_path(self, controller_run_id: str) -> Path:
        name = hashlib.sha256(controller_run_id.encode("utf-8")).hexdigest()
        return self.external_controller_run_witness_root / (name + ".json")

    def _controller_run_witness(
        self, marker: Mapping[str, Any]
    ) -> dict[str, Any]:
        core = {
            "schema": CONTROLLER_RUN_WITNESS_SCHEMA,
            "store_identity_sha256": self.store_identity_sha256,
            "controller_run_marker": dict(marker),
        }
        return {**core, "witness_sha256": self._sha(core)}

    def _ensure_controller_run_witness(
        self, marker: Mapping[str, Any]
    ) -> bool:
        if not self._ensure_external_witness_manifest():
            return False
        run_id = marker.get("controller_run_id")
        if not _text(run_id):
            return False
        witness = self._controller_run_witness(marker)
        path = self._controller_run_witness_path(str(run_id))
        payload = self._canonical(witness) + b"\n"
        return self._ensure_read_only_file(path, payload)

    def _read_controller_run_witnesses(
        self,
    ) -> dict[str, dict[str, Any]]:
        if self._external_witness_manifest_status() != "VALID":
            raise ValueError("external witness manifest invalid")
        try:
            metadata = self.external_controller_run_witness_root.lstat()
        except FileNotFoundError:
            return {}
        if (
            not self._owned_directory_valid(
                self.external_controller_run_witness_root
            )
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise ValueError("controller run witness directory invalid")
        entries = sorted(self.external_controller_run_witness_root.iterdir())
        if len(entries) > _MAX_CONTROLLER_RUN_MARKERS:
            raise ValueError("controller run witness inventory oversized")
        witnesses: dict[str, dict[str, Any]] = {}
        fields = {
            "schema",
            "store_identity_sha256",
            "controller_run_marker",
            "witness_sha256",
        }
        for path in entries:
            witness = owned_file.read_owned_json(
                path,
                max_bytes=_MAX_CONTROLLER_RUN_MARKER_BYTES,
                required_mode=0o400,
            )
            marker = (
                witness.get("controller_run_marker")
                if isinstance(witness, Mapping)
                else None
            )
            core = (
                {
                    key: value
                    for key, value in witness.items()
                    if key != "witness_sha256"
                }
                if isinstance(witness, Mapping)
                else {}
            )
            run_id = (
                marker.get("controller_run_id")
                if isinstance(marker, Mapping)
                else None
            )
            if (
                not isinstance(witness, Mapping)
                or set(witness) != fields
                or witness.get("schema") != CONTROLLER_RUN_WITNESS_SCHEMA
                or witness.get("store_identity_sha256")
                != self.store_identity_sha256
                or not isinstance(marker, Mapping)
                or not _text(run_id)
                or witness.get("witness_sha256") != self._sha(core)
                or path != self._controller_run_witness_path(str(run_id))
                or run_id in witnesses
            ):
                raise ValueError("controller run witness invalid")
            witnesses[str(run_id)] = dict(witness)
        return witnesses

    def _controller_run_marker_path(self, controller_run_id: str) -> Path:
        name = hashlib.sha256(controller_run_id.encode("utf-8")).hexdigest()
        return self.controller_run_marker_root / (name + ".json")

    def _controller_run_marker(
        self,
        *,
        controller_id: str,
        controller_run_id: str,
        activation_sha256: str,
        previous: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        core = {
            "schema": CONTROLLER_RUN_MARKER_SCHEMA,
            "controller_id": controller_id,
            "controller_run_id": controller_run_id,
            "activation_sha256": activation_sha256,
            "store_identity_sha256": self.store_identity_sha256,
            "previous_controller_run_id": (
                previous.get("controller_run_id")
                if isinstance(previous, Mapping)
                else None
            ),
            "previous_marker_sha256": (
                previous.get("marker_sha256")
                if isinstance(previous, Mapping)
                else None
            ),
        }
        return {**core, "marker_sha256": self._sha(core)}

    def _read_controller_run_markers(self) -> dict[str, dict[str, Any]]:
        try:
            metadata = self.controller_run_marker_root.lstat()
        except FileNotFoundError:
            return {}
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or self.controller_run_marker_root.is_symlink()
            or metadata.st_mode & 0o022
            or (
                hasattr(os, "getuid")
                and metadata.st_uid != os.getuid()
            )
        ):
            raise ValueError("controller run marker directory invalid")
        entries = sorted(self.controller_run_marker_root.iterdir())
        if len(entries) > _MAX_CONTROLLER_RUN_MARKERS:
            raise ValueError("controller run marker inventory oversized")
        markers: dict[str, dict[str, Any]] = {}
        fields = {
            "schema",
            "controller_id",
            "controller_run_id",
            "activation_sha256",
            "store_identity_sha256",
            "previous_controller_run_id",
            "previous_marker_sha256",
            "marker_sha256",
        }
        for path in entries:
            marker = owned_file.read_owned_json(
                path,
                max_bytes=_MAX_CONTROLLER_RUN_MARKER_BYTES,
                required_mode=0o400,
            )
            if not isinstance(marker, Mapping) or set(marker) != fields:
                raise ValueError("controller run marker invalid")
            core = {
                key: value
                for key, value in marker.items()
                if key != "marker_sha256"
            }
            run_id = marker.get("controller_run_id")
            previous_run_id = marker.get("previous_controller_run_id")
            previous_marker_sha256 = marker.get("previous_marker_sha256")
            if (
                path.suffix != ".json"
                or not _text(marker.get("controller_id"))
                or not _text(run_id)
                or not _digest(marker.get("activation_sha256"))
                or marker.get("store_identity_sha256")
                != self.store_identity_sha256
                or marker.get("marker_sha256") != self._sha(core)
                or path != self._controller_run_marker_path(str(run_id))
                or (
                    (previous_run_id is None)
                    != (previous_marker_sha256 is None)
                )
                or (
                    previous_run_id is not None
                    and (
                        not _text(previous_run_id)
                        or not _digest(previous_marker_sha256)
                    )
                )
                or run_id in markers
            ):
                raise ValueError("controller run marker seal invalid")
            markers[str(run_id)] = dict(marker)
        return markers

    def _verified_controller_run_marker_chain(
        self, owner: Mapping[str, Any]
    ) -> dict[str, dict[str, Any]]:
        markers = self._read_controller_run_markers()
        witnesses = self._read_controller_run_witnesses()
        if set(witnesses) != set(markers) or any(
            witnesses[run_id].get("controller_run_marker") != marker
            for run_id, marker in markers.items()
        ):
            raise ValueError("controller run witness inventory mismatch")
        run_id = owner.get("controller_run_id")
        current = markers.get(str(run_id))
        if (
            current is None
            or current.get("controller_id") != owner.get("controller_id")
            or current.get("activation_sha256")
            != owner.get("activation_sha256")
        ):
            raise ValueError("active controller run marker missing")
        visited: set[str] = set()
        while current is not None:
            current_run_id = str(current["controller_run_id"])
            if current_run_id in visited:
                raise ValueError("controller run marker cycle")
            visited.add(current_run_id)
            previous_run_id = current.get("previous_controller_run_id")
            if previous_run_id is None:
                current = None
                continue
            previous = markers.get(str(previous_run_id))
            if (
                previous is None
                or previous.get("marker_sha256")
                != current.get("previous_marker_sha256")
            ):
                raise ValueError("controller run marker chain broken")
            current = previous
        if visited != set(markers):
            raise ValueError("controller run marker inventory disconnected")
        return markers

    def _ensure_controller_run_marker(
        self,
        *,
        controller_id: str,
        controller_run_id: str,
        activation_sha256: str,
        previous_owner: Mapping[str, Any] | None,
    ) -> bool:
        try:
            if not self._ensure_external_witness_manifest():
                return False
            markers = self._read_controller_run_markers()
            previous = None
            if previous_owner is not None:
                previous = markers.get(
                    str(previous_owner.get("controller_run_id"))
                )
                if (
                    previous is None
                    or previous.get("controller_id")
                    != previous_owner.get("controller_id")
                    or previous.get("activation_sha256")
                    != previous_owner.get("activation_sha256")
                ):
                    return False
            elif markers and controller_run_id not in markers:
                return False
            marker = self._controller_run_marker(
                controller_id=controller_id,
                controller_run_id=controller_run_id,
                activation_sha256=activation_sha256,
                previous=previous,
            )
            path = self._controller_run_marker_path(controller_run_id)
            payload = self._canonical(marker) + b"\n"
            if not self._ensure_read_only_file(path, payload):
                return False
            if not self._ensure_controller_run_witness(marker):
                return False
            stored = self._read_controller_run_markers().get(controller_run_id)
            witness = self._read_controller_run_witnesses().get(
                controller_run_id
            )
            return bool(
                stored == marker
                and isinstance(witness, Mapping)
                and witness.get("controller_run_marker") == marker
            )
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return False

    def controller_run_marker(
        self, controller_run_id: str
    ) -> dict[str, Any] | None:
        try:
            markers = self._read_controller_run_markers()
            witnesses = self._read_controller_run_witnesses()
            marker = markers.get(controller_run_id)
            witness = witnesses.get(controller_run_id)
            if (
                marker is None
                or not isinstance(witness, Mapping)
                or witness.get("controller_run_marker") != marker
            ):
                return None
            return deepcopy(marker)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def _authority_residue(connection: sqlite3.Connection) -> int:
        run_table_present = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runs'"
        ).fetchone() is not None
        residue_queries = [
            "SELECT COUNT(*) FROM governed_native_owner",
            "SELECT COUNT(*) FROM governed_native_grants",
            "SELECT COUNT(*) FROM governed_native_grant_history",
            "SELECT COUNT(*) FROM governed_native_hook_projection",
            "SELECT COUNT(*) FROM governed_native_hook_projection_history",
        ]
        if run_table_present:
            residue_queries.append(
                "SELECT COUNT(*) FROM runs WHERE run_id LIKE 'nativecontroller-%'"
            )
        return sum(
            int(connection.execute(query).fetchone()[0])
            for query in residue_queries
        )

    def initialize(self) -> None:
        marker_status = self._authority_marker_status()
        tombstone_status = self._authority_tombstone_status()
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS governed_native_owner (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema TEXT NOT NULL,
                    controller_id TEXT NOT NULL,
                    controller_run_id TEXT NOT NULL,
                    activation_sha256 TEXT NOT NULL,
                    store_identity_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governed_native_authority_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    projection_state INTEGER NOT NULL
                        CHECK (projection_state IN (-1, 0, 1))
                );
                CREATE TABLE IF NOT EXISTS governed_native_grants (
                    action_sha256 TEXT PRIMARY KEY,
                    schema TEXT NOT NULL,
                    controller_id TEXT NOT NULL,
                    controller_run_id TEXT NOT NULL,
                    controller_seq INTEGER NOT NULL,
                    controller_event_hash TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    action_kind TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    tool_input_sha256 TEXT NOT NULL,
                    capacity_run_id TEXT,
                    capacity_seq INTEGER,
                    capacity_event_hash TEXT,
                    state TEXT NOT NULL,
                    pretool_event_sha256 TEXT,
                    pretool_report_sha256 TEXT,
                    tool_use_id TEXT,
                    outcome TEXT,
                    result_sha256 TEXT,
                    result_binding_sha256 TEXT,
                    posttool_report_sha256 TEXT
                );
                CREATE TABLE IF NOT EXISTS governed_native_hook_projection (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    controller_id TEXT NOT NULL,
                    controller_run_id TEXT NOT NULL,
                    controller_seq INTEGER NOT NULL,
                    controller_event_hash TEXT NOT NULL,
                    binding_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governed_native_grant_history (
                    transition_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    schema TEXT NOT NULL,
                    action_sha256 TEXT NOT NULL,
                    action_transition INTEGER NOT NULL,
                    transition_type TEXT NOT NULL,
                    previous_record_sha256 TEXT,
                    grant_json TEXT NOT NULL,
                    grant_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL UNIQUE,
                    UNIQUE (action_sha256, action_transition)
                );
                CREATE TABLE IF NOT EXISTS governed_native_hook_projection_history (
                    projection_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    schema TEXT NOT NULL,
                    controller_id TEXT NOT NULL,
                    controller_run_id TEXT NOT NULL,
                    controller_seq INTEGER NOT NULL,
                    controller_event_hash TEXT NOT NULL,
                    binding_sha256 TEXT NOT NULL UNIQUE,
                    previous_binding_sha256 TEXT,
                    record_sha256 TEXT NOT NULL UNIQUE
                );
                """
            )
            meta = connection.execute(
                "SELECT projection_state FROM governed_native_authority_meta "
                "WHERE singleton = 1"
            ).fetchone()
            if meta is None:
                residue = self._authority_residue(connection)
                connection.execute(
                    "INSERT INTO governed_native_authority_meta "
                    "(singleton, projection_state) VALUES (1, ?)",
                    (
                        -1
                        if residue
                        or marker_status != "ABSENT"
                        or tombstone_status != "ABSENT"
                        else 0,
                    ),
                )
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(governed_native_grants)"
                ).fetchall()
            }
            if "tool_use_id" not in columns:
                connection.execute(
                    "ALTER TABLE governed_native_grants ADD COLUMN tool_use_id TEXT"
                )
            for column, declaration in (
                ("action_kind", "TEXT"),
                ("capacity_run_id", "TEXT"),
                ("capacity_seq", "INTEGER"),
                ("capacity_event_hash", "TEXT"),
                ("result_binding_sha256", "TEXT"),
            ):
                if column not in columns:
                    connection.execute(
                        "ALTER TABLE governed_native_grants ADD COLUMN "
                        + column
                        + " "
                        + declaration
                    )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS governed_native_tool_use_unique "
                "ON governed_native_grants(tool_use_id) "
                "WHERE tool_use_id IS NOT NULL"
            )

    @staticmethod
    def _grant_snapshot(row: sqlite3.Row | Mapping[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return {field: row[field] for field in _GRANT_COLUMNS}

    @staticmethod
    def _grant_shape_valid(grant: Mapping[str, Any]) -> bool:
        optional_digests = (
            "pretool_event_sha256",
            "pretool_report_sha256",
            "result_sha256",
            "result_binding_sha256",
            "posttool_report_sha256",
        )
        if (
            set(grant) != set(_GRANT_COLUMNS)
            or grant.get("schema") != GRANT_SCHEMA
            or not _digest(grant.get("action_sha256"))
            or grant.get("action_kind") not in {"spawn", "continue", "stop"}
            or not all(
                _text(grant.get(field))
                for field in (
                    "controller_id",
                    "controller_run_id",
                    "action_id",
                    "tool_name",
                )
            )
            or type(grant.get("controller_seq")) is not int
            or grant["controller_seq"] < 1
            or not _digest(grant.get("controller_event_hash"))
            or not _digest(grant.get("tool_input_sha256"))
            or grant.get("state")
            not in {
                "PROVISIONAL",
                "AUTHORIZED",
                "DISPATCHED",
                "POST_OBSERVED",
                "OUTCOME_UNKNOWN",
                "TERMINAL_OUTCOME_UNKNOWN",
                "TERMINAL_PRETOOL_DENIED",
                "TERMINAL_NOT_DISPATCHED",
                "STALE",
            }
            or any(
                grant.get(field) is not None
                and not _digest(grant.get(field))
                for field in optional_digests
            )
            or (
                grant.get("tool_use_id") is not None
                and not _text(grant.get("tool_use_id"))
            )
            or (
                grant.get("outcome") is not None
                and grant.get("outcome") not in _OUTCOMES
            )
        ):
            return False
        capacity = (
            grant.get("capacity_run_id"),
            grant.get("capacity_seq"),
            grant.get("capacity_event_hash"),
        )
        if grant.get("action_kind") == "spawn":
            if (
                not _text(capacity[0])
                or type(capacity[1]) is not int
                or capacity[1] < 1
                or not _digest(capacity[2])
            ):
                return False
        elif any(value is not None for value in capacity):
            return False
        state = grant.get("state")
        pre_event = grant.get("pretool_event_sha256")
        pre_report = grant.get("pretool_report_sha256")
        tool_use_id = grant.get("tool_use_id")
        outcome = grant.get("outcome")
        result = grant.get("result_sha256")
        result_binding = grant.get("result_binding_sha256")
        post_report = grant.get("posttool_report_sha256")
        if state in {
            "PROVISIONAL",
            "AUTHORIZED",
            "TERMINAL_PRETOOL_DENIED",
            "TERMINAL_NOT_DISPATCHED",
            "STALE",
        }:
            return all(
                value is None
                for value in (
                    pre_event,
                    pre_report,
                    tool_use_id,
                    outcome,
                    result,
                    result_binding,
                    post_report,
                )
            )
        if state in {
            "DISPATCHED",
            "OUTCOME_UNKNOWN",
            "TERMINAL_OUTCOME_UNKNOWN",
        }:
            return bool(
                _digest(pre_event)
                and _text(tool_use_id)
                and outcome is None
                and result is None
                and result_binding is None
                and post_report is None
            )
        return bool(
            state == "POST_OBSERVED"
            and _digest(pre_event)
            and _digest(pre_report)
            and _text(tool_use_id)
            and outcome in _OUTCOMES
            and _digest(result)
            and _digest(result_binding)
            and _digest(post_report)
        )

    @staticmethod
    def _grant_transition_valid(
        previous: Mapping[str, Any] | None,
        current: Mapping[str, Any],
        transition_type: str,
    ) -> bool:
        if not NativeGrantStore._grant_shape_valid(current):
            return False
        if previous is None:
            return transition_type == "PREPARED" and current.get("state") == "PROVISIONAL"
        if not NativeGrantStore._grant_shape_valid(previous):
            return False
        changed = {
            field
            for field in _GRANT_COLUMNS
            if previous.get(field) != current.get(field)
        }
        allowed = {
            "FINALIZED": (
                "PROVISIONAL",
                "AUTHORIZED",
                {"state", "controller_seq", "controller_event_hash"},
            ),
            "CLAIMED": (
                "AUTHORIZED",
                "DISPATCHED",
                {"state", "pretool_event_sha256", "tool_use_id"},
            ),
            "PRETOOL_BOUND": (
                "DISPATCHED",
                "DISPATCHED",
                {"pretool_report_sha256"},
            ),
            "PRETOOL_UNKNOWN": (
                "DISPATCHED",
                "OUTCOME_UNKNOWN",
                {"state"},
            ),
            "POSTTOOL_UNKNOWN": (
                "DISPATCHED",
                "OUTCOME_UNKNOWN",
                {"state"},
            ),
            "PARTIAL_NATIVE_FAILURE_TERMINALIZED": (
                "OUTCOME_UNKNOWN",
                "TERMINAL_OUTCOME_UNKNOWN",
                {"state"},
            ),
            "PRETOOL_DENIAL_TERMINALIZED": (
                "AUTHORIZED",
                "TERMINAL_PRETOOL_DENIED",
                {"state"},
            ),
            "CAPACITY_STALE": (
                "AUTHORIZED",
                "STALE",
                {"state"},
            ),
            # Historical interruption recovery changes authority only; no
            # dispatch claim or result may appear on this terminal transition.
            "INTERRUPTION_TERMINALIZED": (
                "AUTHORIZED",
                "TERMINAL_NOT_DISPATCHED",
                {"state"},
            ),
            "POSTTOOL_RECORDED": (
                "DISPATCHED",
                "POST_OBSERVED",
                {
                    "state",
                    "outcome",
                    "result_sha256",
                    "result_binding_sha256",
                    "posttool_report_sha256",
                },
            ),
            # A completed built-in collaboration call is always visible on
            # the retained owner connection.  Codex versions may also dispatch
            # PreToolUse/PostToolUse for the same call.  Preserve the existing
            # grant row shape while allowing the source-owned controller to
            # record the direct observation when it is the only evidence rail.
            "RETAINED_OWNER_OBSERVED": (
                "AUTHORIZED",
                "POST_OBSERVED",
                {
                    "state",
                    "pretool_event_sha256",
                    "pretool_report_sha256",
                    "tool_use_id",
                    "outcome",
                    "result_sha256",
                    "result_binding_sha256",
                    "posttool_report_sha256",
                },
            ),
        }
        rule = allowed.get(transition_type)
        if rule is None:
            return False
        if (
            previous.get("state") != rule[0]
            or current.get("state") != rule[1]
            or changed != rule[2]
        ):
            return False
        if transition_type == "FINALIZED":
            return current.get("controller_seq") == previous.get("controller_seq") + 1
        return True

    def _verified_grant(
        self, connection: sqlite3.Connection, action_sha256: str
    ) -> dict[str, Any] | None:
        snapshot = self._grant_snapshot(
            connection.execute(
                "SELECT " + ", ".join(_GRANT_COLUMNS)
                + " FROM governed_native_grants WHERE action_sha256 = ?",
                (action_sha256,),
            ).fetchone()
        )
        history = connection.execute(
            "SELECT schema, action_sha256, action_transition, transition_type, "
            "previous_record_sha256, grant_json, grant_sha256, record_sha256 "
            "FROM governed_native_grant_history WHERE action_sha256 = ? "
            "ORDER BY action_transition",
            (action_sha256,),
        ).fetchall()
        if snapshot is None and not history:
            return None
        if snapshot is None or not history:
            raise ValueError("grant history or snapshot missing")
        previous_grant: Mapping[str, Any] | None = None
        previous_record_sha256 = None
        for expected_transition, raw in enumerate(history, start=1):
            row = dict(raw)
            grant = json.loads(str(row.get("grant_json")))
            if not isinstance(grant, Mapping):
                raise ValueError("grant history payload invalid")
            grant = dict(grant)
            core = {
                "schema": row.get("schema"),
                "action_sha256": row.get("action_sha256"),
                "action_transition": row.get("action_transition"),
                "transition_type": row.get("transition_type"),
                "previous_record_sha256": row.get("previous_record_sha256"),
                "grant_sha256": row.get("grant_sha256"),
            }
            if (
                row.get("schema") != GRANT_HISTORY_SCHEMA
                or row.get("action_sha256") != action_sha256
                or row.get("action_transition") != expected_transition
                or row.get("previous_record_sha256")
                != previous_record_sha256
                or row.get("grant_json")
                != self._canonical(grant).decode("utf-8")
                or row.get("grant_sha256") != self._sha(grant)
                or row.get("record_sha256") != self._sha(core)
                or not self._grant_transition_valid(
                    previous_grant, grant, str(row.get("transition_type"))
                )
            ):
                raise ValueError("grant history invalid")
            previous_grant = grant
            previous_record_sha256 = row.get("record_sha256")
        if previous_grant != snapshot:
            raise ValueError("grant snapshot does not match history")
        return snapshot

    def _append_grant_history(
        self,
        connection: sqlite3.Connection,
        *,
        previous: Mapping[str, Any] | None,
        current: Mapping[str, Any],
        transition_type: str,
    ) -> dict[str, Any]:
        if not self._grant_transition_valid(previous, current, transition_type):
            raise ValueError("grant transition invalid")
        tail = connection.execute(
            "SELECT action_transition, record_sha256 FROM governed_native_grant_history "
            "WHERE action_sha256 = ? ORDER BY action_transition DESC LIMIT 1",
            (current["action_sha256"],),
        ).fetchone()
        expected_transition = 1 if tail is None else int(tail["action_transition"]) + 1
        previous_record_sha256 = None if tail is None else str(tail["record_sha256"])
        if (previous is None) != (tail is None):
            raise ValueError("grant history continuity invalid")
        grant_json = self._canonical(current).decode("utf-8")
        grant_sha256 = self._sha(current)
        core = {
            "schema": GRANT_HISTORY_SCHEMA,
            "action_sha256": current["action_sha256"],
            "action_transition": expected_transition,
            "transition_type": transition_type,
            "previous_record_sha256": previous_record_sha256,
            "grant_sha256": grant_sha256,
        }
        record_sha256 = self._sha(core)
        global_tail = connection.execute(
            "SELECT record_sha256 FROM governed_native_grant_history "
            "ORDER BY transition_seq DESC LIMIT 1"
        ).fetchone()
        cursor = connection.execute(
            "INSERT INTO governed_native_grant_history "
            "(schema, action_sha256, action_transition, transition_type, "
            "previous_record_sha256, grant_json, grant_sha256, record_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                GRANT_HISTORY_SCHEMA,
                current["action_sha256"],
                expected_transition,
                transition_type,
                previous_record_sha256,
                grant_json,
                grant_sha256,
                record_sha256,
            ),
        )
        transition_seq = int(cursor.lastrowid)
        witness_core = {
            "schema": GRANT_TRANSITION_WITNESS_SCHEMA,
            "store_identity_sha256": self.store_identity_sha256,
            "transition_seq": transition_seq,
            "action_sha256": current["action_sha256"],
            "action_transition": expected_transition,
            "transition_type": transition_type,
            "previous_action_record_sha256": previous_record_sha256,
            "previous_global_record_sha256": (
                str(global_tail["record_sha256"])
                if global_tail is not None
                else None
            ),
            "grant_sha256": grant_sha256,
            "record_sha256": record_sha256,
        }
        witness = {
            **witness_core,
            "witness_sha256": self._sha(witness_core),
        }
        if not self._record_grant_transition_intent(witness):
            raise ValueError("grant transition witness intent unavailable")
        return witness

    def _grant_transition_witness_path(
        self,
        transition_seq: int,
        record_sha256: str,
        *,
        phase: str,
    ) -> Path:
        if phase not in {"intent", "committed"}:
            raise ValueError("grant transition witness phase invalid")
        return self.grant_transition_witness_root / (
            f"{transition_seq:020d}-{record_sha256}.{phase}.json"
        )

    def _record_grant_transition_intent(
        self, witness: Mapping[str, Any]
    ) -> bool:
        if not self._ensure_external_witness_manifest():
            return False
        transition_seq = witness.get("transition_seq")
        record_sha256 = witness.get("record_sha256")
        if (
            type(transition_seq) is not int
            or transition_seq < 1
            or not _digest(record_sha256)
        ):
            return False
        path = self._grant_transition_witness_path(
            transition_seq, str(record_sha256), phase="intent"
        )
        try:
            siblings = list(
                self.grant_transition_witness_root.glob(
                    f"{transition_seq:020d}-*.intent.json"
                )
            )
        except OSError:
            return False
        if siblings and siblings != [path]:
            return False
        return self._ensure_read_only_file(
            path, self._canonical(witness) + b"\n"
        )

    def _grant_transition_commit(
        self, witness: Mapping[str, Any]
    ) -> dict[str, Any]:
        core = {
            "schema": GRANT_TRANSITION_COMMIT_SCHEMA,
            "store_identity_sha256": self.store_identity_sha256,
            "transition_seq": witness.get("transition_seq"),
            "record_sha256": witness.get("record_sha256"),
            "intent_witness_sha256": witness.get("witness_sha256"),
        }
        return {**core, "commit_sha256": self._sha(core)}

    def _record_grant_transition_commit(
        self, witness: Mapping[str, Any]
    ) -> bool:
        if not self._ensure_external_witness_manifest():
            return False
        transition_seq = witness.get("transition_seq")
        record_sha256 = witness.get("record_sha256")
        if (
            type(transition_seq) is not int
            or transition_seq < 1
            or not _digest(record_sha256)
            or not _digest(witness.get("witness_sha256"))
        ):
            return False
        committed = self._grant_transition_commit(witness)
        path = self._grant_transition_witness_path(
            transition_seq, str(record_sha256), phase="committed"
        )
        return self._ensure_read_only_file(
            path, self._canonical(committed) + b"\n"
        )

    def _read_grant_transition_witnesses(
        self,
    ) -> list[dict[str, Any]]:
        if self._external_witness_manifest_status() != "VALID":
            raise ValueError("external witness manifest invalid")
        try:
            metadata = self.grant_transition_witness_root.lstat()
        except FileNotFoundError:
            return []
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or not self._owned_directory_valid(
                self.grant_transition_witness_root
            )
        ):
            raise ValueError("grant transition witness directory invalid")
        all_entries = sorted(self.grant_transition_witness_root.iterdir())
        if len(all_entries) > _MAX_GRANT_TRANSITION_WITNESSES * 2:
            raise ValueError("grant transition witness inventory oversized")
        entries = [
            path for path in all_entries if path.name.endswith(".intent.json")
        ]
        if any(
            not path.name.endswith((".intent.json", ".committed.json"))
            for path in all_entries
        ):
            raise ValueError("grant transition witness filename invalid")
        fields = {
            "schema",
            "store_identity_sha256",
            "transition_seq",
            "action_sha256",
            "action_transition",
            "transition_type",
            "previous_action_record_sha256",
            "previous_global_record_sha256",
            "grant_sha256",
            "record_sha256",
            "witness_sha256",
        }
        witnesses: list[dict[str, Any]] = []
        seen_sequences: set[int] = set()
        for path in entries:
            witness = owned_file.read_owned_json(
                path,
                max_bytes=_MAX_GRANT_TRANSITION_WITNESS_BYTES,
                required_mode=0o400,
            )
            core = (
                {
                    key: value
                    for key, value in witness.items()
                    if key != "witness_sha256"
                }
                if isinstance(witness, Mapping)
                else {}
            )
            transition_seq = witness.get("transition_seq") if isinstance(
                witness, Mapping
            ) else None
            record_sha256 = witness.get("record_sha256") if isinstance(
                witness, Mapping
            ) else None
            if (
                not isinstance(witness, Mapping)
                or set(witness) != fields
                or witness.get("schema")
                != GRANT_TRANSITION_WITNESS_SCHEMA
                or witness.get("store_identity_sha256")
                != self.store_identity_sha256
                or type(transition_seq) is not int
                or transition_seq < 1
                or transition_seq in seen_sequences
                or not _digest(witness.get("action_sha256"))
                or type(witness.get("action_transition")) is not int
                or witness["action_transition"] < 1
                or not _text(witness.get("transition_type"))
                or (
                    witness.get("previous_action_record_sha256") is not None
                    and not _digest(
                        witness.get("previous_action_record_sha256")
                    )
                )
                or (
                    witness.get("previous_global_record_sha256") is not None
                    and not _digest(
                        witness.get("previous_global_record_sha256")
                    )
                )
                or not _digest(witness.get("grant_sha256"))
                or not _digest(record_sha256)
                or witness.get("witness_sha256") != self._sha(core)
                or path
                != self._grant_transition_witness_path(
                    transition_seq,
                    str(record_sha256),
                    phase="intent",
                )
            ):
                raise ValueError("grant transition witness invalid")
            seen_sequences.add(transition_seq)
            witnesses.append(dict(witness))
        return witnesses

    def _read_grant_transition_commits(
        self,
    ) -> list[dict[str, Any]]:
        if self._external_witness_manifest_status() != "VALID":
            raise ValueError("external witness manifest invalid")
        try:
            metadata = self.grant_transition_witness_root.lstat()
        except FileNotFoundError:
            return []
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or not self._owned_directory_valid(
                self.grant_transition_witness_root
            )
        ):
            raise ValueError("grant transition witness directory invalid")
        entries = sorted(
            path
            for path in self.grant_transition_witness_root.iterdir()
            if path.name.endswith(".committed.json")
        )
        fields = {
            "schema",
            "store_identity_sha256",
            "transition_seq",
            "record_sha256",
            "intent_witness_sha256",
            "commit_sha256",
        }
        commits: list[dict[str, Any]] = []
        seen_sequences: set[int] = set()
        for path in entries:
            committed = owned_file.read_owned_json(
                path,
                max_bytes=_MAX_GRANT_TRANSITION_WITNESS_BYTES,
                required_mode=0o400,
            )
            core = (
                {
                    key: value
                    for key, value in committed.items()
                    if key != "commit_sha256"
                }
                if isinstance(committed, Mapping)
                else {}
            )
            transition_seq = (
                committed.get("transition_seq")
                if isinstance(committed, Mapping)
                else None
            )
            record_sha256 = (
                committed.get("record_sha256")
                if isinstance(committed, Mapping)
                else None
            )
            if (
                not isinstance(committed, Mapping)
                or set(committed) != fields
                or committed.get("schema")
                != GRANT_TRANSITION_COMMIT_SCHEMA
                or committed.get("store_identity_sha256")
                != self.store_identity_sha256
                or type(transition_seq) is not int
                or transition_seq < 1
                or transition_seq in seen_sequences
                or not _digest(record_sha256)
                or not _digest(committed.get("intent_witness_sha256"))
                or committed.get("commit_sha256") != self._sha(core)
                or path
                != self._grant_transition_witness_path(
                    transition_seq,
                    str(record_sha256),
                    phase="committed",
                )
            ):
                raise ValueError("grant transition commit invalid")
            seen_sequences.add(transition_seq)
            commits.append(dict(committed))
        return commits

    def _verify_grant_transition_witnesses(
        self, connection: sqlite3.Connection
    ) -> None:
        rows = connection.execute(
            "SELECT transition_seq, action_sha256, action_transition, "
            "transition_type, previous_record_sha256, grant_sha256, "
            "record_sha256 FROM governed_native_grant_history "
            "ORDER BY transition_seq"
        ).fetchall()
        expected: list[dict[str, Any]] = []
        previous_global_record_sha256 = None
        for raw in rows:
            row = dict(raw)
            core = {
                "schema": GRANT_TRANSITION_WITNESS_SCHEMA,
                "store_identity_sha256": self.store_identity_sha256,
                "transition_seq": int(row["transition_seq"]),
                "action_sha256": str(row["action_sha256"]),
                "action_transition": int(row["action_transition"]),
                "transition_type": str(row["transition_type"]),
                "previous_action_record_sha256": row[
                    "previous_record_sha256"
                ],
                "previous_global_record_sha256": (
                    previous_global_record_sha256
                ),
                "grant_sha256": str(row["grant_sha256"]),
                "record_sha256": str(row["record_sha256"]),
            }
            expected.append({**core, "witness_sha256": self._sha(core)})
            previous_global_record_sha256 = str(row["record_sha256"])
        intents = self._read_grant_transition_witnesses()
        trailing_intent = None
        if len(intents) == len(expected) + 1 and intents[:-1] == expected:
            candidate = intents[-1]
            if (
                candidate.get("previous_global_record_sha256")
                == previous_global_record_sha256
                and candidate.get("transition_seq")
                == (
                    int(rows[-1]["transition_seq"]) + 1
                    if rows
                    else 1
                )
            ):
                trailing_intent = candidate
        if intents != expected and trailing_intent is None:
            raise ValueError("grant transition witness inventory mismatch")
        expected_commits = [
            self._grant_transition_commit(witness)
            for witness in expected
        ]
        if self._read_grant_transition_commits() != expected_commits:
            raise ValueError("grant transition commit inventory mismatch")

    def _verify_all_grants(self, connection: sqlite3.Connection) -> set[str]:
        self._verify_grant_transition_witnesses(connection)
        action_ids = {
            str(row[0])
            for row in connection.execute(
                "SELECT action_sha256 FROM governed_native_grants "
                "UNION SELECT action_sha256 FROM governed_native_grant_history"
            ).fetchall()
        }
        for action_sha256 in sorted(action_ids):
            if self._verified_grant(connection, action_sha256) is None:
                raise ValueError("grant authority missing")
        return action_ids

    def _controller_event(self, row: Mapping[str, Any]) -> Mapping[str, Any]:
        facts = json.loads(str(row["payload"]))
        raw = (
            facts.get("deliverables", {}).get("controller_event")
            if isinstance(facts, Mapping)
            else None
        )
        event = json.loads(raw) if isinstance(raw, str) else None
        if not isinstance(event, Mapping) or set(event) != {
            "schema",
            "event_type",
            "payload",
            "event_sha256",
        }:
            raise ValueError("controller event invalid")
        core = {
            key: event[key]
            for key in ("schema", "event_type", "payload")
        }
        if (
            event.get("schema") != _CONTROLLER_EVENT_SCHEMA
            or event.get("event_sha256") != self._sha(core)
        ):
            raise ValueError("controller event seal invalid")
        return event

    def _retained_hook_record(
        self,
        *,
        session_id: Any,
        report_sha256: Any,
        durable_record_sha256: Any,
    ) -> Mapping[str, Any]:
        if (
            not _text(session_id)
            or not _digest(report_sha256)
            or not _digest(durable_record_sha256)
        ):
            raise ValueError("retained hook evidence identity invalid")
        session_key = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        path = (
            self.path.parent.parent
            / "project-ground"
            / "events"
            / session_key
            / (report_sha256 + ".json")
        )
        record = owned_file.read_owned_json(
            path, max_bytes=_MAX_DURABLE_HOOK_RECORD_BYTES
        )
        if not isinstance(record, Mapping):
            raise ValueError("retained hook evidence invalid")
        core = {
            key: child
            for key, child in record.items()
            if key != "durable_record_sha256"
        }
        if (
            record.get("schema") != _DURABLE_HOOK_EVENT_SCHEMA
            or record.get("report_sha256") != report_sha256
            or record.get("durable_record_sha256")
            != durable_record_sha256
            or self._sha(core) != durable_record_sha256
        ):
            raise ValueError("retained hook evidence seal invalid")
        return record

    def _verify_retained_hook_evidence(
        self,
        *,
        evidence: Any,
        action: Mapping[str, Any],
        grant: Mapping[str, Any],
        session_id: Any,
    ) -> None:
        if (
            not isinstance(evidence, Mapping)
            or set(evidence) != _HOOK_EVIDENCE_FIELDS
            or evidence.get("action") != action
            or grant.get("state") != "POST_OBSERVED"
            or grant.get("pretool_report_sha256")
            != evidence.get("pretool_report_sha256")
            or grant.get("posttool_report_sha256")
            != evidence.get("posttool_report_sha256")
            or grant.get("result_binding_sha256")
            != self._sha(evidence.get("result_binding"))
        ):
            raise ValueError("retained hook evidence binding invalid")
        pretool = self._retained_hook_record(
            session_id=session_id,
            report_sha256=evidence.get("pretool_report_sha256"),
            durable_record_sha256=evidence.get(
                "pretool_durable_record_sha256"
            ),
        )
        posttool = self._retained_hook_record(
            session_id=session_id,
            report_sha256=evidence.get("posttool_report_sha256"),
            durable_record_sha256=evidence.get(
                "posttool_durable_record_sha256"
            ),
        )
        pretool_native = pretool.get("native_controller")
        posttool_native = posttool.get("native_controller")
        pretool_identity = pretool.get("identity")
        posttool_identity = posttool.get("identity")
        if (
            pretool.get("hook_event_name") != "PreToolUse"
            or posttool.get("hook_event_name") != "PostToolUse"
            or not isinstance(pretool_identity, Mapping)
            or not isinstance(posttool_identity, Mapping)
            or pretool_identity.get("session_id") != session_id
            or posttool_identity.get("session_id") != session_id
            or not isinstance(pretool_native, Mapping)
            or not isinstance(posttool_native, Mapping)
            or pretool_native.get("action_id") != action.get("action_id")
            or posttool_native.get("action_id") != action.get("action_id")
            or posttool_native.get("result_binding")
            != evidence.get("result_binding")
        ):
            raise ValueError("retained hook evidence content invalid")

    def _verify_retained_owner_evidence(
        self,
        *,
        evidence: Any,
        action: Mapping[str, Any],
        grant: Mapping[str, Any],
        root_thread_id: Any,
        session_id: Any,
    ) -> None:
        if (
            not isinstance(evidence, Mapping)
            or set(evidence)
            != {
                "schema",
                "action",
                "owner_observation",
                "native_receipt",
                "result_binding",
            }
            or evidence.get("schema")
            != _RETAINED_OWNER_ACTION_EVIDENCE_SCHEMA
            or evidence.get("action") != action
            or not isinstance(evidence.get("owner_observation"), Mapping)
            or not isinstance(evidence.get("native_receipt"), Mapping)
        ):
            raise ValueError("retained owner evidence shape invalid")
        observation = evidence["owner_observation"]
        receipt = evidence["native_receipt"]
        observation_core = {
            key: value
            for key, value in observation.items()
            if key != "report_sha256"
        }
        normalized = native_result.normalize_native_result(
            evidence.get("result_binding"),
            action_kind=action.get("kind"),
            expected_lane_ids=action.get("lane_ids"),
            outcome=receipt.get("outcome"),
        )
        if (
            set(observation)
            != {
                "schema",
                "status",
                "task_id",
                "session_id",
                "turn_id",
                "thread_read_sha256",
                "tool_call_id",
                "native_receipt_sha256",
                "report_sha256",
            }
            or observation.get("schema")
            != _RETAINED_OWNER_OBSERVATION_SCHEMA
            or observation.get("status") != "OBSERVED"
            or observation.get("task_id") != root_thread_id
            or observation.get("session_id") != session_id
            or not _text(observation.get("turn_id"))
            or not _digest(observation.get("thread_read_sha256"))
            or not _text(observation.get("tool_call_id"))
            or observation.get("native_receipt_sha256") != self._sha(receipt)
            or observation.get("report_sha256") != self._sha(observation_core)
            or set(receipt)
            != {
                "schema",
                "action_id",
                "outcome",
                "tool_name",
                "tool_input_sha256",
                "tool_use_id",
                "result_sha256",
                "result_binding",
                "source_pointer",
            }
            or receipt.get("schema") != _NATIVE_ACTION_RECEIPT_SCHEMA
            or receipt.get("action_id") != action.get("action_id")
            or receipt.get("tool_name") != action.get("tool_name")
            or receipt.get("tool_input_sha256")
            != action.get("tool_input_sha256")
            or receipt.get("tool_use_id")
            != observation.get("tool_call_id")
            or receipt.get("result_sha256")
            != self._sha(evidence.get("result_binding"))
            or receipt.get("result_binding") != evidence.get("result_binding")
            or normalized != evidence.get("result_binding")
            or grant.get("state") != "POST_OBSERVED"
            or grant.get("pretool_event_sha256")
            != observation.get("report_sha256")
            or grant.get("pretool_report_sha256")
            != observation.get("report_sha256")
            or grant.get("posttool_report_sha256")
            != observation.get("report_sha256")
            or grant.get("tool_use_id") != observation.get("tool_call_id")
            or grant.get("outcome") != receipt.get("outcome")
            or grant.get("result_sha256") != receipt.get("result_sha256")
            or grant.get("result_binding_sha256")
            != self._sha(evidence.get("result_binding"))
        ):
            raise ValueError("retained owner evidence binding invalid")

    def _controller_actions(
        self, connection: sqlite3.Connection
    ) -> dict[str, dict[str, Any]]:
        actions: dict[str, dict[str, Any]] = {}
        owner = _row(
            connection.execute(
                "SELECT schema, controller_id, controller_run_id, "
                "activation_sha256, store_identity_sha256 "
                "FROM governed_native_owner WHERE singleton = 1"
            ).fetchone()
        )
        if owner is None:
            raise ValueError("controller owner missing")
        markers = self._verified_controller_run_marker_chain(owner)
        run_ids = [
            str(row[0])
            for row in connection.execute(
                "SELECT run_id FROM runs WHERE run_id LIKE 'nativecontroller-%' "
                "ORDER BY run_id"
            ).fetchall()
        ]
        if set(run_ids) != set(markers):
            raise ValueError("controller run inventory mismatch")
        for run_id in run_ids:
            rows = connection.execute(
                "SELECT run_id, run_seq AS seq, kind, actor_key, payload, note, "
                "prev_hash, event_hash, origin FROM events WHERE run_id = ? "
                "AND reserved = 0 ORDER BY run_seq",
                (run_id,),
            ).fetchall()
            chain = [dict(row) for row in rows]
            run_engine.verify_event_chain(chain)
            if not chain:
                raise ValueError("controller stream missing")
            started = json.loads(str(chain[0]["payload"]))
            plan = started.get("plan") if isinstance(started, Mapping) else None
            origin = plan.get("origin") if isinstance(plan, Mapping) else None
            activation = (
                origin.get("governed_native_activation")
                if isinstance(origin, Mapping)
                else None
            )
            marker = markers[run_id]
            if (
                not isinstance(activation, Mapping)
                or marker.get("controller_id") != origin.get("controller_id")
                or marker.get("controller_run_id") != run_id
                or marker.get("activation_sha256") != self._sha(activation)
                or origin.get("activation_sha256") != self._sha(activation)
                or origin.get("store_identity_sha256")
                != self.store_identity_sha256
                or origin.get("controller_run_marker_sha256")
                != marker.get("marker_sha256")
                or origin.get("previous_controller_run_id")
                != marker.get("previous_controller_run_id")
                or origin.get("previous_controller_run_marker_sha256")
                != marker.get("previous_marker_sha256")
            ):
                raise ValueError("controller run marker binding invalid")
            identity = (
                activation.get("identity")
                if isinstance(activation, Mapping)
                and isinstance(activation.get("identity"), Mapping)
                else None
            )
            session_id = (
                identity.get("root_session_id")
                if isinstance(identity, Mapping)
                else None
            )
            root_thread_id = (
                identity.get("root_thread_id")
                if isinstance(identity, Mapping)
                else None
            )
            if not _text(session_id) or not _text(root_thread_id):
                raise ValueError("controller session identity invalid")
            active_action: Mapping[str, Any] | None = None
            for row in chain:
                if json.loads(str(row["origin"])) != run_store.runtime_origin(
                    str(row["kind"])
                ):
                    raise ValueError("controller stream origin invalid")
                if row["kind"] != "applied":
                    continue
                event = self._controller_event(row)
                payload = (
                    event.get("payload")
                    if isinstance(event.get("payload"), Mapping)
                    else {}
                )
                action = None
                capacity_guard = None
                if event.get("event_type") == "stage_result":
                    action = payload.get("action")
                    capacity_guard = payload.get("capacity_guard")
                    active_action = action
                elif event.get("event_type") == "action_observed":
                    if active_action is None:
                        raise ValueError("controller action evidence invalid")
                    outcome = payload.get("outcome")
                    evidence = payload.get(
                        "action_evidence", payload.get("hook_evidence")
                    )
                    if evidence is None:
                        if outcome != "unknown":
                            raise ValueError(
                                "completed action evidence missing"
                            )
                    else:
                        evidence_grant = self._verified_grant(
                            connection,
                            str(active_action.get("action_sha256")),
                        )
                        if evidence_grant is None:
                            raise ValueError(
                                "retained action evidence grant missing"
                            )
                        if (
                            isinstance(evidence, Mapping)
                            and evidence.get("schema")
                            == _RETAINED_OWNER_ACTION_EVIDENCE_SCHEMA
                        ):
                            self._verify_retained_owner_evidence(
                                evidence=evidence,
                                action=active_action,
                                grant=evidence_grant,
                                root_thread_id=root_thread_id,
                                session_id=session_id,
                            )
                        else:
                            self._verify_retained_hook_evidence(
                                evidence=evidence,
                                action=active_action,
                                grant=evidence_grant,
                                session_id=session_id,
                            )
                    action = payload.get("next_action")
                    capacity_guard = payload.get("next_capacity_guard")
                    active_action = action
                if isinstance(action, Mapping):
                    action_sha256 = action.get("action_sha256")
                    action_core = dict(action)
                    action_core.pop("action_sha256", None)
                    if action.get("kind") == "spawn":
                        if (
                            not isinstance(capacity_guard, Mapping)
                            or set(capacity_guard)
                            != {"run_id", "seq", "event_hash"}
                        ):
                            raise ValueError("controller capacity guard invalid")
                    elif capacity_guard is not None:
                        raise ValueError("controller capacity guard unexpected")
                    projection = {
                        "action_sha256": action_sha256,
                        "action_kind": action.get("kind"),
                        "controller_id": action.get("controller_id"),
                        "controller_run_id": run_id,
                        "controller_seq": int(row["seq"]),
                        "controller_event_hash": str(row["event_hash"]),
                        "action_id": action.get("action_id"),
                        "tool_name": action.get("tool_name"),
                        "tool_input_sha256": action.get("tool_input_sha256"),
                        "capacity_run_id": (
                            capacity_guard.get("run_id")
                            if isinstance(capacity_guard, Mapping)
                            else None
                        ),
                        "capacity_seq": (
                            capacity_guard.get("seq")
                            if isinstance(capacity_guard, Mapping)
                            else None
                        ),
                        "capacity_event_hash": (
                            capacity_guard.get("event_hash")
                            if isinstance(capacity_guard, Mapping)
                            else None
                        ),
                    }
                    if (
                        action.get("schema") != _CONTROLLER_ACTION_SCHEMA
                        or not _digest(action_sha256)
                        or self._sha(action_core) != action_sha256
                        or action_sha256 in actions
                        or set(projection) != _GRANT_FIELDS | _CAPACITY_FIELDS
                        or any(
                            projection.get(field) is None
                            for field in _GRANT_FIELDS
                        )
                        or (
                            action.get("kind") == "spawn"
                            and (
                                not _text(projection["capacity_run_id"])
                                or type(projection["capacity_seq"]) is not int
                                or projection["capacity_seq"] < 1
                                or not _digest(
                                    projection["capacity_event_hash"]
                                )
                            )
                        )
                        or (
                            action.get("kind") != "spawn"
                            and any(
                                projection[field] is not None
                                for field in _CAPACITY_FIELDS
                            )
                        )
                    ):
                        raise ValueError("controller action inventory invalid")
                    actions[str(action_sha256)] = projection
        return actions

    def _terminal_unknown_observed_action(
        self, connection: sqlite3.Connection, run_id: str
    ) -> dict[str, Any] | None:
        rows = [
            dict(row)
            for row in connection.execute(
                "SELECT run_id, run_seq AS seq, kind, actor_key, payload, note, "
                "prev_hash, event_hash, origin FROM events WHERE run_id = ? "
                "AND reserved = 0 ORDER BY run_seq",
                (run_id,),
            ).fetchall()
        ]
        if not rows:
            raise ValueError("controller stream missing")
        run_engine.verify_event_chain(rows)
        active_action: Mapping[str, Any] | None = None
        pending: str | None = None
        terminal = False
        cleanup_required = False
        final_observed_action: Mapping[str, Any] | None = None
        terminalization_intent_cursor: dict[str, Any] | None = None
        for index, row in enumerate(rows[1:], start=1):
            if terminal:
                raise ValueError("controller event follows terminal state")
            event = self._controller_event(row)
            event_type = event.get("event_type")
            payload = event.get("payload")
            if not isinstance(payload, Mapping):
                raise ValueError("controller event payload invalid")
            if event_type == "stage_intent":
                if pending is not None:
                    raise ValueError("controller stage intent invalid")
                if active_action is not None:
                    if (
                        index != len(rows) - 2
                        or set(payload)
                        != {
                            "operation",
                            "failure_evidence_sha256",
                            "evaluation_time",
                            "proposed_action_sha256",
                        }
                        or payload.get("operation")
                        != "observed_spawn_stall_terminalization"
                        or not _digest(payload.get("failure_evidence_sha256"))
                        or not _text(payload.get("evaluation_time"))
                        or payload.get("proposed_action_sha256") is not None
                    ):
                        raise ValueError("controller stage intent invalid")
                    final_observed_action = deepcopy(dict(active_action))
                    terminalization_intent_cursor = {
                        "run_id": row.get("run_id"),
                        "seq": row.get("seq"),
                        "event_hash": row.get("event_hash"),
                    }
                    pending = "observed_spawn_stall"
                    continue
                pending = "stage"
                continue
            if event_type == "stage_result":
                if pending == "observed_spawn_stall":
                    stage_report = payload.get("stage_report")
                    receipt = (
                        stage_report.get("receipt")
                        if isinstance(stage_report, Mapping)
                        else None
                    )
                    if (
                        index != len(rows) - 1
                        or payload.get("intent_cursor")
                        != terminalization_intent_cursor
                        or payload.get("action") is not None
                        or payload.get("capacity_guard") is not None
                        or payload.get("terminal") is not True
                        or payload.get("cleanup_required") is not False
                        or payload.get("issues") != []
                        or not isinstance(stage_report, Mapping)
                        or stage_report.get("schema")
                        != _OBSERVED_SPAWN_STALL_STAGE_SCHEMA
                        or stage_report.get("operation")
                        != "observed_spawn_stall_terminalization"
                        or stage_report.get("status") != "PASS"
                        or stage_report.get("disposition")
                        != "OBSERVED_SPAWN_STALL_TERMINALIZED"
                        or stage_report.get("issues") != []
                        or stage_report.get("next_action")
                        != "terminal_capacity_settlement"
                        or payload.get("terminal_evidence_sha256")
                        != self._sha(stage_report)
                        or not isinstance(receipt, Mapping)
                        or receipt.get("abandoned_action_id")
                        != final_observed_action.get("action_id")
                        or receipt.get("abandoned_action_sha256")
                        != final_observed_action.get("action_sha256")
                        or receipt.get("abandoned_tool_use_id") is not None
                        or receipt.get("observed_outcome") != "completed"
                        or receipt.get("worker_terminal_receipt_observed")
                        is not False
                        or receipt.get("worker_process_match_count") != 0
                        or receipt.get("owner_process_match_count") != 0
                        or receipt.get("owner_process_group_cleaned") is not True
                    ):
                        raise ValueError(
                            "observed spawn stall terminal evidence invalid"
                        )
                    pending = None
                    active_action = None
                    cleanup_required = False
                    terminal = True
                    continue
                if pending != "stage":
                    raise ValueError("controller stage result invalid")
                pending = None
                active_action = (
                    deepcopy(dict(payload["action"]))
                    if isinstance(payload.get("action"), Mapping)
                    else None
                )
                cleanup_required = payload.get("cleanup_required") is True
                terminal = payload.get("terminal") is True
                continue
            if event_type == "action_observation_intent":
                if pending is not None or active_action is None:
                    raise ValueError("controller observation intent invalid")
                pending = "observation"
                continue
            if event_type != "action_observed":
                raise ValueError("controller event type invalid")
            if (
                pending != "observation"
                or active_action is None
                or payload.get("action_id") != active_action.get("action_id")
            ):
                raise ValueError("controller action observation invalid")
            observed_action = deepcopy(dict(active_action))
            pending = None
            active_action = (
                deepcopy(dict(payload["next_action"]))
                if isinstance(payload.get("next_action"), Mapping)
                else None
            )
            outcome = payload.get("outcome")
            cleanup_required = bool(
                cleanup_required
                or payload.get("cleanup_required") is True
                or (
                    "cleanup_required" not in payload
                    and outcome in {"failed", "cancelled", "timed_out"}
                )
            )
            terminal_now = bool(
                payload.get("terminal") is True
                or ("terminal" not in payload and outcome == "unknown")
            )
            terminal = terminal_now
            if index == len(rows) - 1 and terminal_now:
                if (
                    outcome != "unknown"
                    or payload.get(
                        "action_evidence", payload.get("hook_evidence")
                    )
                    is not None
                    or payload.get("hook_report_sha256") is not None
                    or payload.get("native_receipt_sha256") is not None
                    or payload.get("next_action") is not None
                    or payload.get("next_capacity_guard") is not None
                    or payload.get("batch_result") is not None
                ):
                    return None
                final_observed_action = observed_action
        if (
            pending is not None
            or active_action is not None
            or not terminal
            or cleanup_required
            or final_observed_action is None
        ):
            return None
        return deepcopy(dict(final_observed_action))

    def owner(self) -> dict[str, Any] | None:
        with self._connect() as connection:
            return _row(
                connection.execute(
                    "SELECT schema, controller_id, controller_run_id, "
                    "activation_sha256, store_identity_sha256 "
                    "FROM governed_native_owner WHERE singleton = 1"
                ).fetchone()
            )

    def hook_projection(self) -> dict[str, Any] | None:
        with self._connect() as connection:
            return _row(
                connection.execute(
                    "SELECT controller_id, controller_run_id, controller_seq, "
                    "controller_event_hash, binding_sha256 "
                    "FROM governed_native_hook_projection WHERE singleton = 1"
                ).fetchone()
            )

    @classmethod
    def _projection_history_core(
        cls,
        projection: Mapping[str, Any],
        previous_binding_sha256: str | None,
    ) -> dict[str, Any]:
        return {
            "schema": HOOK_PROJECTION_HISTORY_SCHEMA,
            "controller_id": projection.get("controller_id"),
            "controller_run_id": projection.get("controller_run_id"),
            "controller_seq": projection.get("controller_seq"),
            "controller_event_hash": projection.get("controller_event_hash"),
            "binding_sha256": projection.get("binding_sha256"),
            "previous_binding_sha256": previous_binding_sha256,
        }

    def _verified_hook_projection(
        self, connection: sqlite3.Connection
    ) -> dict[str, Any] | None:
        if not self._authority_files_valid():
            raise ValueError("canonical authority markers invalid")
        meta = connection.execute(
            "SELECT projection_state FROM governed_native_authority_meta "
            "WHERE singleton = 1"
        ).fetchone()
        current = _row(
            connection.execute(
                "SELECT controller_id, controller_run_id, controller_seq, "
                "controller_event_hash, binding_sha256 "
                "FROM governed_native_hook_projection WHERE singleton = 1"
            ).fetchone()
        )
        history = connection.execute(
            "SELECT projection_seq, schema, controller_id, controller_run_id, "
            "controller_seq, controller_event_hash, binding_sha256, "
            "previous_binding_sha256, record_sha256 "
            "FROM governed_native_hook_projection_history ORDER BY projection_seq"
        ).fetchall()
        if meta is None or int(meta["projection_state"]) != 1:
            raise ValueError("canonical hook projection marker invalid")
        if current is None or not history:
            raise ValueError("canonical hook projection missing")
        previous: dict[str, Any] | None = None
        seen_bindings: set[str] = set()
        for expected_seq, raw in enumerate(history, start=1):
            row = dict(raw)
            projection = {
                "controller_id": row.get("controller_id"),
                "controller_run_id": row.get("controller_run_id"),
                "controller_seq": row.get("controller_seq"),
                "controller_event_hash": row.get("controller_event_hash"),
                "binding_sha256": row.get("binding_sha256"),
            }
            previous_binding = (
                previous.get("binding_sha256") if previous is not None else None
            )
            core = self._projection_history_core(projection, previous_binding)
            if (
                row.get("projection_seq") != expected_seq
                or row.get("schema") != HOOK_PROJECTION_HISTORY_SCHEMA
                or row.get("previous_binding_sha256") != previous_binding
                or row.get("record_sha256") != self._sha(core)
                or not _text(projection["controller_id"])
                or not _text(projection["controller_run_id"])
                or type(projection["controller_seq"]) is not int
                or projection["controller_seq"] < 1
                or not _digest(projection["controller_event_hash"])
                or not _digest(projection["binding_sha256"])
                or projection["binding_sha256"] in seen_bindings
            ):
                raise ValueError("canonical hook projection history invalid")
            seen_bindings.add(str(projection["binding_sha256"]))
            previous = projection
        if current != previous:
            raise ValueError("canonical hook projection head mismatch")
        return current

    def record_hook_projection(
        self,
        binding: Mapping[str, Any],
        *,
        expected_previous: Mapping[str, Any] | None,
    ) -> bool:
        desired = {
            "controller_id": binding.get("controller_id"),
            "controller_run_id": binding.get("controller_run_id"),
            "controller_seq": binding.get("controller_seq"),
            "controller_event_hash": binding.get("controller_event_hash"),
            "binding_sha256": binding.get("binding_sha256"),
        }
        if (
            not _text(desired["controller_id"])
            or not _text(desired["controller_run_id"])
            or type(desired["controller_seq"]) is not int
            or desired["controller_seq"] < 1
            or not _digest(desired["controller_event_hash"])
            or not _digest(desired["binding_sha256"])
        ):
            return False
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = _row(
                connection.execute(
                    "SELECT controller_id, controller_run_id, controller_seq, "
                    "controller_event_hash, binding_sha256 "
                    "FROM governed_native_hook_projection WHERE singleton = 1"
                ).fetchone()
            )
            history_rows = connection.execute(
                "SELECT projection_seq, schema, controller_id, controller_run_id, "
                "controller_seq, controller_event_hash, binding_sha256, "
                "previous_binding_sha256, record_sha256 "
                "FROM governed_native_hook_projection_history ORDER BY projection_seq"
            ).fetchall()
            marker = connection.execute(
                "SELECT projection_state FROM governed_native_authority_meta "
                "WHERE singleton = 1"
            ).fetchone()
            marker_state = int(marker["projection_state"]) if marker is not None else -1
            authority_files_valid = self._authority_files_valid()
            if current is None and history_rows:
                connection.rollback()
                return False
            if current is None:
                if marker_state != 0 or not authority_files_valid:
                    connection.rollback()
                    return False
            elif not authority_files_valid:
                connection.rollback()
                return False
            if current is not None:
                if marker_state != 1:
                    connection.rollback()
                    return False
                try:
                    verified_current = self._verified_hook_projection(connection)
                except ValueError:
                    connection.rollback()
                    return False
                if verified_current != current:
                    connection.rollback()
                    return False
            if current == desired:
                connection.rollback()
                return True
            if current != (
                dict(expected_previous)
                if isinstance(expected_previous, Mapping)
                else None
            ):
                connection.rollback()
                return False
            if current is None:
                connection.execute(
                    "INSERT INTO governed_native_hook_projection "
                    "(singleton, controller_id, controller_run_id, controller_seq, "
                    "controller_event_hash, binding_sha256) VALUES (1, ?, ?, ?, ?, ?)",
                    tuple(desired.values()),
                )
            else:
                connection.execute(
                    "UPDATE governed_native_hook_projection SET controller_id = ?, "
                    "controller_run_id = ?, controller_seq = ?, "
                    "controller_event_hash = ?, binding_sha256 = ? WHERE singleton = 1",
                    tuple(desired.values()),
                )
            previous_binding = (
                current.get("binding_sha256") if current is not None else None
            )
            history_core = self._projection_history_core(
                desired, previous_binding
            )
            connection.execute(
                "INSERT INTO governed_native_hook_projection_history "
                "(schema, controller_id, controller_run_id, controller_seq, "
                "controller_event_hash, binding_sha256, previous_binding_sha256, "
                "record_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    HOOK_PROJECTION_HISTORY_SCHEMA,
                    desired["controller_id"],
                    desired["controller_run_id"],
                    desired["controller_seq"],
                    desired["controller_event_hash"],
                    desired["binding_sha256"],
                    previous_binding,
                    self._sha(history_core),
                ),
            )
            if current is None:
                updated_marker = connection.execute(
                    "UPDATE governed_native_authority_meta "
                    "SET projection_state = 1 "
                    "WHERE singleton = 1 AND projection_state = 0"
                ).rowcount
                if updated_marker != 1:
                    connection.rollback()
                    return False
            connection.commit()
            return True
        except sqlite3.Error:
            connection.rollback()
            return False
        finally:
            connection.close()

    def register_owner(
        self,
        *,
        controller_id: str,
        controller_run_id: str,
        activation_sha256: str,
    ) -> dict[str, Any]:
        expected = {
            "schema": OWNER_SCHEMA,
            "controller_id": controller_id,
            "controller_run_id": controller_run_id,
            "activation_sha256": activation_sha256,
            "store_identity_sha256": self.store_identity_sha256,
        }
        if (
            not _text(controller_id)
            or not _text(controller_run_id)
            or not _digest(activation_sha256)
        ):
            return {"status": "REFUSED", "owner": None}
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = _row(
                connection.execute(
                    "SELECT schema, controller_id, controller_run_id, "
                    "activation_sha256, store_identity_sha256 "
                    "FROM governed_native_owner WHERE singleton = 1"
                ).fetchone()
            )
            if current is None:
                if not self._ensure_controller_run_marker(
                    controller_id=controller_id,
                    controller_run_id=controller_run_id,
                    activation_sha256=activation_sha256,
                    previous_owner=None,
                ):
                    connection.rollback()
                    return {"status": "CONFLICT", "owner": None}
                residue = self._authority_residue(connection)
                marker_status = self._authority_marker_status()
                tombstone_status = self._authority_tombstone_status()
                marker = connection.execute(
                    "SELECT projection_state FROM governed_native_authority_meta "
                    "WHERE singleton = 1"
                ).fetchone()
                if (
                    residue
                    or marker_status != "ABSENT"
                    or tombstone_status != "ABSENT"
                    or marker is None
                    or int(marker["projection_state"]) != 0
                ):
                    connection.rollback()
                    return {"status": "CONFLICT", "owner": None}
                connection.execute(
                    "INSERT INTO governed_native_owner "
                    "(singleton, schema, controller_id, controller_run_id, "
                    "activation_sha256, store_identity_sha256) "
                    "VALUES (1, ?, ?, ?, ?, ?)",
                    (
                        OWNER_SCHEMA,
                        controller_id,
                        controller_run_id,
                        activation_sha256,
                        self.store_identity_sha256,
                    ),
                )
                connection.commit()
                if not self._ensure_authority_files():
                    return {"status": "UNKNOWN", "owner": expected}
                return {"status": "CREATED", "owner": expected}
            if current != expected:
                connection.rollback()
                return {"status": "CONFLICT", "owner": current}
            marker = connection.execute(
                "SELECT projection_state FROM governed_native_authority_meta "
                "WHERE singleton = 1"
            ).fetchone()
            marker_state = int(marker["projection_state"]) if marker is not None else -1
            marker_status = self._authority_marker_status()
            tombstone_status = self._authority_tombstone_status()
            residue = self._authority_residue(connection)
            try:
                run_markers_valid = bool(
                    self._verified_controller_run_marker_chain(current)
                )
            except ValueError:
                run_markers_valid = False
            connection.rollback()
            if (
                marker_status == "VALID"
                and tombstone_status == "VALID"
                and marker_state in {0, 1}
                and run_markers_valid
            ):
                return {"status": "MATCH", "owner": current}
            if (
                marker_state == 0
                and residue == 1
                and marker_status in {"ABSENT", "VALID"}
                and tombstone_status in {"ABSENT", "VALID"}
                and run_markers_valid
                and self._ensure_authority_files()
            ):
                return {"status": "MATCH", "owner": current}
            return {"status": "CONFLICT", "owner": current}
        except sqlite3.Error:
            connection.rollback()
            return {"status": "UNKNOWN", "owner": None}
        finally:
            connection.close()

    def verified_owner_activation(
        self, controller_id: str, controller_run_id: str
    ) -> dict[str, Any] | None:
        owner = self.owner()
        if not (
            owner
            and owner.get("schema") == OWNER_SCHEMA
            and owner.get("controller_id") == controller_id
            and owner.get("controller_run_id") == controller_run_id
            and _digest(owner.get("activation_sha256"))
            and owner.get("store_identity_sha256") == self.store_identity_sha256
        ):
            return None
        try:
            markers = self._verified_controller_run_marker_chain(owner)
            run_marker = markers[controller_run_id]
            with self._connect() as connection:
                marker = connection.execute(
                    "SELECT projection_state FROM governed_native_authority_meta "
                    "WHERE singleton = 1"
                ).fetchone()
                marker_state = (
                    int(marker["projection_state"]) if marker is not None else -1
                )
                if not self._authority_files_valid() or marker_state not in {0, 1}:
                    return None
                self._verified_tip(connection, controller_run_id)
                row = connection.execute(
                    "SELECT payload FROM events WHERE run_id = ? "
                    "AND reserved = 0 ORDER BY run_seq LIMIT 1",
                    (controller_run_id,),
                ).fetchone()
            started = json.loads(str(row["payload"])) if row is not None else None
            plan = started.get("plan") if isinstance(started, Mapping) else None
            origin = plan.get("origin") if isinstance(plan, Mapping) else None
            activation = (
                origin.get("governed_native_activation")
                if isinstance(origin, Mapping)
                else None
            )
            if not (
                isinstance(activation, Mapping)
                and origin.get("activation_sha256") == self._sha(activation)
                and owner.get("activation_sha256") == self._sha(activation)
                and origin.get("controller_id") == controller_id
                and origin.get("store_identity_sha256")
                == self.store_identity_sha256
                and origin.get("controller_run_marker_sha256")
                == run_marker.get("marker_sha256")
                and origin.get("previous_controller_run_id")
                == run_marker.get("previous_controller_run_id")
                and origin.get("previous_controller_run_marker_sha256")
                == run_marker.get("previous_marker_sha256")
            ):
                return None
            return deepcopy(dict(activation))
        except (
            sqlite3.Error,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            run_engine.RunKernelError,
        ):
            return None

    def owner_matches(self, controller_id: str, controller_run_id: str) -> bool:
        return self.verified_owner_activation(
            controller_id, controller_run_id
        ) is not None

    def read_grant_inventory(self) -> dict[str, Any]:
        """Read all canonical grant states without granting owner disposition.

        One read-only SQLite snapshot and the existing external witness checks
        distinguish a verified empty inventory from missing or corrupt state.
        The caller must separately bracket current owner, journal and capacity;
        actual rotation still uses its own atomic unsettled-grant guard.
        """
        owner = None
        counts = None
        count = unsettled = inventory_sha256 = None
        issues = []
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA query_only = ON")
                connection.execute("BEGIN")
                current = _row(connection.execute(
                    "SELECT schema, controller_id, controller_run_id, activation_sha256, "
                    "store_identity_sha256 FROM governed_native_owner WHERE singleton = 1"
                ).fetchone())
                if (current is None or current.get("schema") != OWNER_SCHEMA
                        or current.get("store_identity_sha256") != self.store_identity_sha256):
                    raise ValueError("owner missing")
                self._verified_controller_run_marker_chain(current)
                verified = self._verify_all_grants(connection)
                rows = [dict(row) for row in connection.execute(
                    "SELECT action_sha256, controller_id, controller_run_id, state "
                    "FROM governed_native_grants ORDER BY action_sha256"
                ).fetchall()]
                if {row["action_sha256"] for row in rows} != verified:
                    raise ValueError("grant inventory changed")
                states = ("PROVISIONAL", "AUTHORIZED", "DISPATCHED", "POST_OBSERVED",
                          "OUTCOME_UNKNOWN", "TERMINAL_OUTCOME_UNKNOWN", "TERMINAL_PRETOOL_DENIED",
                          "TERMINAL_NOT_DISPATCHED", "STALE")
                counts = {state: 0 for state in states}
                for row in rows:
                    counts[row["state"]] += 1
                count = len(rows)
                unsettled = sum(counts[state] for state in ("PROVISIONAL", "AUTHORIZED", "DISPATCHED", "OUTCOME_UNKNOWN"))
                inventory_sha256 = self._sha(rows)
                owner = current
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError):
            owner = counts = count = unsettled = inventory_sha256 = None
            issues = ["grant_inventory:unverified"]
        core = {"schema": "orch-dork/native-grant-inventory/v1", "status": "INVALID" if issues else "VERIFIED",
            "issues": issues, "scope": "all_canonical_grants", "owner": owner,
            "store_identity_sha256": self.store_identity_sha256, "grant_count": count,
            "unsettled_grant_count": unsettled, "state_counts": counts, "inventory_sha256": inventory_sha256,
            "continuation_permitted": False, "terminal_claim_permitted": False, "provider_free": True}
        return {**core, "report_sha256": self._sha(core)}

    def rotate_owner(
        self,
        *,
        expected_owner: Mapping[str, Any],
        controller_id: str,
        controller_run_id: str,
        activation_sha256: str,
    ) -> dict[str, Any]:
        replacement = {
            "schema": OWNER_SCHEMA,
            "controller_id": controller_id,
            "controller_run_id": controller_run_id,
            "activation_sha256": activation_sha256,
            "store_identity_sha256": self.store_identity_sha256,
        }
        if (
            not _text(controller_id)
            or not _text(controller_run_id)
            or not _digest(activation_sha256)
        ):
            return {"status": "REFUSED", "owner": None}
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = _row(
                connection.execute(
                    "SELECT schema, controller_id, controller_run_id, "
                    "activation_sha256, store_identity_sha256 "
                    "FROM governed_native_owner WHERE singleton = 1"
                ).fetchone()
            )
            self._verify_all_grants(connection)
            unsettled = connection.execute(
                "SELECT COUNT(*) AS count FROM governed_native_grants "
                "WHERE state IN ('PROVISIONAL', 'AUTHORIZED', 'DISPATCHED', "
                "'OUTCOME_UNKNOWN')"
            ).fetchone()
            if current != dict(expected_owner) or int(unsettled["count"]) != 0:
                connection.rollback()
                return {"status": "CONFLICT", "owner": current}
            if not self._ensure_controller_run_marker(
                controller_id=controller_id,
                controller_run_id=controller_run_id,
                activation_sha256=activation_sha256,
                previous_owner=current,
            ):
                connection.rollback()
                return {"status": "CONFLICT", "owner": current}
            updated = connection.execute(
                "UPDATE governed_native_owner SET schema = ?, controller_id = ?, "
                "controller_run_id = ?, activation_sha256 = ?, "
                "store_identity_sha256 = ? WHERE singleton = 1",
                (
                    OWNER_SCHEMA,
                    controller_id,
                    controller_run_id,
                    activation_sha256,
                    self.store_identity_sha256,
                ),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return {"status": "CONFLICT", "owner": current}
            connection.commit()
            try:
                self._verified_controller_run_marker_chain(replacement)
            except ValueError:
                return {"status": "UNKNOWN", "owner": replacement}
            return {"status": "ROTATED", "owner": replacement}
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            connection.rollback()
            return {"status": "UNKNOWN", "owner": None}
        finally:
            connection.close()

    def stale_terminal_unclaimed_spawn(
        self,
        *,
        expected_owner: Mapping[str, Any],
        terminal_binding: Mapping[str, Any],
        capacity_tip: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Retire one terminal unclaimed spawn whose capacity guard is stale."""

        owner_fields = {
            "schema",
            "controller_id",
            "controller_run_id",
            "activation_sha256",
            "store_identity_sha256",
        }
        binding_core = {
            key: child
            for key, child in terminal_binding.items()
            if key != "binding_sha256"
        }
        if (
            set(expected_owner) != owner_fields
            or expected_owner.get("schema") != OWNER_SCHEMA
            or expected_owner.get("store_identity_sha256")
            != self.store_identity_sha256
            or set(terminal_binding) != _HOOK_BINDING_FIELDS
            or terminal_binding.get("schema") != _HOOK_BINDING_SCHEMA
            or terminal_binding.get("status") != "TERMINAL"
            or terminal_binding.get("action") is not None
            or terminal_binding.get("store_identity_sha256")
            != self.store_identity_sha256
            or terminal_binding.get("binding_sha256") != self._sha(binding_core)
            or set(capacity_tip) != {"run_id", "seq", "event_hash"}
            or not _text(capacity_tip.get("run_id"))
            or type(capacity_tip.get("seq")) is not int
            or capacity_tip["seq"] < 1
            or not _digest(capacity_tip.get("event_hash"))
        ):
            return {"status": "REFUSED", "reason": "grant:retirement_input_invalid"}
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current_owner = _row(
                connection.execute(
                    "SELECT schema, controller_id, controller_run_id, "
                    "activation_sha256, store_identity_sha256 "
                    "FROM governed_native_owner WHERE singleton = 1"
                ).fetchone()
            )
            if current_owner != dict(expected_owner):
                connection.rollback()
                return {"status": "CONFLICT", "reason": "grant:owner_changed"}
            grant_ids = self._verify_all_grants(connection)
            actions = self._controller_actions(connection)
            if grant_ids != set(actions):
                raise ValueError("canonical grant inventory mismatch")
            projection = self._verified_hook_projection(connection)
            controller_tip = self._verified_tip(
                connection, str(expected_owner.get("controller_run_id"))
            )
            expected_controller_tip = {
                "run_id": expected_owner.get("controller_run_id"),
                "seq": terminal_binding.get("controller_seq"),
                "event_hash": terminal_binding.get("controller_event_hash"),
            }
            if (
                controller_tip != expected_controller_tip
                or terminal_binding.get("controller_id")
                != expected_owner.get("controller_id")
                or terminal_binding.get("controller_run_id")
                != expected_owner.get("controller_run_id")
                or not isinstance(projection, Mapping)
                or projection.get("controller_id")
                != terminal_binding.get("controller_id")
                or projection.get("controller_run_id")
                != terminal_binding.get("controller_run_id")
                or projection.get("controller_seq")
                != terminal_binding.get("controller_seq")
                or projection.get("controller_event_hash")
                != terminal_binding.get("controller_event_hash")
                or projection.get("binding_sha256")
                != terminal_binding.get("binding_sha256")
            ):
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:terminal_tip_invalid"}
            unsettled = [
                str(row["action_sha256"])
                for row in connection.execute(
                    "SELECT action_sha256 FROM governed_native_grants "
                    "WHERE state IN ('PROVISIONAL', 'AUTHORIZED', 'DISPATCHED', "
                    "'OUTCOME_UNKNOWN') ORDER BY action_sha256"
                ).fetchall()
            ]
            if not unsettled:
                connection.rollback()
                return {"status": "NOT_REQUIRED"}
            if len(unsettled) != 1:
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:unsettled_set_invalid"}
            action = self._terminal_unknown_observed_action(
                connection, str(expected_owner.get("controller_run_id"))
            )
            action_sha256 = (
                action.get("action_sha256")
                if isinstance(action, Mapping)
                else None
            )
            grant = (
                self._verified_grant(connection, str(action_sha256))
                if _digest(action_sha256)
                else None
            )
            if (
                grant is None
                or unsettled != [action_sha256]
                or actions.get(str(action_sha256)) is None
                or grant.get("controller_id") != expected_owner.get("controller_id")
                or grant.get("controller_run_id")
                != expected_owner.get("controller_run_id")
                or grant.get("state") != "AUTHORIZED"
                or grant.get("action_kind") != "spawn"
                or any(
                    grant.get(field) is not None
                    for field in (
                        "pretool_event_sha256",
                        "pretool_report_sha256",
                        "tool_use_id",
                        "outcome",
                        "result_sha256",
                        "result_binding_sha256",
                        "posttool_report_sha256",
                    )
                )
            ):
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:not_unclaimed_spawn"}
            expected_capacity_tip = {
                "run_id": grant.get("capacity_run_id"),
                "seq": grant.get("capacity_seq"),
                "event_hash": grant.get("capacity_event_hash"),
            }
            current_capacity_tip = self._verified_tip(
                connection, str(grant.get("capacity_run_id"))
            )
            if (
                current_capacity_tip != dict(capacity_tip)
                or current_capacity_tip.get("run_id")
                != expected_capacity_tip.get("run_id")
                or current_capacity_tip.get("seq", 0)
                <= expected_capacity_tip.get("seq", 0)
                or current_capacity_tip == expected_capacity_tip
            ):
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:capacity_not_stale"}
            updated = connection.execute(
                "UPDATE governed_native_grants SET state = 'STALE' "
                "WHERE action_sha256 = ? AND state = 'AUTHORIZED'",
                (action_sha256,),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return {"status": "CONFLICT", "reason": "grant:retirement_conflict"}
            stale = self._grant_snapshot(
                connection.execute(
                    "SELECT " + ", ".join(_GRANT_COLUMNS)
                    + " FROM governed_native_grants WHERE action_sha256 = ?",
                    (action_sha256,),
                ).fetchone()
            )
            witness = self._append_grant_history(
                connection,
                previous=grant,
                current=stale,
                transition_type="CAPACITY_STALE",
            )
            connection.commit()
            if not self._record_grant_transition_commit(witness):
                return {"status": "UNKNOWN", "reason": "grant:witness_unavailable"}
            return {"status": "STALED", "action_sha256": action_sha256}
        except (
            OSError,
            sqlite3.Error,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            run_engine.RunKernelError,
        ):
            connection.rollback()
            return {"status": "UNKNOWN", "reason": "grant:retirement_unavailable"}
        finally:
            connection.close()

    def terminalize_owner_closed_action(
        self,
        *,
        expected_owner: Mapping[str, Any],
        terminal_binding: Mapping[str, Any],
        capacity_tip: Mapping[str, Any],
        capacity_authority: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Retire a sealed closed owner's exact unused continuation.

        Historical denial cuts retain their denial state. A control-call cut
        (an unreadable control result, or the root's own extra advance) uses
        the existing interruption transition and records no tool denial.
        """

        owner_fields = {
            "schema",
            "controller_id",
            "controller_run_id",
            "activation_sha256",
            "store_identity_sha256",
        }
        binding_core = {
            key: child
            for key, child in terminal_binding.items()
            if key != "binding_sha256"
        }
        capacity_state = (
            capacity_authority.get("state")
            if isinstance(capacity_authority, Mapping)
            and isinstance(capacity_authority.get("state"), Mapping)
            else {}
        )
        capacity_validation = shared_capacity.validate_authority_state(
            capacity_state
        )
        capacity_state_sha256 = capacity_state.get("state_sha256")
        if (
            set(expected_owner) != owner_fields
            or expected_owner.get("schema") != OWNER_SCHEMA
            or expected_owner.get("store_identity_sha256")
            != self.store_identity_sha256
            or set(terminal_binding) != _HOOK_BINDING_FIELDS
            or terminal_binding.get("schema") != _HOOK_BINDING_SCHEMA
            or terminal_binding.get("status") != "TERMINAL"
            or terminal_binding.get("action") is not None
            or terminal_binding.get("store_identity_sha256")
            != self.store_identity_sha256
            or terminal_binding.get("binding_sha256") != self._sha(binding_core)
            or set(capacity_tip) != {"run_id", "seq", "event_hash"}
            or not _text(capacity_tip.get("run_id"))
            or type(capacity_tip.get("seq")) is not int
            or capacity_tip["seq"] < 1
            or not _digest(capacity_tip.get("event_hash"))
            or not isinstance(capacity_authority, Mapping)
            or set(capacity_authority)
            != {
                "schema",
                "status",
                "store_id",
                "continuity_verified",
                "state",
                "state_sha256",
                "reason_codes",
            }
            or capacity_authority.get("schema")
            != shared_capacity.AUTHORITY_READ_SCHEMA
            or capacity_authority.get("status") != "VERIFIED"
            or capacity_authority.get("store_id") != capacity_tip.get("run_id")
            or capacity_authority.get("continuity_verified") is not True
            or capacity_authority.get("reason_codes") != []
            or capacity_validation.get("status") != "RESOLVED"
            or capacity_validation.get("active_lane_ids") != set()
            or not _digest(capacity_state_sha256)
            or capacity_authority.get("state_sha256")
            != capacity_state_sha256
        ):
            return {
                "status": "REFUSED",
                "reason": "grant:pretool_denial_input_invalid",
            }
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current_owner = _row(
                connection.execute(
                    "SELECT schema, controller_id, controller_run_id, "
                    "activation_sha256, store_identity_sha256 "
                    "FROM governed_native_owner WHERE singleton = 1"
                ).fetchone()
            )
            if current_owner != dict(expected_owner):
                connection.rollback()
                return {"status": "CONFLICT", "reason": "grant:owner_changed"}
            grant_ids = self._verify_all_grants(connection)
            actions = self._controller_actions(connection)
            if grant_ids != set(actions):
                raise ValueError("canonical grant inventory mismatch")
            projection = self._verified_hook_projection(connection)
            controller_tip = self._verified_tip(
                connection, str(expected_owner.get("controller_run_id"))
            )
            expected_controller_tip = {
                "run_id": expected_owner.get("controller_run_id"),
                "seq": terminal_binding.get("controller_seq"),
                "event_hash": terminal_binding.get("controller_event_hash"),
            }
            if (
                controller_tip != expected_controller_tip
                or terminal_binding.get("controller_id")
                != expected_owner.get("controller_id")
                or terminal_binding.get("controller_run_id")
                != expected_owner.get("controller_run_id")
                or not isinstance(projection, Mapping)
                or projection.get("controller_id")
                != terminal_binding.get("controller_id")
                or projection.get("controller_run_id")
                != terminal_binding.get("controller_run_id")
                or projection.get("controller_seq")
                != terminal_binding.get("controller_seq")
                or projection.get("controller_event_hash")
                != terminal_binding.get("controller_event_hash")
                or projection.get("binding_sha256")
                != terminal_binding.get("binding_sha256")
            ):
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:terminal_tip_invalid",
                }
            unsettled = [
                str(row["action_sha256"])
                for row in connection.execute(
                    "SELECT action_sha256 FROM governed_native_grants "
                    "WHERE state IN ('PROVISIONAL', 'AUTHORIZED', 'DISPATCHED', "
                    "'OUTCOME_UNKNOWN') ORDER BY action_sha256"
                ).fetchall()
            ]
            if not unsettled:
                connection.rollback()
                return {"status": "NOT_REQUIRED"}
            if len(unsettled) != 1:
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:unsettled_set_invalid",
                }
            action_sha256 = unsettled[0]
            grant = self._verified_grant(connection, action_sha256)
            if (
                not isinstance(grant, Mapping)
                or actions.get(action_sha256) is None
                or grant.get("controller_id")
                != expected_owner.get("controller_id")
                or grant.get("controller_run_id")
                != expected_owner.get("controller_run_id")
                or grant.get("state") != "AUTHORIZED"
                or grant.get("action_kind") != "continue"
                or any(
                    grant.get(field) is not None
                    for field in (
                        "pretool_event_sha256",
                        "pretool_report_sha256",
                        "tool_use_id",
                        "outcome",
                        "result_sha256",
                        "result_binding_sha256",
                        "posttool_report_sha256",
                    )
                )
            ):
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:authorized_continuation_invalid",
                }

            rows = [
                dict(row)
                for row in connection.execute(
                    "SELECT run_id, run_seq AS seq, kind, actor_key, payload, "
                    "note, prev_hash, event_hash, origin FROM events "
                    "WHERE run_id = ? AND reserved = 0 ORDER BY run_seq",
                    (expected_owner.get("controller_run_id"),),
                ).fetchall()
            ]
            run_engine.verify_event_chain(rows)
            applied = [row for row in rows if row.get("kind") == "applied"]
            if len(applied) < 2:
                raise ValueError("pretool denial terminal evidence missing")
            intent_row, terminal_row = applied[-2:]
            intent_event = self._controller_event(intent_row)
            terminal_event = self._controller_event(terminal_row)
            intent = intent_event.get("payload")
            terminal = terminal_event.get("payload")
            stage_report = (
                terminal.get("stage_report")
                if isinstance(terminal, Mapping)
                else None
            )
            receipt = (
                stage_report.get("receipt")
                if isinstance(stage_report, Mapping)
                else None
            )
            expected_intent_cursor = {
                "run_id": intent_row.get("run_id"),
                "seq": intent_row.get("seq"),
                "event_hash": intent_row.get("event_hash"),
            }
            receipt_fields = {
                "failure_evidence_sha256",
                "historical_runtime_report_sha256",
                "historical_package_digest",
                "attempt_envelope_artifact_sha256",
                "dedicated_run_artifact_sha256",
                "pre_turn_artifact_sha256",
                "root_rollout_artifact_sha256",
                "pretool_denial_artifact_sha256",
                "pretool_denial_report_sha256",
                "pretool_denial_durable_record_sha256",
                "abandoned_task_id",
                "abandoned_turn_id",
                "abandoned_action_id",
                "abandoned_action_sha256",
                "denied_hook_tool_name",
                "created_workers",
                "owner_process_group_cleaned",
                "capacity_authority_state_sha256",
            }
            digest_fields = receipt_fields - {
                "abandoned_task_id",
                "abandoned_turn_id",
                "abandoned_action_id",
                "denied_hook_tool_name",
                "created_workers",
                "owner_process_group_cleaned",
            }
            legacy_terminal_valid = not (
                intent_event.get("event_type") != "stage_intent"
                or not isinstance(intent, Mapping)
                or set(intent)
                != {
                    "operation",
                    "failure_evidence_sha256",
                    "evaluation_time",
                    "proposed_action_sha256",
                }
                or intent.get("operation")
                != "post_ack_bridge_failure_terminalization"
                or not _digest(intent.get("failure_evidence_sha256"))
                or not _text(intent.get("evaluation_time"))
                or intent.get("proposed_action_sha256") is not None
                or terminal_event.get("event_type") != "stage_result"
                or not isinstance(terminal, Mapping)
                or set(terminal)
                != {
                    "intent_cursor",
                    "stage_report",
                    "action",
                    "capacity_guard",
                    "terminal",
                    "cleanup_required",
                    "terminal_evidence_sha256",
                    "issues",
                }
                or terminal.get("intent_cursor") != expected_intent_cursor
                or terminal.get("action") is not None
                or terminal.get("capacity_guard") is not None
                or terminal.get("terminal") is not True
                or terminal.get("cleanup_required") is not False
                or terminal.get("issues") != []
                or not isinstance(stage_report, Mapping)
                or set(stage_report)
                != {
                    "schema",
                    "operation",
                    "status",
                    "disposition",
                    "issues",
                    "receipt",
                    "next_action",
                }
                or stage_report.get("schema")
                != _POST_ACK_BRIDGE_FAILURE_STAGE_SCHEMA
                or stage_report.get("operation")
                != "post_ack_bridge_failure_terminalization"
                or stage_report.get("status") != "PASS"
                or stage_report.get("disposition")
                != "POST_ACK_BRIDGE_FAILURE_TERMINALIZED"
                or stage_report.get("issues") != []
                or stage_report.get("next_action")
                != "terminal_capacity_settlement"
                or terminal.get("terminal_evidence_sha256")
                != self._sha(stage_report)
                or not isinstance(receipt, Mapping)
                or set(receipt) != receipt_fields
                or receipt.get("failure_evidence_sha256")
                != intent.get("failure_evidence_sha256")
                or any(not _digest(receipt.get(field)) for field in digest_fields)
                or receipt.get("abandoned_action_id")
                != grant.get("action_id")
                or receipt.get("abandoned_action_sha256") != action_sha256
                or receipt.get("denied_hook_tool_name")
                != "multi_agent_v1send_input"
                or not _text(receipt.get("abandoned_task_id"))
                or not _text(receipt.get("abandoned_turn_id"))
                or not isinstance(receipt.get("created_workers"), list)
                or len(receipt["created_workers"]) != 2
                or receipt.get("owner_process_group_cleaned") is not True
                or receipt.get("capacity_authority_state_sha256")
                == capacity_state_sha256
            )
            if not legacy_terminal_valid and not _owner_closed_ack_denial_terminal_valid(
                intent_event, terminal_event, expected_intent_cursor, grant,
                terminal_binding, capacity_state_sha256,
            ):
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:pretool_denial_terminal_evidence_invalid",
                }
            current_capacity_tip = self._verified_tip(
                connection, str(capacity_tip.get("run_id"))
            )
            if current_capacity_tip != dict(capacity_tip):
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:empty_capacity_not_current",
                }
            cut = owner_closed_ack_cut_for_failure(receipt.get("failure_cut"))
            control = cut is not None and cut.control_proof
            terminal_state = "TERMINAL_NOT_DISPATCHED" if control else "TERMINAL_PRETOOL_DENIED"
            updated = connection.execute(
                "UPDATE governed_native_grants "
                "SET state = ? "
                "WHERE action_sha256 = ? AND state = 'AUTHORIZED'",
                (terminal_state, action_sha256),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return {
                    "status": "CONFLICT",
                    "reason": "grant:terminalization_conflict",
                }
            terminal_grant = self._grant_snapshot(
                connection.execute(
                    "SELECT "
                    + ", ".join(_GRANT_COLUMNS)
                    + " FROM governed_native_grants WHERE action_sha256 = ?",
                    (action_sha256,),
                ).fetchone()
            )
            witness = self._append_grant_history(
                connection,
                previous=grant,
                current=terminal_grant,
                transition_type="INTERRUPTION_TERMINALIZED" if control else "PRETOOL_DENIAL_TERMINALIZED",
            )
            connection.commit()
            if not self._record_grant_transition_commit(witness):
                return {
                    "status": "UNKNOWN",
                    "reason": "grant:witness_unavailable",
                }
            return {
                "status": "TERMINALIZED",
                "action_sha256": action_sha256,
                "state": terminal_state,
                "historical_outcome": "not_executed",
                "terminal_evidence_sha256": terminal[
                    "terminal_evidence_sha256"
                ],
                "capacity_state_sha256": capacity_state_sha256,
                **({"control_result_sha256": receipt["control_result_sha256"]} if control
                   else {"pretool_denial_report_sha256": receipt["pretool_denial_report_sha256"]}),
            }
        except (
            OSError,
            sqlite3.Error,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            run_engine.RunKernelError,
        ):
            connection.rollback()
            return {
                "status": "UNKNOWN",
                "reason": "grant:pretool_denial_terminalization_unavailable",
            }
        finally:
            connection.close()

    # Preserve historical denial callers; both names use the same transaction.
    terminalize_pretool_denied_action = terminalize_owner_closed_action

    def terminalize_partial_native_failure_spawn(
        self,
        *,
        expected_owner: Mapping[str, Any],
        terminal_binding: Mapping[str, Any],
        capacity_tip: Mapping[str, Any],
        capacity_authority: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Settle authority, not outcome, for one exact recovered spawn."""

        owner_fields = {
            "schema",
            "controller_id",
            "controller_run_id",
            "activation_sha256",
            "store_identity_sha256",
        }
        binding_core = {
            key: child
            for key, child in terminal_binding.items()
            if key != "binding_sha256"
        }
        capacity_state = (
            capacity_authority.get("state")
            if isinstance(capacity_authority, Mapping)
            and isinstance(capacity_authority.get("state"), Mapping)
            else {}
        )
        capacity_validation = shared_capacity.validate_authority_state(
            capacity_state
        )
        capacity_state_sha256 = capacity_state.get("state_sha256")
        if (
            set(expected_owner) != owner_fields
            or expected_owner.get("schema") != OWNER_SCHEMA
            or expected_owner.get("store_identity_sha256")
            != self.store_identity_sha256
            or set(terminal_binding) != _HOOK_BINDING_FIELDS
            or terminal_binding.get("schema") != _HOOK_BINDING_SCHEMA
            or terminal_binding.get("status") != "TERMINAL"
            or terminal_binding.get("action") is not None
            or terminal_binding.get("store_identity_sha256")
            != self.store_identity_sha256
            or terminal_binding.get("binding_sha256") != self._sha(binding_core)
            or set(capacity_tip) != {"run_id", "seq", "event_hash"}
            or not _text(capacity_tip.get("run_id"))
            or type(capacity_tip.get("seq")) is not int
            or capacity_tip["seq"] < 1
            or not _digest(capacity_tip.get("event_hash"))
            or not isinstance(capacity_authority, Mapping)
            or set(capacity_authority)
            != {
                "schema",
                "status",
                "store_id",
                "continuity_verified",
                "state",
                "state_sha256",
                "reason_codes",
            }
            or capacity_authority.get("schema")
            != shared_capacity.AUTHORITY_READ_SCHEMA
            or capacity_authority.get("status") != "VERIFIED"
            or capacity_authority.get("store_id")
            != capacity_tip.get("run_id")
            or capacity_authority.get("continuity_verified") is not True
            or capacity_authority.get("reason_codes") != []
            or capacity_validation.get("status") != "RESOLVED"
            or capacity_validation.get("active_lane_ids") != set()
            or not _digest(capacity_state_sha256)
            or capacity_authority.get("state_sha256")
            != capacity_state_sha256
        ):
            return {
                "status": "REFUSED",
                "reason": "grant:terminalization_input_invalid",
            }
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current_owner = _row(
                connection.execute(
                    "SELECT schema, controller_id, controller_run_id, "
                    "activation_sha256, store_identity_sha256 "
                    "FROM governed_native_owner WHERE singleton = 1"
                ).fetchone()
            )
            if current_owner != dict(expected_owner):
                connection.rollback()
                return {"status": "CONFLICT", "reason": "grant:owner_changed"}
            grant_ids = self._verify_all_grants(connection)
            actions = self._controller_actions(connection)
            if grant_ids != set(actions):
                raise ValueError("canonical grant inventory mismatch")
            projection = self._verified_hook_projection(connection)
            controller_tip = self._verified_tip(
                connection, str(expected_owner.get("controller_run_id"))
            )
            expected_controller_tip = {
                "run_id": expected_owner.get("controller_run_id"),
                "seq": terminal_binding.get("controller_seq"),
                "event_hash": terminal_binding.get("controller_event_hash"),
            }
            if (
                controller_tip != expected_controller_tip
                or terminal_binding.get("controller_id")
                != expected_owner.get("controller_id")
                or terminal_binding.get("controller_run_id")
                != expected_owner.get("controller_run_id")
                or not isinstance(projection, Mapping)
                or projection.get("controller_id")
                != terminal_binding.get("controller_id")
                or projection.get("controller_run_id")
                != terminal_binding.get("controller_run_id")
                or projection.get("controller_seq")
                != terminal_binding.get("controller_seq")
                or projection.get("controller_event_hash")
                != terminal_binding.get("controller_event_hash")
                or projection.get("binding_sha256")
                != terminal_binding.get("binding_sha256")
            ):
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:terminal_tip_invalid",
                }
            unsettled = [
                str(row["action_sha256"])
                for row in connection.execute(
                    "SELECT action_sha256 FROM governed_native_grants "
                    "WHERE state IN ('PROVISIONAL', 'AUTHORIZED', 'DISPATCHED', "
                    "'OUTCOME_UNKNOWN') ORDER BY action_sha256"
                ).fetchall()
            ]
            if not unsettled:
                connection.rollback()
                return {"status": "NOT_REQUIRED"}
            if len(unsettled) != 1:
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:unsettled_set_invalid",
                }
            action_sha256 = unsettled[0]
            grant = self._verified_grant(connection, action_sha256)
            if not isinstance(grant, Mapping):
                raise ValueError("terminal grant missing")
            if grant.get("state") != "OUTCOME_UNKNOWN":
                connection.rollback()
                return {"status": "NOT_APPLICABLE"}
            if (
                actions.get(action_sha256) is None
                or grant.get("controller_id")
                != expected_owner.get("controller_id")
                or grant.get("controller_run_id")
                != expected_owner.get("controller_run_id")
                or grant.get("action_kind") != "spawn"
                or not _digest(grant.get("pretool_event_sha256"))
                or not _digest(grant.get("pretool_report_sha256"))
                or not _text(grant.get("tool_use_id"))
                or any(
                    grant.get(field) is not None
                    for field in (
                        "outcome",
                        "result_sha256",
                        "result_binding_sha256",
                        "posttool_report_sha256",
                    )
                )
            ):
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:terminal_unknown_spawn_invalid",
                }

            rows = [
                dict(row)
                for row in connection.execute(
                    "SELECT run_id, run_seq AS seq, kind, actor_key, payload, "
                    "note, prev_hash, event_hash, origin FROM events "
                    "WHERE run_id = ? AND reserved = 0 ORDER BY run_seq",
                    (expected_owner.get("controller_run_id"),),
                ).fetchall()
            ]
            run_engine.verify_event_chain(rows)
            applied = [row for row in rows if row.get("kind") == "applied"]
            if len(applied) < 2:
                raise ValueError("partial terminal evidence missing")
            intent_row, terminal_row = applied[-2:]
            intent_event = self._controller_event(intent_row)
            terminal_event = self._controller_event(terminal_row)
            intent = intent_event.get("payload")
            terminal = terminal_event.get("payload")
            stage_report = (
                terminal.get("stage_report")
                if isinstance(terminal, Mapping)
                else None
            )
            receipt = (
                stage_report.get("receipt")
                if isinstance(stage_report, Mapping)
                else None
            )
            expected_intent_cursor = {
                "run_id": intent_row.get("run_id"),
                "seq": intent_row.get("seq"),
                "event_hash": intent_row.get("event_hash"),
            }
            receipt_fields = {
                "failure_evidence_sha256",
                "terminal_snapshot_report_sha256",
                "historical_runtime_report_sha256",
                "historical_package_digest",
                "abandoned_turn_id",
                "created_worker_id",
                "created_logical_lane_id",
                "unmaterialized_logical_lane_ids",
                "worker_terminal_disposition",
                "worker_process_match_count",
                "owner_process_group_cleaned",
                "capacity_authority_state_sha256",
            }
            if (
                intent_event.get("event_type") != "stage_intent"
                or not isinstance(intent, Mapping)
                or set(intent)
                != {
                    "operation",
                    "failure_evidence_sha256",
                    "evaluation_time",
                    "proposed_action_sha256",
                }
                or intent.get("operation")
                != "partial_native_failure_terminalization"
                or not _digest(intent.get("failure_evidence_sha256"))
                or not _text(intent.get("evaluation_time"))
                or intent.get("proposed_action_sha256") is not None
                or terminal_event.get("event_type") != "stage_result"
                or not isinstance(terminal, Mapping)
                or set(terminal)
                != {
                    "intent_cursor",
                    "stage_report",
                    "action",
                    "capacity_guard",
                    "terminal",
                    "cleanup_required",
                    "terminal_evidence_sha256",
                    "issues",
                }
                or terminal.get("intent_cursor") != expected_intent_cursor
                or terminal.get("action") is not None
                or terminal.get("capacity_guard") is not None
                or terminal.get("terminal") is not True
                or terminal.get("cleanup_required") is not False
                or terminal.get("issues") != []
                or not isinstance(stage_report, Mapping)
                or set(stage_report)
                != {
                    "schema",
                    "operation",
                    "status",
                    "disposition",
                    "issues",
                    "receipt",
                    "next_action",
                }
                or stage_report.get("schema")
                != _PARTIAL_NATIVE_FAILURE_STAGE_SCHEMA
                or stage_report.get("operation")
                != "partial_native_failure_terminalization"
                or stage_report.get("status") != "PASS"
                or stage_report.get("disposition")
                != "PARTIAL_NATIVE_FAILURE_TERMINALIZED"
                or stage_report.get("issues") != []
                or stage_report.get("next_action")
                != "terminal_capacity_settlement"
                or terminal.get("terminal_evidence_sha256")
                != self._sha(stage_report)
                or not isinstance(receipt, Mapping)
                or set(receipt) != receipt_fields
                or receipt.get("failure_evidence_sha256")
                != intent.get("failure_evidence_sha256")
                or not _digest(receipt.get("terminal_snapshot_report_sha256"))
                or not _digest(receipt.get("historical_runtime_report_sha256"))
                or not _digest(receipt.get("historical_package_digest"))
                or not _text(receipt.get("abandoned_turn_id"))
                or not _text(receipt.get("created_worker_id"))
                or not _text(receipt.get("created_logical_lane_id"))
                or not isinstance(
                    receipt.get("unmaterialized_logical_lane_ids"), list
                )
                or len(receipt["unmaterialized_logical_lane_ids"]) != 1
                or not _text(receipt["unmaterialized_logical_lane_ids"][0])
                or receipt.get("worker_terminal_disposition") != "BLOCKED"
                or receipt.get("worker_process_match_count") != 0
                or receipt.get("owner_process_group_cleaned") is not True
                or not _digest(
                    receipt.get("capacity_authority_state_sha256")
                )
                or receipt.get("capacity_authority_state_sha256")
                == capacity_state_sha256
            ):
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:partial_terminal_evidence_invalid",
                }
            expected_capacity_tip = {
                "run_id": grant.get("capacity_run_id"),
                "seq": grant.get("capacity_seq"),
                "event_hash": grant.get("capacity_event_hash"),
            }
            current_capacity_tip = self._verified_tip(
                connection, str(grant.get("capacity_run_id"))
            )
            if (
                current_capacity_tip != dict(capacity_tip)
                or current_capacity_tip.get("run_id")
                != expected_capacity_tip.get("run_id")
                or current_capacity_tip.get("seq", 0)
                <= expected_capacity_tip.get("seq", 0)
                or current_capacity_tip == expected_capacity_tip
            ):
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:empty_capacity_not_current",
                }
            updated = connection.execute(
                "UPDATE governed_native_grants "
                "SET state = 'TERMINAL_OUTCOME_UNKNOWN' "
                "WHERE action_sha256 = ? AND state = 'OUTCOME_UNKNOWN'",
                (action_sha256,),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return {
                    "status": "CONFLICT",
                    "reason": "grant:terminalization_conflict",
                }
            terminal_grant = self._grant_snapshot(
                connection.execute(
                    "SELECT "
                    + ", ".join(_GRANT_COLUMNS)
                    + " FROM governed_native_grants WHERE action_sha256 = ?",
                    (action_sha256,),
                ).fetchone()
            )
            witness = self._append_grant_history(
                connection,
                previous=grant,
                current=terminal_grant,
                transition_type="PARTIAL_NATIVE_FAILURE_TERMINALIZED",
            )
            connection.commit()
            if not self._record_grant_transition_commit(witness):
                return {
                    "status": "UNKNOWN",
                    "reason": "grant:witness_unavailable",
                }
            return {
                "status": "TERMINALIZED",
                "action_sha256": action_sha256,
                "state": "TERMINAL_OUTCOME_UNKNOWN",
                "historical_outcome": "unknown",
                "terminal_evidence_sha256": terminal[
                    "terminal_evidence_sha256"
                ],
                "capacity_state_sha256": capacity_state_sha256,
            }
        except (
            OSError,
            sqlite3.Error,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            run_engine.RunKernelError,
        ):
            connection.rollback()
            return {
                "status": "UNKNOWN",
                "reason": "grant:terminalization_unavailable",
            }
        finally:
            connection.close()

    def current_tip(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT run_seq, event_hash FROM events "
                "WHERE run_id = ? AND reserved = 0 ORDER BY run_seq DESC LIMIT 1",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "run_id": run_id,
            "seq": int(row["run_seq"]),
            "event_hash": str(row["event_hash"]),
        }

    def _verified_tip(
        self, connection: sqlite3.Connection, run_id: str
    ) -> dict[str, Any] | None:
        rows = connection.execute(
            "SELECT run_id, run_seq AS seq, kind, actor_key, payload, note, "
            "prev_hash, event_hash, origin FROM events WHERE run_id = ? "
            "AND reserved = 0 ORDER BY run_seq",
            (run_id,),
        ).fetchall()
        if not rows:
            return None
        chain_rows = [dict(row) for row in rows]
        run_engine.verify_event_chain(chain_rows)
        for row in chain_rows:
            if json.loads(str(row["origin"])) != run_store.runtime_origin(
                str(row["kind"])
            ):
                raise ValueError("stream origin invalid")
        return {
            "run_id": run_id,
            "seq": int(rows[-1]["seq"]),
            "event_hash": str(rows[-1]["event_hash"]),
        }

    def verified_tip(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            return self._verified_tip(connection, run_id)

    def custody_valid(self) -> bool:
        """Verify retained controller, grant, hook, and run-marker custody.

        One current-run PROVISIONAL grant is tolerated so a controller can
        recover the documented crash window between intent and stage result.
        It is never sufficient to authorize a native action.
        """

        try:
            if not self._authority_files_valid():
                return False
            with self._connect() as connection:
                owner = _row(
                    connection.execute(
                        "SELECT schema, controller_id, controller_run_id, "
                        "activation_sha256, store_identity_sha256 "
                        "FROM governed_native_owner WHERE singleton = 1"
                    ).fetchone()
                )
                if (
                    owner is None
                    or owner.get("schema") != OWNER_SCHEMA
                    or not _text(owner.get("controller_id"))
                    or not _text(owner.get("controller_run_id"))
                    or not _digest(owner.get("activation_sha256"))
                    or owner.get("store_identity_sha256")
                    != self.store_identity_sha256
                ):
                    return False
                grant_ids = self._verify_all_grants(connection)
                actions = self._controller_actions(connection)
                for action_sha256, expected in actions.items():
                    grant = self._verified_grant(connection, action_sha256)
                    if grant is None or any(
                        grant.get(field) != value
                        for field, value in expected.items()
                    ):
                        return False
                provisional_ids = grant_ids - set(actions)
                if len(provisional_ids) > 1:
                    return False
                tip = self._verified_tip(
                    connection, str(owner["controller_run_id"])
                )
                for action_sha256 in provisional_ids:
                    grant = self._verified_grant(connection, action_sha256)
                    if (
                        grant is None
                        or grant.get("state") != "PROVISIONAL"
                        or grant.get("controller_id")
                        != owner.get("controller_id")
                        or grant.get("controller_run_id")
                        != owner.get("controller_run_id")
                        or tip
                        != {
                            "run_id": grant.get("controller_run_id"),
                            "seq": grant.get("controller_seq"),
                            "event_hash": grant.get("controller_event_hash"),
                        }
                    ):
                        return False
                self._verified_hook_projection(connection)
            return True
        except (
            OSError,
            sqlite3.Error,
            TypeError,
            UnicodeDecodeError,
            ValueError,
            json.JSONDecodeError,
            run_engine.RunKernelError,
        ):
            return False

    def event_hash_at(self, run_id: str, seq: int) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT event_hash FROM events "
                "WHERE run_id = ? AND run_seq = ? AND reserved = 0",
                (run_id, seq),
            ).fetchone()
        return str(row["event_hash"]) if row is not None else None

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    @classmethod
    def _sha(cls, value: Any) -> str:
        return hashlib.sha256(cls._canonical(value)).hexdigest()

    def canonical_authority(self) -> dict[str, Any]:
        """Project owner, activation identity, tip, and lifecycle from SQLite."""

        owner = self.owner()
        if owner is None:
            try:
                with self._connect() as connection:
                    marker = connection.execute(
                        "SELECT projection_state FROM "
                        "governed_native_authority_meta WHERE singleton = 1"
                    ).fetchone()
                    marker_state = (
                        int(marker["projection_state"])
                        if marker is not None
                        else -1
                    )
                    residue = self._authority_residue(connection)
                external_marker = self._authority_marker_status()
                external_tombstone = self._authority_tombstone_status()
                run_markers_absent = not self._read_controller_run_markers()
                external_witness_absent = (
                    self._external_witness_manifest_status() == "ABSENT"
                    and not self.external_witness_root.exists()
                    and not self.external_witness_root.is_symlink()
                )
            except (OSError, sqlite3.Error, TypeError, ValueError):
                marker_state = -1
                residue = -1
                external_marker = "INVALID"
                external_tombstone = "INVALID"
                run_markers_absent = False
                external_witness_absent = False
            return {
                "status": (
                    "LEGACY"
                    if marker_state == 0
                    and residue == 0
                    and external_marker == "ABSENT"
                    and external_tombstone == "ABSENT"
                    and run_markers_absent
                    and external_witness_absent
                    else "INVALID"
                ),
                "owner": None,
                "identity": None,
                "tip": None,
                "lifecycle": None,
                "policy": None,
                "hook_projection": None,
                "ground_state_sha256": None,
                "store_identity_sha256": self.store_identity_sha256,
            }
        run_id = owner.get("controller_run_id")
        try:
            if (
                set(owner)
                != {
                    "schema",
                    "controller_id",
                    "controller_run_id",
                    "activation_sha256",
                    "store_identity_sha256",
                }
                or owner.get("schema") != OWNER_SCHEMA
                or not _text(owner.get("controller_id"))
                or not _text(run_id)
                or not _digest(owner.get("activation_sha256"))
                or owner.get("store_identity_sha256")
                != self.store_identity_sha256
            ):
                raise ValueError("canonical owner invalid")
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT run_id, run_seq AS seq, kind, actor_key, payload, "
                    "note, prev_hash, event_hash, origin FROM events "
                    "WHERE run_id = ? AND reserved = 0 ORDER BY run_seq",
                    (run_id,),
                ).fetchall()
                if not rows:
                    raise ValueError("controller stream missing")
                chain_rows = [dict(row) for row in rows]
                run_engine.verify_event_chain(chain_rows)
                for row in chain_rows:
                    origin = json.loads(str(row["origin"]))
                    if origin != run_store.runtime_origin(str(row["kind"])):
                        raise ValueError("controller stream origin invalid")
                verified_grants = self._verify_all_grants(connection)
                controller_actions = self._controller_actions(connection)
                if verified_grants != set(controller_actions):
                    raise ValueError("canonical grant inventory mismatch")
                for action_sha256, expected in controller_actions.items():
                    grant = self._verified_grant(connection, action_sha256)
                    if grant is None or any(
                        grant.get(field) != value
                        for field, value in expected.items()
                    ):
                        raise ValueError("canonical grant action mismatch")
                projection = self._verified_hook_projection(connection)
                started = json.loads(str(rows[0]["payload"]))
                plan = started.get("plan") if isinstance(started, Mapping) else None
                origin = plan.get("origin") if isinstance(plan, Mapping) else None
                activation = (
                    origin.get("governed_native_activation")
                    if isinstance(origin, Mapping)
                    else None
                )
                if (
                    not isinstance(activation, Mapping)
                    or origin.get("activation_sha256") != self._sha(activation)
                    or owner.get("activation_sha256") != self._sha(activation)
                    or origin.get("controller_id") != owner.get("controller_id")
                    or origin.get("store_identity_sha256")
                    != self.store_identity_sha256
                ):
                    raise ValueError("activation authority invalid")
                identity = activation.get("identity")
                if not isinstance(identity, Mapping):
                    raise ValueError("activation identity missing")
                project_ground_state = activation.get("project_ground_state")
                ground_program = (
                    project_ground_state.get("program")
                    if isinstance(project_ground_state, Mapping)
                    else None
                )
                tool_policy = (
                    ground_program.get("tool_policy")
                    if isinstance(ground_program, Mapping)
                    and isinstance(ground_program.get("tool_policy"), Mapping)
                    else None
                )
                read_only_tools = (
                    tool_policy.get("read_only_tools")
                    if isinstance(tool_policy, Mapping)
                    else None
                )
                if not isinstance(read_only_tools, list):
                    raise ValueError("canonical tool policy missing")
                pending = False
                terminal = False
                terminal_qualified = False
                terminal_evidence_sha256 = None
                action: Mapping[str, Any] | None = None
                cleanup_required = False
                for row in rows[1:]:
                    event = self._controller_event(row)
                    event_type = event["event_type"]
                    payload = event["payload"]
                    if not isinstance(payload, Mapping):
                        raise ValueError("controller event payload invalid")
                    if event_type in {"stage_intent", "action_observation_intent"}:
                        if pending:
                            raise ValueError("overlapping controller intent")
                        pending = True
                    elif event_type == "stage_result":
                        if not pending:
                            raise ValueError("stage result without intent")
                        pending = False
                        action = (
                            payload.get("action")
                            if isinstance(payload.get("action"), Mapping)
                            else None
                        )
                        terminal = terminal or payload.get("terminal") is True
                        stage_report = payload.get("stage_report")
                        claimed_terminal_evidence = payload.get(
                            "terminal_evidence_sha256"
                        )
                        if (
                            payload.get("terminal") is True
                            and isinstance(stage_report, Mapping)
                            and stage_report.get("status") == "PASS"
                            and stage_report.get("disposition")
                            == "TERMINALLY_QUALIFIED"
                            and claimed_terminal_evidence == self._sha(stage_report)
                        ):
                            terminal_qualified = True
                            terminal_evidence_sha256 = claimed_terminal_evidence
                        cleanup_required = payload.get("cleanup_required") is True
                    elif event_type == "action_observed":
                        if not pending or action is None:
                            raise ValueError("action result without intent")
                        outcome = payload.get("outcome")
                        pending = False
                        action = (
                            payload.get("next_action")
                            if isinstance(payload.get("next_action"), Mapping)
                            else None
                        )
                        cleanup_required = bool(
                            payload.get("cleanup_required") is True
                            or (
                                "cleanup_required" not in payload
                                and outcome
                                in {"failed", "cancelled", "timed_out"}
                            )
                        )
                        terminal = terminal or payload.get("terminal") is True or (
                            "terminal" not in payload and outcome == "unknown"
                        )
                    else:
                        raise ValueError("controller event type invalid")
                grant = None
                if isinstance(action, Mapping):
                    grant = self._verified_grant(
                        connection, str(action.get("action_sha256"))
                    )
            tip = {
                "run_id": str(run_id),
                "seq": int(rows[-1]["seq"]),
                "event_hash": str(rows[-1]["event_hash"]),
            }
            if (
                projection.get("controller_id") != owner.get("controller_id")
                or projection.get("controller_run_id") != run_id
                or projection.get("controller_seq") != tip["seq"]
                or projection.get("controller_event_hash") != tip["event_hash"]
            ):
                raise ValueError("canonical hook projection does not match tip")
            grant_state = grant.get("state") if isinstance(grant, Mapping) else None
            expected_status = (
                "TERMINAL"
                if terminal
                else "BLOCKED"
                if pending
                or (
                    action is not None
                    and grant_state not in _DISPATCH_STATES
                )
                else "ACTIVE"
                if action is not None
                else "WAITING"
            )
            ground_record = deepcopy(dict(activation["project_ground_state"]))
            ground_program = ground_record.get("program")
            if not isinstance(ground_program, Mapping):
                raise ValueError("canonical project ground missing")
            ground_program = deepcopy(dict(ground_program))
            if terminal_qualified and terminal_evidence_sha256 is not None:
                ground_program["completion"] = {
                    "final_verification_valid": True,
                    "final_verification_sha256": terminal_evidence_sha256,
                    "independent_observation": "BOUND",
                    "governed_controller_status": "PASS",
                }
            else:
                ground_program["completion"] = {
                    "final_verification_valid": False,
                    "final_verification_sha256": None,
                    "independent_observation": "UNBOUND",
                    "governed_controller_status": "PENDING",
                }
            ground_record["program"] = ground_program
            ground_record["program_sha256"] = self._sha(ground_program)
            ground_state_sha256 = self._sha(ground_record)
            return {
                "status": "VERIFIED",
                "owner": owner,
                "identity": {
                    "controller_id": owner["controller_id"],
                    "controller_run_id": run_id,
                    "root_thread_id": identity.get("root_thread_id"),
                    "root_session_id": identity.get("root_session_id"),
                    "root_model": identity.get("root_model"),
                    "hook_definition_sha256": identity.get(
                        "hook_definition_sha256"
                    ),
                    "hook_registration_sha256": identity.get(
                        "hook_registration_sha256"
                    ),
                    "activation_sha256": owner["activation_sha256"],
                },
                **({"source_roots": deepcopy(activation["source_roots"])}
                   if "source_roots" in activation else {}),
                "tip": tip,
                "lifecycle": {
                    "terminal": terminal,
                    "terminal_qualified": terminal_qualified,
                    "terminal_evidence_sha256": terminal_evidence_sha256,
                    "pending_intent": pending,
                    "cleanup_required": cleanup_required,
                    "action_sha256": (
                        action.get("action_sha256")
                        if isinstance(action, Mapping)
                        else None
                    ),
                    "grant_state": grant_state,
                    "tool_use_id": (
                        grant.get("tool_use_id")
                        if isinstance(grant, Mapping)
                        else None
                    ),
                    "expected_binding_status": expected_status,
                },
                "policy": {"read_only_tools": list(read_only_tools)},
                "hook_projection": projection,
                "ground_state_sha256": ground_state_sha256,
                "store_identity_sha256": self.store_identity_sha256,
            }
        except (
            OSError,
            sqlite3.Error,
            TypeError,
            UnicodeDecodeError,
            ValueError,
            json.JSONDecodeError,
            run_engine.RunKernelError,
        ):
            return {
                "status": "INVALID",
                "owner": owner,
                "identity": None,
                "tip": None,
                "lifecycle": None,
                "policy": None,
                "hook_projection": None,
                "ground_state_sha256": None,
                "store_identity_sha256": self.store_identity_sha256,
            }

    @staticmethod
    def _grant_projection(action: Mapping[str, Any], cursor: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "action_sha256": action.get("action_sha256"),
            "action_kind": action.get("kind"),
            "controller_id": action.get("controller_id"),
            "controller_run_id": cursor.get("run_id"),
            "controller_seq": cursor.get("seq"),
            "controller_event_hash": cursor.get("event_hash"),
            "action_id": action.get("action_id"),
            "tool_name": action.get("tool_name"),
            "tool_input_sha256": action.get("tool_input_sha256"),
        }

    def prepare_action(
        self,
        action: Mapping[str, Any],
        intent_cursor: Mapping[str, Any],
        *,
        capacity_guard: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        expected = self._grant_projection(action, intent_cursor)
        if (
            set(expected) != _GRANT_FIELDS
            or any(value is None for value in expected.values())
            or not _digest(expected["action_sha256"])
            or expected["action_kind"] not in {"spawn", "continue", "stop"}
            or not _text(expected["controller_id"])
            or not _text(expected["controller_run_id"])
            or type(expected["controller_seq"]) is not int
            or expected["controller_seq"] < 1
            or not _digest(expected["controller_event_hash"])
            or not _text(expected["action_id"])
            or not _text(expected["tool_name"])
            or not _digest(expected["tool_input_sha256"])
        ):
            return {"status": "REFUSED", "reason": "grant:projection_invalid"}
        guard = dict(capacity_guard) if isinstance(capacity_guard, Mapping) else None
        if expected["action_kind"] == "spawn":
            if (
                guard is None
                or set(guard) != {"run_id", "seq", "event_hash"}
                or not _text(guard.get("run_id"))
                or type(guard.get("seq")) is not int
                or guard["seq"] < 1
                or not _digest(guard.get("event_hash"))
            ):
                return {
                    "status": "REFUSED",
                    "reason": "grant:capacity_guard_invalid",
                }
        elif guard is not None:
            return {
                "status": "REFUSED",
                "reason": "grant:unexpected_capacity_guard",
            }
        if not self.owner_matches(str(expected["controller_id"]), str(expected["controller_run_id"])):
            return {"status": "REFUSED", "reason": "grant:owner_mismatch"}
        if self.current_tip(str(expected["controller_run_id"])) != dict(intent_cursor):
            return {"status": "REFUSED", "reason": "grant:controller_tip_mismatch"}
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._verified_grant(
                connection, str(expected["action_sha256"])
            )
            if existing is None:
                connection.execute(
                    "INSERT INTO governed_native_grants "
                    "(action_sha256, schema, controller_id, controller_run_id, "
                    "controller_seq, controller_event_hash, action_id, action_kind, "
                    "tool_name, tool_input_sha256, capacity_run_id, capacity_seq, "
                    "capacity_event_hash, state) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROVISIONAL')",
                    (
                        expected["action_sha256"],
                        GRANT_SCHEMA,
                        expected["controller_id"],
                        expected["controller_run_id"],
                        expected["controller_seq"],
                        expected["controller_event_hash"],
                        expected["action_id"],
                        expected["action_kind"],
                        expected["tool_name"],
                        expected["tool_input_sha256"],
                        guard.get("run_id") if guard is not None else None,
                        guard.get("seq") if guard is not None else None,
                        guard.get("event_hash") if guard is not None else None,
                    ),
                )
                current = self._grant_snapshot(
                    connection.execute(
                        "SELECT " + ", ".join(_GRANT_COLUMNS)
                        + " FROM governed_native_grants WHERE action_sha256 = ?",
                        (expected["action_sha256"],),
                    ).fetchone()
                )
                witness = self._append_grant_history(
                    connection,
                    previous=None,
                    current=current,
                    transition_type="PREPARED",
                )
                connection.commit()
                if not self._record_grant_transition_commit(witness):
                    return {
                        "status": "UNKNOWN",
                        "reason": "grant:witness_unavailable",
                    }
                return {"status": "PREPARED"}
            connection.rollback()
            same = all(existing.get(key) == value for key, value in expected.items())
            same = same and (
                all(
                    existing.get(field) == guard.get(key)
                    for field, key in (
                        ("capacity_run_id", "run_id"),
                        ("capacity_seq", "seq"),
                        ("capacity_event_hash", "event_hash"),
                    )
                )
                if guard is not None
                else all(
                    existing.get(field) is None
                    for field in (
                        "capacity_run_id",
                        "capacity_seq",
                        "capacity_event_hash",
                    )
                )
            )
            return {
                "status": "IDEMPOTENT" if same and existing.get("state") == "PROVISIONAL" else "CONFLICT",
                "state": existing.get("state"),
            }
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            connection.rollback()
            return {"status": "UNKNOWN", "reason": "grant:store_unavailable"}
        finally:
            connection.close()

    def finalize_action(
        self, action: Mapping[str, Any], result_cursor: Mapping[str, Any]
    ) -> dict[str, Any]:
        expected = self._grant_projection(action, result_cursor)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._verified_grant(
                connection, str(expected.get("action_sha256"))
            )
            if row is None:
                connection.rollback()
                return {"status": "MISSING"}
            same_static = all(
                row.get(key) == value
                for key, value in expected.items()
                if key not in {"controller_seq", "controller_event_hash"}
            )
            if row.get("state") == "AUTHORIZED":
                same = same_static and all(
                    row.get(key) == expected.get(key)
                    for key in ("controller_seq", "controller_event_hash")
                )
                connection.rollback()
                return {"status": "IDEMPOTENT" if same else "CONFLICT"}
            prior_tip = {
                "run_id": row.get("controller_run_id"),
                "seq": row.get("controller_seq"),
                "event_hash": row.get("controller_event_hash"),
            }
            if (
                row.get("state") != "PROVISIONAL"
                or not same_static
                or type(row.get("controller_seq")) is not int
                or result_cursor.get("seq") != row.get("controller_seq") + 1
                or self.event_hash_at(
                    str(row.get("controller_run_id")), row.get("controller_seq")
                )
                != row.get("controller_event_hash")
                or self.current_tip(str(row.get("controller_run_id")))
                != dict(result_cursor)
                or prior_tip["run_id"] != result_cursor.get("run_id")
            ):
                connection.rollback()
                return {"status": "CONFLICT"}
            updated = connection.execute(
                "UPDATE governed_native_grants SET state = 'AUTHORIZED', "
                "controller_seq = ?, controller_event_hash = ? "
                "WHERE action_sha256 = ? AND state = 'PROVISIONAL'",
                (
                    result_cursor.get("seq"),
                    result_cursor.get("event_hash"),
                    action.get("action_sha256"),
                ),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return {"status": "CONFLICT"}
            current = self._grant_snapshot(
                connection.execute(
                    "SELECT " + ", ".join(_GRANT_COLUMNS)
                    + " FROM governed_native_grants WHERE action_sha256 = ?",
                    (action.get("action_sha256"),),
                ).fetchone()
            )
            witness = self._append_grant_history(
                connection,
                previous=row,
                current=current,
                transition_type="FINALIZED",
            )
            connection.commit()
            if not self._record_grant_transition_commit(witness):
                return {"status": "UNKNOWN"}
            return {"status": "FINALIZED"}
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            connection.rollback()
            return {"status": "UNKNOWN"}
        finally:
            connection.close()

    def read_action(self, action_sha256: str) -> dict[str, Any] | None:
        try:
            with self._connect() as connection:
                return self._verified_grant(connection, action_sha256)
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def _binding_matches(row: Mapping[str, Any], binding: Mapping[str, Any]) -> bool:
        action = (
            binding.get("action")
            if isinstance(binding.get("action"), Mapping)
            else {}
        )
        return bool(
            row.get("schema") == GRANT_SCHEMA
            and row.get("controller_id") == binding.get("controller_id")
            and row.get("controller_run_id") == binding.get("controller_run_id")
            and row.get("controller_seq") == binding.get("controller_seq")
            and row.get("controller_event_hash") == binding.get("controller_event_hash")
            and row.get("action_sha256") == action.get("action_sha256")
            and row.get("action_id") == action.get("action_id")
            and row.get("action_kind") == action.get("kind")
            and row.get("tool_name") == action.get("tool_name")
            and row.get("tool_input_sha256") == action.get("tool_input_sha256")
        )

    def record_retained_owner_observation(
        self,
        binding: Mapping[str, Any],
        *,
        tool_use_id: str,
        outcome: str,
        result_sha256: str,
        result_binding: Any,
        observation_sha256: str,
    ) -> dict[str, Any]:
        """Record or reconcile one call seen on the retained owner stream.

        The three historical hook-digest columns carry the same owner
        observation digest on this path.  The controller event stores the
        complete typed observation and distinguishes its source; keeping the
        grant row shape stable avoids a database migration for a representation
        detail that grants do not otherwise consume.  If hooks already recorded
        the same tool id, outcome, and normalized result, the owner observation
        is corroborating evidence rather than a conflicting second outcome.
        """

        action = (
            binding.get("action")
            if isinstance(binding.get("action"), Mapping)
            else {}
        )
        normalized_result = native_result.normalize_native_result(
            result_binding,
            action_kind=action.get("kind"),
            expected_lane_ids=action.get("lane_ids"),
            outcome=outcome,
        )
        if (
            not _text(tool_use_id)
            or outcome not in _OUTCOMES
            or not _digest(result_sha256)
            or not _digest(observation_sha256)
            or (
                outcome == "completed"
                and (
                    normalized_result is None
                    or normalized_result != result_binding
                )
            )
            or (outcome != "completed" and result_binding is not None)
        ):
            return {
                "status": "REFUSED",
                "reason": "grant:owner_observation_invalid",
            }
        if not self.custody_valid():
            return {
                "status": "REFUSED",
                "reason": "grant:authority_custody_invalid",
            }
        result_binding_sha256 = self._sha(result_binding)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._verified_grant(
                connection, str(action.get("action_sha256"))
            )
            if row is None or not self._binding_matches(row, binding):
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:binding_mismatch"}
            if row.get("state") == "POST_OBSERVED":
                same_call = (
                    row.get("tool_use_id") == tool_use_id
                    and row.get("outcome") == outcome
                )
                # The hook sealed the raw wire result of this call id.  A
                # continuation or stop projects less to the retained owner
                # than the wire returned, so its normalized projection is a
                # witness of the same call rather than a second seal; the
                # controller checks that projection against the sealed
                # binding before it advances.  Spawn projects the created
                # worker id, so both rails must agree exactly.
                same_binding = same_call and (
                    row.get("result_binding_sha256") == result_binding_sha256
                    or action.get("kind")
                    in native_result.OWNER_PROJECTION_WITNESS_KINDS
                )
                same_owner_observation = (
                    same_binding
                    and row.get("result_binding_sha256")
                    == result_binding_sha256
                    and row.get("result_sha256") == result_sha256
                    and row.get("pretool_event_sha256")
                    == observation_sha256
                    and row.get("pretool_report_sha256")
                    == observation_sha256
                    and row.get("posttool_report_sha256")
                    == observation_sha256
                )
                tail = connection.execute(
                    "SELECT transition_type FROM governed_native_grant_history "
                    "WHERE action_sha256 = ? "
                    "ORDER BY action_transition DESC LIMIT 1",
                    (action.get("action_sha256"),),
                ).fetchone()
                hook_observation = bool(
                    # PostToolUse seals the raw wire response while the
                    # retained owner can seal only the normalized app-server
                    # projection. The normalized binding is their common
                    # exact value; the two raw digests intentionally differ.
                    same_binding
                    and tail is not None
                    and tail["transition_type"] == "POSTTOOL_RECORDED"
                )
                connection.rollback()
                return {
                    "status": (
                        "IDEMPOTENT"
                        if same_owner_observation
                        else "RECONCILED"
                        if hook_observation
                        else "REFUSED"
                    ),
                    "reason": (
                        None
                        if same_owner_observation or hook_observation
                        else "grant:observation_conflict"
                    ),
                }
            if row.get("state") != "AUTHORIZED":
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:not_current_authorized",
                }
            expected_tip = {
                "run_id": row.get("controller_run_id"),
                "seq": row.get("controller_seq"),
                "event_hash": row.get("controller_event_hash"),
            }
            if self._verified_tip(
                connection, str(row.get("controller_run_id"))
            ) != expected_tip:
                connection.rollback()
                return {
                    "status": "REFUSED",
                    "reason": "grant:controller_tip_mismatch",
                }
            if row.get("action_kind") == "spawn":
                expected_capacity_tip = {
                    "run_id": row.get("capacity_run_id"),
                    "seq": row.get("capacity_seq"),
                    "event_hash": row.get("capacity_event_hash"),
                }
                if self._verified_tip(
                    connection, str(row.get("capacity_run_id"))
                ) != expected_capacity_tip:
                    connection.rollback()
                    return {
                        "status": "REFUSED",
                        "reason": "grant:capacity_head_stale",
                    }
            updated = connection.execute(
                "UPDATE governed_native_grants SET state = 'POST_OBSERVED', "
                "pretool_event_sha256 = ?, pretool_report_sha256 = ?, "
                "tool_use_id = ?, outcome = ?, result_sha256 = ?, "
                "result_binding_sha256 = ?, posttool_report_sha256 = ? "
                "WHERE action_sha256 = ? AND state = 'AUTHORIZED'",
                (
                    observation_sha256,
                    observation_sha256,
                    tool_use_id,
                    outcome,
                    result_sha256,
                    result_binding_sha256,
                    observation_sha256,
                    action.get("action_sha256"),
                ),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:claim_conflict"}
            current = self._grant_snapshot(
                connection.execute(
                    "SELECT " + ", ".join(_GRANT_COLUMNS)
                    + " FROM governed_native_grants WHERE action_sha256 = ?",
                    (action.get("action_sha256"),),
                ).fetchone()
            )
            witness = self._append_grant_history(
                connection,
                previous=row,
                current=current,
                transition_type="RETAINED_OWNER_OBSERVED",
            )
            connection.commit()
            if not self._record_grant_transition_commit(witness):
                return {
                    "status": "UNKNOWN",
                    "reason": "grant:witness_unavailable",
                }
            if not self.custody_valid():
                return {
                    "status": "UNKNOWN",
                    "reason": "grant:authority_custody_invalid",
                }
            return {"status": "RECORDED"}
        except (
            sqlite3.Error,
            run_engine.RunKernelError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            connection.rollback()
            return {"status": "UNKNOWN", "reason": "grant:store_unavailable"}
        finally:
            connection.close()

    def claim_action(
        self,
        binding: Mapping[str, Any],
        *,
        pretool_event_sha256: str,
        tool_use_id: str,
    ) -> dict[str, Any]:
        if not _digest(pretool_event_sha256) or not _text(tool_use_id):
            return {"status": "REFUSED", "reason": "grant:pretool_event_invalid"}
        if not self.custody_valid():
            return {"status": "REFUSED", "reason": "grant:authority_custody_invalid"}
        action = binding.get("action") if isinstance(binding.get("action"), Mapping) else {}
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            controller_tip = self._verified_tip(
                connection, str(binding.get("controller_run_id"))
            )
            row = self._verified_grant(
                connection, str(action.get("action_sha256"))
            )
            tip_matches = controller_tip == {
                "run_id": binding.get("controller_run_id"),
                "seq": binding.get("controller_seq"),
                "event_hash": binding.get("controller_event_hash"),
            }
            if (
                not tip_matches
                or row is None
                or not self._binding_matches(row, binding)
                or row.get("state") != "AUTHORIZED"
            ):
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:not_current_authorized"}
            if row.get("action_kind") == "spawn":
                expected_capacity_tip = {
                    "run_id": row.get("capacity_run_id"),
                    "seq": row.get("capacity_seq"),
                    "event_hash": row.get("capacity_event_hash"),
                }
                try:
                    current_capacity_tip = self._verified_tip(
                        connection, str(row.get("capacity_run_id"))
                    )
                except (
                    run_engine.RunKernelError,
                    TypeError,
                    ValueError,
                    json.JSONDecodeError,
                ):
                    current_capacity_tip = None
                if current_capacity_tip != expected_capacity_tip:
                    connection.execute(
                        "UPDATE governed_native_grants SET state = 'STALE' "
                        "WHERE action_sha256 = ? AND state = 'AUTHORIZED'",
                        (action.get("action_sha256"),),
                    )
                    stale = self._grant_snapshot(
                        connection.execute(
                            "SELECT " + ", ".join(_GRANT_COLUMNS)
                            + " FROM governed_native_grants WHERE action_sha256 = ?",
                            (action.get("action_sha256"),),
                        ).fetchone()
                    )
                    witness = self._append_grant_history(
                        connection,
                        previous=row,
                        current=stale,
                        transition_type="CAPACITY_STALE",
                    )
                    connection.commit()
                    if not self._record_grant_transition_commit(witness):
                        return {
                            "status": "REFUSED",
                            "reason": "grant:witness_unavailable",
                        }
                    return {
                        "status": "REFUSED",
                        "reason": "grant:capacity_head_stale",
                    }
            updated = connection.execute(
                "UPDATE governed_native_grants SET state = 'DISPATCHED', "
                "pretool_event_sha256 = ?, tool_use_id = ? "
                "WHERE action_sha256 = ? AND state = 'AUTHORIZED'",
                (pretool_event_sha256, tool_use_id, action.get("action_sha256")),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:claim_conflict"}
            dispatched = self._grant_snapshot(
                connection.execute(
                    "SELECT " + ", ".join(_GRANT_COLUMNS)
                    + " FROM governed_native_grants WHERE action_sha256 = ?",
                    (action.get("action_sha256"),),
                ).fetchone()
            )
            witness = self._append_grant_history(
                connection,
                previous=row,
                current=dispatched,
                transition_type="CLAIMED",
            )
            connection.commit()
            if not self._record_grant_transition_commit(witness):
                return {
                    "status": "UNKNOWN",
                    "reason": "grant:witness_unavailable",
                }
            if not self.custody_valid():
                self.mark_pretool_outcome_unknown(
                    str(action.get("action_sha256")),
                    event_sha256=pretool_event_sha256,
                    tool_use_id=tool_use_id,
                )
                return {
                    "status": "REFUSED",
                    "reason": "grant:authority_custody_invalid",
                }
            return {"status": "CLAIMED"}
        except (
            sqlite3.Error,
            run_engine.RunKernelError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            connection.rollback()
            return {"status": "UNKNOWN", "reason": "grant:store_unavailable"}
        finally:
            connection.close()

    def mark_pretool_outcome_unknown(
        self, action_sha256: str, *, event_sha256: str, tool_use_id: str
    ) -> bool:
        if not _digest(action_sha256) or not _digest(event_sha256) or not _text(
            tool_use_id
        ):
            return False
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            previous = self._verified_grant(connection, action_sha256)
            if previous is None:
                connection.rollback()
                return False
            updated = connection.execute(
                "UPDATE governed_native_grants SET state = 'OUTCOME_UNKNOWN' "
                "WHERE action_sha256 = ? AND state = 'DISPATCHED' "
                "AND pretool_event_sha256 = ? AND tool_use_id = ? "
                "AND pretool_report_sha256 IS NULL",
                (action_sha256, event_sha256, tool_use_id),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return False
            current = self._grant_snapshot(
                connection.execute(
                    "SELECT " + ", ".join(_GRANT_COLUMNS)
                    + " FROM governed_native_grants WHERE action_sha256 = ?",
                    (action_sha256,),
                ).fetchone()
            )
            witness = self._append_grant_history(
                connection,
                previous=previous,
                current=current,
                transition_type="PRETOOL_UNKNOWN",
            )
            connection.commit()
            return self._record_grant_transition_commit(witness)
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            connection.rollback()
            return False
        finally:
            connection.close()

    def bind_pretool_report(
        self, action_sha256: str, *, event_sha256: str, report_sha256: str
    ) -> bool:
        if not all(_digest(value) for value in (action_sha256, event_sha256, report_sha256)):
            return False
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            previous = self._verified_grant(connection, action_sha256)
            if previous is None:
                connection.rollback()
                return False
            updated = connection.execute(
                "UPDATE governed_native_grants SET pretool_report_sha256 = ? "
                "WHERE action_sha256 = ? AND state = 'DISPATCHED' "
                "AND pretool_event_sha256 = ? AND pretool_report_sha256 IS NULL",
                (report_sha256, action_sha256, event_sha256),
            ).rowcount
            if updated == 1:
                current = self._grant_snapshot(
                    connection.execute(
                        "SELECT " + ", ".join(_GRANT_COLUMNS)
                        + " FROM governed_native_grants WHERE action_sha256 = ?",
                        (action_sha256,),
                    ).fetchone()
                )
                witness = self._append_grant_history(
                    connection,
                    previous=previous,
                    current=current,
                    transition_type="PRETOOL_BOUND",
                )
                connection.commit()
                return self._record_grant_transition_commit(witness)
            row = connection.execute(
                "SELECT pretool_event_sha256, pretool_report_sha256 FROM governed_native_grants "
                "WHERE action_sha256 = ? AND state = 'DISPATCHED'",
                (action_sha256,),
            ).fetchone()
            same = bool(
                row
                and row["pretool_event_sha256"] == event_sha256
                and row["pretool_report_sha256"] == report_sha256
            )
            connection.rollback()
            return same
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            connection.rollback()
            return False
        finally:
            connection.close()

    def mark_posttool_outcome_unknown(
        self, action_sha256: str, *, tool_use_id: str
    ) -> bool:
        if not _digest(action_sha256) or not _text(tool_use_id):
            return False
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            previous = self._verified_grant(connection, action_sha256)
            if previous is None:
                connection.rollback()
                return False
            updated = connection.execute(
                "UPDATE governed_native_grants SET state = 'OUTCOME_UNKNOWN' "
                "WHERE action_sha256 = ? AND state = 'DISPATCHED' "
                "AND tool_use_id = ?",
                (action_sha256, tool_use_id),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return False
            current = self._grant_snapshot(
                connection.execute(
                    "SELECT " + ", ".join(_GRANT_COLUMNS)
                    + " FROM governed_native_grants WHERE action_sha256 = ?",
                    (action_sha256,),
                ).fetchone()
            )
            witness = self._append_grant_history(
                connection,
                previous=previous,
                current=current,
                transition_type="POSTTOOL_UNKNOWN",
            )
            connection.commit()
            return self._record_grant_transition_commit(witness)
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            connection.rollback()
            return False
        finally:
            connection.close()

    def record_posttool(
        self,
        binding: Mapping[str, Any],
        *,
        tool_use_id: str,
        pretool_report_sha256: str,
        outcome: str,
        result_sha256: str,
        result_binding: Any,
        report_sha256: str,
    ) -> dict[str, Any]:
        action = (
            binding.get("action")
            if isinstance(binding.get("action"), Mapping)
            else {}
        )
        normalized_result = native_result.normalize_native_result(
            result_binding,
            action_kind=action.get("kind"),
            expected_lane_ids=action.get("lane_ids"),
            outcome=outcome,
        )
        if (
            not _text(tool_use_id)
            or not _digest(pretool_report_sha256)
            or outcome not in _OUTCOMES
            or not _digest(result_sha256)
            or not _digest(report_sha256)
            or (
                outcome == "completed"
                and (
                    normalized_result is None
                    or normalized_result != result_binding
                )
            )
            or (outcome != "completed" and result_binding is not None)
        ):
            return {"status": "REFUSED", "reason": "grant:posttool_result_invalid"}
        if not self.custody_valid():
            return {"status": "REFUSED", "reason": "grant:authority_custody_invalid"}
        result_binding_sha256 = self._sha(result_binding)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._verified_grant(
                connection, str(action.get("action_sha256"))
            )
            if row is None or not self._binding_matches(row, binding):
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:binding_mismatch"}
            if row.get("state") == "POST_OBSERVED":
                same = (
                    row.get("outcome") == outcome
                    and row.get("result_sha256") == result_sha256
                    and row.get("result_binding_sha256")
                    == result_binding_sha256
                    and row.get("posttool_report_sha256") == report_sha256
                )
                connection.rollback()
                return {"status": "IDEMPOTENT" if same else "REFUSED"}
            if row.get("state") != "DISPATCHED":
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:not_dispatched"}
            if (
                row.get("tool_use_id") != tool_use_id
                or not _digest(row.get("pretool_event_sha256"))
                or not _digest(row.get("pretool_report_sha256"))
                or row.get("pretool_report_sha256") != pretool_report_sha256
            ):
                connection.rollback()
                return {"status": "REFUSED", "reason": "grant:pretool_not_bound"}
            connection.execute(
                "UPDATE governed_native_grants SET state = 'POST_OBSERVED', "
                "outcome = ?, result_sha256 = ?, result_binding_sha256 = ?, "
                "posttool_report_sha256 = ? "
                "WHERE action_sha256 = ? AND state = 'DISPATCHED'",
                (
                    outcome,
                    result_sha256,
                    result_binding_sha256,
                    report_sha256,
                    action.get("action_sha256"),
                ),
            )
            current = self._grant_snapshot(
                connection.execute(
                    "SELECT " + ", ".join(_GRANT_COLUMNS)
                    + " FROM governed_native_grants WHERE action_sha256 = ?",
                    (action.get("action_sha256"),),
                ).fetchone()
            )
            witness = self._append_grant_history(
                connection,
                previous=row,
                current=current,
                transition_type="POSTTOOL_RECORDED",
            )
            connection.commit()
            if not self._record_grant_transition_commit(witness):
                return {
                    "status": "UNKNOWN",
                    "reason": "grant:witness_unavailable",
                }
            if not self.custody_valid():
                return {
                    "status": "UNKNOWN",
                    "reason": "grant:authority_custody_invalid",
                }
            return {"status": "RECORDED"}
        except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
            connection.rollback()
            return {"status": "UNKNOWN", "reason": "grant:store_unavailable"}
        finally:
            connection.close()

__all__ = [
    "DATABASE_RELATIVE",
    "GRANT_SCHEMA",
    "NATIVE_WITNESS_ROOT_ENV",
    "NativeGrantStore",
    "OWNER_SCHEMA",
    "canonical_database_path",
    "canonical_witness_root",
    "physical_store_sha256",
]
