#!/usr/bin/env python3
"""Prepare and preflight one owner-bound Local qualification host.

This provider-free constructor owns the exact Codex app-server argv and
environment overlay used by a fresh qualification task.  The caller launches
the sealed argv unchanged, then passes the whole create-only private report
back for the pre-turn hook inventory check. Preparation and reconciliation
are provider-free. The opt-in owner-session driver retains the caller's
transport across authorized preparation, approval, execution, and terminal
callbacks; it does not infer authority for their effects.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any
import weakref


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_local_task_runtime as local_task_runtime  # noqa: E402
import orch_dork_model_profile_registry as model_profiles  # noqa: E402
import orch_dork_observer_receipt as observer_receipt  # noqa: E402
import orch_dork_worker_default as worker_default  # noqa: E402


REPORT_SCHEMA = "orch-dork/qualification-host-preparation/v3"
EXTERNAL_EXECUTION_REPORT_SCHEMA = "orch-dork/qualification-host-preparation/v4"
# Issue 203: the same two launches whose app server loads the all-v1 copy of
# the user's catalog.  The schema names the closed field set.
OVERLAY_REPORT_SCHEMA = "orch-dork/qualification-host-preparation/v5"
EXTERNAL_EXECUTION_OVERLAY_REPORT_SCHEMA = "orch-dork/qualification-host-preparation/v6"
_REPORT_SCHEMAS = {
    (False, False): REPORT_SCHEMA,
    (True, False): EXTERNAL_EXECUTION_REPORT_SCHEMA,
    (False, True): OVERLAY_REPORT_SCHEMA,
    (True, True): EXTERNAL_EXECUTION_OVERLAY_REPORT_SCHEMA,
}
_REPORT_SHAPES = {schema: shape for shape, schema in _REPORT_SCHEMAS.items()}
EXECUTION_ENVIRONMENT_SCHEMA = "orch-dork/qualification-execution-environment/v1"
EXECUTION_ENVIRONMENT_ID = "issue170-worker"
# The hosted OpenRouter selector is the default qualification worker route.
# Any other worker or reviewer must have passed onboarding (ADR 0012): the
# host admits a route only from its onboarded profile, never by name.  The
# local engine (``qwen-local/qwen-smart``) killed generation 47 and its
# closed local-Qwen transport is retained for historical replay only.
_WORKER_MODELS = frozenset({worker_default.DEFAULT_WORKER_MODEL})
# The all-v1 copy of the user's catalog the host's app server loads, beside
# its preparation report (ADR 0012): the V2 pin alone does not move a model
# whose catalog row states v2, and an overlay replaces the whole catalog.
CATALOG_OVERLAY_NAME = "catalog-v1.json"
_CATALOG_OVERLAY_FIELDS = frozenset({"path", "sha256", "rows", "rows_rewritten"})
OWNER_CONTEXT_SCHEMA = "orch-dork/qualification-owner-context/v1"
IDLE_TASK_RECONCILIATION_SCHEMA = (
    "orch-dork/qualification-idle-task-reconciliation/v3"
)
QUALIFICATION_CHECKOUT_SCHEMA = (
    "orch-dork/qualification-checkout-pre-call/v2"
)
PREPARATION_REPORT_ENV = "ORCH_DORK_QUALIFICATION_HOST_PREPARATION"
PREPARATION_REPORT_NAME = "host-preparation.json"
CHECKOUT_REPORT_NAME = "qualification-checkout-pre-call.json"
QUALIFICATION_CHECKOUT_MAX_AGE_SECONDS = 300
MAX_PREPARATION_REPORT_BYTES = 131_072
MAX_PROC_FILE_BYTES = 65_536
MAX_PROCESS_ANCESTORS = 32
HOST_SOCKET_WAIT_SECONDS = 10.0
HOST_CLEANUP_SECONDS = 5.0
# A descendant that made itself a process-group leader never receives the
# host group signal, so it is neither killed with the group nor visible to
# _group_absent. It needs its own bounded interval to exit, and its own signal.
HOST_DESCENDANT_CLEANUP_SECONDS = 10.0
# SIGKILL cannot be caught, but the kernel still needs a moment to reap the
# process. Observing exactly once, 50 ms after the signal, can report a
# straggler as remaining while it is already dying, and cleanup is terminal
# for the whole attempt. This window is reserved INSIDE the interval above
# rather than added to it, so the one documented cleanup ceiling never moves,
# and it is paid out of the idle prefix rather than the SIGTERM grace. Keep it
# small: every second here is a second a descendant no longer gets to leave on
# its own, which would record an avoidable escalation in the evidence. Ten
# observations is ample for a signal the kernel cannot refuse.
HOST_DESCENDANT_REAP_SECONDS = 0.5
# The closed escalation vocabulary recorded in the cleanup report. A host that
# exited on its own and one whose descendants had to be signalled are both a
# closed host, but they are not the same event, and evidence that cannot tell
# them apart hides a real leak behind a PASS.
HOST_ESCALATION_NONE = "none"
HOST_ESCALATION_SIGTERM = "sigterm"
HOST_ESCALATION_SIGKILL = "sigkill"
HOST_ESCALATION_UNKNOWN = "unknown"
HOST_OUTPUT_BYTES = 65_536
HOST_OUTPUT_JOIN_SECONDS = 1.0
HOST_CLEANUP_SCHEMA = "orch-dork/qualification-host-cleanup/v1"
# The exact shape of the cleanup report below.  A reader that re-checks a
# persisted cleanup report (orch_dork_governed_native_controller.
# QUALIFICATION_HOST_CLEANUP_FIELDS) holds the same set; a test keeps the
# two copies equal and holds the report builder to it.
HOST_CLEANUP_FIELDS = frozenset({
    "schema", "status", "disposition", "pid", "pgid",
    "preparation_report_sha256", "app_server_argv_sha256",
    "owner_identity_sha256", "process_reaped", "process_group_absent",
    "process_group_members", "descendants_absent", "remaining_descendants",
    "descendant_escalation", "owner_socket_absent", "output_monitor_closed",
    "host_closed", "stdout_bytes", "stderr_bytes", "stdout_sha256",
    "stderr_sha256", "issues", "provider_free", "model_calls",
    "hosted_calls", "credential_reads", "network_calls", "task_creations",
    "native_calls", "report_sha256",
})
FIRST_TURN_TRANSPORT = {
    "schema": "orch-dork/qualification-first-turn-transport/v9",
    "idle_task_timestamp_policy": "each_snapshot_within_checkout_capture_window",
    "owner_gate_reconciliation": {
        "validator": "reconcile_qualification_owner_gate",
        "report_schema": "orch-dork/current-local-task-runtime/v1",
        "task_binding_source": "whole_thread_read_and_exact_completed_mcp_call",
        "owner_binding_source": "pre_turn_owner_inventory",
        "report_contains_task_id": False,
    },
    "connection_policy": (
        "retain_thread_start_connection_through_approval_live_and_terminal"
    ),
    "owner_session_driver": "run_qualification_owner_session",
    "reconnect_after_preflight_permitted": False,
    "approval_wait_requires_original_subscription": True,
    "read_only_polling_restores_subscription": False,
    "idle_task_reconciliation": ["thread/loaded/list", "thread/read"],
    "rollout_file_required_before_first_turn": False,
    "reconnect_before_first_turn_permitted": False,
    "thread_resume_before_first_turn_permitted": False,
    "required_session_start_source": "startup",
    "qualification_owner_context": {
        "schema": OWNER_CONTEXT_SCHEMA,
        "attestation": (
            "private_preparation_report_plus_live_process_ancestor"
        ),
        "disposition": "QUALIFICATION_OWNER_READ_ONLY",
        "protected_controller_mutation_permitted": False,
        "native_action_permitted": False,
        "compatible_active_controller_issues": [
            "native_controller:hook_definition_mismatch"
        ],
        "other_controller_drift_permitted": False,
    },
    "connection_terminal_replay": {
        "schema": (
            "orch-dork/qualification-first-turn-connection-replay/v1"
        ),
        "failure_stage": "first_turn_after_owner_connection_detach",
        "failure_code": "native_controller:root_session_mismatch",
        "legacy_sequence": [
            "thread/start",
            "connection/close",
            "thread/resume",
            "turn/start",
        ],
        "required_sequence": [
            "thread/start",
            "thread/loaded/list",
            "thread/read",
            "turn/start",
        ],
    },
    "active_controller_terminal_replay": {
        "schema": "orch-dork/qualification-first-turn-owner-replay/v2",
        "case_id": "issue171-owner-launch-v7",
        "failure_stage": (
            "qualification_owner_cross_generation_first_session_start"
        ),
        "failure_code": "native_controller:hook_definition_mismatch",
        "observed_reason_codes": [
            "native_controller:hook_definition_mismatch",
            "native_controller:root_session_mismatch",
        ],
        "same_connection_retained": True,
        "required_context": (
            "sealed_process_ancestor_read_only_qualification_owner"
        ),
    },
    "thread_start_terminal_replay": {
        "schema": "orch-dork/qualification-thread-start-replay/v1",
        "case_id": "issue171-owner-launch-v8",
        "failure_stage": (
            "qualification_owner_post_thread_start_reconciliation"
        ),
        "failure_code": (
            "qualification_owner:thread_start_git_info_nullable"
        ),
        "observed_thread_start_git_info": None,
        "thread_start_git_info_required": False,
        "required_provenance_sources": [
            "clean_checkout_pre_call",
            "thread/read",
        ],
    },
    "checkout_pre_call": {
        "schema": QUALIFICATION_CHECKOUT_SCHEMA,
        "create_only": True,
        "local_task_binding_field": "task_project_id",
        "app_server_task_binding_field": None,
        "binding_strategy": (
            "sealed_creation_window_plus_exact_solo_loaded_task"
        ),
        "reconciliation_inputs": [
            "qualification_checkout_report",
            "thread/start",
            "thread/loaded/list",
            "thread/read",
        ],
    },
    "thread_start_request": {
        "schema": "orch-dork/qualification-thread-start-request/v2",
        "builder": "build_qualification_thread_start_params",
        "exact_fields": [
            "approvalPolicy",
            "config",
            "cwd",
            "model",
            "sandbox",
            "serviceName",
        ],
        "experimental_only_fields": [
            "allowProviderModelFallback",
            "historyMode",
            "projectId",
        ],
        "history_mode_source": "server_default_projection_only",
        "experimental_api_capability_required": False,
    },
    "thread_start_request_terminal_replay": {
        "schema": "orch-dork/qualification-thread-start-request-replay/v1",
        "case_id": "issue171-owner-launch-v9",
        "failure_stage": "qualification_owner_thread_start_request",
        "failure_code": (
            "qualification_owner:thread_start_experimental_capability_required"
        ),
        "capability_gated_field": "historyMode",
        "error_code": -32600,
        "error_message": (
            "thread/start.historyMode requires experimentalApi capability"
        ),
        "task_created": False,
    },
    "thread_start_project_terminal_replay": {
        "schema": "orch-dork/qualification-thread-start-request-replay/v2",
        "case_id": "issue171-owner-launch-v10",
        "failure_stage": "qualification_owner_thread_start_request",
        "failure_code": (
            "qualification_owner:thread_start_project_capability_required"
        ),
        "capability_gated_field": "projectId",
        "additional_experimental_only_field": (
            "allowProviderModelFallback"
        ),
        "error_code": -32600,
        "error_message": (
            "thread/start.projectId requires experimentalApi capability"
        ),
        "task_created": False,
    },
}
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")
_TASK_ID = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_TASK_PROJECT_ID = re.compile(
    r"\Aorch-dork-qualification-[0-9a-f]{64}\Z"
)
_MODEL_NAME = re.compile(r"\A[A-Za-z0-9._/-]{1,128}\Z")
_SERVICE_NAME = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")
_COUNTERS = {
    "config_writes": 0,
    "credential_reads": 0,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "network_calls": 0,
    "provider_calls": 0,
    "task_creations": 0,
}
_FIELDS = frozenset(
    {
        "schema",
        "status",
        "disposition",
        "codex_executable",
        "workspace",
        "owner_socket",
        "argv",
        "app_server_argv_sha256",
        "environment",
        "hook_overlay",
        "first_turn_transport",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_CHECKOUT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "disposition",
        "workspace",
        "branch",
        "commit",
        "owner_socket",
        "host_preparation_report_sha256",
        "app_server_argv_sha256",
        "report_path",
        "task_project_id",
        "captured_at_unix_ns",
        "expires_at_unix_ns",
        "clean",
        "provider_free",
        "counters",
        "report_sha256",
    }
)


class QualificationHostError(ValueError):
    """Stable fail-closed qualification-host preparation error."""


_HOST_HANDLE_MINT = object()
_ACTIVE_HOST_HANDLES: weakref.WeakSet[Any] = weakref.WeakSet()


class _RetainedOwnerRpc:
    """One connection and one task; a broken connection is terminal.

    The adapter supplies send/receive/close, never a reconnect factory. The
    driver owns close and keeps this adapter alive through all four phases.
    Authorization callbacks may receive with a short deadline while awaiting
    durable user input; an idle receive timeout does not invalidate ownership.
    """

    def __init__(self, connection: Any, *, execution_environment: Mapping[str, Any] | None = None) -> None:
        self._connection = connection
        self._task_id: str | None = None
        self._start_sent = False
        self._start_request_id: Any = None
        self._failed = False
        self._environment_added = False
        self._environment_add_sent = False
        self._environment_add_request_id: Any = None
        self._execution_environment = (
            validate_qualification_execution_environment(
                execution_environment, workspace=execution_environment.get("workspace"),
            ) if execution_environment is not None else None
        )

    def _selection(self) -> list[dict[str, Any]]:
        binding = self._execution_environment
        if binding is None:
            self._refuse("connection_environment_unavailable")
        return [{"environmentId": binding["environment_id"], "cwd": binding["workspace"],
                 "runtimeWorkspaceRoots": [binding["workspace"]]}]

    def _refuse(self, reason: str) -> None:
        self._failed = True
        raise QualificationHostError("qualification_owner:" + reason)

    def send(self, message: dict[str, Any]) -> None:
        if self._failed:
            self._refuse("connection_terminal")
        method = message.get("method")
        if method not in {
            "initialize", "initialized", "thread/start", "thread/read",
            "thread/loaded/list", "turn/start", "turn/interrupt",
            "environment/add", "environment/info", "environment/status",
        }:
            self._refuse("connection_method_refused")
        if method in {"environment/add", "environment/info", "environment/status"}:
            binding = self._execution_environment
            if binding is None:
                self._refuse("connection_environment_unavailable")
            params = message.get("params", {})
            if not isinstance(params, dict) or params.get("environmentId") != EXECUTION_ENVIRONMENT_ID:
                self._refuse("connection_environment_mismatch")
            if method == "environment/add":
                if (
                    self._environment_add_sent or self._start_sent or "id" not in message
                    or set(params) != {"environmentId", "execServerUrl", "connectTimeoutMs"}
                    or params.get("connectTimeoutMs") != 5000
                    or params.get("execServerUrl") != binding["exec_server_url"]
                ):
                    self._refuse("connection_environment_add_refused")
                self._environment_add_sent = True
                self._environment_add_request_id = message["id"]
            elif not self._environment_added or set(params) != {"environmentId"}:
                self._refuse("connection_environment_unavailable")
        if method == "thread/start":
            if self._execution_environment is not None:
                params = message.get("params", {})
                if (
                    not self._environment_added
                    or params.get("environments") != self._selection()
                    or params.get("cwd") != self._execution_environment["workspace"]
                    or params.get("sandbox") != "danger-full-access"
                ):
                    self._refuse("connection_environment_start_refused")
            if self._start_sent or "id" not in message:
                self._refuse("second_task_refused")
            self._start_sent = True
            self._start_request_id = message["id"]
        if method in {"thread/read", "turn/start", "turn/interrupt"}:
            params = message.get("params", {})
            if not self._task_id or params.get("threadId") != self._task_id:
                self._refuse("connection_task_mismatch")
            if method == "turn/start" and self._execution_environment is not None:
                if (
                    params.get("environments") != self._selection()
                    or params.get("sandboxPolicy") != {"type": "dangerFullAccess"}
                ):
                    self._refuse("connection_environment_turn_refused")
        try:
            self._connection.send(message)
        except Exception:
            self._failed = True
            raise

    def receive(self, deadline: float) -> dict[str, Any]:
        if self._failed:
            self._refuse("connection_terminal")
        try:
            message = self._connection.receive(deadline)
        except TimeoutError:
            raise
        except Exception:
            self._failed = True
            raise
        if not isinstance(message, dict):
            self._refuse("connection_response_invalid")
        if (
            self._environment_add_sent and not self._environment_added
            and message.get("id") == self._environment_add_request_id
        ):
            if message.get("result") != {} or "error" in message:
                self._refuse("connection_environment_add_failed")
            self._environment_added = True
        if (
            self._start_sent and self._task_id is None
            and message.get("id") == self._start_request_id
        ):
            task_id = message.get("result", {}).get("thread", {}).get("id")
            if not isinstance(task_id, str) or not task_id:
                self._refuse("thread_start_invalid")
            self._task_id = task_id
            if self._execution_environment is not None:
                if message["result"]["thread"].get("environments") != self._selection():
                    self._refuse("connection_environment_start_mismatch")
        params = message.get("params", {})
        if isinstance(params, dict) and params.get("threadId") == self._task_id:
            if message.get("method") == "thread/closed":
                self._refuse("owner_subscription_lost:thread_closed")
            if (
                message.get("method") == "thread/status/changed"
                and params.get("status", {}).get("type") == "notLoaded"
            ):
                self._refuse("owner_subscription_lost:not_loaded")
        return message

    def request(
        self, request_id: int | str, method: str, params: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        self.send({"id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        try:
            while True:
                message = self.receive(deadline)
                if message.get("id") != request_id:
                    continue
                if "error" in message or "result" not in message:
                    self._refuse("connection_request_failed")
                return message
        except Exception:
            # A timed-out request has an unknown outcome, unlike idle receive.
            self._failed = True
            raise

    def verify_available(self) -> None:
        """Check the sole owner on this connection immediately before use."""
        if not self._task_id:
            self._refuse("owner_task_missing")
        loaded = self.request(
            "owner-session-loaded", "thread/loaded/list", {}, 30
        )
        if loaded.get("result") != {"data": [self._task_id], "nextCursor": None}:
            self._refuse("not_loaded_before_authorization")
        response = self.request(
            "owner-session-read", "thread/read",
            {"threadId": self._task_id, "includeTurns": False}, 30,
        )
        thread = response.get("result", {}).get("thread", {})
        if (
            thread.get("id") != self._task_id
            or thread.get("sessionId") != self._task_id
            or thread.get("status") != {"type": "idle"}
        ):
            self._refuse("owner_not_idle_before_authorization")


def run_qualification_owner_session(
    *,
    connect: Callable[[], Any],
    prepare: Callable[[Any], Any],
    authorize: Callable[[Any, Any], Any],
    execute: Callable[[Any, Any, Any], Any],
    terminal: Callable[[Any, Any, BaseException | None], None],
    execution_environment: Mapping[str, Any] | None = None,
) -> Any:
    """Retain the creating subscription until terminal evidence is recorded.

    ``connect`` returns one owned send/receive/close transport. ``prepare``
    creates and qualifies the sole task. ``authorize`` waits for and validates
    authorization; its return is opaque and grants no authority by itself.
    ``execute`` must enforce that authorization and the fresh pre-dispatch
    owner inventory. Each phase receives the same restricted RPC connection.
    The terminal callback runs once on success or failure, before close. There
    is no reconnect, task resume, second task, or automatic execution retry.
    """
    binding = (
        validate_qualification_execution_environment(
            execution_environment, workspace=execution_environment.get("workspace"),
        ) if execution_environment is not None else None
    )
    connection = connect()
    rpc = _RetainedOwnerRpc(connection, execution_environment=binding)
    result = None
    error = None
    try:
        prepared = prepare(rpc)
        rpc.verify_available()
        authorization = authorize(rpc, prepared)
        rpc.verify_available()
        result = execute(rpc, prepared, authorization)
        return result
    except BaseException as failure:
        error = failure
        raise
    finally:
        try:
            terminal(rpc, result, error)
        finally:
            connection.close()


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


def _argv_sha256(argv: list[str]) -> str:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise QualificationHostError("qualification_host:argv_invalid")
    return hashlib.sha256(
        b"\0".join(os.fsencode(item) for item in argv) + b"\0"
    ).hexdigest()


def _safe_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise QualificationHostError(f"qualification_host:{label}_unsafe")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except OSError as error:
        raise QualificationHostError(
            f"qualification_host:{label}_unavailable"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QualificationHostError(f"qualification_host:{label}_unsafe")
    return resolved


def create_qualification_controller_root(path: str | Path) -> Path:
    """Create an authorized, fresh controller cwd and its missing parents.

    This is a local write operation, not a read-only preflight or an authority
    grant. The caller must first authorize its frozen destination. Existing
    leaves, aliases, and unsafe parents refuse; existing permissions are never
    repaired. Every directory created by this invocation is mode 0700.
    """

    try:
        target = Path(path)
        if not target.is_absolute() or target.resolve() != target:
            raise QualificationHostError("qualification_host:controller_root_unsafe")
        if os.path.lexists(target):
            raise QualificationHostError("qualification_host:controller_root_exists")
        missing = []
        parent = target
        while not os.path.lexists(parent):
            missing.append(parent)
            if len(missing) > 32:
                raise QualificationHostError("qualification_host:controller_root_unsafe")
            parent = parent.parent
        _safe_directory(parent, "controller_parent")
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            info = directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise QualificationHostError("qualification_host:controller_root_unsafe")
        return target
    except (OSError, TypeError, ValueError) as error:
        if isinstance(error, QualificationHostError):
            raise
        raise QualificationHostError(
            "qualification_host:controller_root_creation_failed"
        ) from error


def _safe_file(
    path: Path,
    label: str,
    *,
    executable: bool = False,
    private: bool = False,
) -> Path:
    if not path.is_absolute() or (path.is_symlink() and not executable):
        raise QualificationHostError(f"qualification_host:{label}_unsafe")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except OSError as error:
        raise QualificationHostError(
            f"qualification_host:{label}_unavailable"
        ) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or (executable and not os.access(resolved, os.X_OK))
        or (private and stat.S_IMODE(info.st_mode) & 0o077)
    ):
        raise QualificationHostError(f"qualification_host:{label}_unsafe")
    return path


def _owner_socket_path(path: Path, *, require_absent: bool) -> Path:
    if not path.is_absolute():
        raise QualificationHostError("qualification_host:owner_socket_unsafe")
    parent = _safe_directory(path.parent, "owner_socket_parent")
    selected = parent / path.name
    if selected != path:
        raise QualificationHostError("qualification_host:owner_socket_unsafe")
    if require_absent and os.path.lexists(selected):
        raise QualificationHostError("qualification_host:owner_socket_exists")
    if not require_absent and os.path.lexists(selected):
        try:
            local_task_runtime.qualification_owner_socket_binding(selected)
        except local_task_runtime.LocalTaskRuntimeError as error:
            raise QualificationHostError(
                "qualification_host:owner_socket_unsafe"
            ) from error
    return selected


@dataclass(frozen=True, slots=True)
class QualificationCheckoutArtifact:
    """Exact clean-checkout evidence sealed before the sole task creation."""

    report: dict[str, Any]
    report_sha256: str
    workspace: Path
    branch: str
    commit: str
    report_path: Path
    task_project_id: str
    captured_at_unix_ns: int
    expires_at_unix_ns: int

    @classmethod
    def from_report(
        cls,
        report: Any,
        *,
        preparation_report: Any,
    ) -> "QualificationCheckoutArtifact":
        preparation = QualificationHostPreparationArtifact.from_report(
            preparation_report
        )
        if not isinstance(report, Mapping) or set(report) != _CHECKOUT_FIELDS:
            raise QualificationHostError(
                "qualification_host:checkout_report_shape_invalid"
            )
        value = deepcopy(dict(report))
        supplied_sha256 = value.pop("report_sha256", None)
        branch = value.get("branch")
        commit = value.get("commit")
        report_path = preparation.owner_socket.parent / CHECKOUT_REPORT_NAME
        task_project_id = value.get("task_project_id")
        captured_at_unix_ns = value.get("captured_at_unix_ns")
        expires_at_unix_ns = value.get("expires_at_unix_ns")
        if (
            report.get("schema") != QUALIFICATION_CHECKOUT_SCHEMA
            or report.get("status") != "PASS"
            or report.get("disposition") != "READY_FOR_SINGLE_TASK_CREATION"
            or not isinstance(report.get("workspace"), str)
            or report.get("workspace") != str(preparation.workspace)
            or not isinstance(branch, str)
            or not branch
            or "\x00" in branch
            or _COMMIT.fullmatch(str(commit)) is None
            or report.get("owner_socket") != str(preparation.owner_socket)
            or report.get("host_preparation_report_sha256")
            != preparation.report_sha256
            or report.get("app_server_argv_sha256")
            != preparation.app_server_argv_sha256
            or report.get("report_path") != str(report_path)
            or _TASK_PROJECT_ID.fullmatch(str(task_project_id)) is None
            or type(captured_at_unix_ns) is not int
            or type(expires_at_unix_ns) is not int
            or captured_at_unix_ns <= 0
            or expires_at_unix_ns
            != captured_at_unix_ns
            + QUALIFICATION_CHECKOUT_MAX_AGE_SECONDS * 1_000_000_000
            or report.get("clean") is not True
            or report.get("provider_free") is not True
            or report.get("counters") != _COUNTERS
            or _SHA256.fullmatch(str(supplied_sha256)) is None
            or supplied_sha256 != _sha(value)
        ):
            raise QualificationHostError(
                "qualification_host:checkout_report_invalid"
            )
        _safe_file(report_path, "checkout_report", private=True)
        try:
            payload = report_path.read_bytes()
        except OSError as error:
            raise QualificationHostError(
                "qualification_host:checkout_report_unavailable"
            ) from error
        if (
            len(payload) > MAX_PREPARATION_REPORT_BYTES
            or payload != _canonical(report) + b"\n"
        ):
            raise QualificationHostError(
                "qualification_host:checkout_report_drift"
            )
        return cls(
            report=deepcopy(dict(report)),
            report_sha256=str(supplied_sha256),
            workspace=preparation.workspace,
            branch=branch,
            commit=str(commit),
            report_path=report_path,
            task_project_id=str(task_project_id),
            captured_at_unix_ns=captured_at_unix_ns,
            expires_at_unix_ns=expires_at_unix_ns,
        )


def _worker_model(value: Any) -> str:
    if not isinstance(value, str) or (
        value not in _WORKER_MODELS and not _passed_onboarding(value)
    ):
        raise QualificationHostError("qualification_host:worker_model_invalid")
    return value


def _passed_onboarding(model: str) -> bool:
    profile = model_profiles.onboarded_profiles.onboarded(model)
    return profile is not None and not model_profiles.onboarded_profiles.not_passed_reasons(profile)


def _reviewer_route(model: Any, effort: Any) -> tuple[str, str]:
    """The sealed reviewer route: an onboarded model that passed onboarding."""

    if (
        not isinstance(model, str)
        or not isinstance(effort, str)
        or effort not in model_profiles.ONBOARDED_EFFORTS
        or not _passed_onboarding(model)
    ):
        raise QualificationHostError("qualification_host:reviewer_route_invalid")
    return model, effort


def _catalog_overlay_valid(value: Any, owner_socket: Any) -> bool:
    """Whether a recorded overlay is the private file the host wrote."""

    if not isinstance(value, Mapping) or set(value) != _CATALOG_OVERLAY_FIELDS:
        return False
    path = Path(str(value.get("path")))
    if path != Path(str(owner_socket)).parent / CATALOG_OVERLAY_NAME:
        return False
    try:
        status = path.lstat()
        data = path.read_bytes()
    except OSError:
        return False
    return (
        stat.S_ISREG(status.st_mode)
        and stat.S_IMODE(status.st_mode) == 0o600
        and status.st_uid == os.getuid()
        and hashlib.sha256(data).hexdigest() == value.get("sha256")
        and type(value.get("rows")) is int
        and isinstance(value.get("rows_rewritten"), list)
    )


def validate_qualification_execution_environment(
    value: Any, *, workspace: str | Path,
) -> dict[str, Any]:
    """Bind a coordinator-owned executor, without claiming OS enforcement.

    The coordinator owns the reviewed launch policy and its independent live
    namespace checks. This contract pins that policy's digest and its private
    loopback transport to the sole environment usable by qualification tools.
    It does not accept an executor's self-report as sandbox evidence.
    """
    if not isinstance(value, Mapping) or set(value) != {
        "schema", "environment_id", "exec_server_url", "workspace", "policy_sha256",
        "code_mode_host_url",
    }:
        raise QualificationHostError("qualification_host:execution_environment_shape_invalid")
    endpoint = value.get("exec_server_url")
    match = re.fullmatch(
        r"ws://127\.0\.0\.1:([1-9][0-9]{0,4})/issue170-executor/[0-9a-f]{64}",
        endpoint if isinstance(endpoint, str) else "",
    )
    code_mode_endpoint = value.get("code_mode_host_url")
    code_mode_match = re.fullmatch(
        r"http://127\.0\.0\.1:([1-9][0-9]{0,4})",
        code_mode_endpoint if isinstance(code_mode_endpoint, str) else "",
    )
    if (
        value.get("schema") != EXECUTION_ENVIRONMENT_SCHEMA
        or value.get("environment_id") != EXECUTION_ENVIRONMENT_ID
        or value.get("workspace") != str(workspace)
        or not Path(str(workspace)).is_absolute()
        or "\x00" in str(workspace)
        or match is None
        or not 1024 <= int(match.group(1)) <= 65535
        or code_mode_match is None
        or not 1024 <= int(code_mode_match.group(1)) <= 65535
        or not isinstance(value.get("policy_sha256"), str)
        or _SHA256.fullmatch(str(value.get("policy_sha256"))) is None
    ):
        raise QualificationHostError("qualification_host:execution_environment_invalid")
    return deepcopy(dict(value))


def _qualification_app_server_argv(
    codex: str,
    overlay: str,
    owner_socket: str,
    binding: Mapping[str, Any] | None,
    catalog_overlay: Any = None,
) -> list[str]:
    # The governed controller consumes PreToolUse/PostToolUse for native
    # subagent actions. Codex MultiAgentV2 does not currently dispatch those
    # hooks, so pin the app server to the V1 surface whose schema and hook
    # lifecycle this runtime implements. Do not inherit a host-local default.
    argv = [
        codex,
        "-c",
        overlay,
        "-c",
        "features.multi_agent_v2.enabled=false",
    ]
    if catalog_overlay is not None:
        # The V2 pin does not move a model whose catalog row states v2, so
        # the app server loads the all-v1 copy of the user's catalog.
        argv.extend(["-c", "model_catalog_json=" + json.dumps(str(catalog_overlay))])
    if binding is not None:
        argv.extend(["-c", "features.code_mode_host=true"])
        # The pinned CLI selects the gRPC provider with --code-mode-host below.
        # Its internal code_mode config is not a public strict-config override.
    argv.extend([
        "--dangerously-bypass-hook-trust", "app-server", "--strict-config",
        "--listen", "unix://" + owner_socket,
    ])
    if binding is not None:
        argv.extend(["--code-mode-host", binding["code_mode_host_url"]])
    return argv


def _execution_first_turn_transport(binding: Mapping[str, Any] | None) -> dict[str, Any]:
    transport = deepcopy(FIRST_TURN_TRANSPORT)
    if binding is not None:
        transport["schema"] = "orch-dork/qualification-first-turn-transport/v10"
        request = transport["thread_start_request"]
        request["schema"] = "orch-dork/qualification-thread-start-request/v3"
        request["exact_fields"] = sorted([*request["exact_fields"], "environments"])
        request["experimental_only_fields"].append("environments")
        request["experimental_api_capability_required"] = True
        transport["execution_environment"] = deepcopy(dict(binding))
        transport["local_environment_purpose"] = "trusted_stdio_mcp_only"
    return transport


def qualification_execution_environment_selection(
    preparation_report: Any,
) -> list[dict[str, Any]]:
    artifact = QualificationHostPreparationArtifact.from_report(preparation_report)
    binding = artifact.execution_environment
    if binding is None:
        raise QualificationHostError("qualification_host:execution_environment_required")
    return [{
        "environmentId": binding["environment_id"],
        "cwd": str(artifact.workspace),
        "runtimeWorkspaceRoots": [str(artifact.workspace)],
    }]


def verify_qualification_task_execution_environment(
    thread: Any, *, preparation_report: Any,
) -> None:
    expected = qualification_execution_environment_selection(preparation_report)
    if not isinstance(thread, Mapping) or thread.get("environments") != expected:
        raise QualificationHostError("qualification_host:task_execution_environment_mismatch")


@dataclass(frozen=True, slots=True)
class QualificationHostPreparationArtifact:
    """Strict whole-report access to one exact host launch contract."""

    report: dict[str, Any]
    report_sha256: str
    argv: tuple[str, ...]
    app_server_argv_sha256: str
    environment: dict[str, str]
    first_turn_transport: dict[str, Any]
    workspace: Path
    owner_socket: Path
    preparation_report_path: Path
    execution_environment: dict[str, Any] | None = None

    @classmethod
    def from_report(cls, report: Any) -> "QualificationHostPreparationArtifact":
        shape = _REPORT_SHAPES.get(report.get("schema")) if isinstance(report, Mapping) else None
        external, overlaid = shape if shape is not None else (False, False)
        fields = (
            _FIELDS
            | ({"execution_environment"} if external else set())
            | ({"catalog_overlay"} if overlaid else set())
        )
        if not isinstance(report, Mapping) or set(report) != fields:
            raise QualificationHostError(
                "qualification_host:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        if overlaid and not _catalog_overlay_valid(value.get("catalog_overlay"), value.get("owner_socket")):
            raise QualificationHostError("qualification_host:catalog_overlay_invalid")
        binding = (
            validate_qualification_execution_environment(
                value.get("execution_environment"), workspace=str(value.get("workspace")),
            ) if external else None
        )
        expected_transport = _execution_first_turn_transport(binding)
        argv = value.get("argv")
        environment = value.get("environment")
        overlay = local_task_runtime.build_qualification_hook_state_override()
        if not isinstance(environment, Mapping):
            raise QualificationHostError("qualification_host:report_invalid")
        expected_environment = {
            local_task_runtime.OWNER_SOCKET_ENV: value.get("owner_socket"),
            observer_receipt.TRUST_STORE_ENV: environment.get(
                observer_receipt.TRUST_STORE_ENV
            ),
            observer_receipt.REPLAY_DB_ENV: environment.get(
                observer_receipt.REPLAY_DB_ENV
            ),
            PREPARATION_REPORT_ENV: str(
                Path(str(value.get("owner_socket"))).parent
                / PREPARATION_REPORT_NAME
            ),
        }
        effort = environment.get(worker_default.WORKER_EFFORT_ENV)
        if not isinstance(effort, str) or effort not in ("medium", "high", "xhigh"):
            raise QualificationHostError("qualification_host:worker_effort_invalid")
        expected_environment[worker_default.WORKER_EFFORT_ENV] = effort
        expected_environment[worker_default.WORKER_MODEL_ENV] = _worker_model(
            environment.get(worker_default.WORKER_MODEL_ENV)
        )
        if worker_default.REVIEWER_MODEL_ENV in environment:
            reviewer = _reviewer_route(
                environment.get(worker_default.REVIEWER_MODEL_ENV),
                environment.get(worker_default.REVIEWER_EFFORT_ENV),
            )
            expected_environment[worker_default.REVIEWER_MODEL_ENV] = reviewer[0]
            expected_environment[worker_default.REVIEWER_EFFORT_ENV] = reviewer[1]
        if external:
            # A remote-only default disables the trusted local stdio MCP rail.
            expected_environment["CODEX_EXEC_SERVER_URL"] = ""
        expected_argv = _qualification_app_server_argv(
            value.get("codex_executable"),
            overlay,
            str(value.get("owner_socket")),
            binding,
            value["catalog_overlay"]["path"] if overlaid else None,
        )
        core = {
            key: child for key, child in value.items() if key != "report_sha256"
        }
        if (
            shape is None
            or value.get("status") != "PASS"
            or value.get("disposition") != "READY_FOR_APP_SERVER_LAUNCH"
            or value.get("hook_overlay") != overlay
            or argv != expected_argv
            or value.get("app_server_argv_sha256")
            != _argv_sha256(expected_argv)
            or dict(environment) != expected_environment
            or value.get("first_turn_transport") != expected_transport
            or value.get("provider_free") is not True
            or value.get("counters") != _COUNTERS
            or _SHA256.fullmatch(str(value.get("report_sha256", ""))) is None
            or value.get("report_sha256") != _sha(core)
        ):
            raise QualificationHostError("qualification_host:report_invalid")
        codex = _safe_file(
            Path(str(value["codex_executable"])),
            "codex_executable",
            executable=True,
        )
        workspace = _safe_directory(
            Path(str(value["workspace"])), "workspace"
        )
        owner_socket = _owner_socket_path(
            Path(str(value["owner_socket"])), require_absent=False
        )
        _safe_file(
            Path(str(expected_environment[observer_receipt.TRUST_STORE_ENV])),
            "observer_trust_store",
            private=True,
        )
        _safe_file(
            Path(str(expected_environment[observer_receipt.REPLAY_DB_ENV])),
            "observer_replay_db",
            private=True,
        )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            argv=tuple(str(item) for item in argv),
            app_server_argv_sha256=str(
                value["app_server_argv_sha256"]
            ),
            environment={
                str(key): str(child) for key, child in environment.items()
            },
            first_turn_transport=expected_transport,
            workspace=workspace,
            owner_socket=owner_socket,
            preparation_report_path=Path(
                str(expected_environment[PREPARATION_REPORT_ENV])
            ),
            execution_environment=binding,
        )


def _create_only_json(
    path: Path,
    value: Mapping[str, Any],
    *,
    label: str = "preparation_report",
) -> None:
    payload = _canonical(value) + b"\n"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise QualificationHostError(
            f"qualification_host:{label}_exists"
        ) from error
    except OSError as error:
        try:
            path.unlink()
        except OSError:
            pass
        raise QualificationHostError(
            f"qualification_host:{label}_unavailable"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_proc_bytes(
    path: Path,
    *,
    expected_uid: int,
    max_bytes: int = MAX_PROC_FILE_BYTES,
    allow_kernel_owned: bool = False,
) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (
                info.st_uid != expected_uid
                and not (allow_kernel_owned is True and info.st_uid == 0)
            )
            or info.st_mode & 0o022
        ):
            raise QualificationHostError(
                "qualification_owner:process_identity_unavailable"
            )
        payload = b""
        while len(payload) <= max_bytes:
            chunk = os.read(
                descriptor,
                min(8192, max_bytes + 1 - len(payload)),
            )
            if not chunk:
                break
            payload += chunk
    finally:
        os.close(descriptor)
    if len(payload) > max_bytes:
        raise QualificationHostError(
            "qualification_owner:process_identity_unavailable"
        )
    return payload


def _status_identity(payload: bytes, *, expected_uid: int) -> tuple[int, int]:
    parent: int | None = None
    uid: int | None = None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QualificationHostError(
            "qualification_owner:process_identity_unavailable"
        ) from error
    for line in text.splitlines():
        if line.startswith("PPid:"):
            fields = line.split()
            if len(fields) == 2 and fields[1].isdigit():
                parent = int(fields[1])
        elif line.startswith("Uid:"):
            fields = line.split()
            if len(fields) == 5 and all(item.isdigit() for item in fields[1:]):
                uid = int(fields[1])
    if parent is None or uid != expected_uid:
        raise QualificationHostError(
            "qualification_owner:process_identity_unavailable"
        )
    return parent, uid


def _find_ancestor_app_server(
    artifact: QualificationHostPreparationArtifact,
    *,
    proc_root: Path,
    parent_pid: int,
) -> int:
    if not proc_root.is_absolute() or proc_root.is_symlink():
        raise QualificationHostError(
            "qualification_owner:process_identity_unavailable"
        )
    current_uid = os.getuid() if hasattr(os, "getuid") else os.stat(".").st_uid
    expected_cmdline = (
        b"\0".join(os.fsencode(item) for item in artifact.argv) + b"\0"
    )
    pid = parent_pid
    observed: set[int] = set()
    for _ in range(MAX_PROCESS_ANCESTORS):
        if pid < 1 or pid in observed:
            break
        observed.add(pid)
        process_root = proc_root / str(pid)
        try:
            root_info = process_root.lstat()
            if (
                process_root.is_symlink()
                or not stat.S_ISDIR(root_info.st_mode)
                or root_info.st_uid != current_uid
            ):
                raise QualificationHostError(
                    "qualification_owner:process_identity_unavailable"
                )
            status_payload = _read_proc_bytes(
                process_root / "status", expected_uid=current_uid
            )
            next_pid, _uid = _status_identity(
                status_payload, expected_uid=current_uid
            )
            cmdline = _read_proc_bytes(
                process_root / "cmdline", expected_uid=current_uid
            )
            if cmdline == expected_cmdline:
                cwd = Path(os.readlink(process_root / "cwd"))
                if (
                    not cwd.is_absolute()
                    or cwd.resolve(strict=True) != artifact.workspace
                    or _argv_sha256(list(artifact.argv))
                    != artifact.app_server_argv_sha256
                ):
                    raise QualificationHostError(
                        "qualification_owner:owner_invocation_mismatch"
                    )
                return pid
            pid = next_pid
        except QualificationHostError:
            raise
        except OSError as error:
            raise QualificationHostError(
                "qualification_owner:process_identity_unavailable"
            ) from error
    raise QualificationHostError(
        "qualification_owner:owner_invocation_mismatch"
    )


def _owner_context_report(
    *,
    status: str,
    disposition: str,
    event: Mapping[str, Any],
    owner_socket: str | None,
    app_server_pid: int | None,
    app_server_argv_sha256: str | None,
    preparation_report_path: str | None,
    preparation_report_sha256: str | None,
    preparation_file_sha256: str | None,
    issues: list[str],
) -> dict[str, Any]:
    core = {
        "schema": OWNER_CONTEXT_SCHEMA,
        "status": status,
        "disposition": disposition,
        "session_id": event.get("session_id"),
        "model": event.get("model"),
        "workspace": event.get("cwd"),
        "source": event.get("source"),
        "owner_socket": owner_socket,
        "app_server_pid": app_server_pid,
        "app_server_argv_sha256": app_server_argv_sha256,
        "preparation_report_path": preparation_report_path,
        "preparation_report_sha256": preparation_report_sha256,
        "preparation_file_sha256": preparation_file_sha256,
        "event_sha256": _sha(event),
        "issues": issues,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "credential_reads": 0,
        "network_calls": 0,
        "task_creations": 0,
        "native_calls": 0,
        "mutations_performed": 0,
    }
    return {**core, "report_sha256": _sha(core)}


def observe_qualification_owner_context(
    event: Mapping[str, Any],
    *,
    env: Mapping[str, str] | None = None,
    proc_root: Path = Path("/proc"),
    parent_pid: int | None = None,
) -> dict[str, Any]:
    """Bind one hook event to its sealed read-only qualification host.

    The check deliberately avoids an app-server RPC: SessionStart executes on
    that server's critical path.  Instead it binds the private constructor
    report to the live Unix socket and to an exact argv/cwd process ancestor.
    """

    values = os.environ if env is None else env
    raw_path = values.get(PREPARATION_REPORT_ENV)
    selected_event = dict(event) if isinstance(event, Mapping) else {}
    try:
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or "\x00" in raw_path
        ):
            raise QualificationHostError(
                "qualification_owner:preparation_report_unavailable"
            )
        report_path = Path(raw_path)
        _safe_file(
            report_path,
            "preparation_report",
            private=True,
        )
        import orch_dork_owned_file as owned_file

        report_payload = owned_file.read_owned_bytes(
            report_path,
            max_bytes=MAX_PREPARATION_REPORT_BYTES,
            required_mode=0o600,
        )
        report = json.loads(report_payload.decode("utf-8"))
        artifact = QualificationHostPreparationArtifact.from_report(report)
        if report_path != artifact.preparation_report_path:
            raise QualificationHostError(
                "qualification_owner:preparation_report_mismatch"
            )
        if any(
            values.get(key) != child
            for key, child in artifact.environment.items()
        ):
            raise QualificationHostError(
                "qualification_owner:environment_mismatch"
            )
        try:
            local_task_runtime.qualification_owner_socket_binding(
                artifact.owner_socket
            )
        except local_task_runtime.LocalTaskRuntimeError as error:
            raise QualificationHostError(
                "qualification_owner:owner_socket_invalid"
            ) from error
        if selected_event.get("cwd") != str(artifact.workspace):
            raise QualificationHostError(
                "qualification_owner:workspace_mismatch"
            )
        if selected_event.get("agent_id") is not None:
            raise QualificationHostError(
                "qualification_owner:root_task_required"
            )
        if (
            selected_event.get("hook_event_name") == "SessionStart"
            and selected_event.get("source") != "startup"
        ):
            raise QualificationHostError(
                "qualification_owner:fresh_startup_required"
            )
        app_server_pid = _find_ancestor_app_server(
            artifact,
            proc_root=proc_root,
            parent_pid=(os.getppid() if parent_pid is None else parent_pid),
        )
        return _owner_context_report(
            status="PASS",
            disposition="QUALIFICATION_OWNER_READ_ONLY",
            event=selected_event,
            owner_socket=str(artifact.owner_socket),
            app_server_pid=app_server_pid,
            app_server_argv_sha256=artifact.app_server_argv_sha256,
            preparation_report_path=str(report_path),
            preparation_report_sha256=artifact.report_sha256,
            preparation_file_sha256=hashlib.sha256(report_payload).hexdigest(),
            issues=[],
        )
    except (
        OSError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        issue = (
            str(error)
            if isinstance(error, QualificationHostError)
            else "qualification_owner:preparation_report_invalid"
        )
        return _owner_context_report(
            status="FAIL",
            disposition="QUALIFICATION_OWNER_UNAVAILABLE",
            event=selected_event,
            owner_socket=None,
            app_server_pid=None,
            app_server_argv_sha256=None,
            preparation_report_path=raw_path,
            preparation_report_sha256=None,
            preparation_file_sha256=None,
            issues=[issue],
        )


def prepare_qualification_host(
    *,
    codex_executable: str | Path,
    workspace: str | Path,
    owner_socket: str | Path,
    observer_trust_store: str | Path,
    observer_replay_db: str | Path,
    worker_model: str | None = None,
    worker_effort: str | None = None,
    execution_environment: Mapping[str, Any] | None = None,
    catalog: Any = None,
    reviewer_model: str | None = None,
    reviewer_effort: str | None = None,
) -> dict[str, Any]:
    """Seal one invocation-local app-server launch without starting it.

    catalog is the catalog the user's app server loads; the host writes its
    all-v1 copy privately and the app server loads it, so every model runs
    on V1 (ADR 0012).  reviewer_model and reviewer_effort seal an onboarded
    reviewer route the qualification plan's standards lane runs on.
    """

    selected_model = _worker_model(
        worker_default.DEFAULT_WORKER_MODEL if worker_model is None else worker_model
    )
    if worker_effort is not None and (
        not isinstance(worker_effort, str) or worker_effort not in ("medium", "high", "xhigh")
    ):
        raise QualificationHostError("qualification_host:worker_effort_invalid")
    reviewer = (
        _reviewer_route(reviewer_model, reviewer_effort)
        if reviewer_model is not None or reviewer_effort is not None
        else None
    )
    codex = _safe_file(
        Path(codex_executable), "codex_executable", executable=True
    )
    root = _safe_directory(Path(workspace), "workspace")
    binding = (
        validate_qualification_execution_environment(execution_environment, workspace=root)
        if execution_environment is not None else None
    )
    socket_path = _owner_socket_path(Path(owner_socket), require_absent=True)
    trust = _safe_file(
        Path(observer_trust_store), "observer_trust_store", private=True
    )
    replay = _safe_file(
        Path(observer_replay_db), "observer_replay_db", private=True
    )
    overlay = local_task_runtime.build_qualification_hook_state_override()
    environment = {
        local_task_runtime.OWNER_SOCKET_ENV: str(socket_path),
        observer_receipt.TRUST_STORE_ENV: str(trust),
        observer_receipt.REPLAY_DB_ENV: str(replay),
        PREPARATION_REPORT_ENV: str(
            socket_path.parent / PREPARATION_REPORT_NAME
        ),
    }
    environment[worker_default.WORKER_EFFORT_ENV] = (
        worker_default.DEFAULT_WORKER_EFFORT if worker_effort is None else worker_effort
    )
    environment[worker_default.WORKER_MODEL_ENV] = selected_model
    if reviewer is not None:
        environment[worker_default.REVIEWER_MODEL_ENV] = reviewer[0]
        environment[worker_default.REVIEWER_EFFORT_ENV] = reviewer[1]
    if binding is not None:
        environment["CODEX_EXEC_SERVER_URL"] = ""
    catalog_overlay = None
    if catalog is not None:
        try:
            rows = model_profiles.onboarded_profiles.catalog_rows(catalog)
            overlay_path = socket_path.parent / CATALOG_OVERLAY_NAME
            digest = model_profiles.onboarded_profiles.write_all_v1_overlay(catalog, overlay_path)
        except (OSError, ValueError) as error:
            raise QualificationHostError("qualification_host:catalog_overlay_invalid") from error
        catalog_overlay = {
            "path": str(overlay_path),
            "sha256": digest,
            "rows": len(rows),
            "rows_rewritten": sorted(
                {
                    model_profiles.onboarded_profiles.row_model(row) or "<unnamed>"
                    for row in rows
                    if model_profiles.onboarded_profiles.row_surface(row) != "v1"
                }
            ),
        }
    argv = _qualification_app_server_argv(
        str(codex),
        overlay,
        str(socket_path),
        binding,
        catalog_overlay["path"] if catalog_overlay is not None else None,
    )
    core = {
        "schema": _REPORT_SCHEMAS[(binding is not None, catalog_overlay is not None)],
        "status": "PASS",
        "disposition": "READY_FOR_APP_SERVER_LAUNCH",
        "codex_executable": str(codex),
        "workspace": str(root),
        "owner_socket": str(socket_path),
        "argv": argv,
        "app_server_argv_sha256": _argv_sha256(argv),
        "environment": environment,
        "hook_overlay": overlay,
        "first_turn_transport": _execution_first_turn_transport(binding),
        "provider_free": True,
        "counters": deepcopy(_COUNTERS),
    }
    if binding is not None:
        core["execution_environment"] = binding
    if catalog_overlay is not None:
        core["catalog_overlay"] = catalog_overlay
    report = {**core, "report_sha256": _sha(core)}
    artifact = QualificationHostPreparationArtifact.from_report(report)
    _create_only_json(artifact.preparation_report_path, report)
    return report


def verify_qualification_host_pre_turn(
    preparation_report: Any,
) -> dict[str, Any]:
    """Require the exact five enabled hooks before task/turn creation."""

    artifact = QualificationHostPreparationArtifact.from_report(
        preparation_report
    )
    inventory = local_task_runtime.observe_qualification_host_hooks(
        socket_path=artifact.owner_socket,
        cwd=artifact.workspace,
    )
    observed = local_task_runtime.OwnerHookInventoryArtifact.from_report(
        inventory
    )
    if (
        observed.app_server_argv_sha256
        != artifact.app_server_argv_sha256
    ):
        raise QualificationHostError(
            "qualification_host:owner_invocation_mismatch"
        )
    return inventory


def _linux_process_stat(payload: bytes, *, expected_pid: int) -> tuple[int, int, int, int]:
    """Return PPID, process group, session, and start ticks from /proc/stat."""

    try:
        closing = payload.rfind(b") ")
        if closing <= 0 or int(payload.split(b" ", 1)[0]) != expected_pid:
            raise ValueError("stat header")
        fields = payload[closing + 2 :].split()
        if len(fields) < 20:
            raise ValueError("stat fields")
        parent, pgid, sid, started = (
            int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19])
        )
        if min(parent, pgid, sid, started) < 1:
            raise ValueError("stat values")
        return parent, pgid, sid, started
    except (TypeError, ValueError, OverflowError) as error:
        raise QualificationHostError(
            "qualification_host:process_identity_unavailable"
        ) from error


def _host_process_identity(
    process: subprocess.Popen[bytes],
    artifact: QualificationHostPreparationArtifact,
) -> dict[str, Any]:
    """Capture an exact direct-child identity before any host cleanup."""

    pid = process.pid
    current_uid = os.getuid() if hasattr(os, "getuid") else os.stat(".").st_uid
    if type(pid) is not int or pid < 1 or process.poll() is not None:
        raise QualificationHostError("qualification_host:process_not_live")
    process_root = Path("/proc") / str(pid)
    expected_cmdline = b"\0".join(os.fsencode(item) for item in artifact.argv) + b"\0"
    try:
        root_info = process_root.lstat()
        if (
            process_root.is_symlink()
            or not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != current_uid
        ):
            raise ValueError("unsafe process root")
        raw_stat = _read_proc_bytes(
            process_root / "stat", expected_uid=current_uid
        )
        parent, pgid, sid, started = _linux_process_stat(
            raw_stat, expected_pid=pid
        )
        raw_argv = _read_proc_bytes(
            process_root / "cmdline", expected_uid=current_uid
        )
        raw_cwd = os.readlink(process_root / "cwd")
        cwd = Path(raw_cwd)
        if (
            raw_argv != expected_cmdline
            or not raw_cwd.startswith("/")
            or raw_cwd.endswith(" (deleted)")
            or cwd.resolve(strict=True) != artifact.workspace
            or parent != os.getpid()
            or pgid != pid
            or sid != pid
            or process.poll() is not None
        ):
            raise ValueError("identity mismatch")
        return {
            "pid": pid,
            "ppid": parent,
            "pgid": pgid,
            "sid": sid,
            "start_ticks": started,
            "uid": current_uid,
            "argv_sha256": hashlib.sha256(raw_argv).hexdigest(),
            "cwd": str(artifact.workspace),
        }
    except (OSError, ValueError) as error:
        if isinstance(error, QualificationHostError):
            raise
        raise QualificationHostError(
            "qualification_host:process_identity_unavailable"
        ) from error


def _owned_process_table() -> dict[int, tuple[int, int, int, int]] | None:
    """Read one stable current-UID process table from Linux procfs.

    The process-directory owner binds each row to the current UID.  Linux may
    present the virtual ``stat`` file itself as kernel-owned, so that
    pseudo-file metadata is accepted only after the directory check and with
    ``O_NOFOLLOW`` still in force.
    """

    current_uid = os.getuid() if hasattr(os, "getuid") else None
    proc_root = Path("/proc")
    try:
        root_info = proc_root.lstat()
        if proc_root.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
            return None
        rows: dict[int, tuple[int, int, int, int]] = {}
        for entry in proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                info = entry.lstat()
            except FileNotFoundError:
                continue
            if (
                current_uid is not None
                and (not stat.S_ISDIR(info.st_mode) or info.st_uid != current_uid)
            ):
                continue
            pid = int(entry.name)
            try:
                payload = _read_proc_bytes(
                    entry / "stat",
                    expected_uid=info.st_uid,
                    allow_kernel_owned=True,
                )
                rows[pid] = _linux_process_stat(payload, expected_pid=pid)
            except FileNotFoundError:
                continue
        return rows
    except (OSError, QualificationHostError, ValueError):
        return None


def _host_process_group_members(pgid: int) -> list[int] | None:
    """Sample every current-user member of one owned POSIX process group."""

    if type(pgid) is not int or pgid < 1:
        return None
    rows = _owned_process_table()
    if rows is None:
        return None
    return sorted(pid for pid, row in rows.items() if row[1] == pgid)


def _owned_descendant_identities(
    root_pid: int,
) -> dict[int, int] | None:
    """Capture the direct child's live descendants by PID and start ticks."""

    rows = _owned_process_table()
    if rows is None or root_pid not in rows:
        return None
    children: dict[int, list[int]] = {}
    for pid, (parent, _pgid, _sid, _started) in rows.items():
        children.setdefault(parent, []).append(pid)
    pending = [root_pid]
    observed: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in observed:
            continue
        observed.add(pid)
        pending.extend(children.get(pid, ()))
    return {pid: rows[pid][3] for pid in observed}


def _recorded_descendants_absent(
    descendants: Mapping[int, int] | None,
) -> tuple[bool, int | None]:
    """Re-read every pre-termination descendant without trusting PID reuse."""

    if descendants is None:
        return False, None
    rows = _owned_process_table()
    if rows is None:
        return False, None
    remaining = [
        pid
        for pid, start_ticks in descendants.items()
        if pid in rows and rows[pid][3] == start_ticks
    ]
    return remaining == [], len(remaining)


def _signal_recorded_descendants(
    descendants: Mapping[int, int],
    signal_number: int,
    *,
    issues: list[str],
) -> bool:
    """Signal only the exact recorded descendants that are still ours.

    Report whether the signal could be delivered at all. A caller that records
    an escalation must not name an action nobody performed: if the process
    table cannot be read, nothing is sent, and the escalation is unknown
    rather than the signal that was merely intended.
    """

    rows = _owned_process_table()
    if rows is None:
        issues.append("qualification_host:descendant_observation_unavailable")
        return False
    for pid, start_ticks in descendants.items():
        row = rows.get(pid)
        # Start ticks make PID reuse unforgeable: a recycled pid is a
        # different process and must never be signalled.
        if row is None or row[3] != start_ticks:
            continue
        try:
            os.kill(pid, signal_number)
        except ProcessLookupError:
            continue
        except (OSError, PermissionError):
            issues.append("qualification_host:descendant_termination_failed")
    return True


def _recorded_descendants_settled(
    descendants: Mapping[int, int] | None,
    *,
    issues: list[str],
) -> tuple[bool, int | None, str]:
    """Wait out, then reap, descendants the group signal could not reach.

    Observing once, immediately after terminating the group, reports a live
    descendant that is merely still exiting. Generation 12 failed exactly that
    way: one descendant, its own group leader so never signalled, independently
    confirmed gone moments later. Cleanup is terminal for the whole attempt, so
    a snapshot taken too early costs a generation.

    Re-observe within the bounded cleanup interval, escalate to a direct signal
    for pids whose recorded start ticks still match, and report what genuinely
    remains.

    Report the escalation level too. A host that exited cleanly and a host
    whose descendants had to be signalled are both a closed host, but they are
    not the same event, and a cleanup report that cannot tell them apart hides
    a real leak behind a PASS.

    Nothing observed is a third case. When the descendant table could not be
    read at all the caller passes None, and the honest answer is unknown:
    reporting none there would assert that no signal was needed, which is a
    claim this path has no evidence for.

    The same rule governs an empty recorded set. Nothing recorded means
    nothing to signal, but only a positive observation can say so, and the
    table can fail to read here too. None means observed-absent, never
    merely unrecorded.
    """

    if descendants is None:
        return False, None, HOST_ESCALATION_UNKNOWN
    absent, remaining = _recorded_descendants_absent(descendants)
    if not descendants:
        return absent, remaining, (
            HOST_ESCALATION_NONE if absent else HOST_ESCALATION_UNKNOWN
        )
    if absent:
        return absent, remaining, HOST_ESCALATION_NONE
    deadline = time.monotonic() + HOST_DESCENDANT_CLEANUP_SECONDS
    # Reserve the reap window inside this interval instead of appending to it,
    # and take it out of the idle wait-and-see prefix rather than out of the
    # grace after SIGTERM. Cutting the grace would both kill a descendant that
    # was about to leave on its own and shrink the observation window to a
    # single poll at small intervals, which is a flake at a one-shot boundary.
    reap = min(
        HOST_DESCENDANT_REAP_SECONDS, HOST_DESCENDANT_CLEANUP_SECONDS / 4
    )
    terminate_at = deadline - (HOST_DESCENDANT_CLEANUP_SECONDS / 2) - reap
    kill_at = deadline - reap
    escalation = HOST_ESCALATION_NONE
    while time.monotonic() < kill_at:
        time.sleep(0.05)
        absent, remaining = _recorded_descendants_absent(descendants)
        if absent:
            return True, remaining, escalation
        if (
            escalation == HOST_ESCALATION_NONE
            and time.monotonic() >= terminate_at
        ):
            escalation = (
                HOST_ESCALATION_SIGTERM
                if _signal_recorded_descendants(
                    descendants, signal.SIGTERM, issues=issues
                )
                else HOST_ESCALATION_UNKNOWN
            )
    killed = _signal_recorded_descendants(
        descendants, signal.SIGKILL, issues=issues
    )
    while True:
        time.sleep(0.05)
        absent, remaining = _recorded_descendants_absent(descendants)
        if absent or time.monotonic() >= deadline:
            return absent, remaining, (
                HOST_ESCALATION_SIGKILL if killed else HOST_ESCALATION_UNKNOWN
            )


class _BoundedHostOutput:
    """Own both app-server streams without retaining unbounded output."""

    __slots__ = (
        "_process_group",
        "_selector",
        "_streams",
        "_buffers",
        "_issues",
        "_lock",
        "_terminate_on_issue",
        "_finished",
        "_thread",
    )

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        if process.stdout is None or process.stderr is None:
            raise QualificationHostError("qualification_host:output_unavailable")
        self._process_group = process.pid
        self._selector = selectors.DefaultSelector()
        self._streams = {"stdout": process.stdout, "stderr": process.stderr}
        self._buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self._issues: list[str] = []
        self._lock = threading.Lock()
        self._terminate_on_issue = False
        self._finished = threading.Event()
        for name, stream in self._streams.items():
            os.set_blocking(stream.fileno(), False)
            self._selector.register(stream, selectors.EVENT_READ, name)
        self._thread = threading.Thread(
            target=self._run,
            name="orch-dork-qualification-host-output",
            daemon=True,
        )
        self._thread.start()

    def _record_issue(self, issue: str) -> None:
        should_terminate = False
        with self._lock:
            if issue not in self._issues:
                self._issues.append(issue)
                should_terminate = self._terminate_on_issue
        if should_terminate:
            try:
                os.killpg(self._process_group, signal.SIGTERM)
            except (OSError, ProcessLookupError, PermissionError):
                pass

    def arm(self) -> bool:
        """Enable immediate containment after the launch owner captures it."""

        with self._lock:
            self._terminate_on_issue = True
            should_terminate = bool(self._issues)
        if should_terminate:
            try:
                os.killpg(self._process_group, signal.SIGTERM)
            except (OSError, ProcessLookupError, PermissionError):
                pass
        return not should_terminate

    def _drain(self, stream: Any, name: str) -> None:
        try:
            chunk = os.read(stream.fileno(), 16_384)
        except BlockingIOError:
            return
        except OSError:
            chunk = b""
            self._record_issue("qualification_host:output_observation_failed")
        if not chunk:
            try:
                self._selector.unregister(stream)
            except Exception:
                pass
            return
        with self._lock:
            buffer = self._buffers[name]
            remaining = HOST_OUTPUT_BYTES - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            exhausted = len(chunk) > remaining
        if exhausted:
            self._record_issue(
                "qualification_host:" + name + "_limit_exceeded"
            )

    def _run(self) -> None:
        try:
            while self._selector.get_map():
                for key, _events in self._selector.select(0.05):
                    self._drain(key.fileobj, str(key.data))
        except Exception:
            self._record_issue("qualification_host:output_observation_failed")
        finally:
            try:
                self._selector.close()
            except Exception:
                pass
            self._finished.set()

    def snapshot(self) -> tuple[bytes, bytes, list[str]]:
        with self._lock:
            return (
                bytes(self._buffers["stdout"]),
                bytes(self._buffers["stderr"]),
                list(self._issues),
            )

    def join(self, timeout: float) -> bool:
        self._thread.join(timeout)
        return self._finished.is_set()

    def abandon(self) -> None:
        for stream in self._streams.values():
            try:
                stream.close()
            except OSError:
                pass


class _QualificationHostHandle:
    """Opaque direct-child handle with a sealed host identity and output owner."""

    __slots__ = (
        "_process",
        "_artifact",
        "_identity",
        "_socket_binding",
        "_owner_identity_sha256",
        "_output",
        "_owner_pid",
        "_closed",
        "_report",
        "__weakref__",
    )

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        artifact: QualificationHostPreparationArtifact,
        identity: dict[str, Any],
        socket_binding: local_task_runtime.QualificationOwnerSocketBinding,
        owner_identity_sha256: str,
        output: _BoundedHostOutput,
        _key: object,
    ) -> None:
        if _key is not _HOST_HANDLE_MINT:
            raise TypeError("qualification host handle is factory-owned")
        object.__setattr__(self, "_process", process)
        object.__setattr__(self, "_artifact", artifact)
        object.__setattr__(self, "_identity", deepcopy(identity))
        object.__setattr__(self, "_socket_binding", socket_binding)
        object.__setattr__(self, "_owner_identity_sha256", owner_identity_sha256)
        object.__setattr__(self, "_output", output)
        object.__setattr__(self, "_owner_pid", os.getpid())
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_report", None)
        _ACTIVE_HOST_HANDLES.add(self)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("qualification host handle is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("qualification host handle is immutable")

    def _abandon_after_fork(self) -> None:
        self._output.abandon()
        object.__setattr__(self, "_closed", True)
        _ACTIVE_HOST_HANDLES.discard(self)

    def _require_owner(self) -> None:
        if os.getpid() != self._owner_pid:
            self._abandon_after_fork()
            raise QualificationHostError("qualification_host:handle_forked")
        if self._closed:
            raise QualificationHostError("qualification_host:handle_closed")

    @property
    def process(self) -> subprocess.Popen[bytes]:
        """The retained direct child for completion-process binding only."""

        self._require_owner()
        return self._process

    @property
    def pid(self) -> int:
        self._require_owner()
        return int(self._identity["pid"])

    @property
    def owner_socket(self) -> Path:
        self._require_owner()
        return self._artifact.owner_socket

    @property
    def owner_identity_sha256(self) -> str:
        self._require_owner()
        return self._owner_identity_sha256

    @property
    def app_server_argv_sha256(self) -> str:
        self._require_owner()
        return self._artifact.app_server_argv_sha256


def _clear_host_handles_after_fork() -> None:
    for handle in tuple(_ACTIVE_HOST_HANDLES):
        handle._abandon_after_fork()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_clear_host_handles_after_fork)


def _verify_sealed_preparation_file(
    artifact: QualificationHostPreparationArtifact,
) -> None:
    """Require the launch input to be the unchanged create-only report."""

    try:
        import orch_dork_owned_file as owned_file

        payload = owned_file.read_owned_bytes(
            artifact.preparation_report_path,
            max_bytes=MAX_PREPARATION_REPORT_BYTES,
            required_mode=0o600,
        )
    except (ImportError, OSError, ValueError) as error:
        raise QualificationHostError(
            "qualification_host:preparation_report_unavailable"
        ) from error
    if payload != _canonical(artifact.report) + b"\n":
        raise QualificationHostError("qualification_host:preparation_report_drift")


def _owned_socket_absent(
    path: Path,
    binding: local_task_runtime.QualificationOwnerSocketBinding,
) -> tuple[bool, str | None]:
    """Remove only the exact direct or rendezvous socket captured at launch."""

    try:
        if binding.advertised_path != path:
            return False, "qualification_host:owner_socket_changed"
        physical_path = binding.physical_path
        rendezvous = binding.rendezvous
        path_present = os.path.lexists(path)
        physical_present = os.path.lexists(physical_path)
        if path_present:
            advertised_info = path.lstat()
            advertised_epoch = (
                advertised_info.st_dev,
                advertised_info.st_ino,
                advertised_info.st_ctime_ns,
                advertised_info.st_uid,
            )
            if advertised_epoch != binding.advertised_epoch:
                return False, "qualification_host:owner_socket_changed"
            if rendezvous:
                if (
                    not stat.S_ISLNK(advertised_info.st_mode)
                    or Path(os.readlink(path)) != physical_path
                ):
                    return False, "qualification_host:owner_socket_changed"
            elif not stat.S_ISSOCK(advertised_info.st_mode):
                return False, "qualification_host:owner_socket_changed"
        if physical_present:
            physical_info = physical_path.lstat()
            physical_epoch = (
                physical_info.st_dev,
                physical_info.st_ino,
                physical_info.st_ctime_ns,
                physical_info.st_uid,
            )
            if (
                not stat.S_ISSOCK(physical_info.st_mode)
                or physical_epoch != binding.physical_epoch
            ):
                return False, "qualification_host:owner_socket_changed"
        if not rendezvous and not path_present:
            return True, None
        if rendezvous:
            if path_present:
                path.unlink()
            if physical_present:
                physical_path.unlink()
        elif path_present:
            path.unlink()
        if os.path.lexists(path) or (
            rendezvous and os.path.lexists(physical_path)
        ):
            return False, "qualification_host:owner_socket_cleanup_failed"
        return True, None
    except OSError:
        return False, "qualification_host:owner_socket_cleanup_failed"


def _socket_epoch_for_host(path: Path) -> tuple[int, int, int, int]:
    try:
        return local_task_runtime.qualification_owner_socket_binding(
            path
        ).physical_epoch
    except local_task_runtime.LocalTaskRuntimeError as error:
        raise QualificationHostError(
            "qualification_host:owner_socket_invalid"
        ) from error


def _socket_kernel_inode(
    path: Path,
    expected_epoch: tuple[int, int, int, int],
) -> int | None:
    """Bind a filesystem Unix socket to its kernel socket object inode."""

    try:
        binding = local_task_runtime.qualification_owner_socket_binding(path)
    except local_task_runtime.LocalTaskRuntimeError:
        return None
    if (
        "\n" in str(binding.physical_path)
        or binding.physical_epoch != expected_epoch
    ):
        return None
    try:
        payload = _read_proc_bytes(
            Path("/proc/net/unix"),
            expected_uid=0,
            max_bytes=MAX_PROC_FILE_BYTES,
        )
        text = payload.decode("utf-8")
    except (OSError, UnicodeDecodeError, QualificationHostError):
        return None
    matches: list[int] = []
    for line in text.splitlines()[1:]:
        fields = line.split(maxsplit=7)
        if len(fields) != 8 or fields[7] != str(binding.physical_path):
            continue
        if fields[4] != "0001" or fields[5] != "01":
            continue
        if not fields[6].isdigit():
            return None
        matches.append(int(fields[6]))
    return matches[0] if len(matches) == 1 and matches[0] > 0 else None


def _host_listener_holders(
    path: Path,
    *,
    pgid: int,
    expected_epoch: tuple[int, int, int, int],
) -> list[int] | None:
    """Find every owned-group process retaining the bound listener FD."""

    socket_inode = _socket_kernel_inode(path, expected_epoch)
    members = _host_process_group_members(pgid)
    current_uid = os.getuid() if hasattr(os, "getuid") else None
    if socket_inode is None or members is None:
        return None
    holders: list[int] = []
    for pid in members:
        process_root = Path("/proc") / str(pid)
        fd_root = process_root / "fd"
        try:
            process_info = process_root.lstat()
            fd_info = fd_root.lstat()
            if (
                process_root.is_symlink()
                or not stat.S_ISDIR(process_info.st_mode)
                or (current_uid is not None and process_info.st_uid != current_uid)
                or fd_root.is_symlink()
                or not stat.S_ISDIR(fd_info.st_mode)
                or (
                    current_uid is not None
                    and fd_info.st_uid not in {current_uid, 0}
                )
            ):
                return None
            for descriptor in fd_root.iterdir():
                if not descriptor.name.isdigit():
                    return None
                try:
                    target = os.readlink(descriptor)
                except FileNotFoundError:
                    continue
                if target == f"socket:[{socket_inode}]":
                    holders.append(pid)
                    break
        except (OSError, ValueError):
            return None
    if (
        _host_process_group_members(pgid) != members
        or _socket_epoch_for_host(path) != expected_epoch
    ):
        return None
    return sorted(holders)


def _capture_verified_host_socket(
    process: subprocess.Popen[bytes],
    artifact: QualificationHostPreparationArtifact,
    expected_identity: Mapping[str, Any],
) -> tuple[local_task_runtime.QualificationOwnerSocketBinding, str]:
    """Prove the listening endpoint belongs to the sealed direct child."""

    transport = local_task_runtime.open_retained_qualification_owner_transport(
        artifact.owner_socket,
        artifact.workspace,
        artifact.app_server_argv_sha256,
    )
    try:
        binding = local_task_runtime.qualification_owner_socket_binding(
            artifact.owner_socket
        )
        if transport.owner_pid != process.pid:
            raise QualificationHostError("qualification_host:socket_peer_mismatch")
        holders = _host_listener_holders(
            artifact.owner_socket,
            pgid=process.pid,
            expected_epoch=binding.physical_epoch,
        )
        if holders is None:
            raise QualificationHostError("qualification_host:socket_peer_unavailable")
        if holders != [process.pid]:
            raise QualificationHostError("qualification_host:socket_peer_mismatch")
        if (
            local_task_runtime.qualification_owner_socket_binding(
                artifact.owner_socket
            )
            != binding
            or _host_process_identity(process, artifact) != expected_identity
        ):
            raise QualificationHostError("qualification_host:process_identity_changed")
        return binding, transport.owner_identity_sha256
    finally:
        transport.close()


def _group_absent(pgid: int) -> tuple[bool, int | None]:
    members = _host_process_group_members(pgid)
    if members is None:
        return False, None
    try:
        os.killpg(pgid, 0)
        signal_absent = False
    except ProcessLookupError:
        signal_absent = True
    except (OSError, PermissionError):
        return False, len(members)
    return signal_absent and members == [], len(members)


def _terminate_owned_host_group(
    process: subprocess.Popen[bytes],
    *,
    pgid: int,
    issues: list[str],
) -> tuple[bool, bool, int | None]:
    """Terminate, reap, and independently observe one owned process group."""

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except (OSError, PermissionError):
        issues.append("qualification_host:process_group_termination_failed")
    deadline = time.monotonic() + HOST_CLEANUP_SECONDS
    killed = False
    process_reaped = process.poll() is not None
    group_absent = False
    group_members: int | None = None
    while time.monotonic() < deadline:
        if not process_reaped:
            try:
                process.wait(timeout=min(0.05, max(0.01, deadline - time.monotonic())))
            except (OSError, subprocess.TimeoutExpired):
                pass
            process_reaped = process.poll() is not None
        group_absent, group_members = _group_absent(pgid)
        if process_reaped and group_absent:
            break
        if not killed and time.monotonic() >= deadline - min(0.25, HOST_CLEANUP_SECONDS):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except (OSError, PermissionError):
                issues.append("qualification_host:process_group_kill_failed")
            killed = True
        time.sleep(0.01)
    if not process_reaped:
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired):
            pass
        process_reaped = process.poll() is not None
    group_absent, group_members = _group_absent(pgid)
    if not group_absent:
        issues.append("qualification_host:process_group_cleanup_failed")
    if not process_reaped:
        issues.append("qualification_host:process_reap_failed")
    return process_reaped, group_absent, group_members


def _abort_unbound_host(
    process: subprocess.Popen[bytes] | None,
    output: _BoundedHostOutput | None,
    *,
    owner_socket: Path,
    socket_binding: local_task_runtime.QualificationOwnerSocketBinding | None,
) -> None:
    """Contain a failed launch and remove only a previously verified socket."""

    process_reaped = process is None
    group_absent = process is None
    if process is not None and type(process.pid) is int and process.pid > 0:
        ignored_issues: list[str] = []
        process_reaped, group_absent, _members = _terminate_owned_host_group(
            process,
            pgid=process.pid,
            issues=ignored_issues,
        )
    if output is not None:
        output.join(HOST_OUTPUT_JOIN_SECONDS)
        output.abandon()
    if (
        process_reaped
        and group_absent
        and socket_binding is not None
    ):
        _owned_socket_absent(owner_socket, socket_binding)


def _cleanup_report(
    handle: _QualificationHostHandle,
    *,
    process_reaped: bool,
    group_absent: bool,
    group_members: int | None,
    descendants_absent: bool,
    remaining_descendants: int | None,
    descendant_escalation: str,
    socket_absent: bool,
    monitor_closed: bool,
    stdout: bytes,
    stderr: bytes,
    issues: list[str],
) -> dict[str, Any]:
    host_closed = (
        process_reaped
        and group_absent
        and descendants_absent
        and socket_absent
        and monitor_closed
    )
    core = {
        "schema": HOST_CLEANUP_SCHEMA,
        "status": "PASS" if host_closed and issues == [] else "FAIL",
        "disposition": (
            "QUALIFICATION_HOST_CLOSED"
            if host_closed and issues == []
            else "QUALIFICATION_HOST_CLEANUP_FAILED"
        ),
        "pid": handle._identity["pid"],
        "pgid": handle._identity["pgid"],
        "preparation_report_sha256": handle._artifact.report_sha256,
        "app_server_argv_sha256": handle._artifact.app_server_argv_sha256,
        "owner_identity_sha256": handle._owner_identity_sha256,
        "process_reaped": process_reaped,
        "process_group_absent": group_absent,
        "process_group_members": group_members,
        "descendants_absent": descendants_absent,
        "remaining_descendants": remaining_descendants,
        "descendant_escalation": descendant_escalation,
        "owner_socket_absent": socket_absent,
        "output_monitor_closed": monitor_closed,
        "host_closed": host_closed,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "issues": sorted(set(issues)),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "credential_reads": 0,
        "network_calls": 0,
        "task_creations": 0,
        "native_calls": 0,
    }
    return {**core, "report_sha256": _sha(core)}


def cleanup_qualification_host(handle: Any) -> dict[str, Any]:
    """Terminate and independently close one sealed qualification host once."""

    if not isinstance(handle, _QualificationHostHandle):
        raise QualificationHostError("qualification_host:handle_invalid")
    if os.getpid() != handle._owner_pid:
        handle._abandon_after_fork()
        raise QualificationHostError("qualification_host:handle_forked")
    if handle._report is not None:
        return deepcopy(handle._report)
    handle._require_owner()
    process = handle._process
    identity_valid = False
    issues: list[str] = []
    try:
        identity_valid = _host_process_identity(process, handle._artifact) == handle._identity
        if not identity_valid:
            issues.append("qualification_host:process_identity_changed")
    except QualificationHostError as error:
        issues.append(str(error))

    process_reaped = process.poll() is not None
    group_absent = False
    group_members: int | None = None
    descendants: dict[int, int] | None = None
    descendants_absent = False
    remaining_descendants: int | None = None
    descendant_escalation = HOST_ESCALATION_UNKNOWN
    if identity_valid:
        captured = _owned_descendant_identities(process.pid)
        if captured is None:
            issues.append("qualification_host:descendant_observation_unavailable")
        else:
            descendants = {
                pid: start_ticks
                for pid, start_ticks in captured.items()
                if pid != process.pid
            }
        process_reaped, group_absent, group_members = _terminate_owned_host_group(
            process,
            pgid=int(handle._identity["pgid"]),
            issues=issues,
        )
        (
            descendants_absent,
            remaining_descendants,
            descendant_escalation,
        ) = _recorded_descendants_settled(descendants, issues=issues)
        if not descendants_absent:
            issues.append("qualification_host:descendant_cleanup_failed")
    else:
        if not process_reaped:
            issues.append("qualification_host:process_cleanup_refused")
        try:
            group_absent, group_members = _group_absent(int(handle._identity["pgid"]))
        except (TypeError, ValueError):
            group_absent, group_members = False, None
        remaining_descendants = None

    monitor_closed = handle._output.join(HOST_OUTPUT_JOIN_SECONDS)
    if not monitor_closed:
        issues.append("qualification_host:output_monitor_cleanup_failed")
    stdout, stderr, output_issues = handle._output.snapshot()
    issues.extend(output_issues)
    if group_absent and process_reaped:
        socket_absent, socket_issue = _owned_socket_absent(
            handle._artifact.owner_socket,
            handle._socket_binding,
        )
        if socket_issue is not None:
            issues.append(socket_issue)
    else:
        socket_absent = False
        issues.append("qualification_host:owner_socket_cleanup_refused")
    handle._output.abandon()
    report = _cleanup_report(
        handle,
        process_reaped=process_reaped,
        group_absent=group_absent,
        group_members=group_members,
        descendants_absent=descendants_absent,
        remaining_descendants=remaining_descendants,
        descendant_escalation=descendant_escalation,
        socket_absent=socket_absent,
        monitor_closed=monitor_closed,
        stdout=stdout,
        stderr=stderr,
        issues=issues,
    )
    object.__setattr__(handle, "_report", deepcopy(report))
    object.__setattr__(handle, "_closed", True)
    _ACTIVE_HOST_HANDLES.discard(handle)
    return report


def launch_qualification_host(preparation_report: Any) -> _QualificationHostHandle:
    """Launch exactly one sealed host and return its PID-bound owner handle."""

    artifact = QualificationHostPreparationArtifact.from_report(preparation_report)
    _verify_sealed_preparation_file(artifact)
    _owner_socket_path(artifact.owner_socket, require_absent=True)
    process: subprocess.Popen[bytes] | None = None
    output: _BoundedHostOutput | None = None
    socket_binding: (
        local_task_runtime.QualificationOwnerSocketBinding | None
    ) = None
    try:
        environment = dict(os.environ)
        environment.update(artifact.environment)
        process = subprocess.Popen(
            list(artifact.argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(artifact.workspace),
            env=environment,
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
        output = _BoundedHostOutput(process)
        expected_identity = _host_process_identity(process, artifact)
        deadline = time.monotonic() + HOST_SOCKET_WAIT_SECONDS
        last_error: QualificationHostError | None = None
        while time.monotonic() < deadline:
            stdout, stderr, output_issues = output.snapshot()
            if output_issues:
                capture_deadline = min(deadline, time.monotonic() + 0.25)
                while (
                    socket_binding is None
                    and os.path.lexists(artifact.owner_socket)
                    and process.poll() is None
                    and time.monotonic() < capture_deadline
                ):
                    try:
                        socket_binding, _owner_identity_sha256 = (
                            _capture_verified_host_socket(
                                process, artifact, expected_identity
                            )
                        )
                    except QualificationHostError as capture_error:
                        if str(capture_error) != (
                            "qualification_host:socket_peer_unavailable"
                        ):
                            break
                        time.sleep(0.01)
                    except local_task_runtime.LocalTaskRuntimeError:
                        break
                raise QualificationHostError(output_issues[0])
            if process.poll() is not None:
                raise QualificationHostError("qualification_host:process_exited")
            if _host_process_identity(process, artifact) != expected_identity:
                raise QualificationHostError("qualification_host:process_identity_changed")
            if os.path.lexists(artifact.owner_socket):
                try:
                    socket_binding, owner_identity_sha256 = (
                        _capture_verified_host_socket(
                            process, artifact, expected_identity
                        )
                    )
                    if not output.arm():
                        raise QualificationHostError(output.snapshot()[2][0])
                    return _QualificationHostHandle(
                        process=process,
                        artifact=artifact,
                        identity=expected_identity,
                        socket_binding=socket_binding,
                        owner_identity_sha256=owner_identity_sha256,
                        output=output,
                        _key=_HOST_HANDLE_MINT,
                    )
                except QualificationHostError as error:
                    if str(error) != "qualification_host:socket_peer_unavailable":
                        raise
                    last_error = error
                except local_task_runtime.LocalTaskRuntimeError as error:
                    last_error = QualificationHostError(
                        "qualification_host:owner_socket_not_ready"
                    )
            time.sleep(0.01)
        if last_error is not None:
            raise last_error
        raise QualificationHostError("qualification_host:owner_socket_timeout")
    except (OSError, ValueError, QualificationHostError) as error:
        _abort_unbound_host(
            process,
            output,
            owner_socket=artifact.owner_socket,
            socket_binding=socket_binding,
        )
        if isinstance(error, QualificationHostError):
            raise
        raise QualificationHostError("qualification_host:launch_failed") from error


def _git_output(repository: Path, *args: str) -> str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise QualificationHostError(
            "qualification_host:checkout_unavailable"
        ) from error
    if completed.returncode != 0 or len(completed.stdout) > 131_072:
        raise QualificationHostError(
            "qualification_host:checkout_unavailable"
        )
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise QualificationHostError(
            "qualification_host:checkout_unavailable"
        ) from error


def capture_qualification_checkout(
    preparation_report: Any,
    *,
    expected_branch: str,
    expected_commit: str,
) -> dict[str, Any]:
    """Seal the exact clean checkout immediately before task creation."""

    preparation = QualificationHostPreparationArtifact.from_report(
        preparation_report
    )
    if (
        not isinstance(expected_branch, str)
        or not expected_branch
        or "\x00" in expected_branch
        or _COMMIT.fullmatch(str(expected_commit)) is None
    ):
        raise QualificationHostError(
            "qualification_host:checkout_expectation_invalid"
        )
    repository = preparation.workspace
    observed_commit = _git_output(repository, "rev-parse", "HEAD")
    observed_branch = _git_output(repository, "branch", "--show-current")
    worktree_status = _git_output(
        repository, "status", "--porcelain", "--untracked-files=all"
    )
    if (
        observed_commit != expected_commit
        or observed_branch != expected_branch
        or worktree_status
    ):
        raise QualificationHostError(
            "qualification_host:checkout_drift"
        )
    captured_at_unix_ns = time.time_ns()
    report_path = preparation.owner_socket.parent / CHECKOUT_REPORT_NAME
    core = {
        "schema": QUALIFICATION_CHECKOUT_SCHEMA,
        "status": "PASS",
        "disposition": "READY_FOR_SINGLE_TASK_CREATION",
        "workspace": str(repository),
        "branch": observed_branch,
        "commit": observed_commit,
        "owner_socket": str(preparation.owner_socket),
        "host_preparation_report_sha256": preparation.report_sha256,
        "app_server_argv_sha256": preparation.app_server_argv_sha256,
        "report_path": str(report_path),
        "task_project_id": (
            "orch-dork-qualification-" + secrets.token_hex(32)
        ),
        "captured_at_unix_ns": captured_at_unix_ns,
        "expires_at_unix_ns": (
            captured_at_unix_ns
            + QUALIFICATION_CHECKOUT_MAX_AGE_SECONDS * 1_000_000_000
        ),
        "clean": True,
        "provider_free": True,
        "counters": deepcopy(_COUNTERS),
    }
    report = {**core, "report_sha256": _sha(core)}
    _create_only_json(report_path, report, label="checkout_report")
    return QualificationCheckoutArtifact.from_report(
        report,
        preparation_report=preparation.report,
    ).report


def build_qualification_thread_start_params(
    preparation_report: Any,
    checkout_report: Any,
    *,
    expected_model: str,
    service_name: str,
    worker_model: str | None = None,
    worker_effort: str | None = None,
) -> dict[str, Any]:
    """Return the closed request, preserving full access inside its executor."""

    preparation = QualificationHostPreparationArtifact.from_report(
        preparation_report
    )
    checkout = QualificationCheckoutArtifact.from_report(
        checkout_report,
        preparation_report=preparation.report,
    )
    if (
        not isinstance(expected_model, str)
        or _MODEL_NAME.fullmatch(expected_model) is None
        or not isinstance(service_name, str)
        or _SERVICE_NAME.fullmatch(service_name) is None
        or time.time_ns() > checkout.expires_at_unix_ns
    ):
        raise QualificationHostError(
            "qualification_host:thread_start_request_invalid"
        )
    config: dict[str, Any] = {"mcp_servers.orch-dork-worker-port.enabled": False}
    selected_model = _worker_model(
        worker_default.DEFAULT_WORKER_MODEL if worker_model is None else worker_model
    )
    if selected_model != preparation.environment[worker_default.WORKER_MODEL_ENV]:
        raise QualificationHostError("qualification_host:worker_model_mismatch")
    if worker_effort is not None:
        if not isinstance(worker_effort, str) or worker_effort not in ("medium", "high", "xhigh"):
            raise QualificationHostError("qualification_host:worker_effort_invalid")
    selected_effort = (
        worker_default.DEFAULT_WORKER_EFFORT if worker_effort is None else worker_effort
    )
    if selected_effort != preparation.environment[worker_default.WORKER_EFFORT_ENV]:
        raise QualificationHostError("qualification_host:worker_effort_mismatch")
    # Keep the plugin-owned transport intact. Codex validates explicit MCP
    # config before loading plugin declarations; an env-only entry is invalid,
    # and a complete replacement loses plugin attribution. The sealed owner
    # environment is forwarded through the plugin's declared env_vars instead.
    params = {
        "approvalPolicy": "never",
        "config": config,
        "cwd": str(preparation.workspace),
        "model": expected_model,
        "sandbox": "danger-full-access",
        "serviceName": service_name,
    }
    if preparation.execution_environment is not None:
        params["environments"] = qualification_execution_environment_selection(preparation.report)
    return params


def _idle(value: Any) -> bool:
    return value == {"type": "idle"}


def _git_info_state(
    value: Any,
    *,
    expected_branch: str,
    expected_commit: str,
) -> str:
    if value is None:
        return "absent"
    if not isinstance(value, Mapping):
        raise QualificationHostError(
            "qualification_host:thread_start_invalid"
        )
    observed_commit = value.get("sha")
    observed_branch = value.get("branch")
    if (
        observed_commit not in (None, expected_commit)
        or observed_branch not in (None, expected_branch)
    ):
        raise QualificationHostError(
            "qualification_host:thread_git_info_contradictory"
        )
    return "matching" if value else "present_without_identity"


def reconcile_qualification_idle_task(
    thread_start_response: Any,
    thread_loaded_list_response: Any,
    thread_read_response: Any,
    *,
    preparation_report: Any,
    checkout_report: Any,
    expected_model: str,
    expected_model_provider: str,
) -> dict[str, Any]:
    """Bind one fresh idle task without trusting nullable task projections."""

    checkout = QualificationCheckoutArtifact.from_report(
        checkout_report,
        preparation_report=preparation_report,
    )
    repository = checkout.workspace
    expected_branch = checkout.branch
    expected_commit = checkout.commit
    if (
        not isinstance(thread_start_response, Mapping)
        or not isinstance(thread_loaded_list_response, Mapping)
        or not isinstance(thread_read_response, Mapping)
        or not isinstance(expected_model, str)
        or not expected_model
        or not isinstance(expected_model_provider, str)
        or not expected_model_provider
    ):
        raise QualificationHostError(
            "qualification_host:thread_start_invalid"
        )
    start_result = thread_start_response.get("result")
    read_result = thread_read_response.get("result")
    start_thread = (
        start_result.get("thread")
        if isinstance(start_result, Mapping)
        else None
    )
    read_thread = (
        read_result.get("thread")
        if isinstance(read_result, Mapping)
        else None
    )
    if not isinstance(start_thread, Mapping) or not isinstance(
        read_thread, Mapping
    ):
        raise QualificationHostError(
            "qualification_host:thread_start_invalid"
        )
    preparation = QualificationHostPreparationArtifact.from_report(preparation_report)
    if preparation.execution_environment is not None:
        for thread in (start_thread, read_thread):
            verify_qualification_task_execution_environment(thread, preparation_report=preparation.report)
    task_id = start_thread.get("id")
    start_path = start_thread.get("path")
    created_at = start_thread.get("createdAt")
    read_created_at = read_thread.get("createdAt")
    observed_at_ns = time.time_ns()
    # Before persistence, Codex builds each loaded snapshot with the current
    # time as createdAt. Bind identity through the exact solo task and source;
    # independently bound both second-resolution observations by this capture.
    timestamps_valid = all(
        type(value) is int
        and checkout.captured_at_unix_ns // 1_000_000_000
        <= value
        <= min(checkout.expires_at_unix_ns, observed_at_ns) // 1_000_000_000
        for value in (created_at, read_created_at)
    )
    loaded_result = thread_loaded_list_response.get("result")
    loaded_task_ids = (
        loaded_result.get("data")
        if isinstance(loaded_result, Mapping)
        else None
    )
    if (
        _TASK_ID.fullmatch(str(task_id)) is None
        or start_thread.get("sessionId") != task_id
        or read_thread.get("id") != task_id
        or read_thread.get("sessionId") != task_id
        or start_result.get("model") != expected_model
        or start_result.get("modelProvider") != expected_model_provider
        or start_result.get("cwd") != str(repository)
        or start_result.get("approvalPolicy") != "never"
        or start_result.get("sandbox") != {"type": "dangerFullAccess"}
        or start_thread.get("model") != expected_model
        or start_thread.get("modelProvider") != expected_model_provider
        or start_thread.get("cwd") != str(repository)
        or start_thread.get("projectId") is not None
        or read_thread.get("model") != expected_model
        or read_thread.get("modelProvider") != expected_model_provider
        or read_thread.get("cwd") != str(repository)
        or read_thread.get("projectId") is not None
        or not timestamps_valid
        or start_thread.get("historyMode") != "paginated"
        or read_thread.get("historyMode") != "paginated"
        or not _idle(start_thread.get("status"))
        or not _idle(read_thread.get("status"))
        or start_thread.get("turns") != []
        or read_thread.get("turns") != []
        or loaded_task_ids != [task_id]
        or loaded_result.get("nextCursor") is not None
        or read_thread.get("path") != start_path
        or observed_at_ns > checkout.expires_at_unix_ns
        or (
            start_path is not None
            and (
                not isinstance(start_path, str)
                or not Path(start_path).is_absolute()
                or "\x00" in start_path
            )
        )
    ):
        raise QualificationHostError(
            "qualification_host:thread_start_invalid"
        )
    start_git_info = _git_info_state(
        start_thread.get("gitInfo"),
        expected_branch=expected_branch,
        expected_commit=expected_commit,
    )
    read_git_info = _git_info_state(
        read_thread.get("gitInfo"),
        expected_branch=expected_branch,
        expected_commit=expected_commit,
    )
    observed_commit = _git_output(repository, "rev-parse", "HEAD")
    observed_branch = _git_output(repository, "branch", "--show-current")
    worktree_status = _git_output(
        repository, "status", "--porcelain", "--untracked-files=all"
    )
    if (
        observed_commit != expected_commit
        or observed_branch != expected_branch
        or worktree_status
    ):
        raise QualificationHostError(
            "qualification_host:checkout_drift"
        )
    core = {
        "schema": IDLE_TASK_RECONCILIATION_SCHEMA,
        "status": "PASS",
        "disposition": "IDLE_TASK_RECONCILED",
        "task_id": task_id,
        "session_id": task_id,
        "workspace": str(repository),
        "model": expected_model,
        "model_provider": expected_model_provider,
        "history_mode": "paginated",
        "task_creation_count": 1,
        "task_project_id": checkout.task_project_id,
        "task_created_at": created_at,
        "task_read_created_at": read_created_at,
        "timestamp_policy": FIRST_TURN_TRANSPORT["idle_task_timestamp_policy"],
        "checkout_pre_call_report_sha256": checkout.report_sha256,
        "thread_start_git_info": start_git_info,
        "thread_read_git_info": read_git_info,
        "rollout_materialized": (
            isinstance(start_path, str) and Path(start_path).is_file()
        ),
        "provenance_sources": [
            "clean_checkout_pre_call",
            "exact_solo_loaded_task",
            "thread/read",
        ],
        "reconciliation_sources": [
            "thread/start",
            "thread/loaded/list",
            "thread/read",
        ],
        "checkout": {
            "branch": observed_branch,
            "commit": observed_commit,
            "clean": True,
        },
        "provider_free": True,
        "counters": deepcopy(_COUNTERS),
    }
    return {**core, "report_sha256": _sha(core)}


def reconcile_qualification_owner_gate(
    owner_report: Any,
    thread_read_response: Any,
    *,
    expected_task_id: str,
    expected_turn_id: str,
    expected_owner_identity_sha256: str,
) -> dict[str, Any]:
    """Bind the sealed public report to its actual owner-turn MCP result.

    Expected task and owner identities come from the previously reconciled
    task and pre-turn owner inventory. The public runtime report intentionally
    omits a task identifier; the owning RPC response supplies that binding.
    Missing independently attributed tool evidence is a refusal.
    """
    counters = (
        "model_calls", "hosted_calls", "credential_reads", "network_calls",
        "task_creations", "native_calls",
    )
    fields = {
        "schema", "status", "disposition", "task_owner_verified",
        "task_loaded", "task_status", "descendant_count",
        "owner_identity_sha256", "issues", "provider_free", "report_sha256",
        *counters,
    }
    if (
        _TASK_ID.fullmatch(str(expected_task_id)) is None
        or _TASK_ID.fullmatch(str(expected_turn_id)) is None
        or _SHA256.fullmatch(str(expected_owner_identity_sha256)) is None
        or not isinstance(owner_report, Mapping)
        or set(owner_report) != fields
    ):
        raise QualificationHostError("qualification_host:owner_report_invalid")
    owner = deepcopy(dict(owner_report))
    core = {key: value for key, value in owner.items() if key != "report_sha256"}
    if (
        owner.get("schema") != local_task_runtime.SCHEMA
        or owner.get("status") != "PASS"
        or owner.get("disposition") != "CURRENT_TASK_RUNTIME_VERIFIED"
        or owner.get("task_owner_verified") is not True
        or owner.get("task_loaded") is not True
        or owner.get("task_status") != "active"
        or type(owner.get("descendant_count")) is not int
        or owner.get("descendant_count") != 0
        or owner.get("owner_identity_sha256") != expected_owner_identity_sha256
        or owner.get("issues") != []
        or owner.get("provider_free") is not True
        or any(type(owner.get(key)) is not int or owner[key] != 0 for key in counters)
        or owner.get("report_sha256") != _sha(core)
    ):
        raise QualificationHostError("qualification_host:owner_report_invalid")
    result = (
        thread_read_response.get("result")
        if isinstance(thread_read_response, Mapping)
        and "error" not in thread_read_response else None
    )
    thread = result.get("thread") if isinstance(result, Mapping) else None
    if (
        not isinstance(thread, Mapping)
        or thread.get("id") != expected_task_id
        or thread.get("sessionId") != expected_task_id
        or not _idle(thread.get("status"))
        or not isinstance(thread.get("turns"), list)
        or len(thread["turns"]) != 1
    ):
        raise QualificationHostError("qualification_host:owner_turn_invalid")
    turn = thread["turns"][0]
    if (
        not isinstance(turn, Mapping)
        or turn.get("id") != expected_turn_id
        or turn.get("status") != "completed"
        or turn.get("error") is not None
        or not isinstance(turn.get("items"), list)
        or any(
            not isinstance(item, Mapping)
            or item.get("type") not in {
                "userMessage", "reasoning", "agentMessage", "mcpToolCall",
            }
            for item in turn["items"]
        )
    ):
        raise QualificationHostError("qualification_host:owner_turn_invalid")
    calls = [item for item in turn["items"] if item.get("type") == "mcpToolCall"]
    if len(calls) != 1:
        raise QualificationHostError("qualification_host:owner_tool_result_invalid")
    call = calls[0]
    tool_result = call.get("result")
    if (
        call.get("server") != "orch-dork"
        or call.get("pluginId") != "orch-dork@orch-dork-local"
        or call.get("tool") != "observe_current_local_task_runtime"
        or call.get("arguments") != {}
        or call.get("status") != "completed"
        or call.get("error") is not None
        or not isinstance(call.get("id"), str)
        or not call["id"]
        or not isinstance(tool_result, Mapping)
        or tool_result.get("structuredContent") != owner
    ):
        raise QualificationHostError("qualification_host:owner_tool_result_invalid")
    reconciled = {
        "schema": "orch-dork/qualification-owner-gate-reconciliation/v1",
        "status": "PASS",
        "disposition": "OWNER_GATE_RECONCILED",
        "task_id": expected_task_id,
        "turn_id": expected_turn_id,
        "tool_call_id": call["id"],
        "owner_identity_sha256": expected_owner_identity_sha256,
        "owner_report": owner,
        "thread_read_response_sha256": _sha(thread_read_response),
        "dispatch_permitted": False,
        "provider_free": True,
        "counters": deepcopy(_COUNTERS),
    }
    return {**reconciled, "report_sha256": _sha(reconciled)}


__all__ = [
    "EXECUTION_ENVIRONMENT_ID",
    "EXECUTION_ENVIRONMENT_SCHEMA",
    "EXTERNAL_EXECUTION_REPORT_SCHEMA",
    "EXTERNAL_EXECUTION_OVERLAY_REPORT_SCHEMA",
    "OVERLAY_REPORT_SCHEMA",
    "CHECKOUT_REPORT_NAME",
    "HOST_CLEANUP_FIELDS",
    "HOST_CLEANUP_SCHEMA",
    "HOST_ESCALATION_NONE",
    "HOST_ESCALATION_SIGKILL",
    "HOST_ESCALATION_SIGTERM",
    "HOST_ESCALATION_UNKNOWN",
    "HOST_CLEANUP_SECONDS",
    "HOST_OUTPUT_BYTES",
    "HOST_SOCKET_WAIT_SECONDS",
    "QualificationCheckoutArtifact",
    "QualificationHostError",
    "QualificationHostPreparationArtifact",
    "FIRST_TURN_TRANSPORT",
    "IDLE_TASK_RECONCILIATION_SCHEMA",
    "OWNER_CONTEXT_SCHEMA",
    "PREPARATION_REPORT_ENV",
    "PREPARATION_REPORT_NAME",
    "QUALIFICATION_CHECKOUT_SCHEMA",
    "QUALIFICATION_CHECKOUT_MAX_AGE_SECONDS",
    "REPORT_SCHEMA",
    "build_qualification_thread_start_params",
    "capture_qualification_checkout",
    "cleanup_qualification_host",
    "create_qualification_controller_root",
    "observe_qualification_owner_context",
    "launch_qualification_host",
    "prepare_qualification_host",
    "qualification_execution_environment_selection",
    "reconcile_qualification_idle_task",
    "reconcile_qualification_owner_gate",
    "run_qualification_owner_session",
    "verify_qualification_host_pre_turn",
    "validate_qualification_execution_environment",
    "verify_qualification_task_execution_environment",
]
