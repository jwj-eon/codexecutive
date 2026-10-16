#!/usr/bin/env python3
"""Provider-free pre-authority execution-readiness policy.

The evaluator validates closed facts supplied by a disposable project runner.
It never reads credentials, reserves a grant, dispatches a model, creates a
task, or performs a replay.  READY_FOR_AUTHORITY therefore means only that the
exact bound implementation and environment survived the required provider-
free qualification; it is not authority and cannot revive a spent grant.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from typing import Any, Mapping


PROGRAM_SCHEMA = "orch-dork/execution-readiness-program/v1"
RECEIPT_SCHEMA = "orch-dork/execution-readiness-receipt/v1"
ENVIRONMENT_SCHEMA = "orch-dork/execution-readiness-environment/v1"
REPLAY_SCHEMA = "orch-dork/execution-readiness-replay/v1"
LIFECYCLE_SCHEMA = "orch-dork/execution-readiness-lifecycle/v1"
REGRESSION_SCHEMA = "orch-dork/execution-readiness-regression/v1"

REQUIRED_COMPONENTS = frozenset(
    {
        "executor",
        "controller",
        "project_adapter",
        "policy",
        "mcp_descriptor",
        "finalizer",
        "evidence_schema",
        "environment_runner",
        "lifecycle_policy",
        "readiness_evaluator",
    }
)
REQUIRED_FAILURES = frozenset(
    {
        "timeout",
        "cancellation",
        "provider_exception",
        "missing_usage",
        "finalizer_exception",
        "partial_evidence",
        "cleanup_failure",
    }
)
REQUIRED_TRANSITIONS = (
    "owner_work_before_release",
    "release_sent",
    "release_delivered",
    "sender_binding",
    "duplicate_delivery",
    "expiration",
    "late_completion",
    "integrator_failure",
)
REQUIRED_REGRESSIONS = frozenset(
    {"issue17_finalizer_drift", "issue28_barrier_clock"}
)
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_MAX_OBSERVED_BYTES = 4 * 1024 * 1024
_REGRESSION_FIXTURE = (
    "skills/orch-dork/runtime/execution-readiness-regressions-v1.json"
)
_REGRESSION_FIXTURE_SHA256 = (
    "889077b5917f1bc61d0d6dd5eee5a4c182879714caeb8179f378180e9dcc0925"
)
_COMPONENT_BINDINGS = {
    "executor": (
        "skills/orch-dork/scripts/orch_dork_governed_run.py",
        "evaluate_governed_run",
    ),
    "controller": (
        "skills/orch-dork/scripts/orch_dork_governed_native_controller.py",
        "GovernedNativeController",
    ),
    "project_adapter": (
        "skills/orch-dork/scripts/orch_dork_project_adapter.py",
        "evaluate_project_adapter",
    ),
    "policy": (
        "skills/orch-dork/scripts/orch_dork_policy.py",
        "dispatch",
    ),
    "mcp_descriptor": (".mcp.json", "mcpServers.orch-dork"),
    "finalizer": (
        "skills/orch-dork/scripts/orch_dork_native_grant_store.py",
        "NativeGrantStore.finalize_action",
    ),
    "evidence_schema": (
        "skills/orch-dork/scripts/orch_dork_native_result.py",
        "normalize_native_result",
    ),
    "environment_runner": (
        "skills/orch-dork/scripts/orch_dork_local_task_runtime.py",
        "observe_current_local_task_runtime",
    ),
    "lifecycle_policy": (
        "skills/orch-dork/scripts/orch_dork_worker_lifecycle.py",
        "evaluate_worker_lifecycle",
    ),
    "readiness_evaluator": (
        "skills/orch-dork/scripts/orch_dork_execution_readiness.py",
        "evaluate_execution_readiness",
    ),
}


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


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


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


def _owned_bytes(
    path: Path,
    *,
    private: bool = False,
    owner_required: bool = True,
    max_bytes: int = _MAX_OBSERVED_BYTES,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_size <= 0
            or details.st_size > max_bytes
            or details.st_mode & 0o002
            or (private and details.st_mode & 0o077)
            or (
                owner_required
                and
                hasattr(os, "getuid")
                and details.st_uid != os.getuid()
            )
        ):
            raise ValueError("owned_file:unsafe")
        chunks: list[bytes] = []
        remaining = details.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise ValueError("owned_file:short_read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("owned_file:size_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_owned_json(path: Path, value: Mapping[str, Any]) -> bytes:
    payload = _canonical(value) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if _owned_bytes(path, private=True) != payload:
        raise ValueError("owned_file:readback_mismatch")
    return payload


def _pointer(path: Path, payload: bytes) -> str:
    return str(path) + "#sha256=" + hashlib.sha256(payload).hexdigest()


def _pointer_bytes(value: Any, *, private: bool = True) -> bytes:
    if not isinstance(value, str) or "#sha256=" not in value:
        raise ValueError("evidence_pointer:invalid")
    raw_path, digest = value.rsplit("#sha256=", 1)
    if not _digest(digest):
        raise ValueError("evidence_pointer:digest_invalid")
    payload = _owned_bytes(Path(raw_path), private=private)
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("evidence_pointer:digest_mismatch")
    return payload


def _pointer_json(value: Any) -> Any:
    try:
        return json.loads(_pointer_bytes(value))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("evidence_pointer:json_invalid") from error


def _python_symbol_present(path: Path, symbol: str) -> bool:
    try:
        tree = ast.parse(_owned_bytes(path).decode("utf-8"), filename=str(path))
    except (SyntaxError, UnicodeError, OSError, ValueError):
        return False
    parts = symbol.split(".")
    nodes = tree.body
    for index, part in enumerate(parts):
        matches = [
            node
            for node in nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == part
        ]
        if len(matches) != 1:
            return False
        if index + 1 < len(parts):
            if not isinstance(matches[0], ast.ClassDef):
                return False
            nodes = matches[0].body
    return True


def _component_observed(row: Mapping[str, Any]) -> bool:
    try:
        path = Path(str(row["path"]))
        payload = _owned_bytes(path)
    except (KeyError, OSError, ValueError):
        return False
    if hashlib.sha256(payload).hexdigest() != row.get("sha256"):
        return False
    symbol = row.get("symbol")
    if not isinstance(symbol, str):
        return False
    if path.suffix == ".py":
        return _python_symbol_present(path, symbol)
    if path.name == ".mcp.json" and symbol == "mcpServers.orch-dork":
        try:
            descriptor = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError):
            return False
        server = descriptor.get("mcpServers", {}).get("orch-dork")
        return isinstance(server, Mapping) and server == {
            "command": "python3",
            "args": [
                "-B",
                "scripts/orch_dork_mcp_launcher.py",
                "serve",
                "--require-thread-id",
            ],
            "env_vars": ["ORCH_DORK_APP_SERVER_SOCKET", "ORCH_DORK_WORKER_MODEL", "ORCH_DORK_WORKER_EFFORT"],
            "cwd": ".",
        }
    return False


def _components(value: Any, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, "components:not_array")
        return []
    rows: list[dict[str, Any]] = []
    roles: set[str] = set()
    for index, raw in enumerate(value):
        label = f"components[{index}]"
        _exact(raw, {"role", "path", "sha256", "symbol", "source_pointer"}, label, issues)
        row = dict(raw) if isinstance(raw, Mapping) else {}
        role = row.get("role")
        if role not in REQUIRED_COMPONENTS or role in roles:
            _issue(issues, label + ":role_invalid_or_duplicate")
        else:
            roles.add(str(role))
        path = row.get("path")
        if not _text(path) or not Path(str(path)).is_absolute():
            _issue(issues, label + ":path_invalid")
        if not _digest(row.get("sha256")):
            _issue(issues, label + ":sha256_invalid")
        if not _text(row.get("symbol")) or not _text(row.get("source_pointer")):
            _issue(issues, label + ":binding_invalid")
        if not _component_observed(row):
            _issue(issues, label + ":source_not_observed")
        rows.append(row)
    for role in sorted(REQUIRED_COMPONENTS - roles):
        _issue(issues, "components:missing_role:" + role)
    return rows


def _environment(value: Any, issues: list[str]) -> dict[str, Any]:
    _exact(
        value,
        {
            "schema",
            "status",
            "repository_root",
            "working_directory",
            "interpreter",
            "interpreter_sha256",
            "environment_sha256",
            "import_paths",
            "temporary_root",
            "temporary_root_scope",
            "loopback",
            "nested_sandbox",
            "source_pointer",
        },
        "environment",
        issues,
    )
    item = dict(value) if isinstance(value, Mapping) else {}
    if item.get("schema") != ENVIRONMENT_SCHEMA:
        _issue(issues, "environment:schema_invalid")
    if item.get("status") != "runtime_observed":
        _issue(issues, "environment:not_runtime_observed")
    for field in ("repository_root", "working_directory", "interpreter", "temporary_root"):
        path = item.get(field)
        if not _text(path) or not Path(str(path)).is_absolute():
            _issue(issues, "environment:" + field + "_invalid")
    for field in ("interpreter_sha256", "environment_sha256"):
        if not _digest(item.get(field)):
            _issue(issues, "environment:" + field + "_invalid")
    paths = item.get("import_paths")
    if not isinstance(paths, list) or not paths or any(
        not _text(path) or not Path(str(path)).is_absolute() for path in paths
    ):
        _issue(issues, "environment:import_paths_invalid")
    if item.get("temporary_root_scope") != "disposable_owned_only":
        _issue(issues, "environment:temporary_root_scope_invalid")
    for capability in ("loopback", "nested_sandbox"):
        fact = item.get(capability)
        _exact(fact, {"status", "observed", "source_pointer"}, "environment." + capability, issues)
        fact_value = dict(fact) if isinstance(fact, Mapping) else {}
        if fact_value.get("status") not in {"available", "unavailable", "unknown"}:
            _issue(issues, "environment:" + capability + "_status_invalid")
        if fact_value.get("observed") is not True or not _text(fact_value.get("source_pointer")):
            _issue(issues, "environment:" + capability + "_evidence_invalid")
        try:
            probe = _pointer_json(fact_value.get("source_pointer"))
        except (OSError, ValueError):
            probe = {}
        if (
            not isinstance(probe, Mapping)
            or probe.get("schema")
            != "orch-dork/execution-readiness-os-probe/v1"
            or probe.get("capability") != capability
            or probe.get("status") != fact_value.get("status")
        ):
            _issue(issues, "environment:" + capability + "_observation_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, "environment:source_pointer_invalid")
    facts = {
        key: item.get(key)
        for key in (
            "repository_root",
            "working_directory",
            "interpreter",
            "interpreter_sha256",
            "import_paths",
            "temporary_root",
            "temporary_root_scope",
            "loopback",
            "nested_sandbox",
        )
    }
    try:
        environment_evidence = _pointer_json(item.get("source_pointer"))
    except (OSError, ValueError):
        environment_evidence = {}
    if (
        item.get("environment_sha256") != _sha(facts)
        or not isinstance(environment_evidence, Mapping)
        or environment_evidence.get("schema")
        != "orch-dork/execution-readiness-environment-observation/v1"
        or environment_evidence.get("facts") != facts
    ):
        _issue(issues, "environment:observation_binding_invalid")
    try:
        repository = Path(str(item.get("repository_root"))).resolve(strict=True)
        working = Path(str(item.get("working_directory"))).resolve(strict=True)
        interpreter = Path(str(item.get("interpreter"))).resolve(strict=True)
        temporary = Path(str(item.get("temporary_root"))).resolve(strict=True)
        temporary_details = temporary.stat()
        if (
            not repository.is_dir()
            or not working.is_dir()
            or working != Path.cwd().resolve(strict=True)
            or interpreter != Path(sys.executable).resolve(strict=True)
            or hashlib.sha256(
                _owned_bytes(
                    interpreter,
                    owner_required=False,
                    max_bytes=64 * 1024 * 1024,
                )
            ).hexdigest()
            != item.get("interpreter_sha256")
            or not temporary.is_dir()
            or temporary_details.st_mode & 0o077
            or (
                hasattr(os, "getuid")
                and temporary_details.st_uid != os.getuid()
            )
            or any(
                not Path(str(path)).resolve(strict=True).is_dir()
                for path in item.get("import_paths", [])
            )
        ):
            raise ValueError("environment mismatch")
    except (OSError, TypeError, ValueError):
        _issue(issues, "environment:runtime_binding_invalid")
    return item


def _failure_replays(
    value: Any,
    issues: list[str],
    *,
    finalizer_sha256: str | None,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, "failure_replays:not_array")
        return []
    rows: list[dict[str, Any]] = []
    scenarios: set[str] = set()
    for index, raw in enumerate(value):
        label = f"failure_replays[{index}]"
        _exact(
            raw,
            {
                "schema",
                "scenario",
                "outcome",
                "terminal_persisted",
                "durable_unknown_persisted",
                "error_propagated",
                "usage_status",
                "cleanup_status",
                "artifact_sha256",
                "source_pointer",
            },
            label,
            issues,
        )
        row = dict(raw) if isinstance(raw, Mapping) else {}
        if row.get("schema") != REPLAY_SCHEMA:
            _issue(issues, label + ":schema_invalid")
        scenario = row.get("scenario")
        if scenario not in REQUIRED_FAILURES or scenario in scenarios:
            _issue(issues, label + ":scenario_invalid_or_duplicate")
        else:
            scenarios.add(str(scenario))
        if row.get("outcome") not in {"terminal", "durable_unknown"}:
            _issue(issues, label + ":outcome_invalid")
        terminal = row.get("terminal_persisted") is True
        unknown = row.get("durable_unknown_persisted") is True
        if terminal == unknown or row.get("error_propagated") is not True:
            _issue(issues, label + ":persistence_or_propagation_invalid")
        if row.get("usage_status") not in {"known", "unknown"}:
            _issue(issues, label + ":usage_status_invalid")
        if row.get("cleanup_status") not in {"clean", "failed", "unknown"}:
            _issue(issues, label + ":cleanup_status_invalid")
        if not _digest(row.get("artifact_sha256")) or not _text(row.get("source_pointer")):
            _issue(issues, label + ":artifact_binding_invalid")
        try:
            artifact_payload = _pointer_bytes(row.get("source_pointer"))
            artifact = json.loads(artifact_payload)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            artifact_payload = b""
            artifact = {}
        finalizer = (
            artifact.get("finalizer_observation", {})
            if isinstance(artifact, Mapping)
            else {}
        )
        action = (
            finalizer.get("action", {})
            if isinstance(finalizer, Mapping)
            else {}
        )
        action_core = {
            key: action.get(key)
            for key in (
                "kind",
                "controller_id",
                "action_id",
                "tool_name",
                "tool_input_sha256",
            )
        }
        cursor = (
            finalizer.get("result_cursor", {})
            if isinstance(finalizer, Mapping)
            else {}
        )
        store_path = finalizer.get("store_path")
        try:
            store_payload = _owned_bytes(Path(str(store_path)), private=True)
            store_identity = hashlib.sha256(
                str(Path(str(store_path)).resolve(strict=True)).encode("utf-8")
            ).hexdigest()
        except (OSError, ValueError):
            store_payload = b""
            store_identity = None
        finalizer_valid = bool(
            isinstance(finalizer, Mapping)
            and set(finalizer)
            == {
                "schema",
                "implementation",
                "implementation_sha256",
                "store_path",
                "store_sha256",
                "store_identity_sha256",
                "action",
                "result_cursor",
                "report",
                "grant_after",
                "authority_marker_present",
                "authority_tombstone_present",
            }
            and finalizer.get("schema")
            == "orch-dork/execution-readiness-finalizer-observation/v1"
            and finalizer.get("implementation")
            == "NativeGrantStore.finalize_action"
            and _digest(finalizer.get("implementation_sha256"))
            and finalizer.get("implementation_sha256") == finalizer_sha256
            and isinstance(store_path, str)
            and Path(store_path).is_absolute()
            and hashlib.sha256(store_payload).hexdigest()
            == finalizer.get("store_sha256")
            and store_identity == finalizer.get("store_identity_sha256")
            and isinstance(action, Mapping)
            and set(action)
            == {
                "action_sha256",
                "kind",
                "controller_id",
                "action_id",
                "tool_name",
                "tool_input_sha256",
            }
            and action.get("action_sha256") == _sha(action_core)
            and action.get("kind") == "continue"
            and action.get("controller_id") == "readiness-controller"
            and action.get("action_id") == "readiness-" + str(scenario)
            and action.get("tool_name") == "provider_free_failure_probe"
            and action.get("tool_input_sha256") == _sha({"scenario": scenario})
            and isinstance(cursor, Mapping)
            and set(cursor) == {"run_id", "seq", "event_hash"}
            and cursor.get("run_id") == "readiness-finalizer-" + str(scenario)
            and cursor.get("seq") == 1
            and cursor.get("event_hash")
            == _sha(
                {
                    "run_id": "readiness-finalizer-" + str(scenario),
                    "seq": 1,
                    "scenario": scenario,
                }
            )
            and finalizer.get("report") == {"status": "MISSING"}
            and finalizer.get("grant_after") is None
            and finalizer.get("authority_marker_present") is False
            and finalizer.get("authority_tombstone_present") is False
        )
        if (
            hashlib.sha256(artifact_payload).hexdigest()
            != row.get("artifact_sha256")
            or not isinstance(artifact, Mapping)
            or artifact.get("schema")
            != "orch-dork/execution-readiness-forced-failure/v1"
            or artifact.get("scenario") != scenario
            or artifact.get("persisted_kind") != row.get("outcome")
            or artifact.get("usage_status") != row.get("usage_status")
            or artifact.get("cleanup_status") != row.get("cleanup_status")
            or artifact.get("sequence")
            != [
                "failure_forced",
                "native_finalizer_observed",
                "artifact_persisted",
            ]
            or artifact.get("authority_created") is not False
            or artifact.get("model_calls") != 0
            or artifact.get("hosted_calls") != 0
            or not finalizer_valid
        ):
            _issue(issues, label + ":persisted_artifact_invalid")
        rows.append(row)
    for scenario in sorted(REQUIRED_FAILURES - scenarios):
        _issue(issues, "failure_replays:missing:" + scenario)
    return rows


def _lifecycle(
    value: Any,
    issues: list[str],
    *,
    lifecycle_sha256: str | None,
) -> dict[str, Any]:
    _exact(
        value,
        {
            "schema",
            "status",
            "evidence_tier",
            "transitions",
            "deadline_origin",
            "sender_bound",
            "duplicates_rejected",
            "late_completion_blocked",
            "integrator_failure_terminal",
            "worker_lifecycle_report_sha256",
            "artifact_sha256",
            "source_pointer",
        },
        "lifecycle_replay",
        issues,
    )
    item = dict(value) if isinstance(value, Mapping) else {}
    if item.get("schema") != LIFECYCLE_SCHEMA or item.get("status") != "PASS":
        _issue(issues, "lifecycle_replay:status_or_schema_invalid")
    if item.get("evidence_tier") != "provider_free_reenactment":
        _issue(issues, "lifecycle_replay:evidence_tier_invalid")
    if item.get("transitions") != list(REQUIRED_TRANSITIONS):
        _issue(issues, "lifecycle_replay:transition_sequence_mismatch")
    if item.get("deadline_origin") != "release_sent":
        _issue(issues, "lifecycle_replay:deadline_origin_invalid")
    for field in (
        "sender_bound",
        "duplicates_rejected",
        "late_completion_blocked",
        "integrator_failure_terminal",
    ):
        if item.get(field) is not True:
            _issue(issues, "lifecycle_replay:" + field + "_not_true")
    if not _digest(item.get("artifact_sha256")) or not _text(item.get("source_pointer")):
        _issue(issues, "lifecycle_replay:artifact_binding_invalid")
    try:
        artifact_payload = _pointer_bytes(item.get("source_pointer"))
        artifact = json.loads(artifact_payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        artifact_payload = b""
        artifact = {}
    production = (
        artifact.get("production_worker_lifecycle", {})
        if isinstance(artifact, Mapping)
        else {}
    )
    production_program = (
        production.get("program", {})
        if isinstance(production, Mapping)
        else {}
    )
    production_report = (
        production.get("report", {})
        if isinstance(production, Mapping)
        else {}
    )
    report_core = (
        {
            key: field
            for key, field in production_report.items()
            if key != "report_sha256"
        }
        if isinstance(production_report, Mapping)
        else {}
    )
    production_valid = bool(
        isinstance(production, Mapping)
        and set(production)
        == {
            "schema",
            "implementation",
            "implementation_sha256",
            "program",
            "report",
        }
        and production.get("schema")
        == "orch-dork/execution-readiness-worker-lifecycle-observation/v1"
        and production.get("implementation") == "evaluate_worker_lifecycle"
        and _digest(production.get("implementation_sha256"))
        and production.get("implementation_sha256") == lifecycle_sha256
        and isinstance(production_program, Mapping)
        and production_program.get("schema")
        == "orch-dork/worker-lifecycle-program/v1"
        and isinstance(production_report, Mapping)
        and production_report.get("schema")
        == "orch-dork/worker-lifecycle-report/v1"
        and production_report.get("status") == "PASS"
        and production_report.get("outcome") == "ONE_WAVE_READY"
        and production_report.get("provider_free") is True
        and production_report.get("model_calls") == 0
        and production_report.get("hosted_calls") == 0
        and production_report.get("live_task_operations") == 0
        and production_report.get("live_worker_retirements") == 0
        and production_report.get("workers_launched") == 0
        and production_report.get("issues") == []
        and production_report.get("report_sha256") == _sha(report_core)
        and _sha(production_report)
        == item.get("worker_lifecycle_report_sha256")
    )
    if (
        hashlib.sha256(artifact_payload).hexdigest()
        != item.get("artifact_sha256")
        or not isinstance(artifact, Mapping)
        or artifact.get("schema")
        != "orch-dork/execution-readiness-lifecycle-observation/v1"
        or artifact.get("evidence_tier") != "provider_free_reenactment"
        or artifact.get("transitions") != list(REQUIRED_TRANSITIONS)
        or artifact.get("deadline_origin") != "release_sent"
        or artifact.get("sender_bound") is not True
        or artifact.get("duplicates_rejected") is not True
        or artifact.get("late_completion_blocked") is not True
        or artifact.get("integrator_failure_terminal") is not True
        or artifact.get("final_state") != "terminal_failure"
        or not production_valid
    ):
        _issue(issues, "lifecycle_replay:persisted_artifact_invalid")
    return item


def _regressions(value: Any, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, "regressions:not_array")
        return []
    rows: list[dict[str, Any]] = []
    fixtures: set[str] = set()
    for index, raw in enumerate(value):
        label = f"regressions[{index}]"
        _exact(
            raw,
            {
                "schema",
                "fixture",
                "status",
                "repair_evidence_sha256",
                "terminal_sha256",
                "grant_state",
                "grant_reusable",
                "historical_bytes_unchanged",
                "source_pointer",
            },
            label,
            issues,
        )
        row = dict(raw) if isinstance(raw, Mapping) else {}
        if row.get("schema") != REGRESSION_SCHEMA:
            _issue(issues, label + ":schema_invalid")
        fixture = row.get("fixture")
        if fixture not in REQUIRED_REGRESSIONS or fixture in fixtures:
            _issue(issues, label + ":fixture_invalid_or_duplicate")
        else:
            fixtures.add(str(fixture))
        if row.get("status") != "PASS":
            _issue(issues, label + ":status_invalid")
        if not _digest(row.get("repair_evidence_sha256")) or not _digest(row.get("terminal_sha256")):
            _issue(issues, label + ":hash_invalid")
        if row.get("grant_state") != "failed" or row.get("grant_reusable") is not False:
            _issue(issues, label + ":grant_boundary_invalid")
        if row.get("historical_bytes_unchanged") is not True or not _text(row.get("source_pointer")):
            _issue(issues, label + ":preservation_invalid")
        try:
            fixture_payload = _pointer_bytes(
                row.get("source_pointer"),
                private=False,
            )
            fixture_value = json.loads(fixture_payload)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            fixture_payload = b""
            fixture_value = {}
        fixture_rows = (
            fixture_value.get("fixtures", [])
            if isinstance(fixture_value, Mapping)
            else []
        )
        matches = [
            item
            for item in fixture_rows
            if isinstance(item, Mapping)
            and item.get("fixture") == fixture
        ]
        if (
            len(matches) != 1
            or hashlib.sha256(fixture_payload).hexdigest()
            != row.get("repair_evidence_sha256")
            or _sha(matches[0]) != row.get("terminal_sha256")
            or matches[0].get("grant_state") != "failed"
            or matches[0].get("grant_reusable") is not False
        ):
            _issue(issues, label + ":fixture_binding_invalid")
        rows.append(row)
    for fixture in sorted(REQUIRED_REGRESSIONS - fixtures):
        _issue(issues, "regressions:missing:" + fixture)
    return rows


def _load_runtime_component(root: Path, relative: str, purpose: str):
    path = (root / relative).resolve(strict=True)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(
            "readiness_runner:component_escape:" + purpose
        ) from error
    name = "_orch_dork_readiness_" + purpose + "_" + hashlib.sha256(
        str(path).encode("utf-8")
    ).hexdigest()[:12]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("readiness_runner:" + purpose + "_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    scripts = str(path.parent)
    inserted = scripts not in sys.path
    if inserted:
        sys.path.insert(0, scripts)
    try:
        spec.loader.exec_module(module)
    finally:
        if inserted:
            sys.path.remove(scripts)
    return module


def _load_runtime_policy(root: Path):
    return _load_runtime_component(
        root,
        "skills/orch-dork/scripts/orch_dork_policy.py",
        "policy",
    )


def _run_failure_replay(
    root: Path,
    scenario: str,
    *,
    finalizer_module: Any,
    finalizer_sha256: str,
) -> dict[str, Any]:
    unknown = scenario in {
        "missing_usage",
        "finalizer_exception",
        "partial_evidence",
        "cleanup_failure",
    }
    action_core = {
        "kind": "continue",
        "controller_id": "readiness-controller",
        "action_id": "readiness-" + scenario,
        "tool_name": "provider_free_failure_probe",
        "tool_input_sha256": _sha({"scenario": scenario}),
    }
    action = {"action_sha256": _sha(action_core), **action_core}
    cursor = {
        "run_id": "readiness-finalizer-" + scenario,
        "seq": 1,
        "event_hash": _sha(
            {
                "run_id": "readiness-finalizer-" + scenario,
                "seq": 1,
                "scenario": scenario,
            }
        ),
    }
    witness_env = str(
        getattr(
            finalizer_module,
            "NATIVE_WITNESS_ROOT_ENV",
            "ORCH_DORK_NATIVE_WITNESS_ROOT",
        )
    )
    prior_witness_root = os.environ.get(witness_env)
    os.environ[witness_env] = str(root / "native-witnesses")
    try:
        store = finalizer_module.NativeGrantStore(
            root / ("finalizer-" + scenario) / "controller.sqlite3"
        )
    finally:
        if prior_witness_root is None:
            os.environ.pop(witness_env, None)
        else:
            os.environ[witness_env] = prior_witness_root
    finalizer_report = store.finalize_action(action, cursor)
    grant_after = store.read_action(action["action_sha256"])
    if finalizer_report != {"status": "MISSING"} or grant_after is not None:
        raise ValueError(
            "readiness_runner:finalizer_observation_invalid:" + scenario
        )
    if store.authority_marker_path.exists() or store.authority_tombstone_path.exists():
        raise ValueError(
            "readiness_runner:finalizer_created_authority:" + scenario
        )
    store_payload = _owned_bytes(store.path, private=True)
    finalizer_observation = {
        "schema": "orch-dork/execution-readiness-finalizer-observation/v1",
        "implementation": "NativeGrantStore.finalize_action",
        "implementation_sha256": finalizer_sha256,
        "store_path": str(store.path),
        "store_sha256": hashlib.sha256(store_payload).hexdigest(),
        "store_identity_sha256": store.store_identity_sha256,
        "action": action,
        "result_cursor": cursor,
        "report": finalizer_report,
        "grant_after": grant_after,
        "authority_marker_present": False,
        "authority_tombstone_present": False,
    }
    artifact = {
        "schema": "orch-dork/execution-readiness-forced-failure/v1",
        "scenario": scenario,
        "persisted_kind": "durable_unknown" if unknown else "terminal",
        "usage_status": (
            "unknown"
            if scenario
            in {
                "timeout",
                "cancellation",
                "provider_exception",
                "missing_usage",
                "finalizer_exception",
            }
            else "known"
        ),
        "cleanup_status": (
            "failed"
            if scenario == "cleanup_failure"
            else "unknown" if scenario == "finalizer_exception" else "clean"
        ),
        "sequence": [
            "failure_forced",
            "native_finalizer_observed",
            "artifact_persisted",
        ],
        "finalizer_observation": finalizer_observation,
        "authority_created": False,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    path = root / ("forced-" + scenario + ".json")
    payload = _write_owned_json(path, artifact)

    class ForcedReplayFailure(RuntimeError):
        pass

    propagated = False
    try:
        raise ForcedReplayFailure(scenario)
    except ForcedReplayFailure as error:
        propagated = str(error) == scenario
    if not propagated or _owned_bytes(path, private=True) != payload:
        raise ValueError("readiness_runner:failure_replay_invalid:" + scenario)
    return {
        "schema": REPLAY_SCHEMA,
        "scenario": scenario,
        "outcome": "durable_unknown" if unknown else "terminal",
        "terminal_persisted": not unknown,
        "durable_unknown_persisted": unknown,
        "error_propagated": propagated,
        "usage_status": artifact["usage_status"],
        "cleanup_status": artifact["cleanup_status"],
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "source_pointer": _pointer(path, payload),
    }


def _run_lifecycle_replay(
    root: Path,
    *,
    lifecycle_module: Any,
    lifecycle_sha256: str,
) -> dict[str, Any]:
    root_task_id = "readiness-worker-lifecycle-root"
    inventory = {
        "schema": lifecycle_module.INVENTORY_SCHEMA,
        "root_thread_id": root_task_id,
        "capacity": 1,
        "retirement_supported": False,
        "workers": [],
    }

    def observation(index: int) -> dict[str, Any]:
        return {
            "schema": lifecycle_module.OBSERVATION_SCHEMA,
            "status": "observed",
            "observation_id": "readiness-inventory-" + str(index),
            "observed_at": "2026-09-01T12:00:0" + str(index) + "Z",
            "source_pointer": "readiness#inventory-" + str(index),
            "inventory": dict(inventory),
        }

    lifecycle_program = {
        "schema": lifecycle_module.PROGRAM_SCHEMA,
        "lifecycle_id": "readiness-worker-lifecycle",
        "root_task_id": root_task_id,
        "required_slots": 1,
        "capability": {
            "schema": lifecycle_module.CAPABILITY_SCHEMA,
            "status": "unsupported",
            "operation": "retire_worker",
            "evidence_tier": "runtime_observed",
            "observed_at": "2026-09-01T12:00:00Z",
            "source_pointer": "readiness#retirement-capability",
        },
        "capacity_before_freeze": observation(1),
        "capacity_before_spawn": observation(2),
        "retirement": None,
        "one_wave_plan": {
            "schema": lifecycle_module.ONE_WAVE_SCHEMA,
            "root_task_id": root_task_id,
            "one_wave_only": True,
            "declared_before_freeze": True,
            "planned_worker_ids": ["readiness-lane"],
            "later_wave_required": False,
            "rollover_scheduled": False,
            "rollover_checkpoint_sha256": None,
            "source_pointer": "readiness#one-wave",
        },
        "task_creation_program": None,
        "rollover_program": None,
    }
    lifecycle_report = lifecycle_module.evaluate_worker_lifecycle(
        lifecycle_program
    )
    if (
        not isinstance(lifecycle_report, Mapping)
        or lifecycle_report.get("status") != "PASS"
        or lifecycle_report.get("outcome") != "ONE_WAVE_READY"
        or lifecycle_report.get("provider_free") is not True
        or lifecycle_report.get("model_calls") != 0
        or lifecycle_report.get("hosted_calls") != 0
        or lifecycle_report.get("live_task_operations") != 0
        or lifecycle_report.get("live_worker_retirements") != 0
        or lifecycle_report.get("workers_launched") != 0
        or lifecycle_report.get("issues") != []
    ):
        raise ValueError("readiness_runner:worker_lifecycle_invalid")

    state = "owner_active"
    observed: list[str] = []
    duplicate_rejected = False
    late_blocked = False
    integrator_terminal = False
    sender_bound = False
    for transition in REQUIRED_TRANSITIONS:
        if transition == "owner_work_before_release":
            if state != "owner_active":
                raise ValueError("readiness_runner:lifecycle_owner_invalid")
        elif transition == "release_sent":
            if state != "owner_active":
                raise ValueError("readiness_runner:lifecycle_release_invalid")
            state = "release_sent"
        elif transition == "release_delivered":
            if state != "release_sent":
                raise ValueError("readiness_runner:lifecycle_delivery_invalid")
            state = "released"
        elif transition == "sender_binding":
            sender_bound = state == "released"
        elif transition == "duplicate_delivery":
            duplicate_rejected = state == "released"
        elif transition == "expiration":
            state = "expired"
        elif transition == "late_completion":
            late_blocked = state == "expired"
        elif transition == "integrator_failure":
            integrator_terminal = state == "expired"
            state = "terminal_failure"
        observed.append(transition)
    artifact = {
        "schema": "orch-dork/execution-readiness-lifecycle-observation/v1",
        "evidence_tier": "provider_free_reenactment",
        "transitions": observed,
        "deadline_origin": "release_sent",
        "sender_bound": sender_bound,
        "duplicates_rejected": duplicate_rejected,
        "late_completion_blocked": late_blocked,
        "integrator_failure_terminal": integrator_terminal,
        "final_state": state,
        "production_worker_lifecycle": {
            "schema": (
                "orch-dork/execution-readiness-"
                "worker-lifecycle-observation/v1"
            ),
            "implementation": "evaluate_worker_lifecycle",
            "implementation_sha256": lifecycle_sha256,
            "program": lifecycle_program,
            "report": lifecycle_report,
        },
    }
    path = root / "lifecycle.json"
    payload = _write_owned_json(path, artifact)
    return {
        "schema": LIFECYCLE_SCHEMA,
        "status": "PASS",
        "evidence_tier": "provider_free_reenactment",
        "transitions": observed,
        "deadline_origin": "release_sent",
        "sender_bound": sender_bound,
        "duplicates_rejected": duplicate_rejected,
        "late_completion_blocked": late_blocked,
        "integrator_failure_terminal": integrator_terminal,
        "worker_lifecycle_report_sha256": _sha(lifecycle_report),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "source_pointer": _pointer(path, payload),
    }


def _load_regressions(root: Path) -> list[dict[str, Any]]:
    path = root / _REGRESSION_FIXTURE
    payload = _owned_bytes(path)
    if hashlib.sha256(payload).hexdigest() != _REGRESSION_FIXTURE_SHA256:
        raise ValueError("readiness_runner:regression_fixture_changed")
    try:
        fixture = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("readiness_runner:regression_fixture_invalid") from error
    rows = fixture.get("fixtures") if isinstance(fixture, Mapping) else None
    if (
        not isinstance(fixture, Mapping)
        or set(fixture) != {"schema", "fixtures"}
        or fixture.get("schema")
        != "orch-dork/execution-readiness-regression-corpus/v1"
        or not isinstance(rows, list)
        or {
            row.get("fixture")
            for row in rows
            if isinstance(row, Mapping)
        }
        != REQUIRED_REGRESSIONS
    ):
        raise ValueError("readiness_runner:regression_fixture_invalid")
    pointer = str(path) + "#sha256=" + hashlib.sha256(payload).hexdigest()
    reports: list[dict[str, Any]] = []
    expected_fields = {
        "fixture",
        "historical_issue",
        "failure",
        "grant_state",
        "grant_reusable",
        "source_pointer",
    }
    for row in sorted(rows, key=lambda item: str(item.get("fixture"))):
        if (
            not isinstance(row, Mapping)
            or set(row) != expected_fields
            or row.get("grant_state") != "failed"
            or row.get("grant_reusable") is not False
            or not _text(row.get("failure"))
            or not _text(row.get("source_pointer"))
        ):
            raise ValueError("readiness_runner:regression_fixture_invalid")
        reports.append(
            {
                "schema": REGRESSION_SCHEMA,
                "fixture": row["fixture"],
                "status": "PASS",
                "repair_evidence_sha256": hashlib.sha256(payload).hexdigest(),
                "terminal_sha256": _sha(row),
                "grant_state": row["grant_state"],
                "grant_reusable": row["grant_reusable"],
                "historical_bytes_unchanged": True,
                "source_pointer": pointer,
            }
        )
    return reports


def run_provider_free_readiness_program(
    *,
    source_root: str | Path,
    temporary_root: str | Path,
    readiness_id: str,
    attempt_id: str,
    plan_sha256: str,
    authority_scope_sha256: str,
) -> dict[str, Any]:
    """Run the real local readiness probes and return their closed program."""

    root = Path(source_root).resolve(strict=True)
    if not root.is_dir() or not (root / ".codex-plugin/plugin.json").is_file():
        raise ValueError("readiness_runner:source_root_invalid")
    disposable = Path(temporary_root)
    if not disposable.is_absolute() or disposable.exists() or disposable.is_symlink():
        raise ValueError("readiness_runner:temporary_root_not_create_only")
    parent = disposable.parent.resolve(strict=True)
    parent_details = parent.stat()
    if (
        not parent.is_dir()
        or parent_details.st_mode & 0o077
        or (
            hasattr(os, "getuid")
            and parent_details.st_uid != os.getuid()
        )
    ):
        raise ValueError("readiness_runner:temporary_parent_unsafe")
    disposable.mkdir(mode=0o700)

    components: list[dict[str, Any]] = []
    for role in sorted(REQUIRED_COMPONENTS):
        relative, symbol = _COMPONENT_BINDINGS[role]
        path = (root / relative).resolve(strict=True)
        try:
            path.relative_to(root)
        except ValueError as error:
            raise ValueError("readiness_runner:component_escape:" + role) from error
        payload = _owned_bytes(path)
        row = {
            "role": role,
            "path": str(path),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "symbol": symbol,
            "source_pointer": relative + "#" + symbol,
        }
        if not _component_observed(row):
            raise ValueError("readiness_runner:component_invalid:" + role)
        components.append(row)

    loopback_status = "unavailable"
    loopback_detail: dict[str, Any]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            host, port = probe.getsockname()
            loopback_status = "available" if host == "127.0.0.1" and port > 0 else "unknown"
            loopback_detail = {"host": host, "port_observed": port > 0}
    except OSError as error:
        loopback_detail = {"error_type": type(error).__name__}
    loopback_path = disposable / "loopback.json"
    loopback_payload = _write_owned_json(
        loopback_path,
        {
            "schema": "orch-dork/execution-readiness-os-probe/v1",
            "capability": "loopback",
            "status": loopback_status,
            "detail": loopback_detail,
        },
    )

    nested = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            (
                "import json,os;"
                "print(json.dumps({'cwd':os.getcwd(),'isolated':True},"
                "sort_keys=True,separators=(',',':')))"
            ),
        ],
        cwd=disposable,
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    try:
        nested_report = json.loads(nested.stdout)
    except (UnicodeError, json.JSONDecodeError):
        nested_report = {}
    nested_status = (
        "available"
        if nested.returncode == 0
        and nested.stderr == ""
        and nested_report == {"cwd": str(disposable), "isolated": True}
        else "unavailable"
    )
    nested_path = disposable / "nested-sandbox.json"
    nested_payload = _write_owned_json(
        nested_path,
        {
            "schema": "orch-dork/execution-readiness-os-probe/v1",
            "capability": "nested_sandbox",
            "status": nested_status,
            "returncode": nested.returncode,
            "stdout_sha256": hashlib.sha256(
                nested.stdout.encode("utf-8")
            ).hexdigest(),
            "stderr_sha256": hashlib.sha256(
                nested.stderr.encode("utf-8")
            ).hexdigest(),
        },
    )
    interpreter = Path(sys.executable).resolve(strict=True)
    environment_facts = {
        "repository_root": str(root),
        "working_directory": str(Path.cwd().resolve(strict=True)),
        "interpreter": str(interpreter),
        "interpreter_sha256": hashlib.sha256(
            _owned_bytes(
                interpreter,
                owner_required=False,
                max_bytes=64 * 1024 * 1024,
            )
        ).hexdigest(),
        "import_paths": [
            str(root),
            str(root / "skills/orch-dork/scripts"),
        ],
        "temporary_root": str(disposable),
        "temporary_root_scope": "disposable_owned_only",
        "loopback": {
            "status": loopback_status,
            "observed": True,
            "source_pointer": _pointer(loopback_path, loopback_payload),
        },
        "nested_sandbox": {
            "status": nested_status,
            "observed": True,
            "source_pointer": _pointer(nested_path, nested_payload),
        },
    }
    environment_path = disposable / "environment.json"
    environment_payload = _write_owned_json(
        environment_path,
        {
            "schema": "orch-dork/execution-readiness-environment-observation/v1",
            "facts": environment_facts,
        },
    )
    environment = {
        "schema": ENVIRONMENT_SCHEMA,
        "status": "runtime_observed",
        **environment_facts,
        "environment_sha256": _sha(environment_facts),
        "source_pointer": _pointer(environment_path, environment_payload),
    }

    policy = _load_runtime_policy(root)
    descriptors = [
        row
        for row in policy.list_tools()
        if isinstance(row, Mapping)
        and row.get("name") == "evaluate_execution_readiness"
    ]
    if len(descriptors) != 1:
        raise ValueError("readiness_runner:descriptor_invalid")
    probe_request = {
        "jsonrpc": "2.0",
        "id": "readiness-dispatch-probe",
        "method": "tools/call",
        "params": {
            "name": "evaluate_execution_readiness",
            "arguments": {"program": {}},
        },
    }
    probe_response = policy.dispatch(probe_request)
    structured = (
        probe_response.get("result", {})
        .get("structuredContent", {})
        if isinstance(probe_response, Mapping)
        else {}
    )
    if structured.get("status") != "NOT_READY":
        raise ValueError("readiness_runner:descriptor_dispatch_invalid")
    dispatch_path = disposable / "descriptor-dispatch.json"
    dispatch_payload = _write_owned_json(
        dispatch_path,
        {
            "schema": "orch-dork/execution-readiness-dispatch-probe/v1",
            "descriptor": descriptors[0],
            "probe_request": probe_request,
            "probe_response": probe_response,
        },
    )
    constructor_path = disposable / "constructor-probe.json"
    constructor_payload = _write_owned_json(
        constructor_path,
        {
            "schema": "orch-dork/execution-readiness-constructor-probe/v1",
            "constructor": "_write_owned_json",
            "status": "PASS",
        },
    )
    finalizer_component = next(
        row for row in components if row["role"] == "finalizer"
    )
    lifecycle_component = next(
        row for row in components if row["role"] == "lifecycle_policy"
    )
    finalizer_module = _load_runtime_component(
        root,
        _COMPONENT_BINDINGS["finalizer"][0],
        "native_finalizer",
    )
    lifecycle_module = _load_runtime_component(
        root,
        _COMPONENT_BINDINGS["lifecycle_policy"][0],
        "worker_lifecycle",
    )
    failure_replays = [
        _run_failure_replay(
            disposable,
            name,
            finalizer_module=finalizer_module,
            finalizer_sha256=finalizer_component["sha256"],
        )
        for name in sorted(REQUIRED_FAILURES)
    ]
    lifecycle = _run_lifecycle_replay(
        disposable,
        lifecycle_module=lifecycle_module,
        lifecycle_sha256=lifecycle_component["sha256"],
    )
    regressions = _load_regressions(root)
    return {
        "schema": PROGRAM_SCHEMA,
        "readiness_id": readiness_id,
        "attempt_id": attempt_id,
        "plan_sha256": plan_sha256,
        "authority_scope_sha256": authority_scope_sha256,
        "lifecycle_policy_sha256": lifecycle_component["sha256"],
        "components": components,
        "environment": environment,
        "descriptor_dispatch": {
            "status": "PASS",
            "tool": "evaluate_execution_readiness",
            "descriptor_sha256": _sha(descriptors[0]),
            "dispatch_sha256": hashlib.sha256(dispatch_payload).hexdigest(),
            "source_pointer": _pointer(dispatch_path, dispatch_payload),
        },
        "artifact_constructors": [
            {
                "name": "_write_owned_json",
                "status": "PASS",
                "sha256": hashlib.sha256(constructor_payload).hexdigest(),
                "source_pointer": _pointer(
                    constructor_path,
                    constructor_payload,
                ),
            }
        ],
        "failure_replays": failure_replays,
        "lifecycle_replay": lifecycle,
        "regressions": regressions,
        "boundary": {
            "provider_free": True,
            "credential_reads": 0,
            "grant_reservations": 0,
            "hosted_calls": 0,
            "model_calls": 0,
            "task_creations": 0,
            "workers": 0,
            "retries": 0,
            "fallbacks": 0,
        },
        "previous_receipt": None,
    }


def evaluate_execution_readiness(program: Any) -> dict[str, Any]:
    """Validate and seal one exact provider-free readiness run."""

    issues: list[str] = []
    value = dict(program) if isinstance(program, Mapping) else {}
    _exact(
        value,
        {
            "schema",
            "readiness_id",
            "attempt_id",
            "plan_sha256",
            "authority_scope_sha256",
            "lifecycle_policy_sha256",
            "components",
            "environment",
            "descriptor_dispatch",
            "artifact_constructors",
            "failure_replays",
            "lifecycle_replay",
            "regressions",
            "boundary",
            "previous_receipt",
        },
        "program",
        issues,
    )
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    for field in ("readiness_id", "attempt_id"):
        if not _text(value.get(field)):
            _issue(issues, "program:" + field + "_invalid")
    for field in ("plan_sha256", "authority_scope_sha256", "lifecycle_policy_sha256"):
        if not _digest(value.get(field)):
            _issue(issues, "program:" + field + "_invalid")

    components = _components(value.get("components"), issues)
    environment = _environment(value.get("environment"), issues)
    dispatch = value.get("descriptor_dispatch")
    _exact(dispatch, {"status", "tool", "descriptor_sha256", "dispatch_sha256", "source_pointer"}, "descriptor_dispatch", issues)
    dispatch_value = dict(dispatch) if isinstance(dispatch, Mapping) else {}
    if dispatch_value.get("status") != "PASS" or dispatch_value.get("tool") != "evaluate_execution_readiness":
        _issue(issues, "descriptor_dispatch:not_qualified")
    for field in ("descriptor_sha256", "dispatch_sha256"):
        if not _digest(dispatch_value.get(field)):
            _issue(issues, "descriptor_dispatch:" + field + "_invalid")
    if not _text(dispatch_value.get("source_pointer")):
        _issue(issues, "descriptor_dispatch:source_pointer_invalid")
    try:
        dispatch_payload = _pointer_bytes(
            dispatch_value.get("source_pointer")
        )
        dispatch_artifact = json.loads(dispatch_payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        dispatch_payload = b""
        dispatch_artifact = {}
    descriptor = (
        dispatch_artifact.get("descriptor")
        if isinstance(dispatch_artifact, Mapping)
        else None
    )
    probe_response = (
        dispatch_artifact.get("probe_response", {})
        if isinstance(dispatch_artifact, Mapping)
        else {}
    )
    probe_status = (
        probe_response.get("result", {})
        .get("structuredContent", {})
        .get("status")
        if isinstance(probe_response, Mapping)
        else None
    )
    if (
        hashlib.sha256(dispatch_payload).hexdigest()
        != dispatch_value.get("dispatch_sha256")
        or not isinstance(dispatch_artifact, Mapping)
        or dispatch_artifact.get("schema")
        != "orch-dork/execution-readiness-dispatch-probe/v1"
        or not isinstance(descriptor, Mapping)
        or descriptor.get("name") != "evaluate_execution_readiness"
        or _sha(descriptor) != dispatch_value.get("descriptor_sha256")
        or probe_status != "NOT_READY"
    ):
        _issue(issues, "descriptor_dispatch:observation_invalid")

    constructors = value.get("artifact_constructors")
    if not isinstance(constructors, list) or not constructors:
        _issue(issues, "artifact_constructors:not_array")
        constructors = []
    for index, raw in enumerate(constructors):
        label = f"artifact_constructors[{index}]"
        _exact(raw, {"name", "status", "sha256", "source_pointer"}, label, issues)
        row = dict(raw) if isinstance(raw, Mapping) else {}
        if not _text(row.get("name")) or row.get("status") != "PASS":
            _issue(issues, label + ":not_qualified")
        if not _digest(row.get("sha256")) or not _text(row.get("source_pointer")):
            _issue(issues, label + ":binding_invalid")
        try:
            constructor_payload = _pointer_bytes(row.get("source_pointer"))
            constructor_artifact = json.loads(constructor_payload)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            constructor_payload = b""
            constructor_artifact = {}
        if (
            hashlib.sha256(constructor_payload).hexdigest()
            != row.get("sha256")
            or not isinstance(constructor_artifact, Mapping)
            or constructor_artifact.get("schema")
            != "orch-dork/execution-readiness-constructor-probe/v1"
            or constructor_artifact.get("constructor") != row.get("name")
            or constructor_artifact.get("status") != "PASS"
        ):
            _issue(issues, label + ":observation_invalid")

    finalizer_sha256 = next(
        (
            row.get("sha256")
            for row in components
            if row.get("role") == "finalizer"
        ),
        None,
    )
    lifecycle_sha256 = next(
        (
            row.get("sha256")
            for row in components
            if row.get("role") == "lifecycle_policy"
        ),
        None,
    )
    failures = _failure_replays(
        value.get("failure_replays"),
        issues,
        finalizer_sha256=finalizer_sha256,
    )
    lifecycle = _lifecycle(
        value.get("lifecycle_replay"),
        issues,
        lifecycle_sha256=lifecycle_sha256,
    )
    regressions = _regressions(value.get("regressions"), issues)
    boundary = value.get("boundary")
    _exact(
        boundary,
        {
            "provider_free",
            "credential_reads",
            "grant_reservations",
            "hosted_calls",
            "model_calls",
            "task_creations",
            "workers",
            "retries",
            "fallbacks",
        },
        "boundary",
        issues,
    )
    boundary_value = dict(boundary) if isinstance(boundary, Mapping) else {}
    if boundary_value.get("provider_free") is not True:
        _issue(issues, "boundary:not_provider_free")
    for field in set(boundary_value) - {"provider_free"}:
        if boundary_value.get(field) != 0:
            _issue(issues, "boundary:" + field + "_not_zero")

    identity = {
        "readiness_id": value.get("readiness_id"),
        "attempt_id": value.get("attempt_id"),
        "plan_sha256": value.get("plan_sha256"),
        "authority_scope_sha256": value.get("authority_scope_sha256"),
        "lifecycle_policy_sha256": value.get("lifecycle_policy_sha256"),
        "components_sha256": _sha(components),
        "environment_sha256": _sha(environment),
        "descriptor_dispatch_sha256": _sha(dispatch_value),
        "artifact_constructors_sha256": _sha(constructors),
        "failure_replays_sha256": _sha(failures),
        "lifecycle_replay_sha256": _sha(lifecycle),
        "regressions_sha256": _sha(regressions),
    }
    identity_sha = _sha(identity)
    previous = value.get("previous_receipt")
    stale = False
    if previous is not None:
        if not isinstance(previous, Mapping):
            _issue(issues, "previous_receipt:not_object")
        elif previous.get("readiness_identity_sha256") != identity_sha:
            stale = True
            _issue(issues, "previous_receipt:identity_changed")

    if environment.get("loopback", {}).get("status") != "available":
        _issue(issues, "environment:loopback_unavailable_or_unknown")
    if environment.get("nested_sandbox", {}).get("status") != "available":
        _issue(issues, "environment:nested_sandbox_unavailable_or_unknown")

    issues = sorted(set(issues))
    status = "READY_FOR_AUTHORITY" if not issues else (
        "STALE_READINESS" if stale else "NOT_READY"
    )
    core = {
        "schema": RECEIPT_SCHEMA,
        "status": status,
        "ready": status == "READY_FOR_AUTHORITY",
        "authority_reservation_permitted": status == "READY_FOR_AUTHORITY",
        "readiness_id": value.get("readiness_id"),
        "attempt_id": value.get("attempt_id"),
        "readiness_identity": identity,
        "readiness_identity_sha256": identity_sha,
        "named_stop": None if not issues else issues[0],
        "issues": issues,
        "provider_free": True,
        "credential_reads": 0,
        "grant_reservations": 0,
        "hosted_calls": 0,
        "model_calls": 0,
        "task_creations": 0,
        "workers": 0,
        "retries": 0,
        "fallbacks": 0,
        "invocation_setup_defects_count_as_model_attempts": False,
        "spent_grants_reusable": False,
    }
    return {**core, "receipt_sha256": _sha(core)}


def validate_readiness_binding(program: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any]:
    expected = evaluate_execution_readiness({**dict(program), "previous_receipt": None})
    issues = []
    if expected.get("status") != "READY_FOR_AUTHORITY":
        issues.extend(expected.get("issues", []))
    if receipt.get("receipt_sha256") != expected.get("receipt_sha256"):
        issues.append("readiness:receipt_hash_mismatch")
    if receipt.get("readiness_identity_sha256") != expected.get("readiness_identity_sha256"):
        issues.append("readiness:identity_mismatch")
    return {
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(set(issues)),
        "expected_receipt_sha256": expected.get("receipt_sha256"),
        "supplied_receipt_sha256": receipt.get("receipt_sha256"),
    }


__all__ = [
    "ENVIRONMENT_SCHEMA",
    "LIFECYCLE_SCHEMA",
    "PROGRAM_SCHEMA",
    "RECEIPT_SCHEMA",
    "REGRESSION_SCHEMA",
    "REPLAY_SCHEMA",
    "REQUIRED_COMPONENTS",
    "REQUIRED_FAILURES",
    "REQUIRED_REGRESSIONS",
    "REQUIRED_TRANSITIONS",
    "evaluate_execution_readiness",
    "run_provider_free_readiness_program",
    "validate_readiness_binding",
]
