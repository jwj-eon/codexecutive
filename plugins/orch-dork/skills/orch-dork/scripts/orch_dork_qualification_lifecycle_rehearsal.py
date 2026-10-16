#!/usr/bin/env python3
"""Rehearse a clean terminal predecessor handing off to a fresh task startup.

This provider-free driver reads the real persisted controller authority, builds
official hook inputs from that whole report, and invokes the runtime-projected
hook executable.  It stops before controller activation, network, model,
worker, or native-action boundaries.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
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

import orch_dork_native_grant_store as native_grant_store  # noqa: E402
import orch_dork_owned_file as owned_file  # noqa: E402


REPORT_SCHEMA = "orch-dork/terminal-successor-session-start-rehearsal/v1"
DECISION_READY = "READY_FOR_SUCCESSOR_ACTIVATION"
ACTIVATED_REPORT_SCHEMA = (
    "orch-dork/activated-successor-session-start-rehearsal/v1"
)
ACTIVATED_DECISION_READY = "READY_FOR_FIRST_TURN"
STARTUP_OBSERVATION_REPORT_SCHEMA = (
    "orch-dork/activated-successor-session-start-observation/v1"
)
STARTUP_OBSERVATION_DECISION_READY = "READY_FOR_CAPACITY_ADMISSION"
FIRST_ACTION_REHEARSAL_REPORT_SCHEMA = (
    "orch-dork/activated-successor-first-action-rehearsal/v2"
)
FIRST_ACTION_REHEARSAL_DECISION_READY = "READY_FOR_ONE_ATTEMPT"
FIRST_ACTION_MCP_BRIDGE_REPORT_SCHEMA = (
    "orch-dork/qualification-successor-first-action-mcp-bridge/v1"
)
ACTION_ADVANCE_MCP_BRIDGE_REPORT_SCHEMA = (
    "orch-dork/qualification-successor-action-advance-mcp-bridge/v1"
)
MAX_HOOK_OUTPUT_BYTES = 65_536
MAX_DURABLE_BYTES = 131_072
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_LIVE_COUNTERS = {
    "authority_grants": 0,
    "canary_calls": 0,
    "capacity_reservations": 0,
    "controller_activations": 0,
    "credential_reads": 0,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "network_calls": 0,
    "provider_calls": 0,
    "task_creations": 0,
    "workers": 0,
}
_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "predecessor",
        "successor",
        "transitions",
        "transition_output_sha256",
        "boundary",
        "provider_free",
        "live_counters",
        "report_sha256",
    }
)
_ACTIVATED_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "pre_turn_report_sha256",
        "controller",
        "successor",
        "transitions",
        "transition_output_sha256",
        "session_health_sha256",
        "startup_event_sha256",
        "boundary",
        "provider_free",
        "live_counters",
        "report_sha256",
    }
)
_STARTUP_OBSERVATION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "pre_turn_report_sha256",
        "controller",
        "session_health_sha256",
        "startup_event_sha256",
        "provider_free",
        "live_counters",
        "report_sha256",
    }
)
_FIRST_ACTION_REHEARSAL_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "pre_turn_report_sha256",
        "session_start_report",
        "first_action_report",
        "mcp_bridge",
        "simulated_first_action",
        "action_advance_report",
        "action_advance_mcp_bridge",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_FIRST_ACTION_REHEARSAL_COUNTERS = {
    "authority_grants_minted": 0,
    "capacity_reservations": 2,
    "controller_stages": 1,
    "hosted_calls": 0,
    "model_calls": 0,
    "hook_calls": 2,
    "mcp_bridge_calls": 2,
    "native_action_authorizations": 2,
    "native_actions": 0,
    "network_calls": 0,
    "provider_calls": 0,
    "simulated_native_results": 1,
    "task_creations": 0,
    "worker_creations": 0,
}


class QualificationLifecycleRehearsalError(ValueError):
    """Stable refusal before the successor activation boundary."""


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


def _sealed(value: Mapping[str, Any], field: str) -> bool:
    return bool(
        _is_sha(value.get(field))
        and value.get(field)
        == _sha({key: child for key, child in value.items() if key != field})
    )


def _session_key(task_id: str) -> str:
    return hashlib.sha256(task_id.encode("utf-8")).hexdigest()


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _owned_directory(
    value: str | Path,
    *,
    label: str,
    private: bool = False,
) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise QualificationLifecycleRehearsalError(label + ":unsafe")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except OSError as error:
        raise QualificationLifecycleRehearsalError(
            label + ":unavailable"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or resolved.is_symlink()
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or stat.S_IMODE(info.st_mode) & (0o022 if private else 0o002)
    ):
        raise QualificationLifecycleRehearsalError(label + ":unsafe")
    return resolved


def _terminal_authority(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise QualificationLifecycleRehearsalError(
            "predecessor_authority:not_object"
        )
    owner = value.get("owner")
    identity = value.get("identity")
    lifecycle = value.get("lifecycle")
    if (
        value.get("status") != "VERIFIED"
        or not isinstance(owner, Mapping)
        or not isinstance(identity, Mapping)
        or not isinstance(lifecycle, Mapping)
        or lifecycle.get("terminal") is not True
        or lifecycle.get("expected_binding_status") != "TERMINAL"
        or lifecycle.get("pending_intent") is not False
        or lifecycle.get("cleanup_required") is not False
        or lifecycle.get("action_sha256") is not None
        or lifecycle.get("tool_use_id") is not None
        or not _text(identity.get("controller_id"))
        or not _text(identity.get("root_thread_id"))
        or not _text(identity.get("root_session_id"))
        or not _text(identity.get("root_model"))
    ):
        raise QualificationLifecycleRehearsalError(
            "predecessor_authority:not_clean_terminal"
        )
    return value


def build_successor_session_start_event(
    predecessor_authority: Any,
    *,
    new_task_id: str,
    cwd: str | Path,
    model: str,
) -> dict[str, Any]:
    """Build the official fresh-task SessionStart input from whole authority."""

    authority = _terminal_authority(predecessor_authority)
    identity = authority["identity"]
    if (
        not _text(new_task_id)
        or new_task_id
        in {identity.get("root_thread_id"), identity.get("root_session_id")}
        or not _text(model)
    ):
        raise QualificationLifecycleRehearsalError(
            "successor_identity:invalid"
        )
    project = _owned_directory(cwd, label="successor_cwd")
    return {
        "session_id": new_task_id,
        "cwd": str(project),
        "hook_event_name": "SessionStart",
        "model": model,
        "permission_mode": "dontAsk",
        "source": "startup",
    }


def _invoke_hook(
    hook: Path,
    event: Mapping[str, Any],
    *,
    plugin_root: Path,
    plugin_data: Path,
) -> dict[str, Any]:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", os.defpath),
        "PLUGIN_DATA": str(plugin_data),
        "PLUGIN_ROOT": str(plugin_root),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        completed = subprocess.run(
            [sys.executable, "-B", str(hook)],
            input=_canonical(event).decode("utf-8"),
            text=True,
            capture_output=True,
            cwd=plugin_root,
            env=environment,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationLifecycleRehearsalError(
            "session_start_hook:unavailable"
        ) from error
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout.encode("utf-8")) > MAX_HOOK_OUTPUT_BYTES
    ):
        raise QualificationLifecycleRehearsalError(
            "session_start_hook:execution_failed"
        )
    try:
        output = json.loads(completed.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationLifecycleRehearsalError(
            "session_start_hook:output_invalid"
        ) from error
    if not isinstance(output, Mapping):
        raise QualificationLifecycleRehearsalError(
            "session_start_hook:output_invalid"
        )
    return dict(output)


def _validate_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _REPORT_FIELDS:
        raise QualificationLifecycleRehearsalError("report:shape_invalid")
    core = {key: child for key, child in value.items() if key != "report_sha256"}
    if (
        value.get("schema") != REPORT_SCHEMA
        or value.get("status") != "PASS"
        or value.get("decision") != DECISION_READY
        or value.get("issues") != []
        or value.get("provider_free") is not True
        or value.get("live_counters") != _LIVE_COUNTERS
        or value.get("report_sha256") != _sha(core)
    ):
        raise QualificationLifecycleRehearsalError("report:invalid")
    return dict(value)


def rehearse_terminal_successor_session_start(
    *,
    plugin_root: str | Path,
    plugin_data: str | Path,
    cwd: str | Path,
    new_task_id: str,
    model: str,
) -> dict[str, Any]:
    """Run the persisted-predecessor startup seam through the real hook."""

    root = _owned_directory(plugin_root, label="plugin_root")
    data = _owned_directory(
        plugin_data,
        label="plugin_data",
        private=True,
    )
    hook = root / "hooks/project_ground_hook.py"
    manifest = root / ".codex-plugin/plugin.json"
    if (
        not hook.is_file()
        or hook.is_symlink()
        or not manifest.is_file()
        or manifest.is_symlink()
    ):
        raise QualificationLifecycleRehearsalError(
            "runtime_projection:invalid"
        )
    grants = native_grant_store.NativeGrantStore(
        native_grant_store.canonical_database_path(data)
    )
    authority = _terminal_authority(grants.canonical_authority())
    startup_event = build_successor_session_start_event(
        authority,
        new_task_id=new_task_id,
        cwd=cwd,
        model=model,
    )
    startup_output = _invoke_hook(
        hook,
        startup_event,
        plugin_root=root,
        plugin_data=data,
    )
    native_event = {
        "session_id": new_task_id,
        "turn_id": new_task_id + "-pre-activation-turn",
        "cwd": startup_event["cwd"],
        "hook_event_name": "PreToolUse",
        "model": model,
        "permission_mode": "dontAsk",
        "tool_name": "functions.exec",
        "tool_use_id": new_task_id + "-pre-activation-tool",
        "tool_input": {"cmd": "true"},
    }
    native_output = _invoke_hook(
        hook,
        native_event,
        plugin_root=root,
        plugin_data=data,
    )
    resume_event = {**startup_event, "source": "resume"}
    resume_output = _invoke_hook(
        hook,
        resume_event,
        plugin_root=root,
        plugin_data=data,
    )
    native_specific = native_output.get("hookSpecificOutput")
    transitions = {
        "startup": (
            "CONTINUE" if startup_output.get("continue") is True else "STOPPED"
        ),
        "resume": (
            "STOPPED" if resume_output.get("continue") is False else "CONTINUE"
        ),
        "native_pre_tool": (
            "DENIED"
            if isinstance(native_specific, Mapping)
            and native_specific.get("permissionDecision") == "deny"
            else "ALLOWED"
        ),
    }
    if transitions != {
        "startup": "CONTINUE",
        "resume": "STOPPED",
        "native_pre_tool": "DENIED",
    }:
        raise QualificationLifecycleRehearsalError(
            "terminal_successor_transition:unexpected"
        )
    predecessor_identity = authority["identity"]
    core = {
        "schema": REPORT_SCHEMA,
        "status": "PASS",
        "decision": DECISION_READY,
        "issues": [],
        "predecessor": {
            "authority_sha256": _sha(authority),
            "controller_id": predecessor_identity["controller_id"],
            "root_session_id": predecessor_identity["root_session_id"],
            "status": "TERMINAL",
        },
        "successor": {
            "cwd": startup_event["cwd"],
            "model": model,
            "source": "startup",
            "task_id": new_task_id,
        },
        "transitions": transitions,
        "transition_output_sha256": {
            "native_pre_tool": _sha(native_output),
            "resume": _sha(resume_output),
            "startup": _sha(startup_output),
        },
        "boundary": {
            "live_boundary_crossed": False,
            "next_authorized_action": "successor_activation",
        },
        "provider_free": True,
        "live_counters": dict(_LIVE_COUNTERS),
    }
    return _validate_report({**core, "report_sha256": _sha(core)})


def _waiting_successor_authority(
    value: Any,
    *,
    controller_id: str,
    task_id: str,
    model: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise QualificationLifecycleRehearsalError(
            "successor_authority:not_object"
        )
    authority = dict(value)
    identity = authority.get("identity")
    lifecycle = authority.get("lifecycle")
    if (
        authority.get("status") != "VERIFIED"
        or not isinstance(authority.get("owner"), Mapping)
        or not isinstance(identity, Mapping)
        or identity.get("controller_id") != controller_id
        or identity.get("root_thread_id") != task_id
        or identity.get("root_session_id") != task_id
        or identity.get("root_model") != model
        or not isinstance(lifecycle, Mapping)
        or lifecycle.get("expected_binding_status") != "WAITING"
        or lifecycle.get("terminal") is not False
        or lifecycle.get("pending_intent") is not False
        or lifecycle.get("cleanup_required") is not False
        or lifecycle.get("action_sha256") is not None
        or lifecycle.get("tool_use_id") is not None
    ):
        raise QualificationLifecycleRehearsalError(
            "successor_authority:not_waiting"
        )
    return authority


def _activated_session_start_artifacts(
    data: Path,
    *,
    task_id: str,
    controller_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    session_key = _session_key(task_id)
    health_path = (
        data / "project-ground" / "session-health" / (session_key + ".json")
    )
    try:
        health = owned_file.read_owned_json(
            health_path,
            max_bytes=MAX_DURABLE_BYTES,
            required_mode=0o600,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise QualificationLifecycleRehearsalError(
            "activated_startup:session_health_unavailable"
        ) from error
    if (
        not isinstance(health, Mapping)
        or set(health)
        != {
            "schema",
            "status",
            "session_id",
            "project_id",
            "generation",
            "state_sha256",
            "health_sha256",
        }
        or health.get("schema")
        != "orch-dork/project-ground-session-health/v1"
        or health.get("status") != "HEALTHY"
        or health.get("session_id") != task_id
        or not _is_sha(health.get("state_sha256"))
        or not _sealed(health, "health_sha256")
    ):
        raise QualificationLifecycleRehearsalError(
            "activated_startup:session_health_invalid"
        )
    event_root = data / "project-ground" / "events" / session_key
    try:
        event_paths = sorted(event_root.glob("*.json"))
    except OSError as error:
        raise QualificationLifecycleRehearsalError(
            "activated_startup:event_inventory_unavailable"
        ) from error
    startup_events: list[dict[str, Any]] = []
    for path in event_paths:
        try:
            event = owned_file.read_owned_json(
                path,
                max_bytes=MAX_DURABLE_BYTES,
                required_mode=0o600,
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            continue
        if (
            isinstance(event, Mapping)
            and event.get("hook_event_name") == "SessionStart"
            and event.get("identity", {}).get("session_id") == task_id
        ):
            startup_events.append(dict(event))
    if len(startup_events) != 1:
        raise QualificationLifecycleRehearsalError(
            "activated_startup:event_count_invalid"
        )
    startup = startup_events[0]
    native = startup.get("native_controller")
    if (
        startup.get("schema")
        != "orch-dork/project-ground-durable-event/v1"
        or startup.get("status") != "PASS"
        or startup.get("decision") != "HEALTHY"
        or startup.get("reason_codes") != []
        or startup.get("mutating") is not False
        or not _is_sha(startup.get("report_sha256"))
        or not _sealed(startup, "durable_record_sha256")
        or not isinstance(native, Mapping)
        or native.get("present") is not True
        or native.get("controller_id") != controller_id
        or native.get("status") != "WAITING"
        or native.get("matched") is not False
        or native.get("action_id") is not None
        or native.get("grant_state") is not None
    ):
        raise QualificationLifecycleRehearsalError(
            "activated_startup:event_invalid"
        )
    return dict(health), startup


def observe_activated_successor_session_start(
    *,
    plugin_data: str | Path,
    pre_turn_report: Any,
    new_task_id: str,
    model: str,
) -> dict[str, Any]:
    """Seal the real hook-written startup state without invoking the hook."""

    import orch_dork_qualification_successor as successor

    data = _owned_directory(plugin_data, label="plugin_data", private=True)
    artifact = successor.QualificationSuccessorArtifact.from_report(
        pre_turn_report
    )
    if (
        artifact.root_task_id != new_task_id
        or artifact.root_session_id != new_task_id
        or artifact.root_model != model
        or artifact.next_stage_action != "capacity_admission"
    ):
        raise QualificationLifecycleRehearsalError(
            "activated_startup:pre_turn_identity_invalid"
        )
    grants = native_grant_store.NativeGrantStore(
        native_grant_store.canonical_database_path(data)
    )
    authority = _waiting_successor_authority(
        grants.canonical_authority(),
        controller_id=artifact.controller_id,
        task_id=new_task_id,
        model=model,
    )
    health, startup = _activated_session_start_artifacts(
        data,
        task_id=new_task_id,
        controller_id=artifact.controller_id,
    )
    core = {
        "schema": STARTUP_OBSERVATION_REPORT_SCHEMA,
        "status": "PASS",
        "decision": STARTUP_OBSERVATION_DECISION_READY,
        "issues": [],
        "pre_turn_report_sha256": artifact.report_sha256,
        "controller": {
            "authority_sha256": _sha(authority),
            "controller_id": artifact.controller_id,
            "expected_binding_status": "WAITING",
            "next_stage_action": artifact.next_stage_action,
            "root_session_id": artifact.root_session_id,
            "root_thread_id": artifact.root_task_id,
        },
        "session_health_sha256": health["health_sha256"],
        "startup_event_sha256": startup["durable_record_sha256"],
        "provider_free": True,
        "live_counters": dict(_LIVE_COUNTERS),
    }
    report = {**core, "report_sha256": _sha(core)}
    if (
        set(report) != _STARTUP_OBSERVATION_FIELDS
        or not _sealed(report, "report_sha256")
    ):
        raise QualificationLifecycleRehearsalError(
            "activated_startup:observation_report_invalid"
        )
    return report


def _invoke_projected_successor_mcp_bridge(
    *,
    plugin_root: Path,
    pre_turn_report_path: str | Path,
    expected_report_sha256: str,
    new_task_id: str,
    tool_name: str,
    request_id: str,
    bridge_schema: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Invoke the real projected stdio MCP caller from its runtime cwd."""

    launcher = plugin_root / "scripts/orch_dork_mcp_launcher.py"
    if not launcher.is_file() or launcher.is_symlink():
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:launcher_invalid"
        )
    try:
        launcher_payload = launcher.read_bytes()
    except OSError as error:
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:launcher_invalid"
        ) from error
    if len(launcher_payload) > 4_194_304:
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:launcher_invalid"
        )
    initialize = {
        "jsonrpc": "2.0",
        "id": request_id + "-initialize",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "orch-dork-qualification-rehearsal",
                "version": "1",
            },
        },
    }
    initialized = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }
    call = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "_meta": {"threadId": new_task_id},
            "name": tool_name,
            "arguments": {
                "pre_turn_report_path": str(pre_turn_report_path),
                "pre_turn_report_sha256": expected_report_sha256,
            },
        },
    }
    payload = b"\n".join(
        _canonical(message)
        for message in (initialize, initialized, call)
    ) + b"\n"
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for name, value in os.environ.items():
        if name in {"CODEX_HOME", "HOME"} or name.startswith(
            "ORCH_DORK_"
        ):
            environment[name] = value
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(launcher),
                "serve",
                "--require-thread-id",
            ],
            cwd=plugin_root,
            env=environment,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:process_unavailable"
        ) from error
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > 16_777_216
    ):
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:process_refused"
        )
    try:
        launcher_readback = launcher.read_bytes()
    except OSError as error:
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:launcher_readback_invalid"
        ) from error
    if launcher_readback != launcher_payload:
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:launcher_drift"
        )
    try:
        responses = [
            json.loads(line)
            for line in completed.stdout.splitlines()
            if line.strip()
        ]
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:response_invalid"
        ) from error
    matches = [
        response
        for response in responses
        if isinstance(response, Mapping)
        and response.get("id") == request_id
    ]
    if len(matches) != 1:
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:response_invalid"
        )
    response = matches[0]
    structured = (
        response.get("result", {}).get("structuredContent")
        if isinstance(response.get("result"), Mapping)
        else None
    )
    if not isinstance(structured, Mapping):
        raise QualificationLifecycleRehearsalError(
            "first_action_mcp_bridge:report_missing"
        )
    result_artifact = None
    if tool_name == "advance_issue94_successor_after_native_action":
        import orch_dork_qualification_successor as successor

        # The dispatcher may emit either the historical v1 receipt
        # (ACTION_ADVANCE_RESULT_ARTIFACT_SCHEMA, full action embedded) or
        # the current v2 receipt (ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA,
        # digest-only action_projection). Both flow through the same
        # independent-pins resolver; that close dispatch is what keeps the
        # projected MCP receiver compatible without rewriting the bridge
        # contract or dropping receipts on the floor.
        if successor.is_issue94_action_advance_result_artifact_receipt(structured):
            result_artifact = dict(structured)
            structured = successor.resolve_issue94_action_advance_mcp_result(
                result_artifact, pre_turn_report_path=pre_turn_report_path,
                expected_report_sha256=expected_report_sha256,
                current_task_id=new_task_id,
            )
    bridge_core = {
        "schema": bridge_schema,
        "status": "PASS",
        "transport": "stdio",
        "runtime_root": str(plugin_root),
        "runtime_cwd": str(plugin_root),
        "require_thread_id": True,
        "launcher_sha256": hashlib.sha256(
            launcher_payload
        ).hexdigest(),
        "request_sha256": _sha(call),
        "response_sha256": _sha(response),
        "response_count": len(responses),
        "returncode": completed.returncode,
        "stderr_bytes": len(completed.stderr),
    }
    if result_artifact is not None:
        # The record describes the resolved logical advance under the caller's
        # existing bridge contract; retain the transport receipt as provenance.
        bridge_core["result_artifact_receipt"] = result_artifact
    bridge = {
        **bridge_core,
        "report_sha256": _sha(bridge_core),
    }
    return dict(structured), bridge


def _validate_activated_report(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _ACTIVATED_REPORT_FIELDS
    ):
        raise QualificationLifecycleRehearsalError(
            "activated_report:shape_invalid"
        )
    core = {
        key: child for key, child in value.items() if key != "report_sha256"
    }
    if (
        value.get("schema") != ACTIVATED_REPORT_SCHEMA
        or value.get("status") != "PASS"
        or value.get("decision") != ACTIVATED_DECISION_READY
        or value.get("issues") != []
        or value.get("provider_free") is not True
        or value.get("live_counters") != _LIVE_COUNTERS
        or value.get("report_sha256") != _sha(core)
    ):
        raise QualificationLifecycleRehearsalError(
            "activated_report:invalid"
        )
    return dict(value)


def rehearse_activated_successor_session_start(
    *,
    plugin_root: str | Path,
    plugin_data: str | Path,
    cwd: str | Path,
    pre_turn_report: Any,
    new_task_id: str,
    model: str,
) -> dict[str, Any]:
    """Run the real first-turn SessionStart after idle-task activation."""

    import orch_dork_qualification_successor as successor

    root = _owned_directory(plugin_root, label="plugin_root")
    data = _owned_directory(plugin_data, label="plugin_data", private=True)
    project = _owned_directory(cwd, label="successor_cwd")
    artifact = successor.QualificationSuccessorArtifact.from_report(
        pre_turn_report
    )
    if (
        artifact.root_task_id != new_task_id
        or artifact.root_session_id != new_task_id
        or artifact.root_model != model
        or artifact.next_stage_action != "capacity_admission"
    ):
        raise QualificationLifecycleRehearsalError(
            "activated_startup:pre_turn_identity_invalid"
        )
    hook = root / "hooks/project_ground_hook.py"
    manifest = root / ".codex-plugin/plugin.json"
    if (
        not hook.is_file()
        or hook.is_symlink()
        or not manifest.is_file()
        or manifest.is_symlink()
    ):
        raise QualificationLifecycleRehearsalError(
            "runtime_projection:invalid"
        )
    grants = native_grant_store.NativeGrantStore(
        native_grant_store.canonical_database_path(data)
    )
    authority = _waiting_successor_authority(
        grants.canonical_authority(),
        controller_id=artifact.controller_id,
        task_id=new_task_id,
        model=model,
    )
    event = {
        "session_id": new_task_id,
        "cwd": str(project),
        "hook_event_name": "SessionStart",
        "model": model,
        "permission_mode": "dontAsk",
        "source": "startup",
    }
    output = _invoke_hook(
        hook,
        event,
        plugin_root=root,
        plugin_data=data,
    )
    transition = "CONTINUE" if output.get("continue") is True else "STOPPED"
    if transition != "CONTINUE":
        raise QualificationLifecycleRehearsalError(
            "activated_startup:transition_unexpected"
        )
    observation = observe_activated_successor_session_start(
        plugin_data=data,
        pre_turn_report=artifact.report,
        new_task_id=new_task_id,
        model=model,
    )
    core = {
        "schema": ACTIVATED_REPORT_SCHEMA,
        "status": "PASS",
        "decision": ACTIVATED_DECISION_READY,
        "issues": [],
        "pre_turn_report_sha256": artifact.report_sha256,
        "controller": {
            "authority_sha256": _sha(authority),
            "controller_id": artifact.controller_id,
            "expected_binding_status": "WAITING",
            "next_stage_action": artifact.next_stage_action,
        },
        "successor": {
            "cwd": str(project),
            "model": model,
            "source": "startup",
            "task_id": new_task_id,
        },
        "transitions": {"session_start": transition},
        "transition_output_sha256": _sha(output),
        "session_health_sha256": observation["session_health_sha256"],
        "startup_event_sha256": observation["startup_event_sha256"],
        "boundary": {
            "live_boundary_crossed": False,
            "model_turn_started": False,
            "next_authorized_action": "capacity_admission",
        },
        "provider_free": True,
        "live_counters": dict(_LIVE_COUNTERS),
    }
    return _validate_activated_report(
        {**core, "report_sha256": _sha(core)}
    )


def rehearse_activated_successor_first_action(
    *,
    plugin_root: str | Path,
    plugin_data: str | Path,
    cwd: str | Path,
    pre_turn_report_path: str | Path,
    expected_report_sha256: str,
    new_task_id: str,
    model: str,
) -> dict[str, Any]:
    """Run startup and the atomic capacity/action seam, then stop pre-native."""

    import orch_dork_qualification_successor as successor

    root = _owned_directory(plugin_root, label="plugin_root")
    data = _owned_directory(plugin_data, label="plugin_data", private=True)
    artifact = successor.read_issue94_successor_pre_turn_artifact(
        pre_turn_report_path,
        expected_report_sha256=expected_report_sha256,
    )
    session_start_report = rehearse_activated_successor_session_start(
        plugin_root=root,
        plugin_data=data,
        cwd=cwd,
        pre_turn_report=artifact.report,
        new_task_id=new_task_id,
        model=model,
    )
    first_action_report, mcp_bridge = (
        _invoke_projected_successor_mcp_bridge(
            plugin_root=root,
            pre_turn_report_path=pre_turn_report_path,
            expected_report_sha256=artifact.report_sha256,
            new_task_id=new_task_id,
            tool_name="authorize_issue94_successor_first_action",
            request_id="successor-first-action",
            bridge_schema=FIRST_ACTION_MCP_BRIDGE_REPORT_SCHEMA,
        )
    )
    first_action = (
        successor.QualificationSuccessorFirstActionArtifact.from_report(
            first_action_report
        )
    )
    native_action = first_action.action
    tool_use_id = "rehearsal-" + native_action["action_id"]
    turn_id = "rehearsal-turn-" + native_action["action_id"]
    hook = root / "hooks/project_ground_hook.py"
    hook_base = {
        "session_id": new_task_id,
        "turn_id": turn_id,
        "cwd": str(_owned_directory(cwd, label="successor_cwd")),
        "tool_use_id": tool_use_id,
        "model": model,
        "permission_mode": "dontAsk",
        "tool_name": native_action["tool_name"],
        "tool_input": native_action["tool_input"],
    }
    pre_output = _invoke_hook(
        hook,
        {
            **hook_base,
            "hook_event_name": "PreToolUse",
        },
        plugin_root=root,
        plugin_data=data,
    )
    simulated_result = json.dumps(
        {
            "agent_id": "01a00000-0000-7000-8000-000000000030",
            "nickname": "Rehearsal",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    post_output = _invoke_hook(
        hook,
        {
            **hook_base,
            "hook_event_name": "PostToolUse",
            "tool_response": simulated_result,
        },
        plugin_root=root,
        plugin_data=data,
    )
    action_advance_report, action_advance_mcp_bridge = (
        _invoke_projected_successor_mcp_bridge(
            plugin_root=root,
            pre_turn_report_path=pre_turn_report_path,
            expected_report_sha256=artifact.report_sha256,
            new_task_id=new_task_id,
            tool_name="advance_issue94_successor_after_native_action",
            request_id="successor-action-advance",
            bridge_schema=ACTION_ADVANCE_MCP_BRIDGE_REPORT_SCHEMA,
        )
    )
    action_advance = (
        successor.QualificationSuccessorActionAdvanceArtifact.from_report(
            action_advance_report
        )
    )
    next_action = action_advance.action
    simulated_core = {
        "schema": "orch-dork/simulated-native-action-result/v1",
        "status": "PASS",
        "action_sha256": native_action["action_sha256"],
        "tool_use_id": tool_use_id,
        "tool_response_sha256": hashlib.sha256(
            _canonical(simulated_result)
        ).hexdigest(),
        "pretool_output_sha256": _sha(pre_output),
        "posttool_output_sha256": _sha(post_output),
        "live_boundary_crossed": False,
    }
    simulated_first_action = {
        **simulated_core,
        "report_sha256": _sha(simulated_core),
    }
    core = {
        "schema": FIRST_ACTION_REHEARSAL_REPORT_SCHEMA,
        "status": "PASS",
        "decision": FIRST_ACTION_REHEARSAL_DECISION_READY,
        "issues": [],
        "pre_turn_report_sha256": artifact.report_sha256,
        "session_start_report": session_start_report,
        "first_action_report": first_action.report,
        "mcp_bridge": mcp_bridge,
        "simulated_first_action": simulated_first_action,
        "action_advance_report": action_advance.report,
        "action_advance_mcp_bridge": action_advance_mcp_bridge,
        "boundary": {
            "live_boundary_crossed": False,
            "native_action_called": False,
            "next_action": (
                next_action.get("tool_name")
                if isinstance(next_action, Mapping)
                else None
            ),
            "next_batch_index": (
                next_action.get("batch_index")
                if isinstance(next_action, Mapping)
                else None
            ),
        },
        "provider_free": True,
        "counters": dict(_FIRST_ACTION_REHEARSAL_COUNTERS),
    }
    report = {**core, "report_sha256": _sha(core)}
    if (
        set(report) != _FIRST_ACTION_REHEARSAL_FIELDS
        or session_start_report.get("decision") != ACTIVATED_DECISION_READY
        or first_action_report.get("decision")
        != FIRST_ACTION_REHEARSAL_DECISION_READY
        or first_action_report.get("pre_turn_report_sha256")
        != artifact.report_sha256
        or first_action_report.get("boundary", {}).get(
            "native_action_called"
        )
        is not False
        or mcp_bridge.get("schema")
        != FIRST_ACTION_MCP_BRIDGE_REPORT_SCHEMA
        or mcp_bridge.get("status") != "PASS"
        or mcp_bridge.get("transport") != "stdio"
        or mcp_bridge.get("runtime_root") != str(root)
        or mcp_bridge.get("runtime_cwd") != str(root)
        or mcp_bridge.get("require_thread_id") is not True
        or not _is_sha(mcp_bridge.get("launcher_sha256"))
        or not _is_sha(mcp_bridge.get("request_sha256"))
        or not _is_sha(mcp_bridge.get("response_sha256"))
        or mcp_bridge.get("response_count") != 2
        or mcp_bridge.get("returncode") != 0
        or mcp_bridge.get("stderr_bytes") != 0
        or not _sealed(mcp_bridge, "report_sha256")
        or not _sealed(simulated_first_action, "report_sha256")
        or simulated_first_action.get("live_boundary_crossed") is not False
        or action_advance_report.get("decision")
        != "READY_FOR_NEXT_ACTION"
        or not isinstance(next_action, Mapping)
        or next_action.get("tool_name")
        != "multi_agent_v1__spawn_agent"
        or next_action.get("batch_index") != 1
        or next_action.get("lane_ids") != ["standards"]
        or action_advance_mcp_bridge.get("schema")
        != ACTION_ADVANCE_MCP_BRIDGE_REPORT_SCHEMA
        or action_advance_mcp_bridge.get("status") != "PASS"
        or action_advance_mcp_bridge.get("transport") != "stdio"
        or action_advance_mcp_bridge.get("runtime_root") != str(root)
        or action_advance_mcp_bridge.get("runtime_cwd") != str(root)
        or action_advance_mcp_bridge.get("require_thread_id") is not True
        or action_advance_mcp_bridge.get("response_count") != 2
        or action_advance_mcp_bridge.get("returncode") != 0
        or action_advance_mcp_bridge.get("stderr_bytes") != 0
        or not _sealed(action_advance_mcp_bridge, "report_sha256")
        or report.get("boundary")
        != {
            "live_boundary_crossed": False,
            "native_action_called": False,
            "next_action": "multi_agent_v1__spawn_agent",
            "next_batch_index": 1,
        }
        or report.get("counters") != _FIRST_ACTION_REHEARSAL_COUNTERS
        or not _sealed(report, "report_sha256")
    ):
        raise QualificationLifecycleRehearsalError(
            "first_action_rehearsal:report_invalid"
        )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-root", type=Path, required=True)
    parser.add_argument("--plugin-data", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--new-task-id", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--pre-turn-report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.pre_turn_report is None:
            report = rehearse_terminal_successor_session_start(
                plugin_root=args.plugin_root,
                plugin_data=args.plugin_data,
                cwd=args.cwd,
                new_task_id=args.new_task_id,
                model=args.model,
            )
            failure_schema = REPORT_SCHEMA
        else:
            pre_turn_report = owned_file.read_owned_json(
                args.pre_turn_report,
                max_bytes=4_194_304,
                required_mode=0o600,
            )
            report = rehearse_activated_successor_first_action(
                plugin_root=args.plugin_root,
                plugin_data=args.plugin_data,
                cwd=args.cwd,
                pre_turn_report_path=args.pre_turn_report,
                expected_report_sha256=pre_turn_report["report_sha256"],
                new_task_id=args.new_task_id,
                model=args.model,
            )
            failure_schema = FIRST_ACTION_REHEARSAL_REPORT_SCHEMA
    except Exception as error:
        failure_schema = (
            FIRST_ACTION_REHEARSAL_REPORT_SCHEMA
            if args.pre_turn_report is not None
            else REPORT_SCHEMA
        )
        issue = (
            str(error)
            if isinstance(
                error,
                (KeyError, OSError, TypeError, ValueError),
            )
            else "unexpected_failure:" + type(error).__name__
        )
        print(
            json.dumps(
                {
                    "schema": failure_schema,
                    "status": "FAIL",
                    "decision": "REFUSED",
                    "issues": [issue],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


__all__ = [
    "ACTION_ADVANCE_MCP_BRIDGE_REPORT_SCHEMA",
    "ACTIVATED_DECISION_READY",
    "ACTIVATED_REPORT_SCHEMA",
    "DECISION_READY",
    "FIRST_ACTION_REHEARSAL_DECISION_READY",
    "FIRST_ACTION_REHEARSAL_REPORT_SCHEMA",
    "FIRST_ACTION_MCP_BRIDGE_REPORT_SCHEMA",
    "REPORT_SCHEMA",
    "STARTUP_OBSERVATION_DECISION_READY",
    "STARTUP_OBSERVATION_REPORT_SCHEMA",
    "observe_activated_successor_session_start",
    "QualificationLifecycleRehearsalError",
    "build_successor_session_start_event",
    "rehearse_activated_successor_session_start",
    "rehearse_activated_successor_first_action",
    "rehearse_terminal_successor_session_start",
]


if __name__ == "__main__":
    raise SystemExit(main())
