#!/usr/bin/env python3
"""Thin Codex lifecycle-hook transport for Orch Dork project ground.

The hook never discovers or fabricates authority.  It reads one sealed state
record produced by the project-native maintenance gateway, binds the current
official hook event, invokes the provider-free evaluator, and emits only the
documented Codex hook response.  Missing or contradictory state fails closed.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Mapping

# Codex runs this hook as plain python3, without -B or PYTHONDONTWRITEBYTECODE.
# Every plugin module is imported later, inside a function; none may write
# bytecode into the installed plugin, whose bytes the projected parity and
# release checks compare (Issue 232).
sys.dont_write_bytecode = True


MAX_STDIN_BYTES = 1_000_000
DIRECT_RESULT_KEY_SETS = (
    frozenset({"agent_id", "nickname"}),
    frozenset({"submission_id"}),
    frozenset({"previous_status"}),
)
DURABLE_EVENT_SCHEMA = "orch-dork/project-ground-durable-event/v1"
DURABLE_EVENT_FIELDS = {
    "schema",
    "report_schema",
    "report_sha256",
    "hook_event_name",
    "decision",
    "status",
    "coverage_class",
    "mutating",
    "tool_input_sha256",
    "state_sha256",
    "completion_invalidated",
    "reason_codes",
    "identity",
    "native_controller",
    "durable_record_sha256",
}
DURABLE_IDENTITY_FIELDS = {
    "project_id",
    "generation",
    "ticket_id",
    "admission_sha256",
    "lease_version",
    "lease_owner_thread_id",
    "current_thread_id",
    "session_id",
    "authority_scope_sha256",
    "workspace_baseline_sha256",
    "writable_scope_sha256",
    "adapter_snapshot_sha256",
    "active_controller_sha256",
    "capsule_sha256",
    "execution_readiness_sha256",
    "plan_sha256",
    "turn_id",
}
# Owner decision D2 (2026-10-03, Issue 192): the hooks enforce only for a task
# a governed state binds and pass every other task through unchanged, so a
# user's ordinary chats keep working while the hooks are enabled.  A governed
# state binds a task either as the lease thread of the project-ground state
# or through a governed-run watcher binding.  The qualification host keeps
# every event governed.
QUALIFICATION_HOST_ENV = "ORCH_DORK_QUALIFICATION_HOST_PREPARATION"
SCOPE_STRICT = "strict"
SCOPE_GOVERNED_RUN = "governed_run"
SCOPE_PASS_THROUGH = "pass_through"
DURABLE_PRETOOL_NATIVE_FIELDS = {
    "present",
    "controller_id",
    "controller_seq",
    "status",
    "action_id",
    "matched",
    "grant_state",
    "pretool_event_sha256",
    "tool_use_id",
}


def _plugin_root() -> Path:
    raw = os.environ.get("PLUGIN_ROOT")
    return Path(raw).resolve() if raw else Path(__file__).resolve().parents[1]


def _plugin_data() -> Path | None:
    raw = os.environ.get("PLUGIN_DATA")
    return Path(raw).resolve() if raw else None


def _load_module():
    script_dir = _plugin_root() / "skills" / "orch-dork" / "scripts"
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    import orch_dork_project_ground_enforcement as enforcement

    return enforcement


def _read_json(path: Path) -> Mapping[str, Any]:
    import orch_dork_owned_file as owned_file

    value = owned_file.read_owned_json(path, max_bytes=MAX_STDIN_BYTES)
    if not isinstance(value, Mapping):
        raise ValueError("JSON object required")
    return value


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _create_only_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8") + b"\n"
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except FileExistsError:
        import orch_dork_owned_file as owned_file

        if owned_file.read_owned_bytes(
            path, max_bytes=max(len(payload), 1)
        ) != payload:
            raise ValueError("create-only hook event conflict")
        return
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _result_payload(tool_response: Any) -> Mapping[str, Any] | None:
    candidates: list[Mapping[str, Any]] = []
    if isinstance(tool_response, str):
        try:
            decoded = json.loads(tool_response)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, Mapping):
            candidates.append(decoded)
    if isinstance(tool_response, Mapping):
        if isinstance(tool_response.get("schema"), str):
            candidates.append(tool_response)
        if set(tool_response) in DIRECT_RESULT_KEY_SETS:
            candidates.append(tool_response)
        for field in ("structuredContent", "structured_content", "result"):
            child = tool_response.get(field)
            if isinstance(child, Mapping):
                candidates.append(child)
        texts: list[str] = []
        output = tool_response.get("output")
        if isinstance(output, str):
            texts.append(output)
        content = tool_response.get("content")
        if isinstance(content, list):
            for child in content:
                if (
                    isinstance(child, Mapping)
                    and child.get("type") == "text"
                    and isinstance(child.get("text"), str)
                ):
                    texts.append(child["text"])
        for text in texts:
            try:
                child = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(child, Mapping):
                candidates.append(child)
    unique = {
        json.dumps(
            candidate,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ): dict(candidate)
        for candidate in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _native_result(tool_response: Any) -> tuple[str, str, Mapping[str, Any] | None]:
    try:
        encoded = json.dumps(
            tool_response,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        encoded = b"null"
        return "unknown", hashlib.sha256(encoded).hexdigest(), None
    status = (
        str(tool_response.get("status", "")).strip().casefold()
        if isinstance(tool_response, Mapping)
        else ""
    )
    outcomes = {
        "completed": "completed",
        "complete": "completed",
        "success": "completed",
        "succeeded": "completed",
        "ok": "completed",
        "passed": "completed",
        "failed": "failed",
        "failure": "failed",
        "error": "failed",
        "spawn_error": "failed",
        "stdin_error": "failed",
        "wait_error": "failed",
        "cancelled": "cancelled",
        "canceled": "cancelled",
        "timed_out": "timed_out",
        "timeout": "timed_out",
        "unknown": "unknown",
    }
    payload = _result_payload(tool_response)
    outcome = outcomes.get(status, "unknown")
    return outcome, hashlib.sha256(encoded).hexdigest(), payload


def _reseal(enforcement: Any, report: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(report)
    value.pop("report_sha256", None)
    value["report_sha256"] = enforcement._sha(value)
    return value


def _deny_grant(enforcement: Any, report: Mapping[str, Any], reason: str) -> dict[str, Any]:
    value = dict(report)
    reasons = list(value.get("reason_codes", []))
    if reason not in reasons:
        reasons.append(reason)
    value["reason_codes"] = reasons
    value["status"] = "BLOCKED"
    value["decision"] = "DENY"
    value["completion_invalidated"] = False
    value["hook_output"] = enforcement._hook_output("PreToolUse", "DENY", reason)
    native = dict(value.get("native_controller", {}))
    native.update(matched=False, grant_state="REFUSED")
    value["native_controller"] = native
    return _reseal(enforcement, value)


def _session_key(session_id: Any) -> str:
    return hashlib.sha256(str(session_id or "missing").encode("utf-8")).hexdigest()


def _health_path(data_root: Path, session_id: Any) -> Path:
    return data_root / "project-ground" / "session-health" / (_session_key(session_id) + ".json")


def _event_path(data_root: Path, session_id: Any, report_sha256: str) -> Path:
    return data_root / "project-ground" / "events" / _session_key(session_id) / (report_sha256 + ".json")


def _read_durable_event(path: Path) -> Mapping[str, Any] | None:
    try:
        import orch_dork_owned_file as owned_file

        value = owned_file.read_owned_json(path, max_bytes=131_072)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, Mapping) else None


def _valid_pretool_event(
    data_root: Path,
    session_id: Any,
    report_sha256: Any,
    *,
    enforcement: Any,
    action: Mapping[str, Any],
    grant: Mapping[str, Any],
    tool_use_id: str,
) -> bool:
    if not isinstance(report_sha256, str):
        return False
    durable = _read_durable_event(
        _event_path(data_root, session_id, report_sha256)
    )
    if not isinstance(durable, Mapping):
        return False
    core = {
        key: child
        for key, child in durable.items()
        if key != "durable_record_sha256"
    }
    native = durable.get("native_controller")
    identity = durable.get("identity")
    return bool(
        set(durable) == DURABLE_EVENT_FIELDS
        and durable.get("schema") == DURABLE_EVENT_SCHEMA
        and durable.get("report_schema") == enforcement.REPORT_SCHEMA
        and durable.get("report_sha256") == report_sha256
        and durable.get("durable_record_sha256") == enforcement._sha(core)
        and durable.get("hook_event_name") == "PreToolUse"
        and durable.get("decision") == "ALLOW"
        and durable.get("status") == "PASS"
        and durable.get("mutating") is True
        and isinstance(identity, Mapping)
        and set(identity) == DURABLE_IDENTITY_FIELDS
        and identity.get("session_id") == session_id
        and isinstance(native, Mapping)
        and set(native) == DURABLE_PRETOOL_NATIVE_FIELDS
        and native.get("present") is True
        and native.get("controller_id") == grant.get("controller_id")
        and native.get("controller_seq") == grant.get("controller_seq")
        and native.get("status") == "ACTIVE"
        and native.get("matched") is True
        and native.get("action_id") == action.get("action_id")
        and native.get("grant_state") == "DISPATCHED"
        and native.get("pretool_event_sha256")
        == grant.get("pretool_event_sha256")
        and native.get("tool_use_id") == tool_use_id
        and grant.get("pretool_report_sha256") == report_sha256
        and grant.get("tool_use_id") == tool_use_id
    )


def _invalidation_path(data_root: Path, session_id: Any) -> Path:
    return data_root / "project-ground" / "completion-invalidated" / (_session_key(session_id) + ".json")


def _scripts_on_path() -> None:
    script_dir = str(_plugin_root() / "skills" / "orch-dork" / "scripts")
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)


def _has_governed_evidence(data_root: Path, session_id: str) -> bool:
    return (
        _health_path(data_root, session_id).exists()
        or (data_root / "project-ground" / "events" / _session_key(session_id)).exists()
    )


def _session_scope(data_root: Path, hook_input: Any) -> str:
    """Which policy, if any, governs this event's task.

    Codex reports every event of a task, a worker's own tool calls included,
    under the task's thread id.  A governed-run binding names that id before
    the task's first turn; the project-ground state names it as its lease
    thread and, once a governed native controller is bound, as the
    controller's root session.  A session that already left governed
    evidence stays governed whatever later happens to that state, so
    deleting or rewriting it never releases a task.  Under the qualification
    host every event stays governed and an event without a session id fails
    closed.
    """

    if QUALIFICATION_HOST_ENV in os.environ:
        return SCOPE_STRICT
    session_id = hook_input.get("session_id") if isinstance(hook_input, Mapping) else None
    if not isinstance(session_id, str) or not session_id:
        return SCOPE_STRICT
    import orch_dork_governed_run_policy as governed_run

    binding = governed_run.binding_path(data_root, session_id)
    if binding.exists() or binding.is_symlink():
        return SCOPE_GOVERNED_RUN
    if _has_governed_evidence(data_root, session_id):
        return SCOPE_STRICT
    try:
        state = _read_json(data_root / "project-ground" / "current.json")
    except (OSError, ValueError):
        return SCOPE_PASS_THROUGH
    lease = state
    for key in ("program", "state", "prerequisites", "lease"):
        lease = lease.get(key) if isinstance(lease, Mapping) else None
    native = state.get("native_controller")
    threads = {
        thread
        for thread in (
            *(
                (lease.get("owner_thread_id"), lease.get("current_thread_id"))
                if isinstance(lease, Mapping)
                else ()
            ),
            *(
                (native.get("root_session_id"), native.get("root_thread_id"))
                if isinstance(native, Mapping)
                else ()
            ),
        )
        if isinstance(thread, str) and thread
    }
    return SCOPE_STRICT if session_id in threads else SCOPE_PASS_THROUGH


def _governed_run_output(data_root: Path, hook_input: Mapping[str, Any]) -> dict[str, Any]:
    """Decide one event of a watcher-bound zero-worker task, failing closed."""

    event_name = hook_input.get("hook_event_name")
    try:
        import orch_dork_governed_run_policy as governed_run
        import orch_dork_owned_file as owned_file

        definition = owned_file.sha256_owned_file(
            Path(__file__), max_bytes=MAX_STDIN_BYTES
        )
        output, _record = governed_run.hook_decision(
            data_root,
            hook_input,
            observed_hook_definition_sha256=definition,
        )
        return output
    except Exception as error:  # noqa: BLE001 - a bound task fails closed
        reason = "Orch Dork governed run: " + type(error).__name__
        if event_name in {"Stop", "SubagentStop"}:
            return {"continue": True, "systemMessage": reason}
        return _fail_output(event_name, reason)


def _pass_through_output(event_name: Any) -> dict[str, Any]:
    if event_name == "PreToolUse":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    return {"continue": True}


def _fail_output(event_name: Any, reason: str) -> dict[str, Any]:
    if event_name == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    if event_name == "SessionStart":
        return {
            "continue": False,
            "stopReason": reason,
            "systemMessage": reason,
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": reason,
            },
        }
    if event_name == "PostToolUse":
        return {
            "systemMessage": reason,
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": reason,
            },
        }
    return {"decision": "block", "reason": reason}


def _codex_compatible_output(report: Mapping[str, Any]) -> dict[str, Any]:
    """Encode successful PreToolUse as implicit allow for current Codex."""

    output = dict(report.get("hook_output", {}))
    specific = output.get("hookSpecificOutput")
    if (
        report.get("hook_event_name") == "PreToolUse"
        and report.get("decision") == "ALLOW"
        and isinstance(specific, Mapping)
        and specific.get("permissionDecision") == "allow"
    ):
        compatible = dict(specific)
        compatible.pop("permissionDecision", None)
        compatible.pop("permissionDecisionReason", None)
        output["hookSpecificOutput"] = compatible
    return output


def _qualification_owner_context(
    hook_input: Any, enforcement: Any
) -> Mapping[str, Any] | None:
    """Read the root-only invocation attestation without app-server RPC.

    The app-server hook environment is inherited by spawned workers.  Their
    events remain governed by the native-controller binding, but cannot match
    the root session/model attested by the qualification owner.  Treating that
    inherited overlay as a supplied worker context would strand every valid
    ``SubagentStop`` pre-work yield as ``qualification_owner:context_invalid``.
    """

    if QUALIFICATION_HOST_ENV not in os.environ:
        return None
    event = enforcement.normalize_hook_input(hook_input)
    if event.get("agent_id") is not None:
        return None
    import orch_dork_qualification_host as qualification_host

    return qualification_host.observe_qualification_owner_context(
        event
    )


def run(hook_input: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
    event_name = hook_input.get("hook_event_name") if isinstance(hook_input, Mapping) else None
    data_root = _plugin_data()
    if data_root is None:
        # Without plugin data no governed state can bind a task, so only the
        # qualification host, where every event is governed, fails closed.
        if QUALIFICATION_HOST_ENV in os.environ:
            return _fail_output(event_name, "Orch Dork project ground READ_ONLY: PLUGIN_DATA unavailable"), None
        return _pass_through_output(event_name), None
    try:
        _scripts_on_path()
        scope = _session_scope(data_root, hook_input)
    except Exception:  # noqa: BLE001 - a scope error keeps the enforcement below
        scope = SCOPE_STRICT
    if scope == SCOPE_PASS_THROUGH:
        return _pass_through_output(event_name), None
    if scope == SCOPE_GOVERNED_RUN:
        return _governed_run_output(data_root, hook_input), None
    try:
        enforcement = _load_module()
        import orch_dork_native_grant_store as native_grant_store
        import orch_dork_native_result as native_result
        import orch_dork_owned_file as owned_file

        state = _read_json(data_root / "project-ground" / "current.json")
        health = None
        if event_name != "SessionStart":
            health_file = _health_path(data_root, hook_input.get("session_id"))
            if health_file.is_file():
                health = _read_json(health_file)
        program = enforcement.program_from_hook_state(hook_input, state, health)
        invalidation_path = _invalidation_path(data_root, hook_input.get("session_id"))
        if invalidation_path.is_file():
            invalidation = _read_json(invalidation_path)
            if invalidation.get("program_sha256") == state.get("program_sha256"):
                program.setdefault("completion", {}).update(
                    final_verification_valid=False,
                    final_verification_sha256=None,
                    independent_observation="UNBOUND",
                    governed_controller_status="PENDING",
                )
        base_report = enforcement.evaluate_project_ground_enforcement(program)
        qualification_owner_context = _qualification_owner_context(
            hook_input, enforcement
        )
        binding = state.get("native_controller") if isinstance(state, Mapping) else None
        grants = native_grant_store.NativeGrantStore(
            native_grant_store.canonical_database_path(data_root)
        )
        observed_hook_definition_sha256 = owned_file.sha256_owned_file(
            Path(__file__), max_bytes=MAX_STDIN_BYTES
        )
        observed_hook_registration_sha256 = owned_file.sha256_owned_file(
            Path(__file__).with_name("hooks.json"), max_bytes=MAX_STDIN_BYTES
        )
        authority = grants.canonical_authority()
        report = enforcement.enforce_native_controller_hook(
            hook_input,
            state,
            base_report,
            observed_hook_definition_sha256=observed_hook_definition_sha256,
            observed_hook_registration_sha256=observed_hook_registration_sha256,
            observed_store_identity_sha256=grants.store_identity_sha256,
            canonical_authority=authority,
            qualification_owner_context=qualification_owner_context,
        )
        claimed_action: tuple[str, str, str] | None = None
        native = report.get("native_controller") if isinstance(report, Mapping) else None
        if (
            event_name == "PreToolUse"
            and report.get("decision") == "ALLOW"
            and report.get("mutating") is True
            and isinstance(binding, Mapping)
            and isinstance(native, Mapping)
            and native.get("matched") is True
        ):
            pretool_event_sha256 = enforcement._sha(
                {
                    "session_id": hook_input.get("session_id"),
                    "turn_id": hook_input.get("turn_id"),
                    "tool_name": hook_input.get("tool_name"),
                    "tool_use_id": hook_input.get("tool_use_id"),
                    "tool_input_sha256": report.get("tool_input_sha256"),
                    "binding_sha256": binding.get("binding_sha256"),
                }
            )
            claimed = grants.claim_action(
                binding,
                pretool_event_sha256=pretool_event_sha256,
                tool_use_id=str(hook_input.get("tool_use_id")),
            )
            if claimed.get("status") != "CLAIMED":
                report = _deny_grant(
                    enforcement,
                    report,
                    "native_controller:single_use_grant_unavailable",
                )
            else:
                claimed_action = (
                    str(binding.get("action", {}).get("action_sha256")),
                    pretool_event_sha256,
                    str(hook_input.get("tool_use_id")),
                )
                report = dict(report)
                report["native_controller"] = {
                    **dict(native),
                    "grant_state": "DISPATCHED",
                    "pretool_event_sha256": pretool_event_sha256,
                    "tool_use_id": hook_input.get("tool_use_id"),
                }
                report = _reseal(enforcement, report)
                action = binding.get("action", {})
                if not grants.bind_pretool_report(
                    str(action.get("action_sha256")),
                    event_sha256=pretool_event_sha256,
                    report_sha256=str(report.get("report_sha256")),
                ):
                    grants.mark_pretool_outcome_unknown(
                        str(action.get("action_sha256")),
                        event_sha256=pretool_event_sha256,
                        tool_use_id=str(hook_input.get("tool_use_id")),
                    )
                    report = _deny_grant(
                        enforcement,
                        report,
                        "native_controller:pretool_receipt_unavailable",
                    )
        elif (
            event_name == "PostToolUse"
            and report.get("decision") == "OBSERVED"
            and report.get("mutating") is True
            and isinstance(binding, Mapping)
            and isinstance(native, Mapping)
            and native.get("matched") is True
        ):
            outcome, result_sha256, result_payload = _native_result(
                hook_input.get("tool_response")
            )
            action = binding.get("action", {})
            normalized_result = native_result.normalize_native_result(
                result_payload,
                action_kind=action.get("kind"),
                expected_lane_ids=action.get("lane_ids"),
                outcome="completed",
            )
            status = (
                str(hook_input.get("tool_response", {}).get("status", ""))
                .strip()
                .casefold()
                if isinstance(hook_input.get("tool_response"), Mapping)
                else ""
            )
            if (
                outcome == "unknown"
                and status == ""
                and normalized_result is not None
            ):
                outcome = "completed"
            result_binding = (
                normalized_result if outcome == "completed" else None
            )
            completed_result_valid = result_binding is not None
            result_valid = bool(
                completed_result_valid
                if outcome == "completed"
                else status == "unknown"
                if outcome == "unknown"
                else True
            )
            grant = grants.read_action(str(action.get("action_sha256")))
            tool_use_id = str(hook_input.get("tool_use_id"))
            pretool_report_sha256 = (
                grant.get("pretool_report_sha256")
                if isinstance(grant, Mapping)
                else None
            )
            pretool_valid = bool(
                isinstance(grant, Mapping)
                and _valid_pretool_event(
                    data_root,
                    hook_input.get("session_id"),
                    pretool_report_sha256,
                    enforcement=enforcement,
                    action=action,
                    grant=grant,
                    tool_use_id=tool_use_id,
                )
            )
            report = dict(report)
            report["native_controller"] = {
                **dict(native),
                "grant_state": (
                    "POST_OBSERVED"
                    if pretool_valid and result_valid
                    else "OUTCOME_UNKNOWN"
                ),
                "tool_use_id": hook_input.get("tool_use_id"),
                "pretool_report_sha256": pretool_report_sha256,
                "outcome": outcome,
                "result_sha256": result_sha256,
                "result_binding": result_binding,
            }
            if not pretool_valid or not result_valid:
                grants.mark_posttool_outcome_unknown(
                    str(action.get("action_sha256")),
                    tool_use_id=tool_use_id,
                )
                reasons = list(report.get("reason_codes", []))
                reasons.append("native_controller:posttool_grant_unavailable")
                if not pretool_valid:
                    reasons.append("native_controller:pretool_record_unavailable")
                if not result_valid:
                    reasons.append("native_controller:native_result_unavailable")
                report["reason_codes"] = sorted(set(reasons))
                report["status"] = "BLOCKED"
                report = _reseal(enforcement, report)
            else:
                report = _reseal(enforcement, report)
                recorded = grants.record_posttool(
                    binding,
                    tool_use_id=tool_use_id,
                    pretool_report_sha256=str(pretool_report_sha256),
                    outcome=outcome,
                    result_sha256=result_sha256,
                    result_binding=result_binding,
                    report_sha256=str(report.get("report_sha256")),
                )
                if recorded.get("status") not in {"RECORDED", "IDEMPOTENT"}:
                    grants.mark_posttool_outcome_unknown(
                        str(action.get("action_sha256")),
                        tool_use_id=tool_use_id,
                    )
                    report = dict(report)
                    reasons = list(report.get("reason_codes", []))
                    reasons.append("native_controller:posttool_grant_unavailable")
                    report["reason_codes"] = sorted(set(reasons))
                    report["status"] = "BLOCKED"
                    report["native_controller"] = {
                        **dict(report["native_controller"]),
                        "grant_state": "OUTCOME_UNKNOWN",
                    }
                    report = _reseal(enforcement, report)
        if event_name == "SessionStart" and report.get("decision") == "HEALTHY":
            session_health = report.get("session_health")
            if isinstance(session_health, Mapping):
                _atomic_json(_health_path(data_root, hook_input.get("session_id")), session_health)
        report_sha256 = report.get("report_sha256")
        if isinstance(report_sha256, str):
            if report.get("completion_invalidated"):
                _atomic_json(
                    invalidation_path,
                    {
                        "schema": "orch-dork/project-ground-completion-invalidation/v1",
                        "program_sha256": state.get("program_sha256"),
                        "report_sha256": report_sha256,
                        "tool_input_sha256": report.get("tool_input_sha256"),
                        "coverage_class": report.get("coverage_class"),
                    },
                )
            durable_core = {
                "schema": DURABLE_EVENT_SCHEMA,
                "report_schema": report.get("schema"),
                "report_sha256": report_sha256,
                "hook_event_name": report.get("hook_event_name"),
                "decision": report.get("decision"),
                "status": report.get("status"),
                "coverage_class": report.get("coverage_class"),
                "mutating": report.get("mutating"),
                "tool_input_sha256": report.get("tool_input_sha256"),
                "state_sha256": report.get("state_sha256"),
                "completion_invalidated": report.get("completion_invalidated"),
                "reason_codes": report.get("reason_codes", []),
                "identity": report.get("identity", {}),
                "native_controller": report.get("native_controller"),
            }
            durable = {
                **durable_core,
                "durable_record_sha256": enforcement._sha(durable_core),
            }
            _create_only_json(_event_path(data_root, hook_input.get("session_id"), report_sha256), durable)
        if isinstance(binding, Mapping):
            try:
                final_state = _read_json(
                    data_root / "project-ground" / "current.json"
                )
                final_custody_valid = grants.custody_valid()
                final_authority = grants.canonical_authority()
                final_hook_definition_sha256 = owned_file.sha256_owned_file(
                    Path(__file__), max_bytes=MAX_STDIN_BYTES
                )
                final_hook_registration_sha256 = owned_file.sha256_owned_file(
                    Path(__file__).with_name("hooks.json"),
                    max_bytes=MAX_STDIN_BYTES,
                )
            except (OSError, ValueError):
                final_state = None
                final_custody_valid = False
                final_authority = dict(authority)
                final_authority["status"] = "INVALID"
                final_hook_definition_sha256 = None
                final_hook_registration_sha256 = None
            if (
                final_state != state
                or not final_custody_valid
                or final_authority.get("status") != "VERIFIED"
                or final_hook_definition_sha256
                != observed_hook_definition_sha256
                or final_hook_registration_sha256
                != observed_hook_registration_sha256
            ):
                if claimed_action is not None:
                    grants.mark_pretool_outcome_unknown(
                        claimed_action[0],
                        event_sha256=claimed_action[1],
                        tool_use_id=claimed_action[2],
                    )
                invalid_authority = dict(final_authority)
                if (
                    final_state != state
                    or not final_custody_valid
                    or final_authority.get("status") != "VERIFIED"
                ):
                    invalid_authority["status"] = "INVALID"
                report = enforcement.enforce_native_controller_hook(
                    hook_input,
                    state,
                    base_report,
                    observed_hook_definition_sha256=(
                        final_hook_definition_sha256
                    ),
                    observed_hook_registration_sha256=(
                        final_hook_registration_sha256
                    ),
                    observed_store_identity_sha256=(
                        grants.store_identity_sha256
                    ),
                    canonical_authority=invalid_authority,
                    qualification_owner_context=qualification_owner_context,
                )
                return _codex_compatible_output(report), report
        return _codex_compatible_output(report), report
    except Exception as error:
        reason = "Orch Dork project ground READ_ONLY: " + type(error).__name__
        return _fail_output(event_name, reason), None


def main() -> int:
    payload = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(payload) > MAX_STDIN_BYTES:
        output = _fail_output(None, "Orch Dork project ground READ_ONLY: hook input too large")
    else:
        try:
            hook_input = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            hook_input = {}
        output, _ = run(hook_input)
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
