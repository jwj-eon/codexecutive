#!/usr/bin/env python3
"""Observe and seal the exact root route for the active Codex turn.

The adapter resolves the current rollout from Codex's per-call MCP ``threadId``
metadata (or the equivalent shell task-identity environment), selects only
``session_meta`` and ``turn_context`` records, and uses the last turn context
as authoritative.  It never infers the collaboration surface from a model
catalog or caller-declared plan.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Mapping

import orch_dork_onboarded_profiles as onboarded_profiles
import orch_dork_worker_default as worker_default


CURRENT_TURN_ROUTE_SCHEMA = "orch-dork/current-turn-route/v1"
CURRENT_TURN_ROUTE_VALIDATION_SCHEMA = (
    "orch-dork/current-turn-route-validation/v1"
)
CURRENT_TURN_ROUTE_IDENTITY_SCHEMA = "orch-dork/current-turn-route-identity/v1"
LIVE_ROUTE_AUTHORIZATION_SCHEMA = (
    "orch-dork/live-route-authorization/v1"
)
LIVE_ROUTE_AUTHORIZATION_PROGRAM_SCHEMA = (
    "orch-dork/live-route-authorization-program/v1"
)
LIVE_ROUTE_AUTHORIZATION_VALIDATION_SCHEMA = (
    "orch-dork/live-route-authorization-validation/v1"
)
LIVE_ROUTE_CONTRACT_SCHEMA = "orch-dork/live-route-contract/v1"
LIVE_ROUTE_AUTHORIZATION_IDENTITY_SCHEMA = (
    "orch-dork/live-route-authorization-identity/v1"
)
NATIVE_ROOT_ROUTED_WORKER_ISSUE = (
    "orchestrated:native_root_routed_worker_encrypted"
)
# ADR 0012: a live root that is neither a registered orchestrator nor
# onboarded needs onboarding, and a live task off the V1 surface refuses,
# naming the reason its model's profile records (onboarded_profiles).
ROOT_MODEL_NOT_ONBOARDED_ISSUE = "routing:root_model_not_onboarded"
ROOT_SURFACE_NOT_V1_ISSUE = "routing:root_surface_not_v1"
# The ADR 0010 matrix's refusals, still produced under a historical replay pin.
_REPLAY_POLICY_ISSUES = frozenset(
    {"routing:root_model_unsupported", "routing:root_surface_unsupported"}
)
_REFUSING_ISSUES = _REPLAY_POLICY_ISSUES | {ROOT_MODEL_NOT_ONBOARDED_ISSUE}
_POLICY_ISSUES = _REFUSING_ISSUES | {NATIVE_ROOT_ROUTED_WORKER_ISSUE}

SESSION_ID_ENV = "CODEX_SESSION_ID"
THREAD_ID_ENV = "CODEX_THREAD_ID"
CODEX_HOME_ENV = "CODEX_HOME"
SURFACES = {"v1", "v2"}
MAX_ROLLOUT_BYTES = 128 * 1024 * 1024
MAX_AUTHORIZATION_STATEMENT_BYTES = 16 * 1024

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{7,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _reject_json_constant(value: str) -> None:
    """Reject the non-standard NaN/Infinity constants accepted by json.loads."""

    raise ValueError(f"non-finite JSON constant: {value}")


def _finite_json_float(value: str) -> float:
    """Parse one JSON float without allowing overflow to infinity."""

    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _model_kind(model: Any) -> str | None:
    cleaned = _text(model)
    if cleaned is None:
        return None
    return "routed" if "/" in cleaned else "native"


def _reasoning_effort(payload: Mapping[str, Any]) -> str | None:
    collaboration = payload.get("collaboration_mode")
    if not isinstance(collaboration, Mapping):
        return None
    settings = collaboration.get("settings")
    if not isinstance(settings, Mapping):
        return None
    return _text(settings.get("reasoning_effort"))


def _native_pair(root_kind: Any, worker_kind: Any, surface: Any) -> bool:
    """A native root with a routed worker on V2: its tasks reach the worker encrypted."""

    return root_kind == "native" and worker_kind == "routed" and surface == "v2"


def _route_policy_issues(root_model: Any, root_kind: Any, worker_kind: Any, surface: Any) -> list[str]:
    """The policy refusals an observed route earns.

    Live (ADR 0012), a root must be admitted, a registered orchestrator or an
    onboarded model, and its governed task must run on V1; a task off V1
    names the reason its model's profile records, or the drift since a
    profile that reached V1.  Under a historical replay pin the pinned era's
    root/surface matrix judges the route instead.
    """

    if worker_default.replay_pinned():
        expected_surface = worker_default.expected_root_surface(root_model)
        if expected_surface is None:
            return ["routing:root_model_unsupported"]
        if surface == expected_surface:
            return []
        if _native_pair(root_kind, worker_kind, surface):
            return [NATIVE_ROOT_ROUTED_WORKER_ISSUE]
        return ["routing:root_surface_unsupported"]
    issues = []
    if not worker_default.root_model_accepted(root_model):
        issues.append(ROOT_MODEL_NOT_ONBOARDED_ISSUE)
    if surface != worker_default.GOVERNED_SURFACE:
        if _native_pair(root_kind, worker_kind, surface):
            issues.append(NATIVE_ROOT_ROUTED_WORKER_ISSUE)
        else:
            reason = onboarded_profiles.v1_refusal_reason(worker_default.onboarded_profile(root_model))
            issues.append(ROOT_SURFACE_NOT_V1_ISSUE + ":" + reason)
    return issues


def _expected_policy_issues(
    root_model: Any, root_kind: Any, worker_kind: Any, surface: Any
) -> set[str]:
    """The policy refusals a sealed report must carry.

    The validator recomputes them exactly as the observer does, from the
    registry and this host's onboarded profiles, so a report that omits or
    invents a refusal is inconsistent.  A host without the root's profile
    therefore refuses a report about an onboarded root: it cannot vouch for
    an admission it cannot read.
    """

    return set(_route_policy_issues(root_model, root_kind, worker_kind, surface))


def _disposition(issues: list[str]) -> str:
    if "routing:identity_changed" in issues:
        return "ROUTE_CHANGED"
    if NATIVE_ROOT_ROUTED_WORKER_ISSUE in issues:
        return "RESTART_REQUIRED"
    if any(
        issue in _REFUSING_ISSUES or issue.startswith(ROOT_SURFACE_NOT_V1_ISSUE + ":")
        for issue in issues
    ):
        return "REFUSED"
    if issues:
        return "ROUTING_UNKNOWN"
    return "SPAWN_COMPATIBLE"


def _identity(report: Mapping[str, Any]) -> dict[str, Any]:
    root = report.get("root") if isinstance(report.get("root"), Mapping) else {}
    worker = (
        report.get("worker")
        if isinstance(report.get("worker"), Mapping)
        else {}
    )
    return {
        "schema": CURRENT_TURN_ROUTE_IDENTITY_SCHEMA,
        "session_id": report.get("session_id"),
        "turn_id": report.get("turn_id"),
        "root_model": root.get("model"),
        "root_effort": root.get("effort"),
        "root_kind": root.get("kind"),
        "collaboration_surface": report.get("collaboration_surface"),
        "worker_model": worker.get("model"),
        "worker_effort": worker.get("effort"),
        "worker_kind": worker.get("kind"),
    }


def _live_route_contract(report: Mapping[str, Any]) -> dict[str, Any]:
    """Project one route onto the fields that survive human approval turns."""

    root = report.get("root") if isinstance(report.get("root"), Mapping) else {}
    worker = (
        report.get("worker")
        if isinstance(report.get("worker"), Mapping)
        else {}
    )
    return {
        "schema": LIVE_ROUTE_CONTRACT_SCHEMA,
        "session_id": report.get("session_id"),
        "root": {
            "model": root.get("model"),
            "effort": root.get("effort"),
            "kind": root.get("kind"),
        },
        "collaboration_surface": report.get("collaboration_surface"),
        "worker": {
            "model": worker.get("model"),
            "effort": worker.get("effort"),
            "kind": worker.get("kind"),
        },
    }


def _authorization_statement_sha256(value: Any) -> str | None:
    if not isinstance(value, str) or not value or value.strip() != value:
        return None
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return None
    if len(encoded) > MAX_AUTHORIZATION_STATEMENT_BYTES:
        return None
    return hashlib.sha256(encoded).hexdigest()


def _digest_or_none(value: Any) -> str | None:
    return (
        value
        if isinstance(value, str) and _SHA256.fullmatch(value) is not None
        else None
    )


def _live_route_transition_issues(
    preflight_route: Mapping[str, Any], current_route: Mapping[str, Any]
) -> list[str]:
    """Return semantic drift across the one permitted approval-turn advance."""

    issues: list[str] = []
    if _live_route_contract(preflight_route) != _live_route_contract(current_route):
        issues.append("authorization:route_contract_changed")
    preflight_line = preflight_route.get("source", {}).get("turn_context_line")
    current_line = current_route.get("source", {}).get("turn_context_line")
    if (
        type(preflight_line) is not int
        or type(current_line) is not int
        or current_route.get("turn_id") == preflight_route.get("turn_id")
        or current_line <= preflight_line
    ):
        issues.append("authorization:turn_not_later")
    return issues


def _locate_rollout(
    *, session_id: str | None, codex_home: str | Path | None, issues: list[str]
) -> Path | None:
    if session_id is None or _IDENTIFIER.fullmatch(session_id) is None:
        if "routing:session_id_missing" not in issues:
            issues.append("routing:session_id_missing")
        return None
    home_text = _text(str(codex_home)) if codex_home is not None else None
    if home_text is None:
        issues.append("routing:codex_home_missing")
        return None
    sessions = Path(home_text).expanduser() / "sessions"
    try:
        sessions_root = sessions.resolve(strict=True)
    except OSError:
        issues.append("routing:sessions_root_unreadable")
        return None
    try:
        candidates = sorted(sessions_root.rglob(f"*-{session_id}.jsonl"))
    except OSError:
        issues.append("routing:sessions_root_unreadable")
        return None
    safe: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_relative_to(sessions_root) and resolved.is_file():
            safe.append(resolved)
    if not safe:
        issues.append("routing:session_file_missing")
        return None
    if len(safe) != 1:
        issues.append("routing:session_file_ambiguous")
        return None
    return safe[0]


def observe_current_turn_route(
    *,
    env: Mapping[str, str] | None = None,
    codex_home: str | Path | None = None,
    task_id: str | None = None,
    worker_model: str | None = None,
    worker_effort: str | None = None,
    expected_identity_sha256: str | None = None,
    require_task_id: bool = False,
) -> dict[str, Any]:
    """Read, resolve, and seal the current task's authoritative route.

    ``expected_identity_sha256`` is the pre-spawn drift check.  It binds the
    task, turn, root model/effort, collaboration surface, and governed worker
    route without depending on mutable rollout length.
    """

    source_env = os.environ if env is None else env
    issues: list[str] = []
    metadata_task_id = _text(task_id)
    if metadata_task_id is not None:
        # Codex injects the active threadId into MCP request metadata.  It is
        # per-call authority and must override any stale process-start env.
        session_id = metadata_task_id
        thread_id = metadata_task_id
    elif require_task_id:
        # Installed MCP transport must provide per-call identity. Falling
        # back to a process-start task id there could bind a later caller to
        # the task that happened to start the long-lived server.
        session_id = None
        thread_id = None
        issues.append("routing:mcp_task_id_missing")
    else:
        session_id = _text(source_env.get(SESSION_ID_ENV))
        thread_id = _text(source_env.get(THREAD_ID_ENV))
    if session_id is None:
        issues.append("routing:session_id_missing")
    if thread_id is not None and session_id is not None and thread_id != session_id:
        issues.append("routing:task_identity_conflict")
    if session_id is not None and _IDENTIFIER.fullmatch(session_id) is None:
        issues.append("routing:session_id_invalid")

    resolved_worker_model = _text(worker_model) or _text(
        worker_default.configured_worker_model(source_env)
    )
    resolved_worker_effort = _text(worker_effort) or _text(
        worker_default.configured_worker_effort(source_env)
    )
    if resolved_worker_model is None:
        issues.append("routing:worker_model_missing")
    if resolved_worker_effort is None:
        issues.append("routing:worker_effort_missing")

    selected_count = 0
    selected_hasher = hashlib.sha256()
    selected_hasher.update(b"[")
    valid_session_meta_seen = False
    session_meta_mismatch = False
    last_context: tuple[int, Mapping[str, Any], bytes] | None = None
    selected_sha256 = None
    resolved_codex_home = codex_home or source_env.get(CODEX_HOME_ENV)
    if resolved_codex_home is None and _text(source_env.get("HOME")) is not None:
        resolved_codex_home = Path(str(source_env["HOME"])) / ".codex"
    path = _locate_rollout(
        session_id=session_id,
        codex_home=resolved_codex_home,
        issues=issues,
    )
    if path is not None:
        rollout_complete = True
        rollout_oversized = False
        try:
            if path.stat().st_size > MAX_ROLLOUT_BYTES:
                issues.append("routing:session_file_too_large")
                rollout_oversized = True
            else:
                with path.open("rb") as handle:
                    total_bytes = 0
                    line_number = 0
                    while True:
                        remaining = MAX_ROLLOUT_BYTES - total_bytes
                        raw_line = handle.readline(remaining + 1)
                        if not raw_line:
                            break
                        total_bytes += len(raw_line)
                        if total_bytes > MAX_ROLLOUT_BYTES:
                            issues.append("routing:session_file_too_large")
                            rollout_oversized = True
                            break
                        line_number += 1
                        if not raw_line.strip():
                            continue
                        try:
                            line = raw_line.decode("utf-8", "strict")
                        except UnicodeDecodeError:
                            issues.append("routing:file_unreadable")
                            continue
                        try:
                            record = json.loads(
                                line,
                                parse_constant=_reject_json_constant,
                                parse_float=_finite_json_float,
                            )
                        except (
                            json.JSONDecodeError,
                            OverflowError,
                            RecursionError,
                            ValueError,
                        ):
                            # The last line of a live JSONL may be mid-append.
                            # It is not authoritative until newline-terminated.
                            if not raw_line.endswith(b"\n"):
                                continue
                            issues.append("routing:session_file_malformed")
                            continue
                        if not isinstance(record, Mapping):
                            continue
                        record_type = record.get("type")
                        payload = record.get("payload")
                        if not isinstance(payload, Mapping) or record_type not in {
                            "session_meta",
                            "turn_context",
                        }:
                            continue
                        try:
                            encoded = _canonical(record)
                        except (OverflowError, RecursionError, TypeError, ValueError):
                            issues.append("routing:session_file_malformed")
                            continue
                        if selected_count:
                            selected_hasher.update(b",")
                        selected_hasher.update(encoded)
                        selected_count += 1
                        if record_type == "session_meta":
                            value = _text(payload.get("id"))
                            if value is not None:
                                valid_session_meta_seen = True
                            if value != session_id:
                                session_meta_mismatch = True
                        else:
                            last_context = (line_number, payload, encoded)
        except OSError:
            issues.append("routing:file_unreadable")
            rollout_complete = False
        if rollout_complete and not rollout_oversized and selected_count:
            selected_hasher.update(b"]")
            selected_sha256 = selected_hasher.hexdigest()
        elif not rollout_complete or rollout_oversized:
            valid_session_meta_seen = False
            session_meta_mismatch = False
            last_context = None

    if not valid_session_meta_seen:
        issues.append("routing:session_meta_missing")
    if session_meta_mismatch:
        issues.append("routing:session_meta_mismatch")
    if last_context is None:
        issues.append("routing:no_turn_context")

    turn_id = None
    root_model = None
    root_effort = None
    surface = None
    turn_context_line = None
    turn_context_sha256 = None
    if last_context is not None:
        turn_context_line, payload, encoded = last_context
        turn_context_sha256 = hashlib.sha256(encoded).hexdigest()
        turn_id = _text(payload.get("turn_id"))
        root_model = _text(payload.get("model"))
        root_effort = _reasoning_effort(payload)
        raw_surface = _text(payload.get("multi_agent_version"))
        surface = raw_surface.lower() if raw_surface is not None else None
        if turn_id is None:
            issues.append("routing:turn_id_missing")
        if root_model is None:
            issues.append("routing:root_model_missing")
        if root_effort is None:
            issues.append("routing:root_effort_missing")
        if surface is None:
            issues.append("routing:surface_missing")
        elif surface not in SURFACES:
            issues.append("routing:surface_invalid")

    root_kind = _model_kind(root_model)
    worker_kind = _model_kind(resolved_worker_model)
    observation_issues = bool(issues)
    if not observation_issues:
        issues.extend(_route_policy_issues(root_model, root_kind, worker_kind, surface))

    report: dict[str, Any] = {
        "schema": CURRENT_TURN_ROUTE_SCHEMA,
        "status": "FAIL" if issues else "PASS",
        "disposition": "ROUTING_UNKNOWN",
        "issues": sorted(set(issues)),
        "session_id": session_id,
        "turn_id": turn_id,
        "root": {
            "model": root_model,
            "effort": root_effort,
            "kind": root_kind,
        },
        "collaboration_surface": surface,
        "worker": {
            "model": resolved_worker_model,
            "effort": resolved_worker_effort,
            "kind": worker_kind,
        },
        "source": {
            "pointer": f"session://{session_id}" if session_id else None,
            "selected_records_sha256": selected_sha256,
            "turn_context_line": turn_context_line,
            "turn_context_sha256": turn_context_sha256,
        },
        "identity_sha256": None,
        "expected_identity_sha256": expected_identity_sha256,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "evidence_tier": "runtime-observed",
    }
    report["identity_sha256"] = _sha256(_identity(report))

    if expected_identity_sha256 is not None:
        if (
            not isinstance(expected_identity_sha256, str)
            or _SHA256.fullmatch(expected_identity_sha256) is None
        ):
            report["issues"].append("routing:expected_identity_invalid")
        elif expected_identity_sha256 != report["identity_sha256"]:
            report["issues"].append("routing:identity_changed")
        report["issues"] = sorted(set(report["issues"]))

    report["disposition"] = _disposition(report["issues"])
    report["status"] = "FAIL" if report["issues"] else "PASS"
    report["report_sha256"] = _sha256(report)
    return report


def validate_current_turn_route(value: Any) -> dict[str, Any]:
    """Validate a route seal without rereading the runtime.

    The root/surface policy that judges a seal is the sealed registry's, so
    an observation and its validation agree in every process without an
    exported overlay.
    """

    issues: list[str] = []
    required = {
        "schema",
        "status",
        "disposition",
        "issues",
        "session_id",
        "turn_id",
        "root",
        "collaboration_surface",
        "worker",
        "source",
        "identity_sha256",
        "expected_identity_sha256",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "evidence_tier",
        "report_sha256",
    }
    report = value if isinstance(value, Mapping) else {}
    if not isinstance(value, Mapping):
        issues.append("routing:report_not_object")
    else:
        for key in sorted(required - set(value)):
            issues.append(f"routing:report_missing:{key}")
        for key in sorted(set(value) - required):
            issues.append(f"routing:report_unknown:{key}")
    if report.get("schema") != CURRENT_TURN_ROUTE_SCHEMA:
        issues.append("routing:schema_invalid")
    reported_issues = report.get("issues")
    if not isinstance(reported_issues, list) or any(
        not isinstance(item, str) for item in reported_issues
    ):
        issues.append("routing:issues_invalid")
        reported_issues = []
    elif reported_issues != sorted(set(reported_issues)):
        issues.append("routing:issues_not_canonical")
    expected_status = "FAIL" if reported_issues else "PASS"
    if report.get("status") != expected_status:
        issues.append("routing:status_invalid")
    if report.get("disposition") not in {
        "SPAWN_COMPATIBLE",
        "RESTART_REQUIRED",
        "REFUSED",
        "ROUTE_CHANGED",
        "ROUTING_UNKNOWN",
    }:
        issues.append("routing:disposition_invalid")
    if report.get("disposition") != _disposition(reported_issues):
        issues.append("routing:disposition_inconsistent")
    if report.get("provider_free") is not True or any(
        report.get(field) != 0 for field in ("model_calls", "hosted_calls")
    ):
        issues.append("routing:adapter_boundary_invalid")
    if report.get("evidence_tier") != "runtime-observed":
        issues.append("routing:evidence_tier_invalid")

    for name in ("root", "worker"):
        route = report.get(name)
        if not isinstance(route, Mapping) or set(route) != {
            "model",
            "effort",
            "kind",
        }:
            issues.append(f"routing:{name}_invalid")
            continue
        if _model_kind(route.get("model")) != route.get("kind"):
            issues.append(f"routing:{name}_kind_invalid")
        if _text(route.get("effort")) is None:
            issues.append(f"routing:{name}_effort_invalid")

    root_route = report.get("root") if isinstance(report.get("root"), Mapping) else {}
    worker_route = (
        report.get("worker")
        if isinstance(report.get("worker"), Mapping)
        else {}
    )
    observed_policy_issues = {
        issue
        for issue in reported_issues
        if issue in _POLICY_ISSUES or issue.startswith(ROOT_SURFACE_NOT_V1_ISSUE + ":")
    }
    if observed_policy_issues != _expected_policy_issues(
        root_route.get("model"),
        root_route.get("kind"),
        worker_route.get("kind"),
        report.get("collaboration_surface"),
    ):
        issues.append("routing:route_policy_inconsistent")

    source = report.get("source")
    if not isinstance(source, Mapping) or set(source) != {
        "pointer",
        "selected_records_sha256",
        "turn_context_line",
        "turn_context_sha256",
    }:
        issues.append("routing:source_invalid")
    else:
        for field in ("selected_records_sha256", "turn_context_sha256"):
            digest = source.get(field)
            if digest is not None and (
                not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
            ):
                issues.append(f"routing:source_{field}_invalid")
        line = source.get("turn_context_line")
        if line is not None and (type(line) is not int or line < 1):
            issues.append("routing:source_turn_context_line_invalid")
        expected_pointer = (
            f"session://{report.get('session_id')}"
            if _text(report.get("session_id")) is not None
            else None
        )
        if source.get("pointer") != expected_pointer:
            issues.append("routing:source_pointer_invalid")

    if _text(report.get("session_id")) is None:
        issues.append("routing:session_id_invalid")
    if _text(report.get("turn_id")) is None:
        issues.append("routing:turn_id_invalid")
    if report.get("collaboration_surface") not in SURFACES:
        issues.append("routing:surface_invalid")

    expected_identity = report.get("expected_identity_sha256")
    if expected_identity is not None and (
        not isinstance(expected_identity, str)
        or _SHA256.fullmatch(expected_identity) is None
    ):
        issues.append("routing:expected_identity_invalid")
    elif expected_identity is not None:
        changed = expected_identity != report.get("identity_sha256")
        if changed != ("routing:identity_changed" in reported_issues):
            issues.append("routing:expected_identity_inconsistent")

    identity_digest = report.get("identity_sha256")
    if (
        not isinstance(identity_digest, str)
        or _SHA256.fullmatch(identity_digest) is None
        or identity_digest != _sha256(_identity(report))
    ):
        issues.append("routing:identity_sha256_mismatch")
    supplied_report_digest = report.get("report_sha256")
    sealed = dict(report)
    sealed.pop("report_sha256", None)
    if (
        not isinstance(supplied_report_digest, str)
        or _SHA256.fullmatch(supplied_report_digest) is None
        or supplied_report_digest != _sha256(sealed)
    ):
        issues.append("routing:report_sha256_mismatch")

    normalized = dict(report) if not issues else None
    return {
        "schema": CURRENT_TURN_ROUTE_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(set(issues)),
        "normalized": normalized,
        "identity_sha256": identity_digest if not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _live_authorization_report(
    *,
    operation: str | None,
    issues: list[str],
    scope_sha256: Any,
    statement_sha256: str | None,
    preflight_route: Mapping[str, Any] | None,
    current_route: Mapping[str, Any] | None = None,
    preparation_report_sha256: str | None = None,
) -> dict[str, Any]:
    scope_sha256 = _digest_or_none(scope_sha256)
    statement_sha256 = _digest_or_none(statement_sha256)
    preparation_report_sha256 = _digest_or_none(preparation_report_sha256)
    canonical_issues = sorted(set(issues))
    preflight_contract_sha256 = (
        _sha256(_live_route_contract(preflight_route))
        if isinstance(preflight_route, Mapping)
        else None
    )
    authorized = operation == "authorize" and not canonical_issues
    task_id = (
        current_route.get("session_id")
        if isinstance(current_route, Mapping)
        else (
            preflight_route.get("session_id")
            if isinstance(preflight_route, Mapping)
            else None
        )
    )
    report: dict[str, Any] = {
        "schema": LIVE_ROUTE_AUTHORIZATION_SCHEMA,
        "operation": operation,
        "status": "PASS" if not canonical_issues else "FAIL",
        "disposition": (
            "READY_FOR_ONE_ATTEMPT"
            if authorized
            else (
                "READY_FOR_HUMAN_AUTHORIZATION"
                if operation == "prepare" and not canonical_issues
                else "REFUSED"
            )
        ),
        "issues": canonical_issues,
        "scope_sha256": scope_sha256,
        "authorization_statement_sha256": statement_sha256,
        "preparation_report_sha256": preparation_report_sha256,
        "task_id": task_id,
        "preflight_route": (
            deepcopy(dict(preflight_route))
            if isinstance(preflight_route, Mapping)
            else None
        ),
        "current_route": (
            deepcopy(dict(current_route))
            if isinstance(current_route, Mapping)
            else None
        ),
        "preflight_route_identity_sha256": (
            preflight_route.get("identity_sha256")
            if isinstance(preflight_route, Mapping)
            else None
        ),
        "preflight_route_contract_sha256": preflight_contract_sha256,
        "preflight_turn_id": (
            preflight_route.get("turn_id")
            if isinstance(preflight_route, Mapping)
            else None
        ),
        "authorization_turn_id": (
            current_route.get("turn_id")
            if isinstance(current_route, Mapping)
            else None
        ),
        "dispatch_route_identity_sha256": (
            current_route.get("identity_sha256") if authorized else None
        ),
        "authorization_identity_sha256": None,
        "authorization_bound": authorized,
        "dispatch_permitted": authorized,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "credential_reads": 0,
        "network_calls": 0,
    }
    if authorized:
        report["authorization_identity_sha256"] = _sha256(
            {
                "schema": LIVE_ROUTE_AUTHORIZATION_IDENTITY_SCHEMA,
                "scope_sha256": scope_sha256,
                "authorization_statement_sha256": statement_sha256,
                "preparation_report_sha256": preparation_report_sha256,
                "task_id": task_id,
                "preflight_turn_id": report["preflight_turn_id"],
                "authorization_turn_id": report["authorization_turn_id"],
                "dispatch_route_identity_sha256": report[
                    "dispatch_route_identity_sha256"
                ],
            }
        )
    report["report_sha256"] = _sha256(report)
    return report


def prepare_live_route_authorization(
    *,
    route_report: Any,
    scope_sha256: Any,
    authorization_statement: Any,
) -> dict[str, Any]:
    """Seal the route and statement that a later human approval may bind.

    The exact current-turn identity remains the ordinary pre-spawn drift
    boundary.  This preparation additionally freezes a semantic route contract
    so a separately authorized later turn can obtain its own exact identity
    without treating the expected turn advance as route substitution.
    """

    issues: list[str] = []
    route_validation = validate_current_turn_route(route_report)
    normalized_route = route_validation.get("normalized")
    if route_validation.get("status") != "PASS" or not isinstance(
        normalized_route, Mapping
    ):
        issues.append("authorization:route_report_invalid")
        normalized_route = None
    elif (
        normalized_route.get("status") != "PASS"
        or normalized_route.get("disposition") != "SPAWN_COMPATIBLE"
    ):
        issues.append("authorization:route_not_spawn_compatible")
    elif normalized_route.get("expected_identity_sha256") is not None:
        issues.append("authorization:preflight_route_not_fresh")

    normalized_scope_sha256 = _digest_or_none(scope_sha256)
    if normalized_scope_sha256 is None:
        issues.append("authorization:scope_sha256_invalid")
    statement_sha256 = _authorization_statement_sha256(authorization_statement)
    if statement_sha256 is None:
        issues.append("authorization:statement_invalid")

    return _live_authorization_report(
        operation="prepare",
        issues=issues,
        scope_sha256=normalized_scope_sha256,
        statement_sha256=statement_sha256,
        preflight_route=normalized_route,
    )


def authorize_live_route_transition(
    *,
    preparation_report: Any,
    authorization_statement: Any,
    current_route_report: Any,
) -> dict[str, Any]:
    """Bind exact human authority to the current turn's unchanged route.

    A successful report supplies the *new* exact route identity.  The caller
    must immediately pass that digest to the ordinary current-turn observer
    before its first live effect.  This function never relaxes that strict
    same-turn drift check.
    """

    issues: list[str] = []
    preparation_validation = validate_live_route_authorization(
        preparation_report
    )
    preparation = (
        preparation_validation.get("normalized")
        if preparation_validation.get("status") == "PASS"
        else None
    )
    if (
        not isinstance(preparation, Mapping)
        or preparation.get("operation") != "prepare"
        or preparation.get("status") != "PASS"
        or preparation.get("disposition")
        != "READY_FOR_HUMAN_AUTHORIZATION"
    ):
        issues.append("authorization:preparation_report_invalid")
        preparation = None

    route_validation = validate_current_turn_route(current_route_report)
    current_route = route_validation.get("normalized")
    if route_validation.get("status") != "PASS" or not isinstance(
        current_route, Mapping
    ):
        issues.append("authorization:current_route_report_invalid")
        current_route = None
    elif (
        current_route.get("status") != "PASS"
        or current_route.get("disposition") != "SPAWN_COMPATIBLE"
    ):
        issues.append("authorization:current_route_not_spawn_compatible")
    elif current_route.get("expected_identity_sha256") is not None:
        issues.append("authorization:current_route_not_fresh")

    supplied_statement_sha256 = _authorization_statement_sha256(
        authorization_statement
    )
    if supplied_statement_sha256 is None:
        issues.append("authorization:statement_invalid")
    elif (
        isinstance(preparation, Mapping)
        and supplied_statement_sha256
        != preparation.get("authorization_statement_sha256")
    ):
        issues.append("authorization:statement_mismatch")

    preflight_route = (
        preparation.get("preflight_route")
        if isinstance(preparation, Mapping)
        and isinstance(preparation.get("preflight_route"), Mapping)
        else None
    )
    if isinstance(preflight_route, Mapping) and isinstance(current_route, Mapping):
        issues.extend(_live_route_transition_issues(preflight_route, current_route))

    return _live_authorization_report(
        operation="authorize",
        issues=issues,
        scope_sha256=(
            preparation.get("scope_sha256")
            if isinstance(preparation, Mapping)
            else None
        ),
        statement_sha256=supplied_statement_sha256,
        preflight_route=preflight_route,
        current_route=current_route,
        preparation_report_sha256=(
            preparation.get("report_sha256")
            if isinstance(preparation, Mapping)
            else None
        ),
    )


def validate_live_route_authorization(value: Any) -> dict[str, Any]:
    """Validate one preparation or authorized cross-turn route handoff."""

    issues: list[str] = []
    report = value if isinstance(value, Mapping) else {}
    required = {
        "schema",
        "operation",
        "status",
        "disposition",
        "issues",
        "scope_sha256",
        "authorization_statement_sha256",
        "preparation_report_sha256",
        "task_id",
        "preflight_route",
        "current_route",
        "preflight_route_identity_sha256",
        "preflight_route_contract_sha256",
        "preflight_turn_id",
        "authorization_turn_id",
        "dispatch_route_identity_sha256",
        "authorization_identity_sha256",
        "authorization_bound",
        "dispatch_permitted",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "credential_reads",
        "network_calls",
        "report_sha256",
    }
    if not isinstance(value, Mapping):
        issues.append("authorization:report_not_object")
    else:
        for key in sorted(required - set(value)):
            issues.append(f"authorization:report_missing:{key}")
        for key in sorted(set(value) - required):
            issues.append(f"authorization:report_unknown:{key}")
    if report.get("schema") != LIVE_ROUTE_AUTHORIZATION_SCHEMA:
        issues.append("authorization:schema_invalid")
    operation = report.get("operation")
    if operation not in {"prepare", "authorize"}:
        issues.append("authorization:operation_invalid")

    reported_issues = report.get("issues")
    if not isinstance(reported_issues, list) or any(
        not isinstance(item, str) for item in reported_issues
    ):
        issues.append("authorization:issues_invalid")
        reported_issues = []
    elif reported_issues != sorted(set(reported_issues)):
        issues.append("authorization:issues_not_canonical")
    expected_status = "FAIL" if reported_issues else "PASS"
    if report.get("status") != expected_status:
        issues.append("authorization:status_invalid")
    expected_disposition = (
        "REFUSED"
        if reported_issues
        else (
            "READY_FOR_HUMAN_AUTHORIZATION"
            if operation == "prepare"
            else "READY_FOR_ONE_ATTEMPT"
        )
    )
    if report.get("disposition") != expected_disposition:
        issues.append("authorization:disposition_invalid")

    for field in (
        "scope_sha256",
        "authorization_statement_sha256",
        "preflight_route_identity_sha256",
        "preflight_route_contract_sha256",
    ):
        digest = report.get(field)
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            issues.append(f"authorization:{field}_invalid")
    for field in (
        "preparation_report_sha256",
        "dispatch_route_identity_sha256",
        "authorization_identity_sha256",
    ):
        digest = report.get(field)
        if digest is not None and (
            not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
        ):
            issues.append(f"authorization:{field}_invalid")

    preflight_route = report.get("preflight_route")
    preflight_validation = validate_current_turn_route(preflight_route)
    if preflight_validation.get("status") != "PASS":
        issues.append("authorization:preflight_route_invalid")
    elif isinstance(preflight_route, Mapping):
        if report.get("task_id") != preflight_route.get("session_id"):
            issues.append("authorization:task_id_mismatch")
        if report.get("preflight_turn_id") != preflight_route.get("turn_id"):
            issues.append("authorization:preflight_turn_id_mismatch")
        if report.get("preflight_route_identity_sha256") != preflight_route.get(
            "identity_sha256"
        ):
            issues.append("authorization:preflight_identity_mismatch")
        if report.get("preflight_route_contract_sha256") != _sha256(
            _live_route_contract(preflight_route)
        ):
            issues.append("authorization:route_contract_sha256_mismatch")
        if not reported_issues and (
            preflight_route.get("status") != "PASS"
            or preflight_route.get("disposition") != "SPAWN_COMPATIBLE"
        ):
            issues.append("authorization:preflight_route_not_spawn_compatible")
        if not reported_issues and preflight_route.get(
            "expected_identity_sha256"
        ) is not None:
            issues.append("authorization:preflight_route_not_fresh")

    authorized = operation == "authorize" and not reported_issues
    current_route = report.get("current_route")
    if operation == "prepare":
        if current_route is not None:
            issues.append("authorization:prepare_current_route_present")
        for field in (
            "preparation_report_sha256",
            "authorization_turn_id",
            "dispatch_route_identity_sha256",
            "authorization_identity_sha256",
        ):
            if report.get(field) is not None:
                issues.append(f"authorization:prepare_{field}_present")
    elif operation == "authorize":
        current_validation = validate_current_turn_route(current_route)
        if current_validation.get("status") != "PASS":
            issues.append("authorization:current_route_invalid")
        elif isinstance(current_route, Mapping):
            if report.get("task_id") != current_route.get("session_id"):
                issues.append("authorization:current_task_id_mismatch")
            if report.get("authorization_turn_id") != current_route.get("turn_id"):
                issues.append("authorization:authorization_turn_id_mismatch")
            expected_dispatch = (
                current_route.get("identity_sha256") if authorized else None
            )
            if report.get("dispatch_route_identity_sha256") != expected_dispatch:
                issues.append("authorization:dispatch_identity_mismatch")
            if authorized and (
                current_route.get("status") != "PASS"
                or current_route.get("disposition") != "SPAWN_COMPATIBLE"
            ):
                issues.append("authorization:current_route_not_spawn_compatible")
            if authorized and current_route.get(
                "expected_identity_sha256"
            ) is not None:
                issues.append("authorization:current_route_not_fresh")
            if authorized and isinstance(preflight_route, Mapping):
                issues.extend(
                    _live_route_transition_issues(preflight_route, current_route)
                )
        if report.get("preparation_report_sha256") is None:
            issues.append("authorization:preparation_identity_missing")

    if report.get("authorization_bound") is not authorized:
        issues.append("authorization:bound_flag_invalid")
    if report.get("dispatch_permitted") is not authorized:
        issues.append("authorization:dispatch_flag_invalid")
    if report.get("provider_free") is not True or any(
        report.get(field) != 0
        for field in (
            "model_calls",
            "hosted_calls",
            "credential_reads",
            "network_calls",
        )
    ):
        issues.append("authorization:provider_boundary_invalid")

    if authorized:
        expected_identity = _sha256(
            {
                "schema": LIVE_ROUTE_AUTHORIZATION_IDENTITY_SCHEMA,
                "scope_sha256": report.get("scope_sha256"),
                "authorization_statement_sha256": report.get(
                    "authorization_statement_sha256"
                ),
                "preparation_report_sha256": report.get(
                    "preparation_report_sha256"
                ),
                "task_id": report.get("task_id"),
                "preflight_turn_id": report.get("preflight_turn_id"),
                "authorization_turn_id": report.get("authorization_turn_id"),
                "dispatch_route_identity_sha256": report.get(
                    "dispatch_route_identity_sha256"
                ),
            }
        )
        if report.get("authorization_identity_sha256") != expected_identity:
            issues.append("authorization:identity_sha256_mismatch")
    elif report.get("authorization_identity_sha256") is not None:
        issues.append("authorization:refused_identity_present")

    supplied_report_sha256 = report.get("report_sha256")
    sealed = dict(report)
    sealed.pop("report_sha256", None)
    if (
        not isinstance(supplied_report_sha256, str)
        or _SHA256.fullmatch(supplied_report_sha256) is None
        or supplied_report_sha256 != _sha256(sealed)
    ):
        issues.append("authorization:report_sha256_mismatch")

    normalized = deepcopy(dict(report)) if not issues else None
    return {
        "schema": LIVE_ROUTE_AUTHORIZATION_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(set(issues)),
        "normalized": normalized,
        "authorization_identity_sha256": (
            report.get("authorization_identity_sha256") if not issues else None
        ),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "credential_reads": 0,
        "network_calls": 0,
    }


def evaluate_live_route_authorization(
    program: Any, *, route_report: Any
) -> dict[str, Any]:
    """Evaluate one closed prepare/authorize program against a live route."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    if not isinstance(program, Mapping):
        issues.append("authorization:program_not_object")
    else:
        for key in sorted({"schema", "operation", "payload"} - set(program)):
            issues.append(f"authorization:program_missing:{key}")
        for key in sorted(set(program) - {"schema", "operation", "payload"}):
            issues.append(f"authorization:program_unknown:{key}")
    if value.get("schema") != LIVE_ROUTE_AUTHORIZATION_PROGRAM_SCHEMA:
        issues.append("authorization:program_schema_invalid")
    operation = value.get("operation")
    if operation not in {"prepare", "authorize"}:
        issues.append("authorization:program_operation_invalid")
        operation = None
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        issues.append("authorization:program_payload_invalid")
        payload = {}
    expected_payload_keys = {
        "prepare": {"scope_sha256", "authorization_statement"},
        "authorize": {"preparation_report", "authorization_statement"},
    }.get(operation, set())
    for key in sorted(expected_payload_keys - set(payload)):
        issues.append(f"authorization:payload_missing:{key}")
    for key in sorted(set(payload) - expected_payload_keys):
        issues.append(f"authorization:payload_unknown:{key}")

    if not issues and operation == "prepare":
        return prepare_live_route_authorization(
            route_report=route_report,
            scope_sha256=payload.get("scope_sha256"),
            authorization_statement=payload.get("authorization_statement"),
        )
    if not issues and operation == "authorize":
        return authorize_live_route_transition(
            preparation_report=payload.get("preparation_report"),
            authorization_statement=payload.get("authorization_statement"),
            current_route_report=route_report,
        )

    route_validation = validate_current_turn_route(route_report)
    normalized_route = route_validation.get("normalized")
    preparation = payload.get("preparation_report")
    preflight_route = (
        preparation.get("preflight_route")
        if isinstance(preparation, Mapping)
        and isinstance(preparation.get("preflight_route"), Mapping)
        else (normalized_route if operation == "prepare" else None)
    )
    return _live_authorization_report(
        operation=operation,
        issues=issues,
        scope_sha256=(
            payload.get("scope_sha256")
            if operation == "prepare"
            else (
                preparation.get("scope_sha256")
                if isinstance(preparation, Mapping)
                else None
            )
        ),
        statement_sha256=_authorization_statement_sha256(
            payload.get("authorization_statement")
        ),
        preflight_route=preflight_route,
        current_route=(normalized_route if operation == "authorize" else None),
        preparation_report_sha256=(
            preparation.get("report_sha256")
            if isinstance(preparation, Mapping)
            else None
        ),
    )
