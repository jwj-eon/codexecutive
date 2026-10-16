#!/usr/bin/env python3
"""Provider-free project-adapter boundary for Orch Dork.

Project adapters are declarative data. This module validates their identity,
configuration, checks, protected resources, workspace policy, external systems,
and approval checkpoints. It never executes an adapter command or grants
authority. A separate helper seals all adapter inputs and outputs into the
existing evidence-bundle format.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence


PROGRAM_SCHEMA = "orch-dork/project-adapter-program/v1"
ADAPTER_SCHEMA = "orch-dork/project-adapter/v1"
REPORT_SCHEMA = "orch-dork/project-adapter-report/v1"
POLICY_VERSION = "project-adapter-policy/v1"
# Issue 33 is intentionally consumed through a narrow, optional binding seam.
# The ticket-admission module owns classification and sealing; this adapter only
# checks that a current ticket carries the sealed record at its mutation gates.
TICKET_ADMISSION_SCHEMA = "orch-dork/ticket-admission/v2"
TICKET_ADMISSION_POLICY_VERSION = "classification-policy/v2"
TICKET_ADMISSION_DECISIONS = {
    "ATOMIC_ADMITTED",
    "ORCHESTRATION_PLAN_REQUIRED",
    "REFUSED",
    "RECLASSIFICATION_REQUIRED",
}
TICKET_ADMISSION_IDENTITY_FIELDS = {
    "ticket_id",
    "ticket_spec_sha256",
    "acceptance_criteria_sha256",
    "authority_scope_sha256",
    "writable_scope_sha256",
    "root_task_id",
    "invocation_identity_sha256",
    "classification_evidence_sha256",
    "candidate_lanes_sha256",
}
TICKET_ADMISSION_IDENTITY_OPTIONAL_FIELDS = {"policy_version"}
TICKET_ADMISSION_GATE_TYPES = {
    "implementation.started",
    "ticket.claimed",
    "ticket.completed",
    "implementation.completed",
    "completion",
    "completion.bound",
}
VERIFICATION_KINDS = {"command", "manual_check", "artifact_check"}
APPROVAL_POLICIES = {"never", "on-request", "untrusted"}
RESULT_OUTCOMES = {"PASS", "FAIL", "UNKNOWN", "NOT_RUN"}
CHECKPOINT_OUTCOMES = {"GRANTED", "AUTHORITY_REQUIRED", "NOT_APPLICABLE", "BLOCKED"}
ACTION_OUTCOMES = {"OBSERVED", "NOT_STARTED", "BLOCKED", "UNKNOWN"}
FORBIDDEN_CONFIG_KEY = re.compile(
    r"(?:credential|password|passwd|secret|authorization|access[_-]?token|"
    r"refresh[_-]?token|api[_-]?key|private[_-]?key|cookie)",
    re.IGNORECASE,
)

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


def _load_bundle():
    path = Path(__file__).resolve().with_name("orch_dork_bundle.py")
    spec = importlib.util.spec_from_file_location("orch_dork_bundle", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("evidence bundle module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bundle = _load_bundle()


def _load_ticket_admission():
    """Load the sibling Issue 33 evaluator without making it a hard dependency.

    The project adapter remains usable for historical (pre-Issue-33) callers,
    while a ticket context opts into the strict v2 admission binding below.
    Dynamic loading also keeps source and isolated plugin loads independent.
    """

    path = Path(__file__).resolve().with_name("orch_dork_ticket_admission.py")
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location("orch_dork_ticket_admission", path)
    if spec is None or spec.loader is None:
        return None
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except (ImportError, OSError, RuntimeError, ValueError):
        # A missing/isolated evaluator is represented as an invalid binding once
        # a ticket context is present; it must never silently grant that gate.
        return None


ticket_admission = _load_ticket_admission()


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


def _issue(issues: list[str], issue: str) -> None:
    if issue not in issues:
        issues.append(issue)


def _exact(value: Any, fields: set[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, f"{path}:not_object")
        return False
    for field in sorted(fields - set(value)):
        _issue(issues, f"{path}:missing:{field}")
    for field in sorted(set(value) - fields):
        _issue(issues, f"{path}:unknown:{field}")
    return set(value) == fields


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096


def _digest(value: Any, path: str, issues: list[str]) -> str | None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _issue(issues, f"{path}:sha256_invalid")
        return None
    return value


def _admission_value(program: Mapping[str, Any]) -> tuple[Any, bool]:
    """Return the current ticket admission and whether ticket gating is active.

    ``ticket_admission`` is canonical.  ``admission`` is accepted as a narrow
    compatibility alias because the active controller uses that shorter name.
    A ticket context can also be declared independently (for example while
    reporting a missing admission); in that case the gate is still active.
    """

    if "ticket_admission" in program:
        return program.get("ticket_admission"), True
    if "admission" in program:
        return program.get("admission"), True
    context_keys = {
        "ticket_id",
        "root_task_id",
        "root_thread_id",
        "admission_sha256",
            "admission_events",
            "mutation_events",
            "observed_events",
            "lifecycle_events",
            "events",
        "ticket_context",
    }
    return None, bool(context_keys.intersection(program))


def _admission_events(program: Mapping[str, Any], admission: Mapping[str, Any]) -> list[Any]:
    """Collect explicit lifecycle events without inventing any facts."""

    for key in ("admission_events", "mutation_events", "observed_events", "lifecycle_events", "events"):
        value = program.get(key)
        if value is not None:
            return value if isinstance(value, list) else [value]
    value = admission.get("events")
    return value if isinstance(value, list) else ([] if value is None else [value])


def _admission_identity(admission: Mapping[str, Any]) -> Mapping[str, Any]:
    identity = admission.get("identity")
    return identity if isinstance(identity, Mapping) else {}


def _ticket_program_for_verifier(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project only ticket fields before calling the sibling verifier."""

    names = {
        "ticket_id", "ticket_key", "id", "ticket_spec", "spec", "canonical_spec",
        "ticket_spec_sha256", "spec_sha256", "ticket_spec_hash", "acceptance_criteria",
        "acceptance", "criteria", "acceptance_criteria_sha256", "acceptance_sha256",
        "criteria_sha256", "authority_scope", "authority", "authority_scope_sha256",
        "authority_sha256", "writable_scope", "owned_resources", "writable_resources",
        "writable_scope_sha256", "root_task_id", "root_thread_id", "task_id", "root_id",
        "invocation_identity", "invocation", "invocation_id", "invocation_identity_sha256",
        "invocation_sha256", "classification", "classification_evidence",
        "classification_evidence_sha256", "classification_sha256", "candidate_lanes",
        "lanes", "decomposition", "candidates", "candidate_lanes_sha256", "lanes_sha256",
        "previous_admission", "prior_admission",
    }
    projected = {key: value[key] for key in names if key in value}
    projected["schema"] = "orch-dork/ticket-admission-program/v2"
    return projected


def validate_ticket_admission_binding(
    program: Any,
    *,
    phase: str | None = None,
) -> dict[str, Any]:
    """Validate the adapter's current ticket-bound admission seam.

    This function deliberately does *not* classify work or mint an admission.
    The ticket-admission evaluator remains the sole authority for those
    operations.  The adapter checks only sealed identity/hash continuity at
    implementation start, the first write-mode resource access, and completion.
    Legacy callers with no ticket context retain the Issue 09 behavior.
    """

    value = program if isinstance(program, Mapping) else {}
    admission, gated = _admission_value(value)
    result: dict[str, Any] = {
        "status": "NOT_APPLICABLE" if not gated else "BLOCKED",
        "gated": gated,
        "schema": TICKET_ADMISSION_SCHEMA,
        "policy_version": TICKET_ADMISSION_POLICY_VERSION,
        "admission_sha256": None,
        "ticket_id": value.get("ticket_id"),
        "root_task_id": value.get("root_task_id", value.get("root_thread_id")),
        "events": [],
        "issues": [],
        "blockers": [],
        "binding_status": "NOT_APPLICABLE" if not gated else "MISSING",
        "source_pointer": "project-adapter#ticket-admission",
    }
    if not gated:
        return result

    blockers: list[str] = result["blockers"]
    issues: list[str] = result["issues"]
    if not isinstance(admission, Mapping):
        blockers.append("ticket_admission_missing")
        return result

    schema = admission.get("schema")
    if schema != TICKET_ADMISSION_SCHEMA:
        blockers.append("ticket_admission_schema_mismatch")
    if admission.get("policy_version") != TICKET_ADMISSION_POLICY_VERSION:
        blockers.append("ticket_admission_policy_version_mismatch")
    decision = admission.get("decision")
    if decision not in TICKET_ADMISSION_DECISIONS:
        blockers.append("ticket_admission_decision_invalid")
    if decision not in {"ATOMIC_ADMITTED", "ORCHESTRATION_PLAN_REQUIRED"}:
        blockers.append("ticket_admission_not_admitted")
    elif decision == "ATOMIC_ADMITTED" and admission.get("admitted") is not True:
        blockers.append("ticket_admission_not_admitted")
    elif decision == "ORCHESTRATION_PLAN_REQUIRED" and not isinstance(admission.get("admitted"), bool):
        blockers.append("ticket_admission_admitted_invalid")

    ticket_id = admission.get("ticket_id")
    root_task_id = admission.get("root_task_id", admission.get("root_thread_id"))
    result["ticket_id"] = ticket_id
    result["root_task_id"] = root_task_id
    if not _identifier(ticket_id):
        blockers.append("ticket_admission_ticket_id_invalid")
    if not _identifier(root_task_id):
        blockers.append("ticket_admission_root_task_id_invalid")
    for field in ("ticket_id", "root_task_id", "root_thread_id"):
        supplied = value.get(field)
        if supplied is not None:
            expected = ticket_id if field == "ticket_id" else root_task_id
            if supplied != expected:
                blockers.append(f"ticket_admission_{field}_mismatch")

    identity = _admission_identity(admission)
    allowed_identity_fields = TICKET_ADMISSION_IDENTITY_FIELDS | TICKET_ADMISSION_IDENTITY_OPTIONAL_FIELDS
    if not TICKET_ADMISSION_IDENTITY_FIELDS.issubset(set(identity)):
        missing = sorted(TICKET_ADMISSION_IDENTITY_FIELDS - set(identity))
        for field in missing:
            blockers.append(f"ticket_admission_identity_missing:{field}")
    extra = sorted(set(identity) - allowed_identity_fields)
    if extra:
        for field in extra:
            issues.append(f"ticket_admission_identity_unknown:{field}")
    for field in TICKET_ADMISSION_IDENTITY_FIELDS:
        if field.endswith("sha256"):
            if _SHA256.fullmatch(str(identity.get(field, ""))) is None:
                blockers.append(f"ticket_admission_identity_invalid:{field}")
    admission_sha = admission.get("admission_sha256", admission.get("admission_hash"))
    result["admission_sha256"] = admission_sha
    if _SHA256.fullmatch(str(admission_sha or "")) is None:
        blockers.append("ticket_admission_hash_invalid")
    declared_hash = value.get("admission_sha256", value.get("admission_hash"))
    if declared_hash is not None and declared_hash != admission_sha:
        blockers.append("ticket_admission_hash_mismatch")

    # Prefer the sibling evaluator's canonical verifier when it is available.
    # The generic fallback remains hash/identity based and never creates a
    # success from absent evidence.
    verifier = getattr(ticket_admission, "validate_admission_binding", None)
    # The sibling verifier recomputes a ticket from its full declarative
    # program.  Do that only when this adapter call actually carries those
    # ticket inputs; otherwise the generic hash/identity checks above are the
    # intended narrow interface.
    has_full_ticket_inputs = all(
        key in value
        for key in ("ticket_spec", "acceptance_criteria", "authority_scope", "classification", "candidate_lanes")
    )
    if callable(verifier) and has_full_ticket_inputs:
        try:
            checked = verifier(_ticket_program_for_verifier(value), admission)
        except (TypeError, ValueError, KeyError):
            checked = None
        if isinstance(checked, Mapping):
            for issue in checked.get("issues", []):
                if str(issue) not in issues:
                    issues.append(str(issue))
            for blocker in checked.get("blockers", checked.get("invalidation_reasons", [])):
                if str(blocker) not in blockers:
                    blockers.append(str(blocker))

    events = _admission_events(value, admission)
    result["events"] = events
    event_types: set[str] = set()
    for index, event in enumerate(events):
        path = f"ticket_admission.events[{index}]"
        if not isinstance(event, Mapping):
            issues.append(f"{path}:not_object")
            continue
        event_type = event.get("type", event.get("event"))
        event_types.add(str(event_type))
        event_hash = event.get("admission_sha256", event.get("admission_hash"))
        # ``evaluate_ticket_admission`` emits pending lifecycle placeholders
        # before sealing the final report hash.  They are durable declarations,
        # not observed mutations; only observed/runtime gate events must carry
        # the exact seal here.
        placeholder = event.get("observed") is False or (
            event_hash is None
            and event.get("source_pointer") in {
                "ticket-admission#claim",
                "ticket-admission#decision",
                "ticket-admission#pending",
            }
        )
        if event_type in TICKET_ADMISSION_GATE_TYPES:
            if not placeholder and event_hash != admission_sha:
                blockers.append(f"ticket_admission_event_hash_mismatch:{event_type}")
            if not placeholder and event.get("ticket_id") is not None and event.get("ticket_id") != ticket_id:
                blockers.append(f"ticket_admission_event_ticket_mismatch:{event_type}")
            if not placeholder and not _text(event.get("source_pointer")):
                issues.append(f"{path}:source_pointer_invalid")
        if event_type == "resource.access":
            operation = str(event.get("operation", event.get("mode", ""))).lower()
            if operation in {"write", "create", "modify", "delete", "mutation"}:
                if event_hash != admission_sha:
                    blockers.append("ticket_admission_first_write_hash_mismatch")

    requested_phase = phase if phase is not None else value.get("phase")
    if requested_phase == "post_implementation":
        completion_events = [
            event for event in events
            if isinstance(event, Mapping)
            and event.get("type", event.get("event")) in {"ticket.completed", "implementation.completed", "completion", "completion.bound"}
        ]
        if not completion_events:
            blockers.append("ticket_admission_completion_event_missing")
        elif all(event.get("observed") is False for event in completion_events):
            blockers.append("ticket_admission_completion_not_observed")
    if blockers:
        result["binding_status"] = "REJECTED"
        result["status"] = "BLOCKED"
    elif issues:
        result["binding_status"] = "INVALID"
        result["status"] = "FAIL"
    else:
        result["binding_status"] = "BOUND"
        result["status"] = "PASS"
    return result


# Short aliases make the seam discoverable to controller/adapter integrations
# without exposing a second classifier or admission implementation.
check_ticket_admission_binding = validate_ticket_admission_binding
admission_binding = validate_ticket_admission_binding


def _string_list(value: Any, path: str, issues: list[str], *, empty: bool = True) -> list[str]:
    if not isinstance(value, list):
        _issue(issues, f"{path}:not_array")
        return []
    if not empty and not value:
        _issue(issues, f"{path}:empty")
    result: list[str] = []
    for index, item in enumerate(value):
        if not _text(item):
            _issue(issues, f"{path}[{index}]:invalid")
        else:
            result.append(str(item).strip())
    if len(result) != len(set(result)):
        _issue(issues, f"{path}:duplicates")
    return result


def _reject_sensitive_keys(value: Any, path: str, issues: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if FORBIDDEN_CONFIG_KEY.search(normalized):
                _issue(issues, f"sensitive_field_forbidden:{path}.{key}")
            _reject_sensitive_keys(item, f"{path}.{key}", issues)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive_keys(item, f"{path}[{index}]", issues)


def _verification_rules(value: Any, path: str, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _issue(issues, f"{path}:not_nonempty_array")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, rule in enumerate(value):
        item_path = f"{path}[{index}]"
        _exact(
            rule,
            {"verification_id", "kind", "argv", "target_pointer", "source_pointer"},
            item_path,
            issues,
        )
        item = rule if isinstance(rule, Mapping) else {}
        verification_id = item.get("verification_id")
        if not _identifier(verification_id) or verification_id in seen:
            _issue(issues, f"{item_path}:verification_id_invalid_or_duplicate")
        elif isinstance(verification_id, str):
            seen.add(verification_id)
        kind = item.get("kind")
        if kind not in VERIFICATION_KINDS:
            _issue(issues, f"{item_path}:kind_invalid")
        argv = _string_list(item.get("argv"), f"{item_path}.argv", issues, empty=kind != "command")
        if kind == "command" and not argv:
            _issue(issues, f"{item_path}:command_argv_empty")
        if kind != "command" and argv:
            _issue(issues, f"{item_path}:non_command_has_argv")
        for field in ("target_pointer", "source_pointer"):
            if not _text(item.get(field)):
                _issue(issues, f"{item_path}:{field}_invalid")
        result.append(dict(item))
    return result


def _external_systems(value: Any, path: str, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, f"{path}:not_array")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, system in enumerate(value):
        item_path = f"{path}[{index}]"
        _exact(system, {"system_id", "actions", "customer_visible", "source_pointer"}, item_path, issues)
        item = system if isinstance(system, Mapping) else {}
        system_id = item.get("system_id")
        if not _identifier(system_id) or system_id in seen:
            _issue(issues, f"{item_path}:system_id_invalid_or_duplicate")
        elif isinstance(system_id, str):
            seen.add(system_id)
        _string_list(item.get("actions"), f"{item_path}.actions", issues, empty=False)
        if not isinstance(item.get("customer_visible"), bool):
            _issue(issues, f"{item_path}:customer_visible_invalid")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{item_path}:source_pointer_invalid")
        result.append(dict(item))
    return result


def _checkpoints(value: Any, path: str, system_ids: set[str], issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, f"{path}:not_array")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, checkpoint in enumerate(value):
        item_path = f"{path}[{index}]"
        _exact(
            checkpoint,
            {"checkpoint_id", "system_id", "action", "required", "source_pointer"},
            item_path,
            issues,
        )
        item = checkpoint if isinstance(checkpoint, Mapping) else {}
        checkpoint_id = item.get("checkpoint_id")
        if not _identifier(checkpoint_id) or checkpoint_id in seen:
            _issue(issues, f"{item_path}:checkpoint_id_invalid_or_duplicate")
        elif isinstance(checkpoint_id, str):
            seen.add(checkpoint_id)
        if item.get("system_id") not in system_ids:
            _issue(issues, f"{item_path}:system_id_unknown")
        if not _text(item.get("action")):
            _issue(issues, f"{item_path}:action_invalid")
        if not isinstance(item.get("required"), bool):
            _issue(issues, f"{item_path}:required_invalid")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{item_path}:source_pointer_invalid")
        result.append(dict(item))
    return result


def _grants(value: Any, path: str, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, f"{path}:not_array")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, grant in enumerate(value):
        item_path = f"{path}[{index}]"
        _exact(grant, {"grant_id", "system_id", "actions", "scope_sha256", "source_pointer"}, item_path, issues)
        item = grant if isinstance(grant, Mapping) else {}
        grant_id = item.get("grant_id")
        if not _identifier(grant_id) or grant_id in seen:
            _issue(issues, f"{item_path}:grant_id_invalid_or_duplicate")
        elif isinstance(grant_id, str):
            seen.add(grant_id)
        if not _identifier(item.get("system_id")):
            _issue(issues, f"{item_path}:system_id_invalid")
        _string_list(item.get("actions"), f"{item_path}.actions", issues, empty=False)
        _digest(item.get("scope_sha256"), f"{item_path}.scope_sha256", issues)
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{item_path}:source_pointer_invalid")
        result.append(dict(item))
    return result


def _verification_results(
    value: Any,
    path: str,
    declared: set[str],
    phase: str,
    issues: list[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, f"{path}:not_array")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(value):
        item_path = f"{path}[{index}]"
        _exact(row, {"verification_id", "phase", "outcome", "output_sha256", "source_pointer"}, item_path, issues)
        item = row if isinstance(row, Mapping) else {}
        verification_id = item.get("verification_id")
        if verification_id not in declared or verification_id in seen:
            _issue(issues, f"{item_path}:verification_id_unknown_or_duplicate")
        elif isinstance(verification_id, str):
            seen.add(verification_id)
        if item.get("phase") != phase:
            _issue(issues, f"{item_path}:phase_mismatch")
        if item.get("outcome") not in RESULT_OUTCOMES:
            _issue(issues, f"{item_path}:outcome_invalid")
        output_sha = item.get("output_sha256")
        if item.get("outcome") in {"PASS", "FAIL", "UNKNOWN"}:
            _digest(output_sha, f"{item_path}.output_sha256", issues)
        elif output_sha is not None:
            _issue(issues, f"{item_path}:not_run_has_output")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{item_path}:source_pointer_invalid")
        result.append(dict(item))
    return result


def evaluate_project_adapter(program: Any) -> dict[str, Any]:
    """Validate one project adapter and its provider-free result records."""

    issues: list[str] = []
    blockers: list[str] = []
    _reject_sensitive_keys(program, "$", issues)
    required_program_fields = {
        "schema",
        "evaluation_id",
        "phase",
        "policy_version",
        "requirement",
        "adapter",
        "authority_boundary",
        "workspace_observation",
        "results",
    }
    optional_ticket_fields = {
        # Optional Issue 33 inputs are closed when supplied; leaving them out
        # preserves the historical Issue 09 adapter program shape.
        "ticket_admission",
        "admission",
        "ticket_spec",
        "spec",
        "canonical_spec",
        "ticket_spec_sha256",
        "spec_sha256",
        "ticket_spec_hash",
        "acceptance_criteria",
        "acceptance",
        "criteria",
        "acceptance_criteria_sha256",
        "acceptance_sha256",
        "criteria_sha256",
        "authority_scope",
        "authority",
        "authority_scope_sha256",
        "authority_sha256",
        "writable_scope",
        "owned_resources",
        "writable_resources",
        "writable_scope_sha256",
        "classification",
        "classification_evidence",
        "candidate_lanes",
        "lanes",
        "decomposition",
        "candidates",
        "invocation_identity",
        "invocation",
        "invocation_id",
        "invocation_identity_sha256",
        "invocation_sha256",
        "classification_evidence_sha256",
        "classification_sha256",
        "candidate_lanes_sha256",
        "lanes_sha256",
        "previous_admission",
        "prior_admission",
        "ticket_key",
        "id",
        "task_id",
        "root_id",
        "ticket_id",
        "root_task_id",
        "root_thread_id",
        "admission_sha256",
        "admission_hash",
        "admission_events",
        "mutation_events",
        "observed_events",
        "lifecycle_events",
        "events",
        "ticket_context",
    }
    if not isinstance(program, Mapping):
        _issue(issues, "program:not_object")
    else:
        for field in sorted(required_program_fields - set(program)):
            _issue(issues, f"program:missing:{field}")
        for field in sorted(set(program) - required_program_fields - optional_ticket_fields):
            _issue(issues, f"program:unknown:{field}")
    value = program if isinstance(program, Mapping) else {}
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not _identifier(value.get("evaluation_id")):
        _issue(issues, "program:evaluation_id_invalid")
    phase = value.get("phase")
    if phase not in {"pre_implementation", "post_implementation"}:
        _issue(issues, "program:phase_invalid")
    if value.get("policy_version") != POLICY_VERSION:
        _issue(issues, "program:policy_version_invalid")

    # Evaluate the Issue 33 admission seam before any project-specific checks
    # determine readiness.  Existing callers without ticket context retain the
    # historical adapter contract; once a ticket context is present, every
    # preflight/postflight report is bound to the same sealed admission hash.
    ticket_binding = validate_ticket_admission_binding(value, phase=phase)
    if ticket_binding.get("gated"):
        for blocker in ticket_binding.get("blockers", []):
            _issue(blockers, str(blocker))
        for issue in ticket_binding.get("issues", []):
            _issue(issues, str(issue))

    requirement = value.get("requirement")
    _exact(
        requirement,
        {"required", "expected_adapter_id", "expected_version", "expected_config_sha256", "source_pointer"},
        "requirement",
        issues,
    )
    requirement_value = requirement if isinstance(requirement, Mapping) else {}
    if not isinstance(requirement_value.get("required"), bool):
        _issue(issues, "requirement:required_invalid")
    for field in ("expected_adapter_id", "expected_version"):
        if not _identifier(requirement_value.get(field)):
            _issue(issues, f"requirement:{field}_invalid")
    _digest(requirement_value.get("expected_config_sha256"), "requirement.expected_config_sha256", issues)
    if not _text(requirement_value.get("source_pointer")):
        _issue(issues, "requirement:source_pointer_invalid")

    adapter = value.get("adapter")
    _exact(adapter, {"status", "definition", "source_pointer"}, "adapter", issues)
    adapter_value = adapter if isinstance(adapter, Mapping) else {}
    adapter_status = adapter_value.get("status")
    if adapter_status not in {"available", "unavailable"}:
        _issue(issues, "adapter:status_invalid")
    if not _text(adapter_value.get("source_pointer")):
        _issue(issues, "adapter:source_pointer_invalid")
    definition = adapter_value.get("definition")
    if adapter_status == "unavailable":
        if definition is not None:
            _issue(issues, "adapter:unavailable_has_definition")
        definition_value: dict[str, Any] = {}
        if requirement_value.get("required") is True:
            blockers.append("required_adapter_unavailable")
    else:
        _exact(
            definition,
            {
                "schema",
                "adapter_id",
                "version",
                "project_kind",
                "configuration",
                "configuration_sha256",
                "workspace_root",
                "focused_verification",
                "final_verification",
                "protected_resources",
                "workspace_baseline",
                "external_systems",
                "approval_checkpoints",
                "source_pointer",
            },
            "adapter.definition",
            issues,
        )
        definition_value = definition if isinstance(definition, Mapping) else {}
        if definition_value.get("schema") != ADAPTER_SCHEMA:
            _issue(issues, "adapter.definition:schema_invalid")
        for field in ("adapter_id", "version"):
            if not _identifier(definition_value.get(field)):
                _issue(issues, f"adapter.definition:{field}_invalid")
        if definition_value.get("project_kind") not in {"coding", "non_coding"}:
            _issue(issues, "adapter.definition:project_kind_invalid")
        configuration = definition_value.get("configuration")
        if not isinstance(configuration, Mapping):
            _issue(issues, "adapter.definition.configuration:not_object")
            configuration = {}
        _reject_sensitive_keys(configuration, "adapter.definition.configuration", issues)
        configuration_sha = definition_value.get("configuration_sha256")
        if configuration_sha != _sha256(configuration):
            _issue(issues, "adapter.definition:configuration_sha256_mismatch")
        if not _text(definition_value.get("workspace_root")):
            _issue(issues, "adapter.definition:workspace_root_invalid")
        focused_rules = _verification_rules(
            definition_value.get("focused_verification"),
            "adapter.definition.focused_verification",
            issues,
        )
        final_rules = _verification_rules(
            definition_value.get("final_verification"),
            "adapter.definition.final_verification",
            issues,
        )
        protected_resources = _string_list(
            definition_value.get("protected_resources"),
            "adapter.definition.protected_resources",
            issues,
            empty=False,
        )
        baseline_policy = definition_value.get("workspace_baseline")
        _exact(
            baseline_policy,
            {"required", "algorithm", "dirty_policy", "source_pointer"},
            "adapter.definition.workspace_baseline",
            issues,
        )
        baseline_value = baseline_policy if isinstance(baseline_policy, Mapping) else {}
        if not isinstance(baseline_value.get("required"), bool):
            _issue(issues, "adapter.definition.workspace_baseline:required_invalid")
        if baseline_value.get("algorithm") != "sha256":
            _issue(issues, "adapter.definition.workspace_baseline:algorithm_invalid")
        if baseline_value.get("dirty_policy") not in {"preserve", "clean_required"}:
            _issue(issues, "adapter.definition.workspace_baseline:dirty_policy_invalid")
        if not _text(baseline_value.get("source_pointer")):
            _issue(issues, "adapter.definition.workspace_baseline:source_pointer_invalid")
        systems = _external_systems(
            definition_value.get("external_systems"),
            "adapter.definition.external_systems",
            issues,
        )
        checkpoints = _checkpoints(
            definition_value.get("approval_checkpoints"),
            "adapter.definition.approval_checkpoints",
            {str(item.get("system_id")) for item in systems},
            issues,
        )
        if not _text(definition_value.get("source_pointer")):
            _issue(issues, "adapter.definition:source_pointer_invalid")
        if definition_value.get("adapter_id") != requirement_value.get("expected_adapter_id"):
            blockers.append("adapter_identity_mismatch")
        if definition_value.get("version") != requirement_value.get("expected_version"):
            blockers.append("adapter_version_mismatch")
        if configuration_sha != requirement_value.get("expected_config_sha256"):
            blockers.append("adapter_configuration_mismatch")

    if adapter_status != "available":
        focused_rules = []
        final_rules = []
        protected_resources = []
        baseline_value = {}
        systems = []
        checkpoints = []

    authority_boundary = value.get("authority_boundary")
    _exact(authority_boundary, {"root", "delegated", "source_pointer"}, "authority_boundary", issues)
    boundary_value = authority_boundary if isinstance(authority_boundary, Mapping) else {}
    if not _text(boundary_value.get("source_pointer")):
        _issue(issues, "authority_boundary:source_pointer_invalid")
    normalized_boundaries: dict[str, dict[str, Any]] = {}
    for boundary_name in ("root", "delegated"):
        boundary = boundary_value.get(boundary_name)
        path = f"authority_boundary.{boundary_name}"
        _exact(
            boundary,
            {"sandbox_scope_sha256", "approval_policy", "external_action_grants", "source_pointer"},
            path,
            issues,
        )
        item = boundary if isinstance(boundary, Mapping) else {}
        _digest(item.get("sandbox_scope_sha256"), f"{path}.sandbox_scope_sha256", issues)
        if item.get("approval_policy") not in APPROVAL_POLICIES:
            _issue(issues, f"{path}:approval_policy_invalid")
        grants = _grants(item.get("external_action_grants"), f"{path}.external_action_grants", issues)
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        normalized_boundaries[boundary_name] = {**dict(item), "external_action_grants": grants}
    root_boundary = normalized_boundaries.get("root", {})
    delegated_boundary = normalized_boundaries.get("delegated", {})
    root_grants_by_id = {
        str(grant.get("grant_id")): grant
        for grant in root_boundary.get("external_action_grants", [])
    }
    delegated_grants = delegated_boundary.get("external_action_grants", [])
    delegated_grants_by_id = {
        str(grant.get("grant_id")): grant for grant in delegated_grants
    }
    base_boundary_preserved = all(
        root_boundary.get(field) == delegated_boundary.get(field)
        for field in ("sandbox_scope_sha256", "approval_policy")
    )
    delegated_grants_preserved = True
    for grant in delegated_grants:
        root_grant = root_grants_by_id.get(str(grant.get("grant_id")))
        comparable = {
            key: item for key, item in grant.items() if key != "source_pointer"
        }
        root_comparable = {
            key: item for key, item in (root_grant or {}).items() if key != "source_pointer"
        }
        if root_grant is None or comparable != root_comparable:
            delegated_grants_preserved = False
    boundary_preserved = base_boundary_preserved and delegated_grants_preserved
    authority_narrowed = boundary_preserved and len(delegated_grants) < len(root_grants_by_id)
    if not boundary_preserved:
        blockers.append("delegation_authority_boundary_changed")

    observation = value.get("workspace_observation")
    _exact(
        observation,
        {"status", "workspace_root", "baseline_sha256", "dirty_paths", "source_pointer"},
        "workspace_observation",
        issues,
    )
    observation_value = observation if isinstance(observation, Mapping) else {}
    observation_status = observation_value.get("status")
    if observation_status not in {"known", "unknown"}:
        _issue(issues, "workspace_observation:status_invalid")
    if not _text(observation_value.get("workspace_root")):
        _issue(issues, "workspace_observation:workspace_root_invalid")
    dirty_paths = _string_list(observation_value.get("dirty_paths"), "workspace_observation.dirty_paths", issues)
    if observation_status == "known":
        _digest(observation_value.get("baseline_sha256"), "workspace_observation.baseline_sha256", issues)
    elif observation_value.get("baseline_sha256") is not None or dirty_paths:
        _issue(issues, "workspace_observation:unknown_has_values")
    if not _text(observation_value.get("source_pointer")):
        _issue(issues, "workspace_observation:source_pointer_invalid")
    if adapter_status == "available":
        if observation_value.get("workspace_root") != definition_value.get("workspace_root"):
            blockers.append("workspace_root_mismatch")
        if baseline_value.get("required") is True and observation_status != "known":
            blockers.append("workspace_baseline_unknown")
        if baseline_value.get("dirty_policy") == "clean_required" and dirty_paths:
            blockers.append("workspace_not_clean")

    results = value.get("results")
    _exact(
        results,
        {"focused_verification", "final_verification", "checkpoint_results", "external_action_results", "source_pointer"},
        "results",
        issues,
    )
    results_value = results if isinstance(results, Mapping) else {}
    if not _text(results_value.get("source_pointer")):
        _issue(issues, "results:source_pointer_invalid")
    focused_results = _verification_results(
        results_value.get("focused_verification"),
        "results.focused_verification",
        {str(item.get("verification_id")) for item in focused_rules},
        "focused",
        issues,
    )
    final_results = _verification_results(
        results_value.get("final_verification"),
        "results.final_verification",
        {str(item.get("verification_id")) for item in final_rules},
        "final",
        issues,
    )

    checkpoint_results_value = results_value.get("checkpoint_results")
    if not isinstance(checkpoint_results_value, list):
        _issue(issues, "results.checkpoint_results:not_array")
        checkpoint_results_value = []
    checkpoint_results: list[dict[str, Any]] = []
    checkpoint_by_id = {str(item.get("checkpoint_id")): item for item in checkpoints}
    seen_checkpoints: set[str] = set()
    for index, row in enumerate(checkpoint_results_value):
        path = f"results.checkpoint_results[{index}]"
        _exact(row, {"checkpoint_id", "outcome", "grant_id", "source_pointer"}, path, issues)
        item = row if isinstance(row, Mapping) else {}
        checkpoint_id = item.get("checkpoint_id")
        if checkpoint_id not in checkpoint_by_id or checkpoint_id in seen_checkpoints:
            _issue(issues, f"{path}:checkpoint_id_unknown_or_duplicate")
        elif isinstance(checkpoint_id, str):
            seen_checkpoints.add(checkpoint_id)
        if item.get("outcome") not in CHECKPOINT_OUTCOMES:
            _issue(issues, f"{path}:outcome_invalid")
        if item.get("outcome") == "GRANTED":
            if not _identifier(item.get("grant_id")):
                _issue(issues, f"{path}:grant_id_invalid")
            else:
                checkpoint = checkpoint_by_id.get(str(checkpoint_id), {})
                grant_id = str(item.get("grant_id"))
                grant = root_grants_by_id.get(grant_id)
                delegated_grant = delegated_grants_by_id.get(grant_id)
                if (
                    grant is None
                    or delegated_grant is None
                    or grant.get("system_id") != checkpoint.get("system_id")
                    or checkpoint.get("action") not in grant.get("actions", [])
                ):
                    blockers.append(
                        f"checkpoint_grant_not_root_authorized:{checkpoint_id}"
                    )
        elif item.get("grant_id") is not None:
            _issue(issues, f"{path}:unexpected_grant_id")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        checkpoint_results.append(dict(item))

    action_results_value = results_value.get("external_action_results")
    if not isinstance(action_results_value, list):
        _issue(issues, "results.external_action_results:not_array")
        action_results_value = []
    action_results: list[dict[str, Any]] = []
    declared_actions = {
        (str(system.get("system_id")), action)
        for system in systems
        for action in system.get("actions", [])
    }
    for index, row in enumerate(action_results_value):
        path = f"results.external_action_results[{index}]"
        _exact(
            row,
            {"system_id", "action", "outcome", "grant_id", "result_sha256", "source_pointer"},
            path,
            issues,
        )
        item = row if isinstance(row, Mapping) else {}
        key = (str(item.get("system_id")), item.get("action"))
        if key not in declared_actions:
            _issue(issues, f"{path}:undeclared_external_action")
        if item.get("outcome") not in ACTION_OUTCOMES:
            _issue(issues, f"{path}:outcome_invalid")
        grant_id = item.get("grant_id")
        if item.get("outcome") == "OBSERVED":
            grant = root_grants_by_id.get(str(grant_id))
            delegated_grant = delegated_grants_by_id.get(str(grant_id))
            if grant is None or delegated_grant is None:
                blockers.append(f"external_action_without_root_grant:{key[0]}:{key[1]}")
            elif grant.get("system_id") != key[0] or key[1] not in grant.get("actions", []):
                blockers.append(f"external_action_outside_root_grant:{key[0]}:{key[1]}")
            _digest(item.get("result_sha256"), f"{path}.result_sha256", issues)
        else:
            if item.get("result_sha256") is not None:
                _issue(issues, f"{path}:non_observed_has_result")
        if grant_id is not None and not _identifier(grant_id):
            _issue(issues, f"{path}:grant_id_invalid")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        action_results.append(dict(item))

    focused_by_id = {str(item.get("verification_id")): item for item in focused_results}
    final_by_id = {str(item.get("verification_id")): item for item in final_results}
    if phase == "pre_implementation":
        if focused_results or final_results or checkpoint_results or action_results:
            _issue(issues, "pre_implementation:results_must_be_empty")
    elif adapter_status == "available":
        for rule in focused_rules:
            if str(rule.get("verification_id")) not in focused_by_id:
                blockers.append(f"focused_verification_missing:{rule.get('verification_id')}")
        for rule in final_rules:
            if str(rule.get("verification_id")) not in final_by_id:
                blockers.append(f"final_verification_missing:{rule.get('verification_id')}")
        for checkpoint in checkpoints:
            if checkpoint.get("required") is True and str(checkpoint.get("checkpoint_id")) not in seen_checkpoints:
                blockers.append(f"checkpoint_result_missing:{checkpoint.get('checkpoint_id')}")

    focused_failures = sorted(
        str(row.get("verification_id"))
        for row in focused_results
        if row.get("outcome") != "PASS"
    )
    final_failures = sorted(
        str(row.get("verification_id"))
        for row in final_results
        if row.get("outcome") != "PASS"
    )
    checkpoint_blocks = sorted(
        str(row.get("checkpoint_id"))
        for row in checkpoint_results
        if checkpoint_by_id.get(str(row.get("checkpoint_id")), {}).get("required") is True
        and row.get("outcome") != "GRANTED"
    )
    external_blocks = sorted(
        f"{row.get('system_id')}:{row.get('action')}"
        for row in action_results
        if row.get("outcome") in {"BLOCKED", "UNKNOWN"}
    )

    contract_valid = not issues and not blockers
    implementation_permitted = phase == "pre_implementation" and contract_valid
    if issues:
        status = "FAIL"
        disposition = "REFUSED_PRE_IMPLEMENTATION" if phase == "pre_implementation" else "INVALID_ADAPTER_EVIDENCE"
    elif blockers:
        status = "REFUSED"
        disposition = "REFUSED_PRE_IMPLEMENTATION" if phase == "pre_implementation" else "BLOCKED"
    elif phase == "pre_implementation":
        status = "PASS"
        disposition = "ADAPTER_READY"
    elif focused_failures:
        status = "FAIL"
        disposition = "FOCUSED_VERIFICATION_FAILED"
    elif final_failures:
        status = "FAIL"
        disposition = "FINAL_VERIFICATION_FAILED"
    elif checkpoint_blocks or external_blocks:
        status = "BLOCKED"
        disposition = "EXTERNAL_ACTION_BLOCKED"
    else:
        status = "PASS"
        disposition = "ADAPTER_PASS"

    definition_sha = _sha256(definition_value) if definition_value else None
    outputs = {
        "workspace_observation": dict(observation_value),
        "focused_verification": focused_results,
        "final_verification": final_results,
        "checkpoint_results": checkpoint_results,
        "external_action_results": action_results,
        "ticket_admission": ticket_binding,
    }
    core = {
        "schema": REPORT_SCHEMA,
        "status": status,
        "disposition": disposition,
        "evaluation_id": value.get("evaluation_id"),
        "phase": phase,
        "policy_version": value.get("policy_version"),
        "adapter_required": requirement_value.get("required"),
        "adapter_status": adapter_status,
        "adapter_id": definition_value.get("adapter_id"),
        "adapter_version": definition_value.get("version"),
        "project_kind": definition_value.get("project_kind"),
        "adapter_definition_sha256": definition_sha,
        "configuration_sha256": definition_value.get("configuration_sha256"),
        "protected_resources": protected_resources,
        "workspace_baseline_policy": dict(baseline_value),
        "workspace_baseline_sha256": observation_value.get("baseline_sha256"),
        "dirty_paths": dirty_paths,
        "declared_external_system_ids": sorted(str(item.get("system_id")) for item in systems),
        "declared_checkpoint_ids": sorted(str(item.get("checkpoint_id")) for item in checkpoints),
        "authority_boundary_preserved": boundary_preserved,
        "authority_narrowed": authority_narrowed,
        "authority_broadened": not boundary_preserved,
        "implementation_permitted": implementation_permitted,
        "commands_executed_by_plugin": 0,
        "authority_inferred": False,
        "focused_failures": focused_failures,
        "final_failures": final_failures,
        "checkpoint_blocks": checkpoint_blocks,
        "external_action_blocks": external_blocks,
        "ticket_admission": ticket_binding,
        "ticket_admission_sha256": ticket_binding.get("admission_sha256"),
        "ticket_admission_binding_status": ticket_binding.get("binding_status"),
        "outputs_sha256": _sha256(outputs),
        "evidence_files": {
            "adapter-requirement.json": dict(requirement_value),
            "adapter-definition.json": definition_value if definition_value else {"status": "unavailable"},
            "adapter-boundary.json": dict(boundary_value),
            "adapter-outputs.json": outputs,
        },
        "blockers": sorted(set(blockers)),
        "issues": sorted(issues),
        "evidence_tier": "submitted",
    }
    return {**core, "report_sha256": _sha256(core)}


def build_pre_implementation_program(
    *,
    evaluation_id: str,
    adapter_definition: Mapping[str, Any],
    authority_boundary: Mapping[str, Any],
    workspace_observation: Mapping[str, Any],
    ticket_program: Mapping[str, Any],
    ticket_admission: Mapping[str, Any],
    admission_events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Construct one canonical adapter gate from whole ticket values.

    The ticket evaluator remains the admission authority.  Copying its full
    declarative program here lets ``evaluate_project_adapter`` re-run that
    authority instead of accepting a caller-authored admission alias or a
    translated digest.
    """

    definition = deepcopy(dict(adapter_definition))
    configuration = definition.get("configuration")
    if not isinstance(configuration, Mapping):
        raise ValueError("adapter_definition:configuration_invalid")
    ticket = deepcopy(dict(ticket_program))
    admission = deepcopy(dict(ticket_admission))
    program = {
        "schema": PROGRAM_SCHEMA,
        "evaluation_id": evaluation_id,
        "phase": "pre_implementation",
        "policy_version": POLICY_VERSION,
        "requirement": {
            "required": True,
            "expected_adapter_id": definition.get("adapter_id"),
            "expected_version": definition.get("version"),
            "expected_config_sha256": definition.get(
                "configuration_sha256"
            ),
            "source_pointer": "qualification-pre-spawn#adapter-requirement",
        },
        "adapter": {
            "status": "available",
            "definition": definition,
            "source_pointer": "qualification-pre-spawn#adapter",
        },
        "authority_boundary": deepcopy(dict(authority_boundary)),
        "workspace_observation": deepcopy(dict(workspace_observation)),
        "results": {
            "focused_verification": [],
            "final_verification": [],
            "checkpoint_results": [],
            "external_action_results": [],
            "source_pointer": "qualification-pre-spawn#empty-results",
        },
        "ticket_admission": admission,
        "ticket_id": admission.get("ticket_id"),
        "root_task_id": admission.get("root_task_id"),
        "admission_sha256": admission.get("admission_sha256"),
        "admission_events": [
            deepcopy(dict(row)) for row in admission_events
        ],
    }
    for name in (
        "ticket_spec",
        "acceptance_criteria",
        "authority_scope",
        "writable_scope",
        "invocation_identity",
        "classification",
        "candidate_lanes",
    ):
        if name in ticket:
            program[name] = deepcopy(ticket[name])
    return program


def create_adapter_evidence_bundle(destination: str | Path, program: Any) -> dict[str, Any]:
    """Evaluate then seal adapter identity, configuration, outputs, and report."""

    report = evaluate_project_adapter(program)
    evidence = dict(report.get("evidence_files", {}))
    evidence["adapter-report.json"] = report
    metadata = {
        "kind": "project_adapter",
        "evaluation_id": report.get("evaluation_id"),
        "adapter_id": report.get("adapter_id"),
        "adapter_version": report.get("adapter_version"),
        "adapter_definition_sha256": report.get("adapter_definition_sha256"),
        "configuration_sha256": report.get("configuration_sha256"),
        "outputs_sha256": report.get("outputs_sha256"),
        "report_sha256": report.get("report_sha256"),
        "disposition": report.get("disposition"),
        "evidence_tier": "submitted",
    }
    sealed = bundle.create_bundle(
        destination,
        evidence,
        metadata=metadata,
        bundle_id=f"project-adapter-{report.get('evaluation_id')}",
    )
    return {"report": report, "bundle": sealed}


def _read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a declarative Orch Dork project adapter")
    sub = parser.add_subparsers(dest="command", required=True)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("program")
    seal = sub.add_parser("seal")
    seal.add_argument("program")
    seal.add_argument("destination")
    args = parser.parse_args(argv)
    try:
        program = _read_json(args.program)
        result = evaluate_project_adapter(program) if args.command == "evaluate" else create_adapter_evidence_bundle(args.destination, program)
    except (OSError, json.JSONDecodeError, bundle.BundleError) as exc:
        print(json.dumps({"status": "FAIL", "issues": [str(exc)]}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    report = result if args.command == "evaluate" else result["report"]
    return 0 if report.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
