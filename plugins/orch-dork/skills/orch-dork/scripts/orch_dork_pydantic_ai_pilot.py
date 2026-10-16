#!/usr/bin/env python3
"""Optional PydanticAI adapter pilot beneath canonical Orch Dork authority.

The module imports no third-party package at load time.  A live caller may use
the current PydanticAI ``Agent`` API; provider-free tests inject the same narrow
factory seam.  PydanticAI may shape a model response, but only Orch Dork's
standard-library TaskSpecV2 and HandoffReceiptV1 validators accept it.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:  # pragma: no cover - isolated direct-file loading.
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault(name, module)
        spec.loader.exec_module(module)
        return module


contracts = _load_sibling("orch_dork_adaptive_contracts")
hostile = _load_sibling("orch_dork_hostile_input")
PROFILE = hostile.PROFILE

PROGRAM_SCHEMA = "orch-dork/pydantic-ai-pilot-program/v1"
REPORT_SCHEMA = "orch-dork/pydantic-ai-pilot-report/v1"
PILOT_VERSION = "pydantic-ai-pilot/v1"

_PROGRAM_FIELDS = frozenset(
    {
        "schema",
        "pilot_id",
        "mode",
        "model_id",
        "prompt",
        "task_spec",
        "output_contract",
        "history_policy",
        "retry_policy",
    }
)
_RETRY_FIELDS = frozenset(
    {
        "owner",
        "tool_retries",
        "output_retries",
        "provider_retries",
        "fallbacks",
    }
)
_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hostile.canonicalize_bounded_json(raw, profile=PROFILE, batch=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _closed(value: Any, fields: frozenset[str], label: str, issues: list[str]) -> dict:
    if not isinstance(value, Mapping):
        _issue(issues, f"{label}:type_invalid")
        return {}
    result = dict(value)
    for field in sorted(fields - set(result)):
        _issue(issues, f"{label}:missing_field:{field}")
    for field in sorted(set(result) - fields):
        _issue(issues, f"{label}:unknown_field:{field}")
    return result


def _text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= PROFILE.max_string_bytes
    )


def _dependency_available() -> bool:
    try:
        return importlib.util.find_spec("pydantic_ai") is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _agent_factory(model: Any, **kwargs: Any):
    module = importlib.import_module("pydantic_ai")
    return module.Agent(model, **kwargs)


def _report(
    *,
    mode: str | None,
    status: str,
    decision: str,
    issues: list[str],
    program_sha256: str | None,
    task_spec_sha256: str | None = None,
    handoff_report: Mapping[str, Any] | None = None,
    adapter_calls: int = 0,
    dependency_available: bool = False,
) -> dict[str, Any]:
    provider_free = mode == "provider_free_fixture"
    valid_handoff = handoff_report is not None and handoff_report.get("valid") is True
    core = {
        "schema": REPORT_SCHEMA,
        "pilot_version": PILOT_VERSION,
        "status": status,
        "decision": decision,
        "issues": sorted(set(issues)),
        "program_sha256": program_sha256,
        "task_spec_sha256": task_spec_sha256,
        "handoff_sha256": handoff_report.get("digest") if valid_handoff else None,
        "handoff_receipt": handoff_report.get("normalized") if valid_handoff else None,
        "canonical_validator": "HandoffReceiptV1",
        "dependency_available": dependency_available,
        "dependency_required": False,
        "adapter_calls": adapter_calls,
        "model_calls": 0 if provider_free else adapter_calls,
        "hosted_calls": 0 if provider_free else None,
        "hosted_calls_known": provider_free,
        "retries": 0,
        "fallbacks": 0,
        "history_retained": False,
        "topology_authority": False,
        "budget_authority": False,
        "completion_authority": False,
        "provider_retry_evidence_tier": "submitted",
        "provider_free": provider_free,
    }
    return {**core, "report_sha256": _sha(core)}


def run_pydantic_ai_pilot(
    program: Any,
    *,
    agent_factory: Callable[..., Any] | None = None,
    availability_probe: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run one no-history, zero-agent-retry structured-output pilot call."""

    issues: list[str] = []
    try:
        program_sha256 = _sha(program)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _report(
            mode=None,
            status="FAIL",
            decision="CONFIGURATION_REJECTED",
            issues=["program:hostile_or_noncanonical"],
            program_sha256=None,
        )
    value = _closed(program, _PROGRAM_FIELDS, "program", issues)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not isinstance(value.get("pilot_id"), str) or _ID.fullmatch(
        value.get("pilot_id", "")
    ) is None:
        _issue(issues, "program:pilot_id_invalid")
    mode = value.get("mode")
    if mode not in {"provider_free_fixture", "live_pilot"}:
        _issue(issues, "program:mode_invalid")
        mode = None
    if not _text(value.get("model_id")):
        _issue(issues, "program:model_id_invalid")
    if not _text(value.get("prompt")):
        _issue(issues, "program:prompt_invalid")
    if value.get("output_contract") != "HandoffReceiptV1":
        _issue(issues, "output_contract_invalid")
    if value.get("history_policy") != "none":
        _issue(issues, "history_policy_invalid")
    retry = _closed(value.get("retry_policy"), _RETRY_FIELDS, "retry_policy", issues)
    if retry.get("owner") != "orch_dork_controller":
        _issue(issues, "retry_owner_invalid")
    if any(
        retry.get(field) != 0
        for field in (
            "tool_retries",
            "output_retries",
            "provider_retries",
            "fallbacks",
        )
    ):
        _issue(issues, "retry_policy_not_zero")

    task_report = contracts.validate_task_spec(value.get("task_spec"))
    if not task_report.get("valid"):
        _issue(issues, "task_spec_invalid")
    task_digest = task_report.get("digest") if task_report.get("valid") else None
    if issues:
        return _report(
            mode=mode,
            status="FAIL",
            decision="CONFIGURATION_REJECTED",
            issues=issues,
            program_sha256=program_sha256,
            task_spec_sha256=task_digest,
        )

    if mode == "provider_free_fixture" and agent_factory is None:
        return _report(
            mode=mode,
            status="FAIL",
            decision="CONFIGURATION_REJECTED",
            issues=["fixture_agent_factory_required"],
            program_sha256=program_sha256,
            task_spec_sha256=task_digest,
        )
    available = agent_factory is not None or (
        availability_probe or _dependency_available
    )()
    if not available:
        return _report(
            mode=mode,
            status="UNAVAILABLE",
            decision="DEPENDENCY_UNAVAILABLE",
            issues=["pydantic_ai_not_installed"],
            program_sha256=program_sha256,
            task_spec_sha256=task_digest,
            dependency_available=False,
        )

    factory = agent_factory or _agent_factory
    retry_budget = {"tools": 0, "output": 0}
    try:
        agent = factory(
            value["model_id"],
            output_type=dict[str, object],
            retries=retry_budget,
            tools=(),
        )
        result = agent.run_sync(value["prompt"], retries=retry_budget)
    except Exception:  # The boundary sanitizes provider/library exception text.
        return _report(
            mode=mode,
            status="FAIL",
            decision="CALL_FAILED",
            issues=["agent_call_failed"],
            program_sha256=program_sha256,
            task_spec_sha256=task_digest,
            adapter_calls=1,
            dependency_available=True,
        )

    output = getattr(result, "output", None)
    if hasattr(output, "model_dump") and callable(output.model_dump):
        output = output.model_dump(mode="json")
    handoff_report = contracts.validate_handoff_receipt(
        output, task_spec=value["task_spec"]
    )
    if not handoff_report.get("valid"):
        return _report(
            mode=mode,
            status="FAIL",
            decision="INVALID_HANDOFF",
            issues=list(handoff_report.get("issues", ["handoff_invalid"])),
            program_sha256=program_sha256,
            task_spec_sha256=task_digest,
            adapter_calls=1,
            dependency_available=True,
        )
    return _report(
        mode=mode,
        status="PASS",
        decision="VALID_HANDOFF",
        issues=[],
        program_sha256=program_sha256,
        task_spec_sha256=task_digest,
        handoff_report=handoff_report,
        adapter_calls=1,
        dependency_available=True,
    )


__all__ = [
    "PILOT_VERSION",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "run_pydantic_ai_pilot",
]
