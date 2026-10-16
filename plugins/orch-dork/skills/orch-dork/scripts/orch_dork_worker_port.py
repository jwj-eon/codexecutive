#!/usr/bin/env python3
"""Provider-free integration boundary for the Issue 30 worker port.

The transport module owns the canonical public wire format.  Workspace and
adapter modules remain independently useful, but this boundary is the only MCP
projection: it validates canonical inputs, performs the two documented legacy
capability-name translations for the internal adapter, and returns a closed
report.  It never contacts a model or route, executes a command, creates a
worktree, applies a patch, changes a provider, or promotes a model.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


def _load_sibling(name: str):
    """Load a sibling when the MCP policy itself was loaded by file path."""

    try:
        return __import__(name)
    except ImportError:
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        previous = sys.modules.get(name)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
            raise
        return module


adapter = _load_sibling("orch_dork_worker_adapter")
transport = _load_sibling("orch_dork_worker_transport")
workspace = _load_sibling("orch_dork_worker_workspace")


PROGRAM_SCHEMA = "orch-dork/worker-port-program/v1"
REPORT_SCHEMA = "orch-dork/worker-port-report/v1"
POLICY_VERSION = "issue30-worker-port-policy/v1"

OPERATIONS = {
    "validate_call",
    "validate_result",
    "validate_manifest",
    "evaluate_capabilities",
    "evaluate_adapter",
    "evaluate_workspace",
    "validate_evidence",
    "evaluate_qualification",
    "evaluate_activation",
}

_PROGRAM_FIELDS = {"schema", "program_id", "operation", "payload"}
_EVIDENCE_FIELDS = {
    "schema",
    "evidence_id",
    "sections",
    "section_hashes",
    "bundle_sha256",
    "excluded_fields",
}
_CAPABILITY_ALIASES = {"edit": "edit_patch", "test": "focused_test"}
_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|credential|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|private[_-]?key|raw[_-]?authorization|"
    r"authorization[_-]?material|private[_-]?reasoning|chain[_-]?of[_-]?thought|"
    r"session[_-]?(?:body|bodies)|copied[_-]?session|request[_-]?body|"
    r"response[_-]?body|endpoint|base[_-]?url)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?:-----BEGIN [^-]*PRIVATE KEY-----|\bBearer\s+\S+|"
    r"\b(?:sk|gh[pousr]|xox[baprs])[-_][A-Za-z0-9_-]{8,}|"
    r"\bAKIA[0-9A-Z]{12,})",
    re.IGNORECASE,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], issue: str) -> None:
    if issue not in issues:
        issues.append(issue)


def _exact(value: Any, fields: set[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, path + ":not_object")
        return False
    for key in sorted(fields - set(value)):
        _issue(issues, path + ":missing:" + key)
    for key in sorted(set(value) - fields):
        _issue(issues, path + ":unknown:" + str(key))
    return set(value) == fields


def _sensitive_paths(value: Any, path: str = "payload") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if _SENSITIVE_KEY.search(str(key)):
                found.append(child_path)
            found.extend(_sensitive_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_sensitive_paths(child, f"{path}[{index}]"))
    elif isinstance(value, str) and _SENSITIVE_VALUE.search(value):
        found.append(path)
    return sorted(set(found))


def _mapped_capabilities(values: Sequence[Any]) -> list[str]:
    result = []
    for value in values:
        mapped = _CAPABILITY_ALIASES.get(str(value), str(value))
        if mapped not in result:
            result.append(mapped)
    return sorted(result)


def _adapter_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Project the strict transport manifest into the inert adapter shape."""

    quantization = manifest.get("quantization", {})
    runtime = manifest.get("runtime", {})
    return {
        "schema": adapter.MANIFEST_SCHEMA,
        "logical_model_id": manifest.get("logical_model_id"),
        "served_names": deepcopy(manifest.get("served_names")),
        "checkpoint": {
            "revision": manifest.get("checkpoint_revision"),
            "weight_digest": manifest.get("weight_digest_sha256"),
        },
        "limits": {
            "context_tokens": manifest.get("context_limit_tokens"),
            "output_tokens": manifest.get("output_limit_tokens"),
        },
        "protocols": deepcopy(manifest.get("protocols")),
        "capabilities": _mapped_capabilities(manifest.get("capabilities", [])),
        "quantization": {
            "kind": quantization.get("scheme") if isinstance(quantization, Mapping) else None,
            "bits": quantization.get("bits") if isinstance(quantization, Mapping) else None,
        },
        "runtime": {
            "kind": runtime.get("name") if isinstance(runtime, Mapping) else None,
            "version": runtime.get("version") if isinstance(runtime, Mapping) else None,
        },
        "allowed_tool_profiles": deepcopy(manifest.get("allowed_tool_profiles")),
    }


def _adapter_call(call: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(call))
    result["required_capabilities"] = _mapped_capabilities(
        call.get("required_capabilities", [])
    )
    return result


def _adapter_profile(profile_id: str) -> dict[str, Any]:
    profile = transport.CAPABILITY_PROFILES.get(profile_id, {})
    return {
        "schema": adapter.CAPABILITY_SCHEMA,
        "name": profile_id,
        "capabilities": _mapped_capabilities(profile.get("required_capabilities", [])),
    }


def _evaluate_adapter(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    fields = {
        "adapter_kind",
        "adapter_id",
        "call",
        "manifest",
        "requested_profile",
        "route",
        "response",
        "lifecycle",
    }
    if not isinstance(payload, Mapping):
        return {"status": "FAIL", "issues": ["adapter_payload:not_object"]}
    for key in sorted(set(payload) - fields):
        _issue(issues, "adapter_payload:unknown:" + str(key))
    for key in ("adapter_kind", "adapter_id", "call", "manifest", "requested_profile"):
        if key not in payload:
            _issue(issues, "adapter_payload:missing:" + key)

    call_report = transport.validate_worker_call(payload.get("call"))
    manifest_report = transport.validate_model_manifest(payload.get("manifest"))
    profile_id = payload.get("requested_profile")
    capability_report = transport.evaluate_capability_compatibility(
        {
            "schema": transport.CAPABILITY_PROGRAM_SCHEMA,
            "program_id": "worker-port-adapter-capabilities",
            "requested_profile": profile_id,
            "required_capabilities": (
                payload.get("call", {}).get("required_capabilities", [])
                if isinstance(payload.get("call"), Mapping)
                else []
            ),
            "manifest": payload.get("manifest"),
        }
    )
    for name, report in (
        ("call", call_report),
        ("manifest", manifest_report),
        ("capability", capability_report),
    ):
        if report.get("status") != "PASS":
            issues.extend(f"{name}:{item}" for item in report.get("issues", []))

    adapter_report: dict[str, Any] = {
        "status": "FAIL",
        "issues": ["adapter:canonical_prerequisite_failed"],
        "contacted": False,
        "commands_executed": 0,
        "model_calls": 0,
    }
    if not issues and isinstance(profile_id, str):
        normalized = {
            "schema": adapter.PROGRAM_SCHEMA,
            "adapter_kind": payload.get("adapter_kind"),
            "adapter_id": payload.get("adapter_id"),
            "call": _adapter_call(call_report["canonical"]),
            "manifest": _adapter_manifest(manifest_report["canonical"]),
            "capability_profile": _adapter_profile(profile_id),
            "response": deepcopy(payload.get("response", {})),
            "lifecycle": deepcopy(payload.get("lifecycle", {})),
        }
        if payload.get("route") is not None:
            normalized["route"] = deepcopy(payload.get("route"))
        adapter_report = adapter.evaluate_worker_adapter(normalized)
        if adapter_report.get("status") != "PASS":
            issues.extend("adapter:" + item for item in adapter_report.get("issues", []))

    return {
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "call": call_report,
        "manifest": manifest_report,
        "capabilities": capability_report,
        "adapter": adapter_report,
        "capability_aliases": deepcopy(_CAPABILITY_ALIASES),
        "canonical_contract": "transport",
        "contacted": False,
        "commands_executed": 0,
        "model_calls": 0,
    }


def _validate_evidence(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    _exact(payload, _EVIDENCE_FIELDS, "evidence", issues)
    value = payload if isinstance(payload, Mapping) else {}
    sections = value.get("sections") if isinstance(value.get("sections"), Mapping) else {}
    hashes = value.get("section_hashes") if isinstance(value.get("section_hashes"), Mapping) else {}
    if set(sections) != set(adapter.EVIDENCE_SECTIONS):
        _issue(issues, "evidence:section_set_mismatch")
    if set(hashes) != set(adapter.EVIDENCE_SECTIONS):
        _issue(issues, "evidence:hash_set_mismatch")
    for name in adapter.EVIDENCE_SECTIONS:
        if sections.get(name) is None:
            _issue(issues, "evidence:null_section:" + name)

    call_report = transport.validate_worker_call(sections.get("call"))
    manifest_report = transport.validate_model_manifest(sections.get("manifest"))
    profile_report = transport.validate_capability_profile(
        sections.get("capability_profile")
    )
    for name, report in (
        ("call", call_report),
        ("manifest", manifest_report),
        ("profile", profile_report),
    ):
        if report.get("status") != "PASS":
            issues.extend(f"evidence:{name}:{item}" for item in report.get("issues", []))

    call = call_report.get("canonical") if call_report.get("status") == "PASS" else {}
    if call and sections.get("assignment") != call.get("assignment"):
        _issue(issues, "evidence:assignment_contradiction")
    if call and sections.get("base_revision") != call.get("base_revision"):
        _issue(issues, "evidence:base_revision_contradiction")

    patch = sections.get("patch") if isinstance(sections.get("patch"), Mapping) else {}
    if patch.get("applied") is not False:
        _issue(issues, "evidence:patch_application_forbidden")
    diff = patch.get("diff")
    diff_sha = patch.get("diff_sha256")
    if not isinstance(diff, str) or not diff:
        _issue(issues, "evidence:patch_missing")
    elif diff_sha != hashlib.sha256(diff.encode("utf-8")).hexdigest():
        _issue(issues, "evidence:patch_hash_mismatch")

    subreport = adapter.validate_worker_evidence(value)
    if subreport.get("status") != "PASS":
        issues.extend(subreport.get("issues", []))
    return {
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "verified": not issues,
        "bundle_sha256": value.get("bundle_sha256") if not issues else None,
        "call": call_report,
        "manifest": manifest_report,
        "capability_profile": profile_report,
        "adapter_evidence": subreport,
    }


def _paired_qualification(payload: Any) -> dict[str, Any]:
    base = adapter.evaluate_worker_qualification(payload)
    issues = list(base.get("issues", []))
    value = payload if isinstance(payload, Mapping) else {}
    rows = value.get("runs", [])
    if not isinstance(rows, list):
        rows = []
    groups: dict[tuple[Any, ...], dict[str, int]] = {}
    required_row_fields = {
        "revision",
        "prompt_sha256",
        "budgets_sha256",
        "tools_sha256",
        "evaluator_version",
    }
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            _issue(issues, f"qualification:runs[{index}]:not_object")
            continue
        model = row.get("model")
        if model not in {"qwen", "luna"}:
            continue
        signature = (
            row.get("task_id"),
            row.get("suite"),
            row.get("repetition"),
            *(row.get(field) for field in sorted(required_row_fields)),
        )
        counts = groups.setdefault(signature, {"qwen": 0, "luna": 0})
        counts[str(model)] += 1
        if row.get("evidence_status", "sealed") != "sealed" or row.get("evidence") is None:
            _issue(issues, "MISSING_EVIDENCE")
        for field in (
            "lifecycle_conformant",
            "capability_conformant",
            "scope_evidence_valid",
            "patch_accepted",
        ):
            if row.get(field) is not True:
                _issue(issues, f"qualification:runs[{index}]:{field}_required")
        expected_score = 100 if "hidden" in str(row.get("suite", "")).lower() else 20
        if row.get("score") != expected_score:
            _issue(issues, f"qualification:runs[{index}]:score_not_exact")
    for signature, counts in groups.items():
        if counts["qwen"] != counts["luna"] or counts["qwen"] != 1:
            _issue(issues, "qualification:unmatched_pair:" + str(signature[0]))

    if rows:
        for task in ("RouteWeave", "ReleaseForge"):
            for suite in ("public", "hidden"):
                for model in ("qwen", "luna"):
                    repetitions = {
                        row.get("repetition")
                        for row in rows
                        if isinstance(row, Mapping)
                        and str(row.get("task_id", "")).lower() == task.lower()
                        and str(row.get("suite", "")).lower() == suite
                        and row.get("model") == model
                    }
                    if len(repetitions) < 2 or None in repetitions:
                        _issue(
                            issues,
                            f"qualification:repetition_missing:{task}:{suite}:{model}",
                        )

    missing = "MISSING_EVIDENCE" in issues or not rows
    status = "INCONCLUSIVE" if missing else ("PASS" if not issues else "FAIL")
    return {
        **base,
        "status": status,
        "promotable": status == "PASS",
        "issues": sorted(set(issues)),
        "matched_pair_count": len(groups),
        "exact_pairing_required": True,
        "repeated_single_lane_required": True,
        "luna_remains_default": True,
    }


def _subreport(operation: str, payload: Any) -> dict[str, Any]:
    if operation == "validate_call":
        return transport.validate_worker_call(payload)
    if operation == "validate_result":
        return transport.validate_worker_result(payload)
    if operation == "validate_manifest":
        return transport.validate_model_manifest(payload)
    if operation == "evaluate_capabilities":
        return transport.evaluate_capability_compatibility(payload)
    if operation == "evaluate_adapter":
        return _evaluate_adapter(payload)
    if operation == "evaluate_workspace":
        return workspace.evaluate_workspace_program(payload)
    if operation == "validate_evidence":
        return _validate_evidence(payload)
    if operation == "evaluate_qualification":
        return _paired_qualification(payload)
    if operation == "evaluate_activation":
        return adapter.evaluate_release_activation(payload)
    return {"status": "FAIL", "issues": ["program:operation_invalid"]}


def evaluate_worker_port(program: Any) -> dict[str, Any]:
    """Evaluate one closed provider-free worker-port operation."""

    issues: list[str] = []
    _exact(program, _PROGRAM_FIELDS, "program", issues)
    value = program if isinstance(program, Mapping) else {}
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not isinstance(value.get("program_id"), str) or not value.get("program_id"):
        _issue(issues, "program:program_id_invalid")
    operation = value.get("operation")
    if operation not in OPERATIONS:
        _issue(issues, "program:operation_invalid")
    for path in _sensitive_paths(value.get("payload")):
        _issue(issues, "program:sensitive_value:" + path)

    subreport = (
        _subreport(str(operation), value.get("payload"))
        if not issues
        else {"status": "FAIL", "issues": ["program:preflight_failed"]}
    )
    substatus = subreport.get("status")
    if operation == "evaluate_workspace":
        valid = subreport.get("validation_status") == "PASS"
    else:
        valid = substatus == "PASS"
    if not valid and substatus not in {"BLOCKED", "INCONCLUSIVE"}:
        issues.extend("subreport:" + item for item in subreport.get("issues", []))
    if issues:
        status = "FAIL"
    elif substatus in {"BLOCKED", "INCONCLUSIVE"}:
        status = str(substatus)
    elif valid:
        status = "PASS"
    else:
        status = "FAIL"

    core = {
        "schema": REPORT_SCHEMA,
        "status": status,
        "program_id": value.get("program_id"),
        "operation": operation,
        "policy_version": POLICY_VERSION,
        "issues": sorted(set(issues)),
        "subreport": subreport,
        "provider_free": True,
        "contacted": False,
        "commands_executed": 0,
        "model_calls": 0,
        "workspace_mutated": False,
        "candidate_applied": False,
        "route_promoted": False,
    }
    return {**core, "report_sha256": _sha256(core)}


__all__ = [
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "POLICY_VERSION",
    "OPERATIONS",
    "evaluate_worker_port",
]
