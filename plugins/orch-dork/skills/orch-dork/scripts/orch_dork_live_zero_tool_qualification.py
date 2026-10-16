#!/usr/bin/env python3
"""Provider-free pre-authorization qualification for the zero-tool transport.

The public interface deliberately accepts the already sealed zero-tool request
and two runtime roots, then returns one path-free sealed report.  Exact
OpenCodex translation runs behind an injected/default contained-process
adapter; raw requests, responses, process output, paths, and reasoning never
cross the report interface.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_live_zero_tool as zero_tool  # noqa: E402
import orch_dork_process_containment as containment  # noqa: E402


QUALIFICATION_SCHEMA = "orch-dork/zero-tool-transport-qualification/v1"
QUALIFICATION_VALIDATION_SCHEMA = (
    "orch-dork/zero-tool-transport-qualification-validation/v1"
)
PROBE_INPUT_SCHEMA = "orch-dork/open-codex-zero-tool-probe-input/v2"
PROBE_OUTPUT_SCHEMA = "orch-dork/open-codex-zero-tool-probe-output/v2"
REASONING_ENVELOPE_CONTRACT = "opencodex-2.35-hidden-reasoning/v1"
RUNTIME_IDENTITY_SCHEMA = "orch-dork/zero-tool-transport-runtime-identity/v1"

_OPENCODEX_FILES = (
    "package.json",
    "node_modules/bun/bin/bun.exe",
    "src/responses/parser.ts",
    "src/responses/schema.ts",
    "src/adapters/openai-chat.ts",
    "src/bridge.ts",
    "src/lab/conformance/fixture-provider.ts",
    "src/lib/translator-budget.ts",
    "src/server/auth-cors.ts",
)
_OPENCODEX_SOURCE_TREES = ("src", "node_modules/zod")
_PROBE_RELATIVE = (
    "skills/orch-dork/scripts/orch_dork_live_zero_tool_probe.ts"
)
_PLUGIN_FILES = (
    "skills/orch-dork/scripts/orch_dork_live_zero_tool.py",
    "skills/orch-dork/scripts/orch_dork_live_zero_tool_qualification.py",
    "skills/orch-dork/scripts/orch_dork_qualification_rehearsal.py",
    _PROBE_RELATIVE,
    "skills/orch-dork/scripts/orch_dork_live_recovery.py",
    "skills/orch-dork/scripts/orch_dork_standing_authority.py",
    "skills/orch-dork/scripts/orch_dork_process_containment.py",
    "skills/orch-dork/scripts/orch_dork_hostile_input.py",
    "skills/orch-dork/runtime/qualification-rehearsal-replays-v1.json",
)
_PROBE_FIELDS = frozenset(
    {
        "schema",
        "request",
        "cases",
        "credential_reads",
        "network_calls",
        "model_calls",
        "hosted_calls",
    }
)
_PROBE_REQUEST_FIELDS = frozenset(
    {
        "request_schema",
        "reasoning_envelope_contract",
        "include_reasoning_absent",
        "reasoning_output_mode",
        "reasoning_effort",
        "hide_thinking_summary",
        "tools_count",
        "tool_choice",
        "stream",
        "store",
        "structured_output_type",
    }
)
_EXPECTED_CASES = ("content_only", "reasoning_rich")
_QUALIFICATION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "qualified",
        "issues",
        "request_sha256",
        "runtime_identity",
        "checks",
        "provider_free",
        "credential_reads",
        "network_calls",
        "model_calls",
        "hosted_calls",
        "qualification_sha256",
    }
)
_SUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {
        "$defs",
        "$ref",
        "additionalProperties",
        "anyOf",
        "const",
        "description",
        "enum",
        "items",
        "maxItems",
        "minItems",
        "properties",
        "required",
        "title",
        "type",
    }
)


@dataclass(frozen=True)
class TransportRuntime:
    """Local source roots needed to re-derive one runtime identity."""

    plugin_root: Path
    opencodex_root: Path


def _compact(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_compact(value).encode("utf-8")).hexdigest()


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_root(value: Any) -> Path | None:
    try:
        path = Path(value)
        if not path.is_absolute() or path.is_symlink():
            return None
        resolved = path.resolve(strict=True)
        if resolved != path or not resolved.is_dir():
            return None
        return path
    except (OSError, TypeError, ValueError):
        return None


def _file_row(root: Path, relative: str, *, executable: bool = False) -> dict[str, Any] | None:
    path = root.joinpath(*relative.split("/"))
    try:
        if path.is_symlink() or not path.is_file():
            return None
        resolved = path.resolve(strict=True)
        if os.path.commonpath((str(root), str(resolved))) != str(root):
            return None
        if executable and not os.access(path, os.X_OK):
            return None
        data = path.read_bytes()
    except (OSError, ValueError):
        return None
    return {"name": relative, "bytes": len(data), "sha256": _bytes_sha256(data)}


def _tree_row(root: Path, relative: str) -> dict[str, Any] | None:
    """Bind an exact source tree without exposing its file list."""

    tree = root.joinpath(*relative.split("/"))
    try:
        if tree.is_symlink() or not tree.is_dir():
            return None
        resolved_tree = tree.resolve(strict=True)
        if os.path.commonpath((str(root), str(resolved_tree))) != str(root):
            return None
        rows: list[dict[str, Any]] = []
        total_bytes = 0
        for path in sorted(tree.rglob("*")):
            if path.is_symlink():
                return None
            if path.is_dir():
                continue
            if not path.is_file():
                return None
            resolved = path.resolve(strict=True)
            if os.path.commonpath((str(tree), str(resolved))) != str(tree):
                return None
            data = path.read_bytes()
            total_bytes += len(data)
            rows.append(
                {
                    "name": path.relative_to(tree).as_posix(),
                    "bytes": len(data),
                    "sha256": _bytes_sha256(data),
                }
            )
        if not rows:
            return None
    except (OSError, ValueError):
        return None
    closure = {
        "schema": "orch-dork/source-tree-closure/v1",
        "files": rows,
    }
    return {
        "name": relative,
        "file_count": len(rows),
        "bytes": total_bytes,
        "sha256": _sha256(closure),
    }


def _runtime_identity(
    runtime: Any,
    issues: list[str],
) -> tuple[dict[str, Any] | None, Path | None]:
    if not isinstance(runtime, TransportRuntime):
        issues.append("runtime:type_invalid")
        return None, None
    plugin_root = _safe_root(runtime.plugin_root)
    opencodex_root = _safe_root(runtime.opencodex_root)
    if plugin_root is None:
        issues.append("runtime:plugin_root_invalid")
    if opencodex_root is None:
        issues.append("runtime:opencodex_root_invalid")
    if plugin_root is None or opencodex_root is None:
        return None, None

    plugin_rows = [_file_row(plugin_root, name) for name in _PLUGIN_FILES]
    ocx_rows = [
        _file_row(
            opencodex_root,
            name,
            executable=name == "node_modules/bun/bin/bun.exe",
        )
        for name in _OPENCODEX_FILES
    ]
    source_trees = [
        _tree_row(opencodex_root, name)
        for name in _OPENCODEX_SOURCE_TREES
    ]
    if any(row is None for row in plugin_rows):
        issues.append("runtime:plugin_closure_unavailable")
    if any(row is None for row in ocx_rows) or any(
        row is None for row in source_trees
    ):
        issues.append("runtime:opencodex_closure_unavailable")
    if issues:
        return None, None
    try:
        package = json.loads((opencodex_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        issues.append("runtime:opencodex_package_invalid")
        return None, None
    if (
        not isinstance(package, Mapping)
        or package.get("name") != "@bitkyc08/opencodex"
        or not isinstance(package.get("version"), str)
        or not package["version"]
    ):
        issues.append("runtime:opencodex_package_invalid")
        return None, None
    core = {
        "schema": RUNTIME_IDENTITY_SCHEMA,
        "opencodex": {
            "name": package["name"],
            "version": package["version"],
            "files": ocx_rows,
            "source_trees": source_trees,
        },
        "plugin": {"files": plugin_rows},
    }
    return {**core, "runtime_identity_sha256": _sha256(core)}, opencodex_root


def _schema_issues(schema: Any) -> list[str]:
    issues: list[str] = []

    def visit(value: Any, pointer: str) -> None:
        if not isinstance(value, Mapping):
            issues.append("schema:not_object:" + pointer)
            return
        for key, child in value.items():
            if key not in _SUPPORTED_SCHEMA_KEYWORDS:
                issues.append("schema:unsupported_keyword:" + str(key))
                continue
            if key in {"properties", "$defs"}:
                if not isinstance(child, Mapping):
                    issues.append("schema:mapping_invalid:" + key)
                else:
                    for name, nested in child.items():
                        visit(nested, pointer + "/" + key + "/" + str(name))
            elif key == "items" and isinstance(child, Mapping):
                visit(child, pointer + "/items")
            elif key == "anyOf":
                if not isinstance(child, list):
                    issues.append("schema:anyof_invalid")
                else:
                    for index, nested in enumerate(child):
                        visit(nested, pointer + "/anyOf/" + str(index))

    visit(schema, "#")
    return sorted(set(issues))


def _qualification_terminal(
    request: Mapping[str, Any],
    *,
    request_validation: Mapping[str, Any],
) -> dict[str, Any]:
    if request_validation.get("status") != "PASS":
        raise ValueError("qualification_terminal:request_not_validated")
    if request.get("schema") == zero_tool.ROUTE_PREFLIGHT_REQUEST_SCHEMA:
        return deepcopy(dict(request["candidate"]))
    assignment = request.get("assignment")
    if not isinstance(assignment, Mapping):  # canonical validation guarantees this
        raise ValueError("qualification_terminal:assignment_invalid")
    task = assignment.get("task")
    items = task.get("items") if isinstance(task, Mapping) else None
    identifiers = sorted(
        str(item["id"])
        for item in items or []
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    )
    findings = identifiers[:1]
    unknowns = identifiers[1:]
    return {
        "schema": assignment.get("output_schema"),
        "lane_id": assignment.get("lane_id"),
        "request_sha256": assignment.get("request_sha256"),
        "assignment_sha256": assignment.get("assignment_sha256"),
        "findings": findings,
        "unknowns": unknowns,
    }


def _report(
    *,
    issues: list[str],
    request_sha256: str | None,
    runtime_identity: Mapping[str, Any] | None,
    checks: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "schema": QUALIFICATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "qualified": not issues,
        "issues": sorted(set(issues)),
        "request_sha256": request_sha256,
        "runtime_identity": deepcopy(dict(runtime_identity)) if runtime_identity else None,
        "checks": deepcopy(dict(checks)),
        "provider_free": True,
        "credential_reads": 0,
        "network_calls": 0,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "qualification_sha256": _sha256(core)}


def qualify_zero_tool_transport(
    request: Any,
    runtime_closure: Any,
    *,
    runner: Callable[..., Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Qualify one exact request contract against one installed translator."""

    issues: list[str] = []
    request_value = request if isinstance(request, Mapping) else {}
    request_schema = request_value.get("schema")
    if request_schema == zero_tool.ROUTE_PREFLIGHT_REQUEST_SCHEMA:
        request_validation = (
            zero_tool.validate_route_preflight_zero_tool_request(request)
        )
        response_observer = (
            zero_tool.observe_route_preflight_zero_tool_response
        )
    else:
        request_validation = zero_tool.validate_live_zero_tool_request(request)
        response_observer = zero_tool.observe_live_zero_tool_response
    if request_validation.get("status") != "PASS":
        issues.extend("request:" + item for item in request_validation.get("issues", []))
    request_sha = request_value.get("request_sha256")
    runtime_identity, opencodex_root = _runtime_identity(runtime_closure, issues)
    body = request_value.get("body") if isinstance(request_value.get("body"), Mapping) else {}
    text = body.get("text") if isinstance(body.get("text"), Mapping) else {}
    response_format = text.get("format") if isinstance(text.get("format"), Mapping) else {}
    schema = response_format.get("schema")
    schema_issues = _schema_issues(schema)
    issues.extend(schema_issues)
    checks: dict[str, Any] = {
        "request": {
            "status": request_validation.get("status", "FAIL"),
            "issues": list(request_validation.get("issues", [])),
        },
        "schema_profile": {
            "status": "PASS" if not schema_issues else "FAIL",
            "issues": schema_issues,
        },
        "probe": {"status": "NOT_RUN", "reason": None, "cleanup_status": None},
        "cases": [],
    }
    if issues or runtime_identity is None or opencodex_root is None:
        return _report(
            issues=issues,
            request_sha256=request_sha if isinstance(request_sha, str) else None,
            runtime_identity=runtime_identity,
            checks=checks,
        )

    probe_input = {
        "schema": PROBE_INPUT_SCHEMA,
        "opencodex_root": str(opencodex_root),
        "request_schema": request_value.get("schema"),
        "request_body": deepcopy(dict(body)),
        "terminal_result": _qualification_terminal(
            request_value,
            request_validation=request_validation,
        ),
        "response_model": zero_tool.response_wire_model(
            request_value.get("route", {}).get("model")
        ),
    }
    selected_runner = runner or containment.run_contained
    process = selected_runner(
        [
            str(opencodex_root / "node_modules/bun/bin/bun.exe"),
            str(runtime_closure.plugin_root / _PROBE_RELATIVE),
        ],
        input_bytes=_compact(probe_input).encode("utf-8"),
        expect_json=True,
        case_id="issue140-zero-tool-transport",
        surface="zero-tool-transport-probe",
    )
    process_status = process.get("status") if isinstance(process, Mapping) else None
    process_reason = process.get("reason") if isinstance(process, Mapping) else None
    cleanup_status = process.get("cleanup_status") if isinstance(process, Mapping) else None
    checks["probe"] = {
        "status": process_status,
        "reason": process_reason if isinstance(process_reason, str) else None,
        "cleanup_status": cleanup_status if isinstance(cleanup_status, str) else None,
    }
    post_issues: list[str] = []
    post_identity, _post_root = _runtime_identity(
        runtime_closure,
        post_issues,
    )
    if post_issues or post_identity != runtime_identity:
        issues.append("runtime:changed_during_probe")
    if process_status != "PASS" or cleanup_status != "complete":
        issues.append("probe:process_invalid")
    if issues:
        return _report(
            issues=issues,
            request_sha256=request_sha,
            runtime_identity=runtime_identity,
            checks=checks,
        )

    probe = process.get("parsed_output")
    if (
        not isinstance(probe, Mapping)
        or set(probe) != _PROBE_FIELDS
        or probe.get("schema") != PROBE_OUTPUT_SCHEMA
    ):
        issues.append("probe:shape_invalid")
        probe = {}
    request_probe = probe.get("request") if isinstance(probe.get("request"), Mapping) else {}
    if set(request_probe) != _PROBE_REQUEST_FIELDS:
        issues.append("probe:request_shape_invalid")
    expected_request = {
        "request_schema": (
            zero_tool.ROUTE_PREFLIGHT_REQUEST_SCHEMA
            if request_schema == zero_tool.ROUTE_PREFLIGHT_REQUEST_SCHEMA
            else zero_tool.REQUEST_SCHEMA_V2
        ),
        "reasoning_envelope_contract": REASONING_ENVELOPE_CONTRACT,
        "include_reasoning_absent": True,
        "reasoning_output_mode": "hidden_envelope",
        "reasoning_effort": request_value.get("route", {}).get("effort"),
        "hide_thinking_summary": True,
        "tools_count": 0,
        "tool_choice": "none",
        "stream": False,
        "store": False,
        "structured_output_type": "json_schema",
    }
    if dict(request_probe) != expected_request:
        issues.append("probe:request_semantics_mismatch")
    for field in ("credential_reads", "network_calls", "model_calls", "hosted_calls"):
        if probe.get(field) != 0:
            issues.append("probe:" + field + "_nonzero")

    raw_cases = probe.get("cases")
    if not isinstance(raw_cases, list):
        issues.append("probe:cases_invalid")
        raw_cases = []
    seen: set[str] = set()
    for raw_case in raw_cases:
        if not isinstance(raw_case, Mapping) or set(raw_case) != {"id", "response"}:
            issues.append("probe:case_shape_invalid")
            continue
        case_id = raw_case.get("id")
        if case_id not in _EXPECTED_CASES or case_id in seen:
            issues.append("probe:case_id_invalid")
            continue
        seen.add(str(case_id))
        response = raw_case.get("response")
        try:
            raw_response = _compact(response).encode("utf-8")
        except (TypeError, ValueError, OverflowError):
            raw_response = b""
        observed = response_observer(
            request,
            raw_response,
            observer_id="issue140-" + str(case_id) + "-observer",
        )
        case_issues = list(observed.get("issues", []))
        if observed.get("status") != "PASS":
            issues.extend(str(case_id) + ":" + item for item in case_issues)
        output = response.get("output") if isinstance(response, Mapping) else None
        output_types = [
            item.get("type") if isinstance(item, Mapping) else type(item).__name__
            for item in output
        ] if isinstance(output, list) else []
        checks["cases"].append(
            {
                "id": case_id,
                "status": observed.get("status", "FAIL"),
                "issues": case_issues,
                "output_count": len(output) if isinstance(output, list) else None,
                "output_types": output_types,
            }
        )
    if seen != set(_EXPECTED_CASES):
        issues.append("probe:required_case_missing")
    checks["cases"] = sorted(checks["cases"], key=lambda item: str(item["id"]))
    return _report(
        issues=issues,
        request_sha256=request_sha,
        runtime_identity=runtime_identity,
        checks=checks,
    )


def validate_zero_tool_transport_qualification(value: Any) -> dict[str, Any]:
    """Validate one report without trusting its status label or self-seal."""

    issues: list[str] = []
    if not isinstance(value, Mapping) or set(value) != _QUALIFICATION_FIELDS:
        issues.append("qualification:shape_invalid")
        value = value if isinstance(value, Mapping) else {}
    if value.get("schema") != QUALIFICATION_SCHEMA:
        issues.append("qualification:schema_invalid")
    raw_issues = value.get("issues")
    if (
        not isinstance(raw_issues, list)
        or any(not isinstance(item, str) or not item for item in raw_issues)
        or raw_issues != sorted(set(raw_issues))
    ):
        issues.append("qualification:issues_invalid")
        raw_issues = []
    expected_status = "PASS" if not raw_issues else "FAIL"
    if value.get("status") != expected_status or value.get("qualified") is not (not raw_issues):
        issues.append("qualification:disposition_invalid")
    if value.get("request_sha256") is not None and not _is_sha(value.get("request_sha256")):
        issues.append("qualification:request_digest_invalid")
    if value.get("status") == "PASS" and not _is_sha(
        value.get("request_sha256")
    ):
        issues.append("qualification:request_digest_invalid")
    for field in (
        "credential_reads",
        "network_calls",
        "model_calls",
        "hosted_calls",
    ):
        if value.get(field) != 0:
            issues.append("qualification:" + field + "_nonzero")
    if value.get("provider_free") is not True:
        issues.append("qualification:provider_boundary_invalid")

    runtime = value.get("runtime_identity")
    if runtime is not None:
        if not isinstance(runtime, Mapping) or set(runtime) != {
            "schema",
            "opencodex",
            "plugin",
            "runtime_identity_sha256",
        }:
            issues.append("qualification:runtime_shape_invalid")
        else:
            runtime_core = {
                key: deepcopy(item)
                for key, item in runtime.items()
                if key != "runtime_identity_sha256"
            }
            if (
                runtime.get("schema") != RUNTIME_IDENTITY_SCHEMA
                or not _is_sha(runtime.get("runtime_identity_sha256"))
                or runtime.get("runtime_identity_sha256") != _sha256(runtime_core)
            ):
                issues.append("qualification:runtime_seal_invalid")
            opencodex = runtime.get("opencodex")
            plugin = runtime.get("plugin")
            if (
                not isinstance(opencodex, Mapping)
                or set(opencodex)
                != {"name", "version", "files", "source_trees"}
                or opencodex.get("name") != "@bitkyc08/opencodex"
                or not isinstance(opencodex.get("version"), str)
                or not opencodex.get("version")
                or not isinstance(plugin, Mapping)
                or set(plugin) != {"files"}
            ):
                issues.append("qualification:runtime_identity_invalid")
            for label, parent, expected_names in (
                ("opencodex", opencodex, set(_OPENCODEX_FILES)),
                ("plugin", plugin, set(_PLUGIN_FILES)),
            ):
                rows = parent.get("files") if isinstance(parent, Mapping) else None
                if (
                    not isinstance(rows, list)
                    or {row.get("name") for row in rows if isinstance(row, Mapping)}
                    != expected_names
                    or any(
                        not isinstance(row, Mapping)
                        or set(row) != {"name", "bytes", "sha256"}
                        or type(row.get("bytes")) is not int
                        or row["bytes"] < 0
                        or not _is_sha(row.get("sha256"))
                        for row in rows or []
                    )
                ):
                    issues.append("qualification:" + label + "_files_invalid")
            source_trees = (
                opencodex.get("source_trees")
                if isinstance(opencodex, Mapping)
                else None
            )
            if (
                not isinstance(source_trees, list)
                or {
                    row.get("name")
                    for row in source_trees
                    if isinstance(row, Mapping)
                }
                != set(_OPENCODEX_SOURCE_TREES)
                or any(
                    not isinstance(row, Mapping)
                    or set(row)
                    != {"name", "file_count", "bytes", "sha256"}
                    or type(row.get("file_count")) is not int
                    or row["file_count"] < 1
                    or type(row.get("bytes")) is not int
                    or row["bytes"] < 1
                    or not _is_sha(row.get("sha256"))
                    for row in source_trees or []
                )
            ):
                issues.append("qualification:opencodex_trees_invalid")
    elif value.get("status") == "PASS":
        issues.append("qualification:runtime_missing")

    checks = value.get("checks")
    if not isinstance(checks, Mapping) or set(checks) != {
        "request",
        "schema_profile",
        "probe",
        "cases",
    }:
        issues.append("qualification:checks_shape_invalid")
        checks = {}
    cases = checks.get("cases") if isinstance(checks, Mapping) else None
    if not isinstance(cases, list):
        issues.append("qualification:cases_invalid")
        cases = []
    seen: set[str] = set()
    for case in cases:
        if (
            not isinstance(case, Mapping)
            or set(case) != {"id", "status", "issues", "output_count", "output_types"}
            or case.get("id") not in _EXPECTED_CASES
            or case.get("id") in seen
            or case.get("status") not in {"PASS", "FAIL"}
            or not isinstance(case.get("issues"), list)
            or type(case.get("output_count")) is not int
            or case["output_count"] < 0
            or not isinstance(case.get("output_types"), list)
            or any(not isinstance(item, str) for item in case["output_types"])
        ):
            issues.append("qualification:case_invalid")
            continue
        seen.add(str(case["id"]))
    if value.get("status") == "PASS":
        expected_cases_v1 = [
            {
                "id": case_id,
                "status": "PASS",
                "issues": [],
                "output_count": 1,
                "output_types": ["message"],
            }
            for case_id in _EXPECTED_CASES
        ]
        expected_cases_v2 = [
            {
                "id": "content_only",
                "status": "PASS",
                "issues": [],
                "output_count": 1,
                "output_types": ["message"],
            },
            {
                "id": "reasoning_rich",
                "status": "PASS",
                "issues": [],
                "output_count": 2,
                "output_types": ["reasoning", "message"],
            },
        ]
        if cases != expected_cases_v1 and cases != expected_cases_v2:
            issues.append("qualification:passing_cases_invalid")
        if (
            checks.get("request")
            != {"status": "PASS", "issues": []}
            or checks.get("schema_profile")
            != {"status": "PASS", "issues": []}
            or checks.get("probe")
            != {
                "status": "PASS",
                "reason": None,
                "cleanup_status": "complete",
            }
        ):
            issues.append("qualification:passing_checks_invalid")

    supplied = value.get("qualification_sha256")
    core = {
        key: deepcopy(item)
        for key, item in value.items()
        if key != "qualification_sha256"
    }
    if not _is_sha(supplied) or supplied != _sha256(core):
        issues.append("qualification:seal_mismatch")
    report_core = {
        "schema": QUALIFICATION_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(set(issues)),
        "qualification_status": value.get("status"),
        "qualification_sha256": supplied if _is_sha(supplied) else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**report_core, "report_sha256": _sha256(report_core)}


__all__ = [
    "PROBE_INPUT_SCHEMA",
    "PROBE_OUTPUT_SCHEMA",
    "QUALIFICATION_SCHEMA",
    "QUALIFICATION_VALIDATION_SCHEMA",
    "RUNTIME_IDENTITY_SCHEMA",
    "REASONING_ENVELOPE_CONTRACT",
    "TransportRuntime",
    "qualify_zero_tool_transport",
    "validate_zero_tool_transport_qualification",
]
