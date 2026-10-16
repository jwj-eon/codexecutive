#!/usr/bin/env python3
"""Compose bounded native session observations for one advisory scan.

The caller supplies the existing exact-hash attempt-observer manifest.  This
adapter does not search session storage.  It binds the attempt graph with the
canonical attempt observer, observes each declared child with the canonical
runtime route/terminal/usage observer, and emits only compact identifiers,
hashes, counts, and allow-listed facts.  It never copies prompts, messages,
reasoning, raw terminal bodies, session paths, or private signing material.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


def _load_sibling(name: str):
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name + " unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


try:
    import orch_dork_attempt_observer as attempt_observer
    import orch_dork_observer_authority as observer_authority
    import orch_dork_observer_receipt as observer_receipts
    import orch_dork_routing_verify as routing_verify
except ModuleNotFoundError:  # isolated spec loading and clean package probes.
    attempt_observer = _load_sibling("orch_dork_attempt_observer")
    observer_receipts = _load_sibling("orch_dork_observer_receipt")
    observer_authority = _load_sibling("orch_dork_observer_authority")
    routing_verify = _load_sibling("orch_dork_routing_verify")


PROGRAM_SCHEMA = "orch-dork/native-scan-observation-program/v1"
REPORT_SCHEMA = "orch-dork/native-scan-observation/v1"
ATTESTATION_SCHEMA = "orch-dork/native-scan-observation-attestation/v1"
MAX_LANES = 16
MAX_INPUT_BYTES = 262_144
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ISSUE_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+\-]{0,255}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value))


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def _closed(
    value: Any,
    fields: set[str],
    label: str,
    issues: list[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return {}
    if set(value) != fields:
        _issue(issues, label + ":shape_invalid")
    return dict(value)


def _issue_codes(value: Any, label: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > 256:
        _issue(issues, label + ":invalid")
        return []
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _ISSUE_CODE.fullmatch(item):
            _issue(issues, label + ":item_invalid")
        elif item not in result:
            result.append(item)
    return result


def _validate_projection(
    value: Any,
    index: int,
    issues: list[str],
) -> dict[str, Any]:
    label = f"lanes[{index}]"
    lane = _closed(
        value,
        {
            "lane_id",
            "worker_id",
            "status",
            "issues",
            "source_pointer",
            "source_sha256",
            "route",
            "terminal",
            "usage",
            "observation_sha256",
        },
        label,
        issues,
    )
    for field in ("lane_id", "worker_id"):
        if not _identifier(lane.get(field)):
            _issue(issues, f"{label}:{field}_invalid")
    if lane.get("status") not in {"PASS", "FAIL"}:
        _issue(issues, label + ":status_invalid")
    _issue_codes(lane.get("issues"), label + ".issues", issues)
    if not _identifier(lane.get("source_pointer")):
        _issue(issues, label + ":source_pointer_invalid")
    for field in ("source_sha256", "observation_sha256"):
        if not _sha256(lane.get(field)):
            _issue(issues, f"{label}:{field}_invalid")

    route = _closed(
        lane.get("route"),
        {"session_id", "model", "effort", "context_policy", "inherited_history"},
        label + ".route",
        issues,
    )
    if route.get("session_id") != lane.get("worker_id"):
        _issue(issues, label + ":route_session_mismatch")
    if not _identifier(route.get("model")):
        _issue(issues, label + ":route_model_invalid")
    if route.get("effort") is not None and not _identifier(route.get("effort")):
        _issue(issues, label + ":route_effort_invalid")
    if route.get("context_policy") not in {"none", "inherited"}:
        _issue(issues, label + ":route_context_invalid")
    if type(route.get("inherited_history")) is not bool or (
        route.get("context_policy") == "none"
    ) != (route.get("inherited_history") is False):
        _issue(issues, label + ":route_history_invalid")

    terminal = _closed(
        lane.get("terminal"),
        {"schema", "json_sha256", "record"},
        label + ".terminal",
        issues,
    )
    if not _identifier(terminal.get("schema")):
        _issue(issues, label + ":terminal_schema_invalid")
    if not _sha256(terminal.get("json_sha256")):
        _issue(issues, label + ":terminal_json_sha256_invalid")
    terminal_record = _closed(
        terminal.get("record"),
        {"line", "sha256"},
        label + ".terminal.record",
        issues,
    )
    if type(terminal_record.get("line")) is not int or terminal_record["line"] <= 0:
        _issue(issues, label + ":terminal_line_invalid")
    if not _sha256(terminal_record.get("sha256")):
        _issue(issues, label + ":terminal_record_sha256_invalid")

    usage = _closed(
        lane.get("usage"),
        {
            "status",
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "total_tokens",
            "tool_calls",
            "source_pointer",
            "record",
        },
        label + ".usage",
        issues,
    )
    if usage.get("source_pointer") != lane.get("source_pointer"):
        _issue(issues, label + ":usage_source_mismatch")
    usage_record = _closed(
        usage.get("record"),
        {"line", "sha256"},
        label + ".usage.record",
        issues,
    )
    numeric_fields = (
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "tool_calls",
    )
    if usage.get("status") == "observed":
        valid_numbers = all(
            type(usage.get(field)) is int and usage[field] >= 0
            for field in numeric_fields
        )
        if not valid_numbers or (
            usage.get("cached_input_tokens", 0) > usage.get("input_tokens", 0)
            or usage.get("reasoning_tokens", 0) > usage.get("output_tokens", 0)
            or usage.get("total_tokens")
            != usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        ):
            _issue(issues, label + ":usage_arithmetic_invalid")
        if type(usage_record.get("line")) is not int or usage_record["line"] <= 0:
            _issue(issues, label + ":usage_line_invalid")
        if not _sha256(usage_record.get("sha256")):
            _issue(issues, label + ":usage_record_sha256_invalid")
    elif usage.get("status") == "unknown":
        if any(usage.get(field) is not None for field in numeric_fields) or any(
            usage_record.get(field) is not None for field in ("line", "sha256")
        ):
            _issue(issues, label + ":usage_unknown_shape_invalid")
    else:
        _issue(issues, label + ":usage_status_invalid")
    return lane


def validate_native_scan_observation(value: Any) -> dict[str, Any]:
    """Validate one sealed, path-free native advisory observation report."""

    issues: list[str] = []
    fields = {
        "schema",
        "status",
        "decision",
        "attempt_id",
        "graph_status",
        "observation_status",
        "qualification_evidence_status",
        "claim_permitted",
        "attempt_observation_sha256",
        "graph",
        "lanes",
        "evidence_unknowns",
        "issues",
        "host_key_reads",
        "files_read",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "observation_sha256",
        "signed_receipt",
        "report_sha256",
    }
    report = _closed(value, fields, "observation", issues)
    if report.get("schema") != REPORT_SCHEMA:
        _issue(issues, "observation:schema_invalid")
    if report.get("status") != "PASS" or report.get("decision") != "OBSERVED_ADVISORY":
        _issue(issues, "observation:not_passing")
    if not _identifier(report.get("attempt_id")):
        _issue(issues, "observation:attempt_id_invalid")
    if report.get("graph_status") != "BOUND":
        _issue(issues, "observation:graph_not_bound")
    if report.get("observation_status") not in {"COMPLETE", "PARTIAL"}:
        _issue(issues, "observation:status_invalid")
    if report.get("qualification_evidence_status") not in {
        "EVIDENCE_COMPLETE",
        "EVIDENCE_INCOMPLETE",
    }:
        _issue(issues, "observation:qualification_status_invalid")
    if report.get("claim_permitted") is not False:
        _issue(issues, "observation:claim_boundary_invalid")
    if not _sha256(report.get("attempt_observation_sha256")):
        _issue(issues, "observation:attempt_sha256_invalid")

    graph = _closed(
        report.get("graph"),
        {"root_thread_id", "lanes"},
        "observation.graph",
        issues,
    )
    if not _identifier(graph.get("root_thread_id")):
        _issue(issues, "observation:root_thread_id_invalid")
    graph_rows = graph.get("lanes")
    if not isinstance(graph_rows, list) or not 2 <= len(graph_rows) <= MAX_LANES:
        _issue(issues, "observation:graph_lanes_invalid")
        graph_rows = []
    graph_members: set[tuple[str, str]] = set()
    for index, raw_row in enumerate(graph_rows):
        row = _closed(
            raw_row,
            {"lane_id", "worker_id", "parent_thread_id"},
            f"observation.graph.lanes[{index}]",
            issues,
        )
        if not all(
            _identifier(row.get(field))
            for field in ("lane_id", "worker_id", "parent_thread_id")
        ):
            _issue(issues, f"observation.graph.lanes[{index}]:identity_invalid")
            continue
        member = (str(row["lane_id"]), str(row["worker_id"]))
        if member in graph_members:
            _issue(issues, "observation:graph_membership_duplicate")
        graph_members.add(member)

    lane_values = report.get("lanes")
    if not isinstance(lane_values, list) or not 2 <= len(lane_values) <= MAX_LANES:
        _issue(issues, "observation:lanes_invalid")
        lane_values = []
    lanes = [
        _validate_projection(row, index, issues)
        for index, row in enumerate(lane_values)
    ]
    lane_members = {
        (str(row.get("lane_id")), str(row.get("worker_id")))
        for row in lanes
        if _identifier(row.get("lane_id")) and _identifier(row.get("worker_id"))
    }
    if len(lane_members) != len(lanes) or lane_members != graph_members:
        _issue(issues, "observation:lane_membership_mismatch")

    evidence_unknowns = _issue_codes(
        report.get("evidence_unknowns"), "observation.evidence_unknowns", issues
    )
    if report.get("issues") != []:
        _issue(issues, "observation:issues_present")
    complete = bool(lanes) and all(row.get("status") == "PASS" for row in lanes)
    expected_observation_status = "COMPLETE" if complete else "PARTIAL"
    if report.get("observation_status") != expected_observation_status:
        _issue(issues, "observation:completeness_mismatch")
    expected_qualification = (
        "EVIDENCE_COMPLETE"
        if complete and not evidence_unknowns
        else "EVIDENCE_INCOMPLETE"
    )
    if report.get("qualification_evidence_status") != expected_qualification:
        _issue(issues, "observation:qualification_mismatch")
    if type(report.get("host_key_reads")) is not int or report.get("host_key_reads", -1) < 0:
        _issue(issues, "observation:host_key_reads_invalid")
    if report.get("files_read") != 1 + len(lanes):
        _issue(issues, "observation:files_read_invalid")
    if report.get("provider_free") is not True or any(
        report.get(field) != 0 for field in ("model_calls", "hosted_calls")
    ):
        _issue(issues, "observation:adapter_boundary_invalid")
    if report.get("signed_receipt") is not None and not isinstance(
        report.get("signed_receipt"), Mapping
    ):
        _issue(issues, "observation:signed_receipt_invalid")

    supplied_observation_sha256 = report.get("observation_sha256")
    observation_core = dict(report)
    observation_core.pop("report_sha256", None)
    observation_core.pop("signed_receipt", None)
    observation_core.pop("observation_sha256", None)
    if not _sha256(supplied_observation_sha256) or supplied_observation_sha256 != _digest(
        observation_core
    ):
        _issue(issues, "observation:observation_seal_invalid")
    supplied_report_sha256 = report.get("report_sha256")
    sealed = dict(report)
    sealed.pop("report_sha256", None)
    if not _sha256(supplied_report_sha256) or supplied_report_sha256 != _digest(sealed):
        _issue(issues, "observation:report_seal_invalid")

    return {
        "valid": not issues,
        "issues": sorted(issues),
        "normalized": dict(report) if not issues else None,
        "digest": supplied_report_sha256 if not issues else None,
    }


def bind_native_scan_observation(
    value: Any,
    *,
    scan_id: str,
    root_thread_id: str,
    expected_members: Mapping[str, str],
    expected_model: str,
    expected_effort: str,
    expected_terminal_schema: str,
) -> dict[str, Any]:
    """Bind one valid observation to the exact advisory execution graph."""

    validation = validate_native_scan_observation(value)
    report = validation.get("normalized")
    if not validation.get("valid") or not isinstance(report, Mapping):
        return {
            "valid": False,
            "report_issues": list(validation["issues"]),
            "issues": [],
            "normalized": None,
            "evidence_unknowns": [],
        }

    issues: list[str] = []
    graph = report["graph"]
    graph_members = {
        str(row["lane_id"]): row["worker_id"] for row in graph["lanes"]
    }
    graph_parents = {
        str(row["lane_id"]): row["parent_thread_id"] for row in graph["lanes"]
    }
    lane_members: dict[str, Any] = {}
    for row in report["lanes"]:
        lane_id = str(row["lane_id"])
        lane_members[lane_id] = row["worker_id"]
        missing_usage_only = (
            row["status"] == "FAIL"
            and row["issues"] == ["usage:exact_record_missing"]
            and row["usage"].get("status") == "unknown"
        )
        if row["status"] != "PASS" and not missing_usage_only:
            _issue(issues, "lane_contradiction:" + lane_id)
        route = row["route"]
        if (
            route.get("model") != expected_model
            or route.get("effort") != expected_effort
            or route.get("context_policy") != "none"
            or route.get("inherited_history") is not False
        ):
            _issue(issues, "route_contradiction:" + lane_id)
        if row["terminal"].get("schema") != expected_terminal_schema:
            _issue(issues, "terminal_contradiction:" + lane_id)

    expected = dict(expected_members)
    if report["attempt_id"] != scan_id:
        _issue(issues, "scan_id_mismatch")
    if graph["root_thread_id"] != root_thread_id:
        _issue(issues, "root_mismatch")
    if graph_members != expected or lane_members != expected:
        _issue(issues, "membership_mismatch")
    if any(parent != root_thread_id for parent in graph_parents.values()):
        _issue(issues, "parent_mismatch")

    normalized = {
        "status": "observed",
        "attempt_id": report["attempt_id"],
        "observation_status": report["observation_status"],
        "observed_lane_ids": sorted(lane_members),
        "observation_sha256": report["observation_sha256"],
        "report_sha256": report["report_sha256"],
    }
    return {
        "valid": not issues,
        "report_issues": [],
        "issues": sorted(issues),
        "normalized": normalized if not issues else None,
        "evidence_unknowns": list(report["evidence_unknowns"]),
    }


def program_descriptor() -> dict[str, Any]:
    """Return the closed public schema for one bounded observer invocation."""

    identifier = {
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "pattern": _IDENTIFIER.pattern,
    }
    signing = {
        "oneOf": [
            {
                "type": "object",
                "properties": {"mode": {"const": "none"}},
                "required": ["mode"],
                "additionalProperties": False,
            },
            {
                "type": "object",
                "properties": {
                    "mode": {"const": "host"},
                    "issued_at": {"type": "string", "minLength": 1, "maxLength": 64},
                    "valid_until": {"type": "string", "minLength": 1, "maxLength": 64},
                    "nonce": dict(identifier),
                },
                "required": ["mode", "issued_at", "valid_until", "nonce"],
                "additionalProperties": False,
            },
        ]
    }
    return {
        "type": "object",
        "properties": {
            "schema": {"const": PROGRAM_SCHEMA},
            "observer_id": identifier,
            "attempt_manifest": {"type": "object", "maxProperties": 7},
            "signing": signing,
        },
        "required": ["schema", "observer_id", "attempt_manifest", "signing"],
        "additionalProperties": False,
    }


def _refusal(
    *,
    issues: Sequence[str],
    attempt_id: Any = None,
    graph_status: str = "UNBOUND",
    attempt_observation_sha256: str | None = None,
) -> dict[str, Any]:
    core = {
        "schema": REPORT_SCHEMA,
        "status": "FAIL",
        "decision": "REFUSED",
        "attempt_id": attempt_id if _identifier(attempt_id) else None,
        "graph_status": graph_status,
        "observation_status": "NOT_OBSERVED",
        "qualification_evidence_status": "EVIDENCE_INCOMPLETE",
        "claim_permitted": False,
        "attempt_observation_sha256": attempt_observation_sha256,
        "graph": {"root_thread_id": None, "lanes": []},
        "lanes": [],
        "evidence_unknowns": [],
        "issues": sorted(set(issues)),
        "signed_receipt": None,
        "host_key_reads": 0,
        "files_read": 0,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _digest(core)}


def _validate_program(program: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not isinstance(program, Mapping):
        return {}, ["program:not_object"]
    try:
        if len(_canonical(program)) > MAX_INPUT_BYTES:
            _issue(issues, "program:too_large")
    except (TypeError, ValueError, UnicodeError):
        _issue(issues, "program:not_canonical_json")
    fields = {"schema", "observer_id", "attempt_manifest", "signing"}
    if set(program) - fields:
        _issue(issues, "program:unknown_fields")
    for field in sorted(fields - set(program)):
        _issue(issues, "program:missing:" + field)
    value = dict(program)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not _identifier(value.get("observer_id")):
        _issue(issues, "program:observer_id_invalid")
    manifest = value.get("attempt_manifest")
    if not isinstance(manifest, Mapping):
        _issue(issues, "program:attempt_manifest_invalid")
        manifest = {}
    children = manifest.get("children") if isinstance(manifest, Mapping) else None
    if not isinstance(children, list) or not 2 <= len(children) <= MAX_LANES:
        _issue(issues, "program:lane_count_invalid")
    signing = value.get("signing")
    if not isinstance(signing, Mapping):
        _issue(issues, "program:signing_invalid")
    elif signing.get("mode") == "none":
        if set(signing) != {"mode"}:
            _issue(issues, "program:signing_none_shape_invalid")
    elif signing.get("mode") == "host":
        if set(signing) != {"mode", "issued_at", "valid_until", "nonce"}:
            _issue(issues, "program:signing_host_shape_invalid")
        if not all(
            isinstance(signing.get(field), str) and bool(signing.get(field))
            for field in ("issued_at", "valid_until")
        ) or not _identifier(signing.get("nonce")):
            _issue(issues, "program:signing_host_value_invalid")
    else:
        _issue(issues, "program:signing_mode_invalid")
    return value, issues


def _default_host_signer():
    state_dir = observer_authority.default_state_dir()
    identity = observer_authority.inspect_authority(state_dir=state_dir)
    signer = observer_receipts.FileHostSigner.from_host_file(
        state_dir / observer_authority.SEED_FILENAME,
        key_id=identity["key_id"],
        host_id=identity["host_id"],
    )
    return signer, identity.get("generation")


def _runtime_projection(lane_id: str, worker_id: str, report: Mapping[str, Any]) -> dict[str, Any]:
    terminal_record = report.get("terminal_record")
    usage_record = report.get("usage_record")
    return {
        "lane_id": lane_id,
        "worker_id": worker_id,
        "status": report.get("status"),
        "issues": sorted(
            str(item) for item in report.get("issues", []) if isinstance(item, str)
        ),
        "source_pointer": report.get("source_pointer"),
        "source_sha256": report.get("source_sha256"),
        "route": report.get("route"),
        "terminal": {
            "schema": report.get("terminal_schema"),
            "json_sha256": report.get("terminal_json_sha256"),
            "record": {
                "line": terminal_record.get("line"),
                "sha256": terminal_record.get("sha256"),
            }
            if isinstance(terminal_record, Mapping)
            else {"line": None, "sha256": None},
        },
        "usage": {
            **dict(report.get("usage", {})),
            "source_pointer": report.get("source_pointer"),
            "record": {
                "line": usage_record.get("line"),
                "sha256": usage_record.get("sha256"),
            }
            if isinstance(usage_record, Mapping)
            else {"line": None, "sha256": None},
        },
        "observation_sha256": report.get("report_sha256"),
    }


def observe_native_scan(
    program: Any,
    *,
    signer: Any = None,
) -> dict[str, Any]:
    """Observe one exact-hash attempt and its declared child sessions."""

    value, issues = _validate_program(program)
    manifest = value.get("attempt_manifest") if isinstance(value, Mapping) else {}
    attempt_id = manifest.get("attempt_id") if isinstance(manifest, Mapping) else None
    if issues:
        return _refusal(issues=issues, attempt_id=attempt_id)

    observer_id = value["observer_id"]
    root = manifest.get("root")
    children = manifest.get("children")
    root_thread_id = root.get("thread_id") if isinstance(root, Mapping) else None
    if observer_id == root_thread_id:
        _issue(issues, "observer:not_independent_of_root")
    root_path = root.get("path") if isinstance(root, Mapping) else None
    if not isinstance(root_path, str) or not root_path or len(root_path) > 4096:
        _issue(issues, "root:source_path_invalid")
    elif Path(root_path).is_symlink():
        _issue(issues, "root:source_symlink")
    child_paths: set[str] = set()
    for index, child in enumerate(children):
        if not isinstance(child, Mapping):
            _issue(issues, f"children[{index}]:not_object")
            continue
        if child.get("hash_scope", "full_file") != "full_file":
            _issue(issues, f"children[{index}]:full_file_hash_required")
        if observer_id == child.get("thread_id"):
            _issue(issues, f"children[{index}]:observer_not_independent")
        source_path = child.get("path")
        if (
            not isinstance(source_path, str)
            or not source_path
            or len(source_path) > 4096
        ):
            _issue(issues, f"children[{index}]:source_path_invalid")
        elif Path(source_path).is_symlink():
            _issue(issues, f"children[{index}]:source_symlink")
        elif source_path == root_path or source_path in child_paths:
            _issue(issues, f"children[{index}]:source_path_reused")
        else:
            child_paths.add(source_path)
    if issues:
        return _refusal(issues=issues, attempt_id=attempt_id)

    attempt_report = attempt_observer.observe_attempt(manifest)
    attempt_sha256 = _digest(attempt_report)
    graph_status = str(attempt_report.get("binding_status", "UNBOUND"))
    if attempt_report.get("status") == "FAIL" or graph_status != "BOUND":
        return _refusal(
            issues=["attempt:exact_binding_required"],
            attempt_id=attempt_id,
            graph_status=graph_status,
            attempt_observation_sha256=attempt_sha256,
        )

    lane_reports: list[dict[str, Any]] = []
    evidence_unknowns: list[str] = [
        "attempt:" + item
        for item in attempt_report.get("unknown_reasons", [])
        if isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_.:+\-]+", item)
    ]
    graph_lanes: list[dict[str, str]] = []
    for child in sorted(children, key=lambda row: str(row.get("lane_id"))):
        lane_id = str(child["lane_id"])
        worker_id = str(child["thread_id"])
        runtime = routing_verify.observe_session_runtime(
            str(child["path"]),
            session_id=worker_id,
            observer_id=observer_id,
        )
        if runtime.get("source_sha256") != child.get("file_sha256"):
            return _refusal(
                issues=["runtime:source_hash_mismatch:" + lane_id],
                attempt_id=attempt_id,
                graph_status=graph_status,
                attempt_observation_sha256=attempt_sha256,
            )
        projection = _runtime_projection(lane_id, worker_id, runtime)
        lane_reports.append(projection)
        graph_lanes.append(
            {
                "lane_id": lane_id,
                "worker_id": worker_id,
                "parent_thread_id": str(child["parent_thread_id"]),
            }
        )
        for item in projection["issues"]:
            value_issue = lane_id + ":" + item
            if value_issue not in evidence_unknowns:
                evidence_unknowns.append(value_issue)

    complete = all(row["status"] == "PASS" for row in lane_reports)
    qualification_complete = complete and not evidence_unknowns
    signing = value["signing"]
    generation = None
    host_key_reads = 0
    if signing["mode"] == "host" and signer is None:
        try:
            signer, generation = _default_host_signer()
            host_key_reads = 1
        except Exception as exc:
            reason = getattr(exc, "reason", None) or str(exc)
            safe_reason = (
                reason
                if isinstance(reason, str) and re.fullmatch(r"[A-Za-z0-9_.:+\-]+", reason)
                else "authority_unavailable"
            )
            return _refusal(
                issues=["signing:" + safe_reason],
                attempt_id=attempt_id,
                graph_status=graph_status,
                attempt_observation_sha256=attempt_sha256,
            )

    core = {
        "schema": REPORT_SCHEMA,
        "status": "PASS",
        "decision": "OBSERVED_ADVISORY",
        "attempt_id": attempt_id,
        "graph_status": graph_status,
        "observation_status": "COMPLETE" if complete else "PARTIAL",
        "qualification_evidence_status": (
            "EVIDENCE_COMPLETE"
            if qualification_complete
            else "EVIDENCE_INCOMPLETE"
        ),
        "claim_permitted": False,
        "attempt_observation_sha256": attempt_sha256,
        "graph": {
            "root_thread_id": root_thread_id,
            "lanes": graph_lanes,
        },
        "lanes": lane_reports,
        "evidence_unknowns": sorted(evidence_unknowns),
        "issues": [],
        "host_key_reads": host_key_reads,
        "files_read": 1 + len(lane_reports),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    observation_sha256 = _digest(core)
    signed_receipt = None
    if signing["mode"] == "host":
        payload = {
            "schema": ATTESTATION_SCHEMA,
            "attempt_id": attempt_id,
            "observation_sha256": observation_sha256,
            "lane_source_sha256s": {
                row["lane_id"]: row["source_sha256"] for row in lane_reports
            },
            "trust_generation": generation,
        }
        try:
            signed_receipt = signer.issue(
                "native_scan_observation",
                payload,
                issued_at=signing["issued_at"],
                valid_until=signing["valid_until"],
                nonce=signing["nonce"],
            )
        except Exception as exc:
            reason = getattr(exc, "reason", None) or "receipt_invalid"
            safe_reason = (
                reason
                if isinstance(reason, str)
                and re.fullmatch(r"[A-Za-z0-9_.:+\-]+", reason)
                else "receipt_invalid"
            )
            return _refusal(
                issues=["signing:" + safe_reason],
                attempt_id=attempt_id,
                graph_status=graph_status,
                attempt_observation_sha256=attempt_sha256,
            )
    sealed = {
        **core,
        "observation_sha256": observation_sha256,
        "signed_receipt": signed_receipt,
    }
    return {**sealed, "report_sha256": _digest(sealed)}


def _load_program(path: str) -> Any:
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("program:file_invalid")
    return json.loads(source.read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        report = observe_native_scan(_load_program(args.program))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        report = _refusal(issues=["program:unreadable"])
    rendered = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTESTATION_SCHEMA",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "bind_native_scan_observation",
    "observe_native_scan",
    "program_descriptor",
    "validate_native_scan_observation",
]
