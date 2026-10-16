#!/usr/bin/env python3
"""Compact provider-free state machine for read-only advisory scans."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


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
    import orch_dork_adaptive_contracts as contracts
    import orch_dork_efficiency_governor as governor
    import orch_dork_native_scan_observer as native_observer
except ModuleNotFoundError:  # isolated spec loading and clean package probes.
    contracts = _load_sibling("orch_dork_adaptive_contracts")
    governor = _load_sibling("orch_dork_efficiency_governor")
    native_observer = _load_sibling("orch_dork_native_scan_observer")


PROGRAM_SCHEMA_V1 = "orch-dork/advisory-scan-program/v1"
PROGRAM_SCHEMA_V2 = "orch-dork/advisory-scan-program/v2"
PROGRAM_SCHEMA_V3 = "orch-dork/advisory-scan-program/v3"
REPORT_SCHEMA_V1 = "orch-dork/advisory-scan-report/v1"
REPORT_SCHEMA_V2 = "orch-dork/advisory-scan-report/v2"
REPORT_SCHEMA_V3 = "orch-dork/advisory-scan-report/v3"
PREPARATION_SCHEMA_V1 = "orch-dork/advisory-scan-preparation/v1"
PREPARATION_SCHEMA_V2 = "orch-dork/advisory-scan-preparation/v2"
PREPARATION_SCHEMA_V3 = "orch-dork/advisory-scan-preparation/v3"

# Stable aliases preserve the public v1 import and replay surface.
PROGRAM_SCHEMA = PROGRAM_SCHEMA_V1
REPORT_SCHEMA = REPORT_SCHEMA_V1
PREPARATION_SCHEMA = PREPARATION_SCHEMA_V1
_SCHEMA_FAMILIES = {
    PROGRAM_SCHEMA_V1: (REPORT_SCHEMA_V1, PREPARATION_SCHEMA_V1),
    PROGRAM_SCHEMA_V2: (REPORT_SCHEMA_V2, PREPARATION_SCHEMA_V2),
    PROGRAM_SCHEMA_V3: (REPORT_SCHEMA_V3, PREPARATION_SCHEMA_V3),
}
NATIVE_OBSERVATION_UNKNOWN_REASONS = frozenset(
    {
        "native_observer_unavailable",
        "native_session_records_unavailable",
    }
)
MAX_LANES = 16
MAX_STRING_BYTES = 4096
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,255}$")


def _schema_family(program_schema: Any) -> tuple[str, str]:
    return _SCHEMA_FAMILIES.get(
        program_schema,
        (REPORT_SCHEMA_V1, PREPARATION_SCHEMA_V1),
    )


def report_schema_for(program_schema: Any) -> str:
    """Return the report schema paired with a supported program version."""

    return _schema_family(program_schema)[0]


def _program_variant(schema: str) -> dict[str, Any]:
    identifier = {
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "pattern": _IDENTIFIER.pattern,
    }
    text = {"type": "string", "minLength": 1, "maxLength": MAX_STRING_BYTES}
    string_list = {
        "type": "array",
        "maxItems": 64,
        "items": dict(text),
    }
    lane = {
        "type": "object",
        "properties": {
            "id": dict(identifier),
            "objective": dict(text),
            "read_scope": {**string_list, "minItems": 1},
            "excluded_scope": dict(string_list),
            "deliverable": dict(text),
            "verification": {**string_list, "minItems": 1},
            "allowed_tools": {
                **string_list,
                "minItems": 0 if schema in {PROGRAM_SCHEMA_V2, PROGRAM_SCHEMA_V3} else 1,
            },
        },
        "required": [
            "id",
            "objective",
            "read_scope",
            "excluded_scope",
            "deliverable",
            "verification",
            "allowed_tools",
        ],
        "additionalProperties": False,
    }
    runtime_fields: dict[str, Any] = {
        "preparation": {"type": "object", "maxProperties": 8},
        "creation_results": {
            "type": "array",
            "maxItems": MAX_LANES,
            "items": {"type": "object", "maxProperties": 8},
        },
        "terminal_results": {
            "type": "array",
            "maxItems": MAX_LANES,
            "items": {"type": "object", "maxProperties": 12},
        },
        "root_verification": {"type": "object", "maxProperties": 6},
    }
    runtime_required = list(runtime_fields)
    if schema in {PROGRAM_SCHEMA_V2, PROGRAM_SCHEMA_V3}:
        runtime_fields["native_observation"] = {
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "status": {"const": "observed"},
                        "report": {"type": "object", "maxProperties": 32},
                    },
                    "required": ["status", "report"],
                    "additionalProperties": False,
                },
                {
                    "type": "object",
                    "properties": {
                        "status": {"const": "unknown"},
                        "reason": {
                            "type": "string",
                            "enum": sorted(NATIVE_OBSERVATION_UNKNOWN_REASONS),
                        },
                        "source_pointer": dict(text),
                    },
                    "required": ["status", "reason", "source_pointer"],
                    "additionalProperties": False,
                },
            ]
        }
        runtime_required.append("native_observation")
    runtime = {
        "type": "object",
        "properties": runtime_fields,
        "required": runtime_required,
        "additionalProperties": False,
    }
    runtime_descriptor = (
        {"oneOf": [{"type": "null"}, runtime]}
        if schema in {PROGRAM_SCHEMA_V2, PROGRAM_SCHEMA_V3}
        else {"type": ["object", "null"]}
    )
    return {
        "type": "object",
        "properties": {
            "schema": {"const": schema},
            "operation": {"type": "string", "enum": ["prepare", "finalize"]},
            "scan_id": dict(identifier),
            "root": {
                "type": "object",
                "properties": {
                    "thread_id": dict(identifier),
                    "model": dict(identifier),
                    "effort": dict(identifier),
                },
                "required": ["thread_id", "model", "effort"],
                "additionalProperties": False,
            },
            "objective": dict(text),
            "lanes": {
                "type": "array",
                "minItems": 2,
                "maxItems": MAX_LANES,
                "items": lane,
            },
            "authority": {
                "type": "object",
                "properties": {
                    "authority_id": dict(identifier),
                    "status": {"const": "granted"},
                    "scope": {"const": "read_only"},
                },
                "required": ["authority_id", "status", "scope"],
                "additionalProperties": False,
            },
            "protected_resources": dict(string_list),
            "limits": {
                "type": "object",
                "properties": {
                    "context_tokens": {"type": "integer", "minimum": 1},
                    "output_tokens": {"type": "integer", "minimum": 1},
                    "handoff_tokens": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1200,
                    },
                    "tool_calls": {"type": "integer", "minimum": 1},
                },
                "required": [
                    "context_tokens",
                    "output_tokens",
                    "handoff_tokens",
                    "tool_calls",
                ],
                "additionalProperties": False,
            },
            "runtime": runtime_descriptor,
        },
        "required": [
            "schema",
            "operation",
            "scan_id",
            "root",
            "objective",
            "lanes",
            "authority",
            "protected_resources",
            "limits",
            "runtime",
        ],
        "additionalProperties": False,
    }


def program_descriptor() -> dict[str, Any]:
    """Return the exact public schemas for supported advisory transitions."""

    return {
        "oneOf": [
            _program_variant(PROGRAM_SCHEMA_V1),
            _program_variant(PROGRAM_SCHEMA_V2),
            _program_variant(PROGRAM_SCHEMA_V3),
        ]
    }


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


def _text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= MAX_STRING_BYTES
        and "\x00" not in value
    )


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value))


def _exact(value: Any, fields: set[str], label: str, issues: list[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return {}
    unknown = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    for field in unknown:
        _issue(issues, f"{label}:unknown:{field}")
    for field in missing:
        _issue(issues, f"{label}:missing:{field}")
    return dict(value)


def _string_list(value: Any, label: str, issues: list[str], *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value) or len(value) > 64:
        _issue(issues, label + ":invalid")
        return []
    result: list[str] = []
    for item in value:
        if not _text(item):
            _issue(issues, label + ":item_invalid")
        elif item not in result:
            result.append(item)
    return result


def _limits(value: Any, issues: list[str]) -> dict[str, int]:
    item = _exact(
        value,
        {"context_tokens", "output_tokens", "handoff_tokens", "tool_calls"},
        "limits",
        issues,
    )
    result: dict[str, int] = {}
    for field in ("context_tokens", "output_tokens", "handoff_tokens", "tool_calls"):
        amount = item.get(field)
        if type(amount) is not int or amount <= 0:
            _issue(issues, f"limits:{field}_invalid")
        else:
            result[field] = amount
    if result.get("handoff_tokens", 0) > 1200:
        _issue(issues, "limits:handoff_tokens_exceeds_contract")
    return result


def _prepare(value: Mapping[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    report_schema, preparation_schema = _schema_family(value.get("schema"))
    scan_id = value.get("scan_id")
    if not _identifier(scan_id):
        _issue(issues, "scan_id:invalid")
        scan_id = "invalid-scan"
    if not _text(value.get("objective")):
        _issue(issues, "objective:invalid")

    root = _exact(value.get("root"), {"thread_id", "model", "effort"}, "root", issues)
    for field in ("thread_id", "model", "effort"):
        if not _identifier(root.get(field)):
            _issue(issues, f"root:{field}_invalid")

    authority = _exact(
        value.get("authority"),
        {"authority_id", "status", "scope"},
        "authority",
        issues,
    )
    if not _identifier(authority.get("authority_id")):
        _issue(issues, "authority:id_invalid")
    if authority.get("status") != "granted":
        _issue(issues, "authority:not_granted")
    if authority.get("scope") != "read_only":
        _issue(issues, "authority:not_read_only")

    protected_resources = _string_list(
        value.get("protected_resources"), "protected_resources", issues
    )
    limits = _limits(value.get("limits"), issues)
    lanes_value = value.get("lanes")
    if not isinstance(lanes_value, list) or not 2 <= len(lanes_value) <= MAX_LANES:
        _issue(issues, "lanes:count_invalid")
        lanes_value = []

    lane_rows: list[dict[str, Any]] = []
    lane_ids: set[str] = set()
    for index, raw_lane in enumerate(lanes_value):
        label = f"lanes[{index}]"
        lane_fields = {
            "id",
            "objective",
            "read_scope",
            "excluded_scope",
            "deliverable",
            "verification",
            "allowed_tools",
        }
        # A v3 lane may name the node profile it runs on (ADR 0012: an
        # onboarded identifier routes it to any onboarded model); a lane
        # that names none runs the registry's default implementer.
        names_profile = (
            value.get("schema") == PROGRAM_SCHEMA_V3
            and isinstance(raw_lane, Mapping)
            and "model_profile" in raw_lane
        )
        if names_profile:
            lane_fields.add("model_profile")
        lane = _exact(
            raw_lane,
            lane_fields,
            label,
            issues,
        )
        lane_id = lane.get("id")
        if not _identifier(lane_id) or lane_id in lane_ids:
            _issue(issues, label + ":id_invalid_or_duplicate")
            continue
        lane_ids.add(str(lane_id))
        if names_profile and (
            not governor.model_profiles.is_node_profile_id(lane.get("model_profile"))
            or governor.model_profiles.resolve_node_profile(lane.get("model_profile")) is None
        ):
            _issue(issues, label + ":model_profile_invalid")
        if not _text(lane.get("objective")) or not _text(lane.get("deliverable")):
            _issue(issues, label + ":text_invalid")
        read_scope = _string_list(lane.get("read_scope"), label + ".read_scope", issues)
        excluded_scope = _string_list(
            lane.get("excluded_scope"),
            label + ".excluded_scope",
            issues,
            nonempty=False,
        )
        verification = _string_list(
            lane.get("verification"), label + ".verification", issues
        )
        allowed_tools = _string_list(
            lane.get("allowed_tools"),
            label + ".allowed_tools",
            issues,
            nonempty=value.get("schema") not in {PROGRAM_SCHEMA_V2, PROGRAM_SCHEMA_V3},
        )
        lane_rows.append(
            {
                **lane,
                "id": str(lane_id),
                "read_scope": read_scope,
                "excluded_scope": excluded_scope,
                "verification": verification,
                "allowed_tools": allowed_tools,
            }
        )

    workers = []
    task_specs = []
    # Every lane runs the registry's default implementer profile.  Closed v1
    # receipts replay under the expand-step alias of that profile (the
    # registry's historical replay adapter); later programs name the exact
    # profile identifier (Issue 185).
    implementer = governor.model_profiles.default_profile("implementer")
    if len(implementer["aliases"]) != 1:
        raise ValueError("advisory_scan:implementer_alias_ambiguous")
    lane_profile = (
        implementer["aliases"][0]
        if value.get("schema") == PROGRAM_SCHEMA_V1
        else implementer["profile_id"]
    )
    for lane in lane_rows:
        lane_id = lane["id"]
        semantic_root = f"scan/{scan_id}/{lane_id}"
        worker = {
            "id": lane_id,
            "executor": "subagent",
            "justification": "Own one disjoint, independently verifiable read-only scan lane",
            "objective": lane["objective"],
            "deliverables": [semantic_root + "/handoff"],
            "owned_resources": [semantic_root],
            "excluded_resources": lane["excluded_scope"],
            "dependencies": [],
            "verification": lane["verification"],
            "optional": False,
        }
        if "model_profile" in lane:
            worker["model_profile"] = lane["model_profile"]
        workers.append(worker)
        task_spec = {
            "schema": contracts.TASK_SPEC_SCHEMA,
            "id": lane_id,
            "kind": "probe",
            "goal": lane["objective"],
            "rationale": "Produce one bounded evidence-backed advisory scan handoff",
            "non_goals": ["Mutate any resource", "Spawn another worker"],
            "dependencies": [],
            "input_refs": [],
            "read_scope": lane["read_scope"],
            "write_scope": [],
            "deliverable": {
                "schema": (contracts.HANDOFF_RECEIPT_SCHEMA if value.get("schema") == PROGRAM_SCHEMA_V3
                           else "orch-dork/scan-lane-result/v1"),
                "media_type": "application/json",
                "description": lane["deliverable"],
            },
            "acceptance_checks": [
                {"id": f"scan-check-{index + 1}", "description": check, "required": True}
                for index, check in enumerate(lane["verification"])
            ],
            "executor": "subagent",
            "model_profile": lane.get("model_profile", lane_profile),
            "allowed_tools": lane["allowed_tools"],
            "risk": {"level": "low", "reasons": ["read_only"]},
            "budgets": {
                **limits,
                "retries": 0,
            },
            "may_request_decomposition": False,
            "failure_policy": {
                "on_blocked": "return_receipt",
                "on_failed": "return_receipt",
                "on_budget_exhausted": "return_receipt",
            },
        }
        task_report = contracts.validate_task_spec(task_spec)
        if not task_report.get("valid"):
            for issue in task_report.get("issues", []):
                _issue(issues, f"task_specs:{lane_id}:{issue}")
        task_specs.append(
            {
                "lane_id": lane_id,
                "task_spec": task_report.get("normalized") or task_spec,
                "task_spec_sha256": task_report.get("digest"),
            }
        )

    logical_plan = {
        "schema": governor.LOGICAL_PLAN_SCHEMA,
        "plan_id": str(scan_id),
        "revision": 1,
        "predecessor_plan_sha256": None,
        "planner": {
            "role": "sol",
            "root_thread_id": root.get("thread_id"),
            "model": root.get("model"),
            "effort": root.get("effort"),
        },
        "objective": value.get("objective"),
        "finite": True,
        "logical_worker_count": len(workers),
        "workers": workers,
        "execution": {
            "profile": "finite_dag/v1",
            "capacity_source": "runtime_inventory",
            "worker_model": governor.worker_model(),
            "worker_effort": governor.worker_effort(),
            "context_policy": "none",
            "workers_can_spawn": False,
            "retries_allowed": 0,
            "fallbacks_allowed": 0,
            "replacements_allowed": 0,
        },
        "integration": {
            "strategy": "dependency_ordered",
            "release_required": False,
            "final_verification": ["Root verifies every required typed lane handoff"],
        },
        "authority": {
            "authority_id": authority.get("authority_id"),
            "scope": "provider_free",
            "status": authority.get("status"),
            "authorized_worker_ids": [row["id"] for row in workers],
        },
        "protected_resources": protected_resources,
        "acceptance_criteria": [
            f"{lane['id']} returns a valid typed read-only scan handoff"
            for lane in lane_rows
        ],
    }
    if any("model_profile" in worker for worker in workers):
        # A lane naming its profile makes the plan registry-routed: freeze
        # the sealed routing policy that names each lane's profile.
        logical_plan = governor.bind_routing_policy(logical_plan)
    plan_report = governor.validate_logical_plan(logical_plan)
    if plan_report.get("status") != "PASS":
        for issue in plan_report.get("issues", []):
            _issue(issues, "logical_plan:" + str(issue))

    status = "PASS" if not issues else "FAIL"
    preparation_core = {
        "schema": preparation_schema,
        "scan_id": scan_id,
        "logical_plan_sha256": plan_report.get("plan_sha256"),
        "task_spec_sha256s": {
            row["lane_id"]: row["task_spec_sha256"] for row in task_specs
        },
    }
    preparation = {
        **preparation_core,
        "preparation_sha256": _digest(preparation_core),
    }
    core = {
        "schema": report_schema,
        "operation": "prepare",
        "status": status,
        "decision": "PREPARED" if status == "PASS" else "REFUSED",
        "scan_id": scan_id,
        "preparation": preparation if status == "PASS" else None,
        "logical_plan": logical_plan if status == "PASS" else None,
        "logical_plan_sha256": plan_report.get("plan_sha256"),
        "task_specs": task_specs if status == "PASS" else [],
        "execution_status": "NOT_STARTED",
        "handoff_status": "NOT_STARTED",
        "qualification_status": "ADVISORY_ONLY",
        "claim_permitted": False,
        "evidence_unknowns": ["runtime_route", "usage", "custody", "terminal_observation"],
        "next_action": {
            "kind": "evaluate_runtime_gates" if status == "PASS" else "stop",
            "reason": (
                "Bind current route, capacity, lifecycle, admission, and ownership before native creation"
                if status == "PASS"
                else "Correct the named preparation issues before any native creation"
            ),
        },
        "issues": sorted(issues),
        "workers_created": 0,
        "model_calls": 0,
        "hosted_calls": 0,
        "provider_free": True,
    }
    return {**core, "report_sha256": _digest(core)}


def _finalize(value: Mapping[str, Any]) -> dict[str, Any]:
    is_v3 = value.get("schema") == PROGRAM_SCHEMA_V3
    requires_native = value.get("schema") in {PROGRAM_SCHEMA_V2, PROGRAM_SCHEMA_V3}
    prepared_input = dict(value)
    prepared_input["operation"] = "prepare"
    prepared_input["runtime"] = None
    prepared = _prepare(prepared_input)
    if prepared.get("status") != "PASS":
        core = {
            key: item
            for key, item in prepared.items()
            if key != "report_sha256"
        }
        core["operation"] = "finalize"
        core["decision"] = "REFUSED"
        return {**core, "report_sha256": _digest(core)}

    issues: list[str] = []
    runtime_fields = {
        "preparation",
        "creation_results",
        "terminal_results",
        "root_verification",
    }
    if requires_native:
        runtime_fields.add("native_observation")
    runtime = _exact(
        value.get("runtime"),
        runtime_fields,
        "runtime",
        issues,
    )
    if runtime.get("preparation") != prepared.get("preparation"):
        _issue(issues, "runtime:preparation_mismatch")

    lane_ids = [row["lane_id"] for row in prepared["task_specs"]]
    task_specs = {row["lane_id"]: row["task_spec"] for row in prepared["task_specs"]}
    root_thread_id = value.get("root", {}).get("thread_id")

    creations = runtime.get("creation_results")
    if not isinstance(creations, list):
        _issue(issues, "runtime.creation_results:not_array")
        creations = []
    creation_by_lane: dict[str, dict[str, Any]] = {}
    worker_ids: set[str] = set()
    for index, raw_creation in enumerate(creations):
        label = f"runtime.creation_results[{index}]"
        creation = _exact(
            raw_creation,
            {"lane_id", "worker_id", "status", "fresh", "parent_thread_id"},
            label,
            issues,
        )
        lane_id = creation.get("lane_id")
        worker_id = creation.get("worker_id")
        if lane_id not in lane_ids or lane_id in creation_by_lane:
            _issue(issues, label + ":lane_invalid_or_duplicate")
            continue
        if not _identifier(worker_id) or worker_id in worker_ids:
            _issue(issues, label + ":worker_invalid_or_duplicate")
            continue
        if (
            creation.get("status") != "created"
            or creation.get("fresh") is not True
            or creation.get("parent_thread_id") != root_thread_id
        ):
            _issue(issues, label + ":creation_not_bound")
        creation_by_lane[str(lane_id)] = creation
        worker_ids.add(str(worker_id))
    if set(creation_by_lane) != set(lane_ids):
        _issue(issues, "runtime.creation_results:membership_mismatch")

    terminals = runtime.get("terminal_results")
    if not isinstance(terminals, list):
        _issue(issues, "runtime.terminal_results:not_array")
        terminals = []
    terminal_by_lane: dict[str, dict[str, Any]] = {}
    completed_lane_ids: list[str] = []
    failed_lane_ids: list[str] = []
    valid_handoff_lanes: set[str] = set()
    evidence_unknowns: set[str] = set()
    native_observation: dict[str, Any] | None = None
    observed_terminal_digests: dict[str, str] = {}
    if requires_native:
        raw_observation = runtime.get("native_observation")
        if not isinstance(raw_observation, Mapping):
            _issue(issues, "runtime.native_observation:not_object")
        elif raw_observation.get("status") == "unknown":
            issue_count = len(issues)
            observation = _exact(
                raw_observation,
                {"status", "reason", "source_pointer"},
                "runtime.native_observation",
                issues,
            )
            reason = observation.get("reason")
            if reason not in NATIVE_OBSERVATION_UNKNOWN_REASONS:
                _issue(issues, "runtime.native_observation:unknown_reason_invalid")
            if not _text(observation.get("source_pointer")):
                _issue(issues, "runtime.native_observation:source_pointer_invalid")
            if len(issues) == issue_count:
                native_observation = observation
                evidence_unknowns.add("native_observation:" + str(reason))
        elif raw_observation.get("status") == "observed":
            observation = _exact(
                raw_observation,
                {"status", "report"},
                "runtime.native_observation",
                issues,
            )
            binding = native_observer.bind_native_scan_observation(
                observation.get("report"),
                scan_id=str(value.get("scan_id")),
                root_thread_id=str(root_thread_id),
                expected_members={
                    lane_id: str(creation["worker_id"])
                    for lane_id, creation in creation_by_lane.items()
                },
                expected_model=governor.worker_model(),
                expected_effort=governor.worker_effort(),
                expected_terminal_schema=(contracts.HANDOFF_RECEIPT_SCHEMA if is_v3
                                          else "orch-dork/scan-lane-result/v1"),
            )
            for item in binding.get("report_issues", []):
                _issue(
                    issues,
                    "runtime.native_observation.report:" + str(item),
                )
            for item in binding.get("issues", []):
                _issue(
                    issues,
                    "runtime.native_observation:" + str(item),
                )
            normalized_binding = binding.get("normalized")
            if isinstance(normalized_binding, Mapping):
                native_observation = dict(normalized_binding)
                observed_terminal_digests = {
                    row["lane_id"]: row["terminal"]["json_sha256"]
                    for row in observation["report"]["lanes"]
                }
            for item in binding.get("evidence_unknowns", []):
                evidence_unknowns.add("native_observation:" + str(item))
        else:
            _issue(issues, "runtime.native_observation:status_invalid")
    normalized_terminals: list[dict[str, Any]] = []
    for index, raw_terminal in enumerate(terminals):
        label = f"runtime.terminal_results[{index}]"
        terminal = _exact(
            raw_terminal,
            {
                "lane_id",
                "worker_id",
                "status",
                "handoff_receipt",
                "usage",
                "incremental_packets",
                "custody",
            },
            label,
            issues,
        )
        lane_id = terminal.get("lane_id")
        if lane_id not in lane_ids or lane_id in terminal_by_lane:
            _issue(issues, label + ":lane_invalid_or_duplicate")
            continue
        creation = creation_by_lane.get(str(lane_id), {})
        if terminal.get("worker_id") != creation.get("worker_id"):
            _issue(issues, label + ":worker_mismatch")
        status = terminal.get("status")
        if status == "completed":
            completed_lane_ids.append(str(lane_id))
        elif status in {"failed", "cancelled", "timed_out"}:
            failed_lane_ids.append(str(lane_id))
        else:
            _issue(issues, label + ":status_invalid")
            failed_lane_ids.append(str(lane_id))

        handoff_report = contracts.validate_handoff_receipt(
            terminal.get("handoff_receipt"),
            task_spec=task_specs.get(str(lane_id)),
        )
        if is_v3 and observed_terminal_digests.get(str(lane_id)) != _digest(terminal.get("handoff_receipt")):
            _issue(issues, label + ":native_handoff_digest_mismatch")
        handoff_disposition = handoff_report.get("normalized", {}).get(
            "disposition"
        )
        if (
            handoff_report.get("valid")
            and status == "completed"
            and handoff_disposition == "complete"
        ):
            valid_handoff_lanes.add(str(lane_id))
        else:
            for item in handoff_report.get("issues", []):
                _issue(issues, f"{label}:handoff:{item}")
            if (
                handoff_report.get("valid")
                and status == "completed"
                and handoff_disposition != "complete"
            ):
                _issue(issues, label + ":handoff_disposition_mismatch")

        usage = terminal.get("usage")
        if not isinstance(usage, Mapping):
            _issue(issues, label + ":usage_not_object")
        elif usage.get("status") == "unknown":
            expected = {"status", "reason", "source_pointer"}
            if set(usage) != expected or not _text(usage.get("reason")) or not _text(
                usage.get("source_pointer")
            ):
                _issue(issues, label + ":usage_unknown_invalid")
            evidence_unknowns.add("usage")
        elif usage.get("status") == "observed":
            expected = {
                "status",
                "input_tokens",
                "cached_input_tokens",
                "output_tokens",
                "reasoning_tokens",
                "total_tokens",
                "tool_calls",
                "source_pointer",
            }
            numeric_fields = expected - {"status", "source_pointer"}
            valid_numbers = all(
                type(usage.get(field)) is int and usage[field] >= 0
                for field in numeric_fields
            )
            valid_arithmetic = (
                valid_numbers
                and usage["cached_input_tokens"] <= usage["input_tokens"]
                and usage["reasoning_tokens"] <= usage["output_tokens"]
                and usage["total_tokens"]
                == usage["input_tokens"] + usage["output_tokens"]
            )
            if (
                set(usage) != expected
                or not valid_arithmetic
                or not _text(usage.get("source_pointer"))
            ):
                _issue(issues, label + ":usage_observed_invalid")
        else:
            _issue(issues, label + ":usage_status_invalid")

        packets = terminal.get("incremental_packets")
        if not isinstance(packets, list):
            _issue(issues, label + ":incremental_packets_not_array")
            packets = []
        if not packets:
            evidence_unknowns.add("incremental_packets")
        for packet_index, packet in enumerate(packets):
            packet_report = contracts.validate_incremental_claim_packet(
                packet,
                task_spec=task_specs.get(str(lane_id)),
            )
            if not packet_report.get("valid"):
                for item in packet_report.get("issues", []):
                    _issue(
                        issues,
                        f"{label}:incremental_packets[{packet_index}]:{item}",
                    )

        custody = terminal.get("custody")
        if not isinstance(custody, Mapping) or set(custody) != {
            "coverage",
            "source_pointer",
        }:
            _issue(issues, label + ":custody_invalid")
        elif custody.get("coverage") not in {"complete", "unknown"} or not _text(
            custody.get("source_pointer")
        ):
            _issue(issues, label + ":custody_invalid")
        elif custody.get("coverage") == "unknown":
            evidence_unknowns.add("custody")

        terminal_by_lane[str(lane_id)] = terminal
        normalized_terminals.append(
            {
                **terminal,
                "handoff_receipt": terminal.get("handoff_receipt") if is_v3 else handoff_report.get("normalized"),
            }
        )
    if set(terminal_by_lane) != set(lane_ids):
        _issue(issues, "runtime.terminal_results:membership_mismatch")

    verification = _exact(
        runtime.get("root_verification"),
        {"status", "verified_lane_ids", "source_pointer"},
        "runtime.root_verification",
        issues,
    )
    verified_lane_ids = verification.get("verified_lane_ids")
    if (
        verification.get("status") != "passed"
        or not isinstance(verified_lane_ids, list)
        or sorted(verified_lane_ids) != sorted(lane_ids)
        or not _text(verification.get("source_pointer"))
    ):
        _issue(issues, "runtime.root_verification:not_complete")

    all_completed = sorted(completed_lane_ids) == sorted(lane_ids) and not failed_lane_ids
    handoffs_complete = valid_handoff_lanes == set(lane_ids)
    status = "PASS" if not issues and all_completed and handoffs_complete else "FAIL"
    core = {
        "schema": report_schema_for(value.get("schema")),
        "operation": "finalize",
        "status": status,
        "decision": "COMPLETED_ADVISORY" if status == "PASS" else "FAILED",
        "scan_id": value.get("scan_id"),
        "preparation": prepared["preparation"],
        "logical_plan": prepared["logical_plan"],
        "logical_plan_sha256": prepared["logical_plan_sha256"],
        "task_specs": prepared["task_specs"],
        "terminal_results": normalized_terminals,
        "execution_status": "DRAINED" if all_completed else "DRAINED_WITH_FAILURES",
        "handoff_status": "COMPLETE" if handoffs_complete else "INCOMPLETE",
        "qualification_status": "ADVISORY_ONLY",
        "claim_permitted": False,
        "evidence_unknowns": sorted(evidence_unknowns),
        "next_action": {
            "kind": "complete_advisory_report" if status == "PASS" else "stop",
            "reason": (
                "Report completed work and unknown qualification evidence separately"
                if status == "PASS"
                else "Preserve the failed lane or invalid evidence without retry or replacement"
            ),
        },
        "issues": sorted(issues),
        "completed_lane_ids": sorted(completed_lane_ids),
        "failed_lane_ids": sorted(set(failed_lane_ids)),
        "workers_created": len(creation_by_lane),
        "model_calls": 0,
        "hosted_calls": 0,
        "provider_free": True,
    }
    if requires_native:
        core["native_observation"] = native_observation
    return {**core, "report_sha256": _digest(core)}


def evaluate_advisory_scan(program: Any) -> dict[str, Any]:
    issues: list[str] = []
    value = _exact(
        program,
        {
            "schema",
            "operation",
            "scan_id",
            "root",
            "objective",
            "lanes",
            "authority",
            "protected_resources",
            "limits",
            "runtime",
        },
        "program",
        issues,
    )
    if value.get("schema") not in _SCHEMA_FAMILIES:
        _issue(issues, "program:schema_invalid")
    if value.get("operation") not in {"prepare", "finalize"}:
        _issue(issues, "program:operation_invalid")
    if value.get("operation") == "prepare" and value.get("runtime") is not None:
        _issue(issues, "program:prepare_runtime_must_be_null")
    if value.get("operation") == "finalize" and value.get("runtime") is None:
        _issue(issues, "program:finalize_runtime_required")
    if issues:
        core = {
            "schema": report_schema_for(value.get("schema")),
            "operation": value.get("operation"),
            "status": "FAIL",
            "decision": "REFUSED",
            "scan_id": value.get("scan_id"),
            "preparation": None,
            "logical_plan": None,
            "logical_plan_sha256": None,
            "task_specs": [],
            "execution_status": "NOT_STARTED",
            "handoff_status": "NOT_STARTED",
            "qualification_status": "ADVISORY_ONLY",
            "claim_permitted": False,
            "evidence_unknowns": [],
            "next_action": {"kind": "stop", "reason": "Program shape is invalid"},
            "issues": sorted(issues),
            "workers_created": 0,
            "model_calls": 0,
            "hosted_calls": 0,
            "provider_free": True,
        }
        return {**core, "report_sha256": _digest(core)}
    if value.get("operation") == "finalize":
        return _finalize(value)
    return _prepare(value)


__all__ = [
    "NATIVE_OBSERVATION_UNKNOWN_REASONS",
    "PREPARATION_SCHEMA",
    "PREPARATION_SCHEMA_V1",
    "PREPARATION_SCHEMA_V2",
    "PREPARATION_SCHEMA_V3",
    "PROGRAM_SCHEMA",
    "PROGRAM_SCHEMA_V1",
    "PROGRAM_SCHEMA_V2",
    "PROGRAM_SCHEMA_V3",
    "REPORT_SCHEMA",
    "REPORT_SCHEMA_V1",
    "REPORT_SCHEMA_V2",
    "REPORT_SCHEMA_V3",
    "evaluate_advisory_scan",
    "program_descriptor",
    "report_schema_for",
]
