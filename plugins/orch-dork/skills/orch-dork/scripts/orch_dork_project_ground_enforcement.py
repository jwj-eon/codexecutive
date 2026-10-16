#!/usr/bin/env python3
"""Provider-free mechanical project-ground mutation gate.

Issue 42 composes the previously sealed project enrollment, immutable adapter,
ticket admission, lease, active controller, execution readiness, and durable
capsule into one closed pre-mutation decision.  The evaluator is deliberately
total and side-effect free.  The plugin-bundled hook is a thin transport that
loads a gateway-produced state record, normalizes the official Codex hook
event, and renders this report as an official hook response.

Hooks are a useful local guardrail, not a universal security boundary.  Tool
classes that do not traverse ``PreToolUse`` are never promoted by this module:
they require an exact sandbox or project-native gateway receipt, otherwise the
decision is ``DENY``.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import types
from typing import Any, Mapping, Sequence


def _load_owned_file():
    """Reuse or publish only this gate's exact owned-file sibling."""
    name = "orch_dork_owned_file"
    path = Path(__file__).resolve(strict=True).with_name(name + ".py")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ImportError("owned-file dependency is not regular source")
        source = stream.read()
    after = path.lstat()
    if (not stat.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino) != (metadata.st_dev, metadata.st_ino)):
        raise ImportError("owned-file dependency source changed")
    code = compile(source, str(path), "exec", dont_inherit=True)
    if name in sys.modules:
        module = sys.modules[name]
        if type(module) is not types.ModuleType:
            raise ImportError("foreign owned-file dependency")
        fields = vars(module)
        spec = fields.get("__spec__")
        if type(spec) is not importlib.machinery.ModuleSpec:
            raise ImportError("foreign owned-file dependency spec")
        spec_fields = vars(spec)
        loader = spec_fields.get("loader")
        if (spec_fields.get("_initializing", False) is not False
                or type(loader) is not importlib.machinery.SourceFileLoader
                or fields.get("__loader__") is not loader):
            raise ImportError("foreign owned-file dependency")
        for values, key, wanted in (
                (fields, "__name__", name), (fields, "__file__", str(path)),
                (spec_fields, "name", name), (spec_fields, "origin", str(path)),
                (vars(loader), "name", name), (vars(loader), "path", str(path))):
            if type(values.get(key)) is not str or values[key] != wanted:
                raise ImportError("foreign owned-file dependency")
        # This sibling has one literal bound and plain functions with literal
        # defaults. Derive them from held source without publishing another module.
        reference = types.ModuleType(name)
        vars(reference)["__file__"] = str(path)
        exec(code, vars(reference))
        def same_defaults(actual, expected):
            if type(actual) is not type(expected):
                return False
            if type(expected) in (type(None), bool, int, str):
                return actual == expected
            if type(expected) is tuple:
                return len(actual) == len(expected) and all(same_defaults(a, e) for a, e in zip(actual, expected))
            if type(expected) is dict:
                return (all(type(key) is str for key in actual)
                        and len(actual) == len(expected)
                        and all(key in actual and same_defaults(actual[key], value) for key, value in expected.items()))
            return False
        bound = vars(reference)["MAX_PRIVATE_ROLLOUT_BYTES"]
        if (type(fields.get("MAX_PRIVATE_ROLLOUT_BYTES")) is not int
                or fields["MAX_PRIVATE_ROLLOUT_BYTES"] != bound):
            raise ImportError("foreign owned-file dependency rollout bound")
        # This sibling defines plain top-level functions; metadata cannot attest their code.
        for definition in code.co_consts:
            if type(definition) is types.CodeType:
                function = module.__dict__.get(definition.co_name)
                original = vars(reference)[definition.co_name]
                if (type(function) is not types.FunctionType
                        or function.__code__ != definition
                        or function.__globals__ is not module.__dict__
                        or not same_defaults(function.__defaults__, original.__defaults__)
                        or not same_defaults(function.__kwdefaults__, original.__kwdefaults__)):
                    raise ImportError("foreign owned-file dependency code: " + definition.co_name)
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


owned_file = _load_owned_file()


PROGRAM_SCHEMA = "orch-dork/project-ground-enforcement-program/v1"
REPORT_SCHEMA = "orch-dork/project-ground-mutation-decision/v1"
SESSION_HEALTH_SCHEMA = "orch-dork/project-ground-session-health/v1"
NATIVE_CONTROLLER_HOOK_SCHEMA = "orch-dork/governed-native-hook-binding/v1"
QUALIFICATION_OWNER_CONTEXT_SCHEMA = (
    "orch-dork/qualification-owner-context/v1"
)
HOOK_STATE_SCHEMA = "orch-dork/project-ground-hook-state/v1"
POLICY_VERSION = "project-ground-enforcement-policy/v1"
QUALIFICATION_OWNER_COMPATIBLE_CONTROLLER_ISSUES = frozenset(
    {"native_controller:hook_definition_mismatch"}
)

HOOK_EVENTS = frozenset(
    {"SessionStart", "PreToolUse", "PostToolUse", "Stop", "SubagentStop"}
)
SUPPORTED_PRETOOL_CLASSES = frozenset(
    {"shell", "apply_patch", "mcp", "local_function", "code_mode_nested"}
)
GATEWAY_ONLY_CLASSES = frozenset(
    {
        "write_stdin",
        "child_process",
        "hosted",
        "specialized",
        "computer_use",
        "external_process",
    }
)
ALL_COVERAGE_CLASSES = SUPPORTED_PRETOOL_CLASSES | GATEWAY_ONLY_CLASSES
REQUIRED_PROTECTED_RESOURCES = frozenset(
    {
        "semantic:project-binding",
        "semantic:project-enrollment-record",
        "semantic:adapter-snapshot",
        "semantic:execution-lease",
        "semantic:evidence-seal",
        "semantic:ticket-admission",
        "semantic:hook-state",
        "semantic:coordinator-capsule",
    }
)

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_SENSITIVE_KEY = re.compile(
    r"(?:credential|secret|token|password|api[_-]?key|authorization|cookie|private[_-]?reason)",
    re.IGNORECASE,
)
_READ_ONLY_MCP = re.compile(
    r"(?:^|__)(?:read|get|list|find|search|open|view|inspect|status|query)(?:_|$)",
    re.IGNORECASE,
)
_READ_ONLY_LOCAL = frozenset(
    {
        "view_image",
        "list_mcp_resources",
        "list_mcp_resource_templates",
        "read_mcp_resource",
        "get_goal",
        "read_thread",
        "list_threads",
        "wait_threads",
        "list_agents",
        "wait_agent",
        "multi_agent_v1__wait_agent",
        "multi_agent_v1wait_agent",
    }
)
# A command is exempt only within this small, option-aware read grammar.
# In particular, a familiar executable name says nothing about its options.
# Quoted shell syntax is conservatively guarded too; this is not a shell AST.
_SHELL_DYNAMIC_CHARACTERS = frozenset("\n\r\0;&|><`$(){}*?[]~!\\")
_SHELL_READ_FLAGS = {
    name: frozenset(flags.split())
    for name, flags in {
        "basename": "--help --version",
        "cmp": "-s -l --silent --quiet --verbose",
        "dirname": "--help --version",
        "du": "-a -s -h -k -m --summarize --human-readable",
        "file": "-b -i -L --brief --mime --mime-type --mime-encoding",
        "find": "-print -print0 -prune -a -o",
        "grep": "-n -i -v -l -L -r -R -s -c -h -H -o -w -x -F -E",
        "head": "-q -v --quiet --silent --verbose",
        "ls": "-l -a -A -d -h -R -1 -s -t -r --all --almost-all --directory",
        "pwd": "-L -P --logical --physical",
        "readlink": "-f -e -m --canonicalize --canonicalize-existing --canonicalize-missing",
        "rg": "-n -i -v -l -s -c -o -w -x -F --files --hidden --no-ignore --no-config",
        "sha256sum": "-b -t --binary --text",
        "shasum": "-b -t --binary --text",
        "sort": "-r -n -u -b -f -M -V --reverse --numeric-sort --unique",
        "stat": "-L -t --dereference --terse",
        "tail": "-q -v --quiet --silent --verbose",
        "uname": "-a -s -n -r -v -m -p -i -o",
        "uniq": "-c -d -u --count --repeated --unique",
        "wc": "-l -w -c -m -L --lines --words --bytes --chars --max-line-length",
        "which": "-a --all",
    }.items()
}
_SHELL_COUNT_OPTIONS = {"-n": "count", "-c": "count", "--lines": "count", "--bytes": "count"}
_SHELL_READ_VALUE_OPTIONS = {
    "head": _SHELL_COUNT_OPTIONS,
    "tail": _SHELL_COUNT_OPTIONS,
    "find": {"-type": "file_type", "-name": "text", "-iname": "text"},
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


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _mapping(value: Any, label: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return {}
    return value


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> Mapping[str, Any]:
    item = _mapping(value, label, issues)
    for key in sorted(keys - set(item)):
        _issue(issues, label + ":missing:" + key)
    for key in sorted(set(item) - keys):
        suffix = "sensitive_unknown" if _SENSITIVE_KEY.search(str(key)) else "unknown:" + str(key)
        _issue(issues, label + ":" + suffix)
    return item


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _hash(value: Any, label: str, issues: list[str], *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _issue(issues, label + ":sha256_invalid")
        return None
    return value


def _string_list(value: Any, label: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list) or any(not _text(item) for item in value):
        _issue(issues, label + ":invalid")
        return []
    return [str(item) for item in value]


def _event(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "hook_event_name",
            "session_id",
            "turn_id",
            "cwd",
            "model",
            "permission_mode",
            "source",
            "agent_id",
            "agent_type",
            "stop_hook_active",
            "tool_name",
            "tool_use_id",
            "tool_input",
            "tool_response",
            "code_mode_nested",
        },
        "event",
        issues,
    )
    name = item.get("hook_event_name")
    if name not in HOOK_EVENTS:
        _issue(issues, "event:hook_event_name_invalid")
    for key in ("session_id", "cwd", "model", "permission_mode"):
        if not _text(item.get(key)):
            _issue(issues, "event:" + key + "_invalid")
    if name != "SessionStart" and not _text(item.get("turn_id")):
        _issue(issues, "event:turn_id_invalid")
    if name in {"PreToolUse", "PostToolUse"}:
        if not _text(item.get("tool_name")):
            _issue(issues, "event:tool_name_invalid")
        if not _text(item.get("tool_use_id")):
            _issue(issues, "event:tool_use_id_invalid")
        if not isinstance(item.get("tool_input"), Mapping):
            _issue(issues, "event:tool_input_not_object")
    if name == "SessionStart" and item.get("source") not in {"startup", "resume", "clear", "compact"}:
        _issue(issues, "event:source_invalid")
    if not isinstance(item.get("stop_hook_active"), bool):
        _issue(issues, "event:stop_hook_active_invalid")
    if not isinstance(item.get("code_mode_nested"), bool):
        _issue(issues, "event:code_mode_nested_invalid")
    return dict(item)


def _hook_health(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "enabled",
            "trusted",
            "managed",
            "source",
            "status",
            "expected_sha256",
            "observed_sha256",
            "timeout_ms",
            "matching_decisions",
        },
        "state.hook",
        issues,
    )
    for key in ("enabled", "trusted", "managed"):
        if not isinstance(item.get(key), bool):
            _issue(issues, "state.hook:" + key + "_invalid")
    if item.get("source") not in {"plugin", "project", "user", "managed"}:
        _issue(issues, "state.hook:source_invalid")
    if item.get("status") not in {"ready", "missing", "disabled", "untrusted", "timed_out", "crashed", "contradictory"}:
        _issue(issues, "state.hook:status_invalid")
    expected = _hash(item.get("expected_sha256"), "state.hook:expected", issues)
    observed = _hash(item.get("observed_sha256"), "state.hook:observed", issues, optional=True)
    timeout = item.get("timeout_ms")
    if type(timeout) is not int or timeout < 1 or timeout > 30_000:
        _issue(issues, "state.hook:timeout_ms_invalid")
    decisions = _string_list(item.get("matching_decisions"), "state.hook:matching_decisions", issues)
    if any(value not in {"allow", "deny", "observe", "continue"} for value in decisions):
        _issue(issues, "state.hook:matching_decision_invalid")
    return {**dict(item), "expected_sha256": expected, "observed_sha256": observed, "matching_decisions": decisions}


def _prerequisites(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "ticket_admission",
            "enrollment",
            "adapter",
            "execution_readiness",
            "lease",
            "active_controller",
            "capsule",
            "authority",
            "workspace",
        },
        "state.prerequisites",
        issues,
    )
    ticket = _exact(
        item.get("ticket_admission"),
        {"status", "decision", "ticket_id", "admission_sha256", "implementation_permitted", "plan_sha256"},
        "state.prerequisites.ticket_admission",
        issues,
    )
    if ticket.get("status") != "PASS" or ticket.get("decision") not in {"ATOMIC_ADMITTED", "ORCHESTRATION_PLAN_REQUIRED"}:
        _issue(issues, "prerequisite:ticket_admission_invalid")
    if ticket.get("implementation_permitted") is not True:
        _issue(issues, "prerequisite:implementation_not_permitted")
    _hash(ticket.get("admission_sha256"), "prerequisite:ticket_admission", issues)
    _hash(ticket.get("plan_sha256"), "prerequisite:plan", issues, optional=True)

    enrollment = _exact(
        item.get("enrollment"),
        {"status", "decision", "project_id", "generation", "manifest_sha256", "record_sha256"},
        "state.prerequisites.enrollment",
        issues,
    )
    if enrollment.get("status") != "PASS" or enrollment.get("decision") != "ACTIVE":
        _issue(issues, "prerequisite:enrollment_not_active")
    if type(enrollment.get("generation")) is not int or enrollment.get("generation", 0) < 1:
        _issue(issues, "prerequisite:project_generation_invalid")
    _hash(enrollment.get("manifest_sha256"), "prerequisite:manifest", issues)
    _hash(enrollment.get("record_sha256"), "prerequisite:enrollment_record", issues)

    adapter = _exact(
        item.get("adapter"),
        {"status", "decision", "snapshot_sha256", "report_sha256"},
        "state.prerequisites.adapter",
        issues,
    )
    if adapter.get("status") != "PASS" or adapter.get("decision") not in {"ALLOW", "PASS"}:
        _issue(issues, "prerequisite:adapter_refused")
    _hash(adapter.get("snapshot_sha256"), "prerequisite:adapter_snapshot", issues)
    _hash(adapter.get("report_sha256"), "prerequisite:adapter_report", issues)

    readiness = _exact(item.get("execution_readiness"), {"status", "report_sha256"}, "state.prerequisites.execution_readiness", issues)
    if readiness.get("status") != "PASS":
        _issue(issues, "prerequisite:execution_readiness_invalid")
    _hash(readiness.get("report_sha256"), "prerequisite:execution_readiness", issues)

    lease = _exact(
        item.get("lease"),
        {"status", "version", "owner_thread_id", "current_thread_id", "checkpoint_sha256", "cas_valid"},
        "state.prerequisites.lease",
        issues,
    )
    if lease.get("status") != "active_successor":
        _issue(issues, "prerequisite:lease_not_active")
    if type(lease.get("version")) is not int or lease.get("version", 0) < 1:
        _issue(issues, "prerequisite:lease_version_invalid")
    if lease.get("owner_thread_id") != lease.get("current_thread_id"):
        _issue(issues, "prerequisite:lease_owner_mismatch")
    if lease.get("cas_valid") is not True:
        _issue(issues, "prerequisite:lease_cas_invalid")
    _hash(lease.get("checkpoint_sha256"), "prerequisite:lease_checkpoint", issues)

    controller = _exact(item.get("active_controller"), {"status", "report_sha256"}, "state.prerequisites.active_controller", issues)
    if controller.get("status") != "PASS":
        _issue(issues, "prerequisite:active_controller_invalid")
    _hash(controller.get("report_sha256"), "prerequisite:active_controller", issues)

    capsule = _exact(item.get("capsule"), {"status", "capsule_sha256"}, "state.prerequisites.capsule", issues)
    if capsule.get("status") != "PASS":
        _issue(issues, "prerequisite:capsule_invalid")
    _hash(capsule.get("capsule_sha256"), "prerequisite:capsule", issues)

    authority = _exact(item.get("authority"), {"scope_sha256", "writable_scope_sha256", "grants_sha256", "narrowed"}, "state.prerequisites.authority", issues)
    for key in ("scope_sha256", "writable_scope_sha256", "grants_sha256"):
        _hash(authority.get(key), "prerequisite:authority:" + key, issues)
    if authority.get("narrowed") is not True:
        _issue(issues, "prerequisite:authority_not_narrowed")

    workspace = _exact(item.get("workspace"), {"baseline_sha256", "current_sha256", "baseline_valid"}, "state.prerequisites.workspace", issues)
    _hash(workspace.get("baseline_sha256"), "prerequisite:workspace_baseline", issues)
    _hash(workspace.get("current_sha256"), "prerequisite:workspace_current", issues)
    if workspace.get("baseline_valid") is not True:
        _issue(issues, "prerequisite:workspace_baseline_invalid")
    return deepcopy(dict(item))


def _lifecycle(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "session_health",
            "resumed",
            "compacted",
            "duplicate_task",
            "concurrent_writers",
            "binding_revalidated",
            "mutation_seq",
            "expected_mutation_seq",
        },
        "state.lifecycle",
        issues,
    )
    for key in ("resumed", "compacted", "duplicate_task", "binding_revalidated"):
        if not isinstance(item.get(key), bool):
            _issue(issues, "state.lifecycle:" + key + "_invalid")
    if type(item.get("concurrent_writers")) is not int or item.get("concurrent_writers", 0) < 1:
        _issue(issues, "state.lifecycle:concurrent_writers_invalid")
    for key in ("mutation_seq", "expected_mutation_seq"):
        if type(item.get(key)) is not int or item.get(key, -1) < 0:
            _issue(issues, "state.lifecycle:" + key + "_invalid")
    health = item.get("session_health")
    if health is not None:
        health = _exact(
            health,
            {"schema", "status", "session_id", "project_id", "generation", "state_sha256", "health_sha256"},
            "state.lifecycle.session_health",
            issues,
        )
        if health.get("schema") != SESSION_HEALTH_SCHEMA or health.get("status") != "HEALTHY":
            _issue(issues, "lifecycle:session_health_invalid")
        _hash(health.get("state_sha256"), "lifecycle:session_state", issues)
        declared = _hash(health.get("health_sha256"), "lifecycle:session_health", issues)
        if declared is not None and declared != _sha({key: value for key, value in health.items() if key != "health_sha256"}):
            _issue(issues, "lifecycle:session_health_hash_mismatch")
        health = dict(health)
    return {**dict(item), "session_health": health}


def _sandbox(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(value, {"status", "profile", "covered_classes", "writable_roots", "source_pointer"}, "state.sandbox", issues)
    if item.get("status") not in {"PASS", "PARTIAL", "FAIL"}:
        _issue(issues, "state.sandbox:status_invalid")
    covered = _string_list(item.get("covered_classes"), "state.sandbox:covered_classes", issues)
    if any(value not in ALL_COVERAGE_CLASSES for value in covered):
        _issue(issues, "state.sandbox:coverage_class_invalid")
    roots = _string_list(item.get("writable_roots"), "state.sandbox:writable_roots", issues)
    return {**dict(item), "covered_classes": covered, "writable_roots": roots}


def _state(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(value, {"hook", "prerequisites", "lifecycle", "sandbox", "source_pointer"}, "state", issues)
    return {
        "hook": _hook_health(item.get("hook"), issues),
        "prerequisites": _prerequisites(item.get("prerequisites"), issues),
        "lifecycle": _lifecycle(item.get("lifecycle"), issues),
        "sandbox": _sandbox(item.get("sandbox"), issues),
        "source_pointer": item.get("source_pointer"),
    }


def _tool_policy(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {"supported_hook_classes", "gateway_only_classes", "read_only_tools", "max_tool_input_bytes"},
        "tool_policy",
        issues,
    )
    supported = _string_list(item.get("supported_hook_classes"), "tool_policy:supported_hook_classes", issues)
    gateway_only = _string_list(item.get("gateway_only_classes"), "tool_policy:gateway_only_classes", issues)
    read_only = _string_list(item.get("read_only_tools"), "tool_policy:read_only_tools", issues)
    if set(supported) != set(SUPPORTED_PRETOOL_CLASSES):
        _issue(issues, "tool_policy:supported_hook_classes_incomplete")
    if set(gateway_only) != set(GATEWAY_ONLY_CLASSES):
        _issue(issues, "tool_policy:gateway_only_classes_incomplete")
    limit = item.get("max_tool_input_bytes")
    if type(limit) is not int or limit < 1 or limit > 1_000_000:
        _issue(issues, "tool_policy:max_tool_input_bytes_invalid")
        limit = 0
    return {**dict(item), "supported_hook_classes": supported, "gateway_only_classes": gateway_only, "read_only_tools": read_only, "max_tool_input_bytes": limit}


def _gateways(value: Any, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, "gateways:not_array")
        return []
    rows: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item = _exact(
            raw,
            {"gateway_id", "coverage_class", "status", "exact_tool_input_sha256", "resources", "authority_narrowed", "source_pointer"},
            f"gateways[{index}]",
            issues,
        )
        if not _text(item.get("gateway_id")):
            _issue(issues, f"gateways[{index}]:gateway_id_invalid")
        if item.get("coverage_class") not in ALL_COVERAGE_CLASSES:
            _issue(issues, f"gateways[{index}]:coverage_class_invalid")
        if item.get("status") not in {"AUTHORIZED", "REFUSED"}:
            _issue(issues, f"gateways[{index}]:status_invalid")
        _hash(item.get("exact_tool_input_sha256"), f"gateways[{index}]:tool_input", issues)
        resources = _string_list(item.get("resources"), f"gateways[{index}]:resources", issues)
        if item.get("authority_narrowed") is not True:
            _issue(issues, f"gateways[{index}]:authority_not_narrowed")
        rows.append({**dict(item), "resources": resources})
    return rows


def _completion(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {"final_verification_valid", "final_verification_sha256", "independent_observation", "governed_controller_status"},
        "completion",
        issues,
    )
    if not isinstance(item.get("final_verification_valid"), bool):
        _issue(issues, "completion:final_verification_valid_invalid")
    _hash(item.get("final_verification_sha256"), "completion:final_verification", issues, optional=True)
    if item.get("independent_observation") not in {"BOUND", "UNBOUND", "CONTRADICTORY"}:
        _issue(issues, "completion:independent_observation_invalid")
    if item.get("governed_controller_status") not in {"PASS", "BLOCKED", "PENDING"}:
        _issue(issues, "completion:governed_controller_status_invalid")
    return dict(item)


def _program(program: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    item = _exact(
        program,
        {"schema", "event", "state", "tool_policy", "protected_resources", "gateways", "completion", "source_pointer"},
        "program",
        issues,
    )
    if item.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    protected = _string_list(item.get("protected_resources"), "protected_resources", issues)
    if not protected:
        _issue(issues, "protected_resources:empty")
    for required in sorted(REQUIRED_PROTECTED_RESOURCES - set(protected)):
        _issue(issues, "protected_resources:required_missing:" + required)
    return (
        {
            "schema": PROGRAM_SCHEMA,
            "event": _event(item.get("event"), issues),
            "state": _state(item.get("state"), issues),
            "tool_policy": _tool_policy(item.get("tool_policy"), issues),
            "protected_resources": protected,
            "gateways": _gateways(item.get("gateways"), issues),
            "completion": _completion(item.get("completion"), issues),
            "source_pointer": item.get("source_pointer"),
        },
        issues,
    )


def classify_tool(tool_name: str | None, tool_input: Mapping[str, Any] | None, *, nested: bool = False) -> tuple[str, bool]:
    """Return the conservative coverage class and mutation judgment."""

    name = tool_name or ""
    payload = tool_input if isinstance(tool_input, Mapping) else {}
    if nested:
        return "code_mode_nested", _tool_mutates(name, payload)
    lowered = name.lower()
    if lowered in {"apply_patch", "edit", "write"}:
        return "apply_patch", True
    if lowered in {"bash", "exec_command"}:
        command = payload.get("command", payload.get("cmd"))
        if isinstance(command, str) and re.search(r"(?:^|\s)(?:&|nohup)(?:\s|$)", command):
            return "child_process", True
        # Caller-selected execution machinery is outside the read grammar.
        overridden = any(key in payload for key in ("shell", "env", "environment"))
        ambiguous = "command" in payload and "cmd" in payload
        return "shell", overridden or ambiguous or _shell_mutates(command)
    if lowered == "write_stdin":
        return "write_stdin", True
    if lowered.startswith("mcp__"):
        return "mcp", _READ_ONLY_MCP.search(lowered) is None
    if "computer" in lowered or lowered in {"screenshot", "click", "type"}:
        return "computer_use", True
    if lowered.startswith(("web__", "websearch", "browser__", "chrome__")):
        return "hosted", True
    if lowered.startswith(("image_gen__", "figma__", "specialized__")):
        return "specialized", True
    if lowered.startswith(("external__", "process__")):
        return "external_process", True
    return "local_function", lowered not in _READ_ONLY_LOCAL


def _tool_mutates(name: str, payload: Mapping[str, Any]) -> bool:
    return classify_tool(name, payload, nested=False)[1]


def _canonical_native_tool_name(value: Any) -> str:
    name = str(value or "").strip().casefold()
    aliases = {
        "agent": "spawn_agent",
        "spawn_agent": "spawn_agent",
        "multi_agent_v1__spawn_agent": "spawn_agent",
        "send_input": "send_input",
        "multi_agent_v1__send_input": "send_input",
        "multi_agent_v1send_input": "send_input",
        "close_agent": "close_agent",
        "multi_agent_v1__close_agent": "close_agent",
        "multi_agent_v1close_agent": "close_agent",
        "wait_agent": "wait_agent",
        "multi_agent_v1__wait_agent": "wait_agent",
        "multi_agent_v1wait_agent": "wait_agent",
    }
    return aliases.get(name, name)


def _qualification_owner_context_valid(
    event: Mapping[str, Any], context: Any
) -> bool:
    fields = {
        "schema",
        "status",
        "disposition",
        "session_id",
        "model",
        "workspace",
        "source",
        "owner_socket",
        "app_server_pid",
        "app_server_argv_sha256",
        "preparation_report_path",
        "preparation_report_sha256",
        "preparation_file_sha256",
        "event_sha256",
        "issues",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "credential_reads",
        "network_calls",
        "task_creations",
        "native_calls",
        "mutations_performed",
        "report_sha256",
    }
    if not isinstance(context, Mapping) or set(context) != fields:
        return False
    core = {
        key: child
        for key, child in context.items()
        if key != "report_sha256"
    }
    owner_socket = context.get("owner_socket")
    preparation_path = context.get("preparation_report_path")
    try:
        socket_path = Path(str(owner_socket))
        report_path = Path(str(preparation_path))
    except (TypeError, ValueError):
        return False
    return bool(
        context.get("schema") == QUALIFICATION_OWNER_CONTEXT_SCHEMA
        and context.get("status") == "PASS"
        and context.get("disposition") == "QUALIFICATION_OWNER_READ_ONLY"
        and context.get("session_id") == event.get("session_id")
        and context.get("model") == event.get("model")
        and context.get("workspace") == event.get("cwd")
        and context.get("source") == event.get("source")
        and event.get("agent_id") is None
        and socket_path.is_absolute()
        and report_path.is_absolute()
        and report_path.parent == socket_path.parent
        and report_path.name == "host-preparation.json"
        and type(context.get("app_server_pid")) is int
        and context.get("app_server_pid", 0) > 0
        and all(
            isinstance(context.get(field), str)
            and _SHA256.fullmatch(context[field]) is not None
            for field in (
                "app_server_argv_sha256",
                "preparation_report_sha256",
                "preparation_file_sha256",
                "event_sha256",
                "report_sha256",
            )
        )
        and context.get("event_sha256") == _sha(event)
        and context.get("issues") == []
        and context.get("provider_free") is True
        and all(
            context.get(field) == 0
            for field in (
                "model_calls",
                "hosted_calls",
                "credential_reads",
                "network_calls",
                "task_creations",
                "native_calls",
                "mutations_performed",
            )
        )
        and context.get("report_sha256") == _sha(core)
    )


def _qualification_owner_route_observer_input(tool_input: Any) -> bool:
    return bool(
        isinstance(tool_input, Mapping)
        and set(tool_input).issubset({"expected_identity_sha256"})
        and (
            "expected_identity_sha256" not in tool_input
            or isinstance(tool_input.get("expected_identity_sha256"), str)
            and _SHA256.fullmatch(tool_input["expected_identity_sha256"])
            is not None
        )
    )


def _qualification_owner_handoff_input(tool_input: Any) -> bool:
    if not isinstance(tool_input, Mapping) or set(tool_input) != {"program"}:
        return False
    program = tool_input.get("program")
    if (
        not isinstance(program, Mapping)
        or set(program) != {"schema", "operation", "payload"}
        or program.get("schema")
        != "orch-dork/live-route-authorization-program/v1"
        or program.get("operation") not in {"prepare", "authorize"}
        or not isinstance(program.get("payload"), Mapping)
    ):
        return False
    payload = program["payload"]
    statement = payload.get("authorization_statement")
    if not isinstance(statement, str) or not statement.strip():
        return False
    if program["operation"] == "prepare":
        return bool(
            set(payload) == {"scope_sha256", "authorization_statement"}
            and isinstance(payload.get("scope_sha256"), str)
            and _SHA256.fullmatch(payload["scope_sha256"]) is not None
        )
    return bool(
        set(payload) == {"preparation_report", "authorization_statement"}
        and isinstance(payload.get("preparation_report"), Mapping)
    )


def _shell_read_arguments(
    arguments: Sequence[str], flags: frozenset[str], value_options: Mapping[str, str],
    *, max_operands: int | None = None,
) -> bool:
    """Accept literal operands and only enumerated non-writing options."""

    short_flags = {flag[1] for flag in flags if len(flag) == 2 and flag.startswith("-")}
    cursor = 0
    operands = 0
    while cursor < len(arguments):
        argument = arguments[cursor]
        cursor += 1
        if argument == "--":
            # Everything remaining is a literal operand, not an option.
            return max_operands is None or operands + len(arguments) - cursor <= max_operands
        if not argument.startswith("-") or argument == "-":
            operands += 1
            if max_operands is not None and operands > max_operands:
                return False
            continue
        if argument in flags:
            continue
        option, separator, value = argument.partition("=")
        kind = value_options.get(option)
        attached_count = re.fullmatch(r"(-[A-Za-z])([0-9]{1,7})", argument)
        if kind is None and attached_count and value_options.get(attached_count[1]) == "count":
            kind, separator, value = "count", "attached", attached_count[2]
        if kind is not None:
            if not separator:
                if cursor >= len(arguments):
                    return False
                value = arguments[cursor]
                cursor += 1
            if (
                (kind == "count" and re.fullmatch(r"[0-9]{1,7}", value))
                or (kind == "file_type" and value in {"f", "d", "l"})
                or (kind == "text" and value and not value.startswith("-"))
            ):
                continue
            return False
        if not argument.startswith("--") and len(argument) > 2 and all(
            character in short_flags for character in argument[1:]
        ):
            continue
        return False
    return True


def _git_shell_read_only(arguments: Sequence[str]) -> bool:
    if not arguments:
        return False
    operation, *options = arguments
    option_region = options[:options.index("--")] if "--" in options else options
    if operation in {"branch", "tag"}:
        flags = frozenset({"-l", "--list", "-n"}) if operation == "tag" else frozenset({
            "-l", "--list", "-a", "--all", "-r", "--remotes", "-v", "--verbose", "--show-current",
        })
        if not options or all(option in flags for option in options):
            return True
        return bool(
            any(option in {"-l", "--list"} for option in option_region)
            and _shell_read_arguments(options, flags, {})
        )
    flags_by_operation = {
        "status": {"-s", "-b", "-z", "--short", "--branch", "--porcelain", "--porcelain=v1", "--porcelain=v2"},
        "rev-parse": {"--verify", "--short", "--show-toplevel", "--git-dir", "--git-common-dir", "--is-inside-work-tree"},
        "ls-files": {"-z", "--cached", "--stage", "--others", "--exclude-standard"},
        "log": {"--oneline", "--no-patch", "--no-decorate", "--all"},
        "diff": {"--no-ext-diff", "--no-textconv", "--stat", "--name-only", "--name-status", "--numstat", "--cached", "--staged", "--check", "--no-color", "-p"},
        "show": {"--no-ext-diff", "--no-textconv", "--stat", "--name-only", "--no-patch", "--oneline", "--no-color"},
    }
    flags = flags_by_operation.get(operation)
    if flags is None:
        return False
    if operation in {"diff", "show"} and not {"--no-ext-diff", "--no-textconv"}.issubset(option_region):
        return False
    values = {"-n": "count", "--max-count": "count"} if operation == "log" else {}
    return _shell_read_arguments(options, frozenset(flags), values)


def _shell_mutates(command: Any) -> bool:
    if not isinstance(command, str) or not command.strip():
        return True
    if len(command) > 8192 or any(character in _SHELL_DYNAMIC_CHARACTERS for character in command):
        return True
    try:
        tokens = shlex.split(command)
    except ValueError:
        return True
    if not tokens or len(tokens) > 128:
        return True
    executable = Path(tokens[0]).name
    if tokens[0] != executable:
        return True
    if executable == "git":
        return not _git_shell_read_only(tokens[1:])
    if executable == "find" and "--" in tokens[1:]:
        # find still parses action expressions after its starting points.
        return True
    if executable == "sed":
        # Admit only the common bounded line-print form, never sed programs.
        return not (
            len(tokens) >= 3
            and tokens[1] == "-n"
            and re.fullmatch(r"[0-9]+(?:,[0-9]+)?p", tokens[2])
            and _shell_read_arguments(tokens[3:], frozenset(), {})
        )
    flags = _SHELL_READ_FLAGS.get(executable)
    return flags is None or not _shell_read_arguments(
        tokens[1:], flags, _SHELL_READ_VALUE_OPTIONS.get(executable, {}),
        max_operands=1 if executable == "uniq" else None,
    )


def _hook_ready(state: Mapping[str, Any]) -> bool:
    hook = state.get("hook", {})
    return bool(
        hook.get("enabled")
        and hook.get("trusted")
        and hook.get("status") == "ready"
        and hook.get("expected_sha256") == hook.get("observed_sha256")
        and "deny" not in hook.get("matching_decisions", [])
    )


def _state_identity(state: Mapping[str, Any]) -> dict[str, Any]:
    prereq = state.get("prerequisites", {})
    return {
        "project_id": prereq.get("enrollment", {}).get("project_id"),
        "generation": prereq.get("enrollment", {}).get("generation"),
        "ticket_id": prereq.get("ticket_admission", {}).get("ticket_id"),
        "admission_sha256": prereq.get("ticket_admission", {}).get("admission_sha256"),
        "plan_sha256": prereq.get("ticket_admission", {}).get("plan_sha256"),
        "lease_version": prereq.get("lease", {}).get("version"),
        "lease_owner_thread_id": prereq.get("lease", {}).get("owner_thread_id"),
        "current_thread_id": prereq.get("lease", {}).get("current_thread_id"),
        "adapter_snapshot_sha256": prereq.get("adapter", {}).get("snapshot_sha256"),
        "authority_scope_sha256": prereq.get("authority", {}).get("scope_sha256"),
        "writable_scope_sha256": prereq.get("authority", {}).get("writable_scope_sha256"),
        "workspace_baseline_sha256": prereq.get("workspace", {}).get("baseline_sha256"),
        "execution_readiness_sha256": prereq.get("execution_readiness", {}).get("report_sha256"),
        "active_controller_sha256": prereq.get("active_controller", {}).get("report_sha256"),
        "capsule_sha256": prereq.get("capsule", {}).get("capsule_sha256"),
    }


def _state_without_session_health(state: Mapping[str, Any]) -> dict[str, Any]:
    value = deepcopy(dict(state))
    lifecycle = value.get("lifecycle")
    if isinstance(lifecycle, dict):
        lifecycle["session_health"] = None
    return value


def build_session_health(program: Mapping[str, Any]) -> dict[str, Any]:
    """Build the sealed health record emitted only for a healthy SessionStart."""

    value, issues = _program(program)
    event, state = value["event"], value["state"]
    if issues or event.get("hook_event_name") != "SessionStart" or not _hook_ready(state):
        raise ValueError("healthy SessionStart program required")
    identity = _state_identity(state)
    record = {
        "schema": SESSION_HEALTH_SCHEMA,
        "status": "HEALTHY",
        "session_id": event["session_id"],
        "project_id": identity["project_id"],
        "generation": identity["generation"],
        "state_sha256": _sha(
            {"state": _state_without_session_health(state), "identity": identity}
        ),
    }
    return {**record, "health_sha256": _sha(record)}


def _health_matches(value: Mapping[str, Any]) -> bool:
    state, event = value["state"], value["event"]
    health = state.get("lifecycle", {}).get("session_health")
    if not isinstance(health, Mapping):
        return False
    identity = _state_identity(state)
    return bool(
        health.get("status") == "HEALTHY"
        and health.get("session_id") == event.get("session_id")
        and health.get("project_id") == identity.get("project_id")
        and health.get("generation") == identity.get("generation")
        and health.get("state_sha256")
        == _sha({"state": _state_without_session_health(state), "identity": identity})
        and health.get("health_sha256")
        == _sha({key: item for key, item in health.items() if key != "health_sha256"})
    )


def _gateway_for(value: Mapping[str, Any], coverage_class: str, tool_input_sha256: str) -> Mapping[str, Any] | None:
    matches = [
        row
        for row in value.get("gateways", [])
        if row.get("coverage_class") == coverage_class
        and row.get("exact_tool_input_sha256") == tool_input_sha256
    ]
    if len(matches) != 1:
        return None
    row = matches[0]
    if row.get("status") != "AUTHORIZED" or row.get("authority_narrowed") is not True:
        return None
    return row


def _protected_hit(value: Mapping[str, Any], tool_input: Mapping[str, Any], gateway: Mapping[str, Any] | None) -> str | None:
    serialized = _canonical(tool_input).decode("utf-8", errors="replace")
    for resource in value.get("protected_resources", []):
        if resource in serialized:
            if gateway is None or resource not in gateway.get("resources", []):
                return resource
    return None


def _lifecycle_blocks(state: Mapping[str, Any]) -> list[str]:
    lifecycle = state.get("lifecycle", {})
    issues: list[str] = []
    if lifecycle.get("duplicate_task"):
        _issue(issues, "lifecycle:duplicate_task_read_only")
    if lifecycle.get("concurrent_writers") != 1:
        _issue(issues, "lifecycle:split_brain_writers")
    if (lifecycle.get("resumed") or lifecycle.get("compacted")) and not lifecycle.get("binding_revalidated"):
        _issue(issues, "lifecycle:binding_revalidation_required")
    if lifecycle.get("mutation_seq") != lifecycle.get("expected_mutation_seq"):
        _issue(issues, "lifecycle:mutation_sequence_stale")
    return issues


def _session_source_blocks(event: Mapping[str, Any], state: Mapping[str, Any]) -> list[str]:
    lifecycle = state.get("lifecycle", {})
    source = event.get("source")
    issues: list[str] = []
    if source == "resume" and lifecycle.get("resumed") is not True:
        _issue(issues, "lifecycle:resume_state_missing")
    if source == "compact" and lifecycle.get("compacted") is not True:
        _issue(issues, "lifecycle:compact_state_missing")
    return issues


def _hook_output(event_name: str, decision: str, reason: str, *, health: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if event_name == "PreToolUse":
        if decision == "ALLOW":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "additionalContext": reason,
                }
            }
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    if event_name == "SessionStart":
        context = "Orch Dork project ground HEALTHY." if health is not None else "Orch Dork project ground is READ_ONLY: " + reason
        return {
            "continue": health is not None,
            "stopReason": None if health is not None else reason,
            "systemMessage": context,
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": context,
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
    return (
        {"decision": "block", "reason": reason}
        if decision == "CONTINUE"
        else {"continue": True, "systemMessage": reason}
    )


def evaluate_project_ground_enforcement(program: Any) -> dict[str, Any]:
    """Return one closed provider-free lifecycle or mutation decision."""

    value, issues = _program(program)
    event, state = value["event"], value["state"]
    event_name = event.get("hook_event_name")
    state_sha256 = _sha(state)
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), Mapping) else {}
    tool_input_sha256 = _sha(tool_input)
    coverage_class, mutating = classify_tool(
        event.get("tool_name"), tool_input, nested=bool(event.get("code_mode_nested"))
    )
    health: dict[str, Any] | None = None
    decision = "READ_ONLY"
    reason_codes = list(issues)
    gateway: Mapping[str, Any] | None = None
    completion_invalidated = False

    if not _hook_ready(state):
        _issue(reason_codes, "enforcement:hook_not_ready")
    for item in _lifecycle_blocks(state):
        _issue(reason_codes, item)

    if event_name == "SessionStart":
        for item in _session_source_blocks(event, state):
            _issue(reason_codes, item)
        if not reason_codes:
            health = build_session_health(value)
            decision = "HEALTHY"
        else:
            decision = "READ_ONLY"
    elif event_name == "PreToolUse":
        if not _health_matches(value):
            _issue(reason_codes, "lifecycle:session_health_missing_or_stale")
        if len(_canonical(tool_input)) > value["tool_policy"].get("max_tool_input_bytes", 0):
            _issue(reason_codes, "tool:input_too_large")
        if event.get("tool_name") in value["tool_policy"].get("read_only_tools", []):
            mutating = False
        gateway = _gateway_for(value, coverage_class, tool_input_sha256)
        if mutating and coverage_class in GATEWAY_ONLY_CLASSES:
            sandbox_covers = (
                state.get("sandbox", {}).get("status") == "PASS"
                and coverage_class in state.get("sandbox", {}).get("covered_classes", [])
            )
            if gateway is None and not sandbox_covers:
                _issue(reason_codes, "coverage:uncovered_mutation:" + coverage_class)
        protected = _protected_hit(value, tool_input, gateway)
        if protected is not None:
            _issue(reason_codes, "protected_resource:gateway_required:" + protected)
        if mutating and reason_codes:
            decision = "DENY"
        elif mutating:
            decision = "ALLOW"
            completion_invalidated = True
        else:
            decision = "ALLOW"
    elif event_name == "PostToolUse":
        decision = "OBSERVED"
        completion_invalidated = mutating
        if mutating:
            _issue(reason_codes, "completion:final_verification_invalidated")
    elif event_name in {"Stop", "SubagentStop"}:
        completion = value["completion"]
        if (
            completion.get("final_verification_valid")
            and isinstance(completion.get("final_verification_sha256"), str)
            and _SHA256.fullmatch(completion["final_verification_sha256"]) is not None
            and completion.get("independent_observation") == "BOUND"
            and completion.get("governed_controller_status") == "PASS"
            and not reason_codes
        ):
            decision = "STOP_ALLOWED"
        else:
            decision = "CONTINUE"
            _issue(reason_codes, "completion:governed_terminal_evidence_required")
    else:
        _issue(reason_codes, "event:unsupported")

    reason = "; ".join(reason_codes) if reason_codes else (
        "project ground healthy" if decision in {"HEALTHY", "ALLOW", "STOP_ALLOWED"} else "observation recorded"
    )
    report = {
        "schema": REPORT_SCHEMA,
        "policy_version": POLICY_VERSION,
        "status": "PASS" if decision in {"HEALTHY", "ALLOW", "OBSERVED", "STOP_ALLOWED"} else "BLOCKED",
        "decision": decision,
        "hook_event_name": event_name,
        "coverage_class": coverage_class if event_name in {"PreToolUse", "PostToolUse"} else None,
        "mutating": mutating if event_name in {"PreToolUse", "PostToolUse"} else False,
        "tool_input_sha256": tool_input_sha256 if event_name in {"PreToolUse", "PostToolUse"} else None,
        "state_sha256": state_sha256,
        "identity": {
            **_state_identity(state),
            "session_id": event.get("session_id"),
            "turn_id": event.get("turn_id"),
        },
        "session_health": health,
        "gateway_id": gateway.get("gateway_id") if gateway is not None else None,
        "completion_invalidated": completion_invalidated,
        "post_tool_observation_only": event_name == "PostToolUse",
        "continuation_control_only": event_name in {"Stop", "SubagentStop"},
        "independent_terminal_qualification_required": True,
        "reason_codes": reason_codes,
        "hook_output": _hook_output(event_name or "PreToolUse", decision, reason, health=health),
        "provider_free": True,
        "hosted_calls": 0,
        "model_calls": 0,
        "credential_reads": 0,
        "authority_grants_minted": 0,
        "mutations_performed": 0,
    }
    return {**report, "report_sha256": _sha(report)}


def normalize_hook_input(hook_input: Any) -> dict[str, Any]:
    """Normalize the stable official hook fields without reading transcripts."""

    value = hook_input if isinstance(hook_input, Mapping) else {}
    event_name = value.get("hook_event_name")
    return {
        "hook_event_name": event_name,
        "session_id": value.get("session_id"),
        "turn_id": value.get("turn_id"),
        "cwd": value.get("cwd"),
        "model": value.get("model"),
        "permission_mode": value.get("permission_mode", "default"),
        "source": value.get("source"),
        "agent_id": value.get("agent_id"),
        "agent_type": value.get("agent_type"),
        "stop_hook_active": bool(value.get("stop_hook_active", False)),
        "tool_name": value.get("tool_name"),
        "tool_use_id": value.get("tool_use_id"),
        "tool_input": value.get("tool_input") if isinstance(value.get("tool_input"), Mapping) else {},
        "tool_response": value.get("tool_response"),
        "code_mode_nested": bool(value.get("code_mode_nested", False)),
    }


def program_from_hook_state(hook_input: Any, state_record: Any, session_health: Any = None) -> dict[str, Any]:
    """Bind an official hook event to one gateway-produced immutable template."""

    if not isinstance(state_record, Mapping) or state_record.get("schema") != HOOK_STATE_SCHEMA:
        raise ValueError("valid hook state record required")
    template = state_record.get("program")
    if not isinstance(template, Mapping):
        raise ValueError("hook state program missing")
    declared = state_record.get("program_sha256")
    if not isinstance(declared, str) or declared != _sha(template):
        raise ValueError("hook state hash mismatch")
    program = deepcopy(dict(template))
    program["event"] = normalize_hook_input(hook_input)
    program.setdefault("state", {}).setdefault("lifecycle", {})["session_health"] = (
        deepcopy(session_health) if isinstance(session_health, Mapping) else None
    )
    return program


def enforce_native_controller_hook(
    hook_input: Any,
    state_record: Any,
    report: Any,
    *,
    observed_hook_definition_sha256: str,
    observed_hook_registration_sha256: str,
    observed_store_identity_sha256: str,
    canonical_authority: Any,
    qualification_owner_context: Any = None,
) -> dict[str, Any]:
    """Narrow project-ground output to the controller's sole exact action.

    Legacy/advisory state has no ``native_controller`` member and is returned
    unchanged.  Once activated, the outer binding can only narrow a project-
    ground ALLOW; it can never turn a denial into permission.
    """

    authority = (
        canonical_authority if isinstance(canonical_authority, Mapping) else {}
    )
    owner = authority.get("owner") if isinstance(authority.get("owner"), Mapping) else None
    binding_present = bool(
        isinstance(state_record, Mapping) and "native_controller" in state_record
    )
    if (
        authority.get("status") == "LEGACY"
        and owner is None
        and not binding_present
    ):
        return deepcopy(dict(report)) if isinstance(report, Mapping) else {}
    value = deepcopy(dict(report)) if isinstance(report, Mapping) else {}
    binding = state_record.get("native_controller") if binding_present else None
    issues: list[str] = []
    if not binding_present:
        _issue(issues, "native_controller:binding_required")
    if authority.get("status") != "VERIFIED" or owner is None:
        _issue(issues, "native_controller:canonical_authority_invalid")
    canonical_identity = (
        authority.get("identity")
        if isinstance(authority.get("identity"), Mapping)
        else {}
    )
    canonical_tip = (
        authority.get("tip") if isinstance(authority.get("tip"), Mapping) else {}
    )
    lifecycle = (
        authority.get("lifecycle")
        if isinstance(authority.get("lifecycle"), Mapping)
        else {}
    )
    canonical_policy = (
        authority.get("policy")
        if isinstance(authority.get("policy"), Mapping)
        else {}
    )
    canonical_projection = (
        authority.get("hook_projection")
        if isinstance(authority.get("hook_projection"), Mapping)
        else {}
    )
    expected_binding_fields = {
        "schema",
        "controller_id",
        "controller_run_id",
        "controller_seq",
        "controller_event_hash",
        "root_thread_id",
        "root_session_id",
        "root_model",
        "hook_definition_sha256",
        "hook_registration_sha256",
        "store_identity_sha256",
        "ground_state_sha256",
        "status",
        "action",
        "binding_sha256",
    }
    if not isinstance(binding, Mapping) or set(binding) != expected_binding_fields:
        _issue(issues, "native_controller:binding_invalid")
        binding = {}
    core = {
        key: binding.get(key)
        for key in expected_binding_fields
        if key != "binding_sha256"
    }
    if binding.get("schema") != NATIVE_CONTROLLER_HOOK_SCHEMA:
        _issue(issues, "native_controller:schema_invalid")
    for field in (
        "controller_id",
        "controller_run_id",
        "root_thread_id",
        "root_session_id",
        "root_model",
    ):
        if not _text(binding.get(field)):
            _issue(issues, "native_controller:" + field + "_invalid")
    if type(binding.get("controller_seq")) is not int or binding.get("controller_seq", 0) < 1:
        _issue(issues, "native_controller:sequence_invalid")
    for field in (
        "controller_event_hash",
        "hook_definition_sha256",
        "hook_registration_sha256",
        "store_identity_sha256",
        "ground_state_sha256",
        "binding_sha256",
    ):
        if (
            not isinstance(binding.get(field), str)
            or _SHA256.fullmatch(binding[field]) is None
        ):
            _issue(issues, "native_controller:" + field + "_invalid")
    if binding.get("binding_sha256") != _sha(core):
        _issue(issues, "native_controller:binding_seal_invalid")
    projected_binding = {
        "controller_id": binding.get("controller_id"),
        "controller_run_id": binding.get("controller_run_id"),
        "controller_seq": binding.get("controller_seq"),
        "controller_event_hash": binding.get("controller_event_hash"),
        "binding_sha256": binding.get("binding_sha256"),
    }
    if projected_binding != canonical_projection:
        _issue(issues, "native_controller:canonical_projection_mismatch")
    ground_state = {
        key: child
        for key, child in state_record.items()
        if key != "native_controller"
    } if isinstance(state_record, Mapping) else {}
    observed_ground_state_sha256 = _sha(ground_state)
    if (
        binding.get("ground_state_sha256") != observed_ground_state_sha256
        or authority.get("ground_state_sha256") != observed_ground_state_sha256
    ):
        _issue(issues, "native_controller:canonical_ground_state_mismatch")
    if binding.get("hook_definition_sha256") != observed_hook_definition_sha256:
        _issue(issues, "native_controller:hook_definition_mismatch")
    if (
        binding.get("hook_registration_sha256")
        != observed_hook_registration_sha256
    ):
        _issue(issues, "native_controller:hook_registration_mismatch")
    if binding.get("store_identity_sha256") != observed_store_identity_sha256:
        _issue(issues, "native_controller:store_identity_mismatch")
    if authority.get("store_identity_sha256") != observed_store_identity_sha256:
        _issue(issues, "native_controller:canonical_store_identity_mismatch")
    for field in (
        "controller_id",
        "controller_run_id",
        "root_thread_id",
        "root_session_id",
        "root_model",
        "hook_definition_sha256",
        "hook_registration_sha256",
    ):
        if binding.get(field) != canonical_identity.get(field):
            _issue(issues, "native_controller:canonical_" + field + "_mismatch")
    if (
        binding.get("controller_seq") != canonical_tip.get("seq")
        or binding.get("controller_event_hash") != canonical_tip.get("event_hash")
        or binding.get("controller_run_id") != canonical_tip.get("run_id")
    ):
        _issue(issues, "native_controller:canonical_tip_mismatch")
    status = binding.get("status")
    if status not in {"WAITING", "ACTIVE", "BLOCKED", "TERMINAL"}:
        _issue(issues, "native_controller:status_invalid")
    if status != lifecycle.get("expected_binding_status"):
        _issue(issues, "native_controller:canonical_status_mismatch")
    action = binding.get("action")
    expected_action_fields = {
        "action_id",
        "action_sha256",
        "kind",
        "actor_thread_id",
        "lane_ids",
        "tool_name",
        "tool_input_sha256",
    }
    if status == "ACTIVE":
        if not isinstance(action, Mapping) or set(action) != expected_action_fields:
            _issue(issues, "native_controller:action_invalid")
            action = {}
        for field in (
            "action_id",
            "kind",
            "actor_thread_id",
            "tool_name",
        ):
            if not _text(action.get(field)):
                _issue(issues, "native_controller:action_" + field + "_invalid")
        for field in ("action_sha256", "tool_input_sha256"):
            if (
                not isinstance(action.get(field), str)
                or _SHA256.fullmatch(action[field]) is None
            ):
                _issue(issues, "native_controller:action_" + field + "_invalid")
        lane_ids = action.get("lane_ids")
        if (
            not isinstance(lane_ids, list)
            or not lane_ids
            or lane_ids != sorted(set(lane_ids))
            or any(not _text(item) for item in lane_ids)
        ):
            _issue(issues, "native_controller:action_lane_ids_invalid")
        if action.get("actor_thread_id") != binding.get("root_thread_id"):
            _issue(issues, "native_controller:action_root_mismatch")
        if action.get("action_sha256") != lifecycle.get("action_sha256"):
            _issue(issues, "native_controller:canonical_action_mismatch")
    elif action is not None:
        _issue(issues, "native_controller:inactive_action_present")

    event = normalize_hook_input(hook_input)
    event_name = event.get("hook_event_name")
    mutating = bool(value.get("mutating"))
    qualification_owner_context_supplied = qualification_owner_context is not None
    qualification_owner_context_sealed = _qualification_owner_context_valid(
        event, qualification_owner_context
    )
    if (
        qualification_owner_context_supplied
        and not qualification_owner_context_sealed
    ):
        _issue(issues, "qualification_owner:context_invalid")
    qualification_owner_compatible_controller_issues = [
        issue
        for issue in issues
        if issue in QUALIFICATION_OWNER_COMPATIBLE_CONTROLLER_ISSUES
    ]
    qualification_owner_context_valid = bool(
        qualification_owner_context_sealed
        and len(qualification_owner_compatible_controller_issues) == len(issues)
        and authority.get("status") == "VERIFIED"
        and owner is not None
        and status in {"WAITING", "ACTIVE", "TERMINAL"}
    )
    if qualification_owner_context_valid:
        issues[:] = [
            issue
            for issue in issues
            if issue not in QUALIFICATION_OWNER_COMPATIBLE_CONTROLLER_ISSUES
        ]
    clean_terminal_authority = bool(
        status == "TERMINAL"
        and action is None
        and authority.get("status") == "VERIFIED"
        and owner is not None
        and lifecycle.get("terminal") is True
        and lifecycle.get("pending_intent") is False
        and lifecycle.get("cleanup_required") is False
        and lifecycle.get("action_sha256") is None
        and lifecycle.get("tool_use_id") is None
        and not issues
    )
    clean_terminal_successor_context = bool(
        clean_terminal_authority
        and _text(event.get("session_id"))
        and event.get("session_id") != binding.get("root_session_id")
        and _text(event.get("model"))
        and event.get("agent_id") is None
    )
    current_root_context = bool(
        not issues
        and authority.get("status") == "VERIFIED"
        and owner is not None
        and event.get("session_id") == binding.get("root_session_id")
        and event.get("model") == binding.get("root_model")
        and event.get("agent_id") is None
    )
    tool_event = event_name in {"PreToolUse", "PostToolUse"}
    tool_name = event.get("tool_name")
    tool_input = event.get("tool_input", {})
    read_only_shell_event = bool(
        tool_event
        and value.get("coverage_class") == "shell"
        and value.get("mutating") is False
        and (
            clean_terminal_successor_context
            or current_root_context
            or qualification_owner_context_valid
        )
    )
    runtime_observer_event = bool(
        tool_event
        and tool_name
        == "mcp__orch_dork__observe_current_local_task_runtime"
        and tool_input == {}
        and (
            clean_terminal_successor_context
            or current_root_context
            or qualification_owner_context_valid
        )
    )
    native_wait_event = bool(
        tool_event
        and _canonical_native_tool_name(tool_name) == "wait_agent"
        and current_root_context
    )
    route_observer_event = bool(
        tool_event
        and tool_name
        == "mcp__orch_dork__observe_current_orchestration_route"
        and _qualification_owner_route_observer_input(tool_input)
        and qualification_owner_context_valid
    )
    live_handoff_event = bool(
        tool_event
        and tool_name == "mcp__orch_dork__evaluate_live_route_handoff"
        and _qualification_owner_handoff_input(tool_input)
        and qualification_owner_context_valid
    )
    controller_input = tool_input if isinstance(tool_input, Mapping) else {}
    controller_program = (
        controller_input.get("program")
        if isinstance(controller_input.get("program"), Mapping)
        else {}
    )
    controller_program_exact = bool(
        tool_name == "mcp__orch_dork__advance_governed_native_controller"
        and set(controller_input) == {"program", "source_roots"}
        and isinstance(controller_input.get("source_roots"), Mapping)
        and bool(controller_input.get("source_roots"))
        and set(controller_program)
        == {"schema", "controller_id", "operation", "expected_cursor", "payload"}
        and controller_program.get("schema")
        == "orch-dork/governed-native-controller-program/v1"
        and _text(controller_program.get("controller_id"))
        and isinstance(controller_program.get("payload"), Mapping)
    )
    if controller_program_exact:
        try:
            owned_file.activated_source_roots(
                controller_input["source_roots"], authority.get("source_roots")
            )
        except (OSError, TypeError, ValueError):
            _issue(issues, "native_controller:source_roots_mismatch")
            controller_program_exact = False

    first_action_input_exact = bool(
        tool_name
        == (
            "mcp__orch_dork__"
            "authorize_issue94_successor_first_action"
        )
        and set(controller_input)
        == {"pre_turn_report_path", "pre_turn_report_sha256"}
        and isinstance(
            controller_input.get("pre_turn_report_path"), str
        )
        and Path(controller_input["pre_turn_report_path"]).is_absolute()
        and isinstance(
            controller_input.get("pre_turn_report_sha256"), str
        )
        and _SHA256.fullmatch(
            controller_input["pre_turn_report_sha256"]
        )
        is not None
    )
    action_advance_input_exact = bool(
        tool_name
        == (
            "mcp__orch_dork__"
            "advance_issue94_successor_after_native_action"
        )
        and set(controller_input)
        == {"pre_turn_report_path", "pre_turn_report_sha256"}
        and isinstance(
            controller_input.get("pre_turn_report_path"), str
        )
        and Path(controller_input["pre_turn_report_path"]).is_absolute()
        and isinstance(
            controller_input.get("pre_turn_report_sha256"), str
        )
        and _SHA256.fullmatch(
            controller_input["pre_turn_report_sha256"]
        )
        is not None
    )
    bootstrap_action_advance_input_exact = bool(
        tool_name
        == "mcp__orch_dork__advance_issue94_bootstrapped_after_native_action"
        and set(controller_input)
        == {"bootstrap_artifact_path", "bootstrap_report_sha256"}
        and isinstance(controller_input.get("bootstrap_artifact_path"), str)
        and Path(controller_input["bootstrap_artifact_path"]).is_absolute()
        and isinstance(controller_input.get("bootstrap_report_sha256"), str)
        and _SHA256.fullmatch(controller_input["bootstrap_report_sha256"])
        is not None
    )
    review_submission_input_exact = bool(
        tool_name == "mcp__orch_dork__submit_issue94_semantic_review"
        and set(controller_input) == {"pre_turn_report_path", "pre_turn_report_sha256", "subject_sha256", "verifications"}
        and isinstance(controller_input.get("pre_turn_report_path"), str)
        and Path(controller_input["pre_turn_report_path"]).is_absolute()
        and all(isinstance(controller_input.get(key), str) and _SHA256.fullmatch(controller_input[key]) is not None
                for key in ("pre_turn_report_sha256", "subject_sha256"))
        and isinstance(controller_input.get("verifications"), list) and len(controller_input["verifications"]) == 2
        and all(isinstance(row, dict) for row in controller_input["verifications"])
    )
    bootstrap_review_submission_input_exact = bool(
        tool_name == "mcp__orch_dork__submit_issue94_bootstrapped_semantic_review"
        and set(controller_input)
        == {
            "bootstrap_artifact_path",
            "bootstrap_report_sha256",
            "subject_sha256",
            "verifications",
        }
        and isinstance(controller_input.get("bootstrap_artifact_path"), str)
        and Path(controller_input["bootstrap_artifact_path"]).is_absolute()
        and all(
            isinstance(controller_input.get(key), str)
            and _SHA256.fullmatch(controller_input[key]) is not None
            for key in ("bootstrap_report_sha256", "subject_sha256")
        )
        and isinstance(controller_input.get("verifications"), list)
        and len(controller_input["verifications"]) == 2
        and all(isinstance(row, dict) for row in controller_input["verifications"])
    )
    controller_operation = controller_program.get("operation")
    controller_pretool_base_reasons = value.get("reason_codes", [])
    controller_pretool_base_safe = bool(
        isinstance(controller_pretool_base_reasons, list)
        and all(
            isinstance(reason, str)
            and reason.startswith("protected_resource:gateway_required:")
            for reason in controller_pretool_base_reasons
        )
    )
    first_action_pretool_base_safe = bool(
        isinstance(controller_pretool_base_reasons, list)
        and all(
            isinstance(reason, str)
            and (
                reason == "native_controller:exact_action_required"
                or reason.startswith(
                    "protected_resource:gateway_required:"
                )
            )
            for reason in controller_pretool_base_reasons
        )
    )
    current_root_control_pretool = bool(
        event_name == "PreToolUse"
        and controller_program_exact
        and current_root_context
        and controller_pretool_base_safe
        and controller_program.get("controller_id") == binding.get("controller_id")
        and (
            controller_operation == "inspect"
            or (
                controller_operation == "stage"
                and status == "WAITING"
                and action is None
                and lifecycle.get("pending_intent") is False
            )
            or (
                controller_operation == "observe"
                and status == "ACTIVE"
                and lifecycle.get("grant_state") == "POST_OBSERVED"
            )
        )
    )
    controller_posttool_observation = bool(
        event_name == "PostToolUse"
        and controller_program_exact
        and current_root_context
        and controller_program.get("controller_id")
        == binding.get("controller_id")
        and controller_operation in {"activate", "stage", "observe", "inspect"}
    )
    current_root_first_action_pretool = bool(
        event_name == "PreToolUse"
        and first_action_input_exact
        and current_root_context
        and first_action_pretool_base_safe
        and status == "WAITING"
        and action is None
        and lifecycle.get("pending_intent") is False
        and lifecycle.get("cleanup_required") is False
    )
    first_action_posttool_observation = bool(
        event_name == "PostToolUse"
        and first_action_input_exact
        and current_root_context
    )
    current_root_action_advance_pretool = bool(
        event_name == "PreToolUse"
        and (action_advance_input_exact or bootstrap_action_advance_input_exact)
        and current_root_context
        and first_action_pretool_base_safe
        and lifecycle.get("pending_intent") is False
        and lifecycle.get("cleanup_required") is False
        and (
            (
                status == "ACTIVE"
                and lifecycle.get("grant_state") == "POST_OBSERVED"
            )
            or (
                status == "WAITING"
                and action is None
                and lifecycle.get("grant_state") is None
                and lifecycle.get("action_sha256") is None
                and lifecycle.get("tool_use_id") is None
            )
        )
    )
    action_advance_posttool_observation = bool(
        event_name == "PostToolUse"
        and (action_advance_input_exact or bootstrap_action_advance_input_exact)
        and current_root_context
    )
    current_root_review_submission_pretool = bool(
        event_name == "PreToolUse"
        and (review_submission_input_exact or bootstrap_review_submission_input_exact)
        and current_root_context
        and first_action_pretool_base_safe
        and status == "WAITING"
        and action is None
        and lifecycle.get("pending_intent") is False
        and lifecycle.get("cleanup_required") is False
        and lifecycle.get("grant_state") is None
        and lifecycle.get("action_sha256") is None
        and lifecycle.get("tool_use_id") is None
    )
    review_submission_posttool_observation = bool(
        event_name == "PostToolUse"
        and (review_submission_input_exact or bootstrap_review_submission_input_exact)
        and current_root_context
    )
    controller_control_plane_event = bool(
        current_root_control_pretool
        or controller_posttool_observation
    )
    bootstrap_safe_tool_event = bool(
        read_only_shell_event
        or runtime_observer_event
        or route_observer_event
        or live_handoff_event
        or native_wait_event
        or controller_control_plane_event
        or current_root_first_action_pretool
        or first_action_posttool_observation
        or current_root_action_advance_pretool
        or action_advance_posttool_observation
        or current_root_review_submission_pretool
        or review_submission_posttool_observation
    )
    if runtime_observer_event or route_observer_event or live_handoff_event:
        mutating = False
        value["mutating"] = False
        value["completion_invalidated"] = False
        reason = "; ".join(value.get("reason_codes", [])) or "project ground healthy"
        value["hook_output"] = _hook_output(
            event_name or "PreToolUse", value.get("decision", "ALLOW"), reason
        )
    if current_root_control_pretool:
        mutating = True
        value["status"] = "PASS"
        value["decision"] = "ALLOW"
        value["mutating"] = True
        value["completion_invalidated"] = True
        value["reason_codes"] = []
        value["hook_output"] = _hook_output(
            "PreToolUse", "ALLOW", "governed controller control plane"
        )
    if current_root_first_action_pretool:
        mutating = True
        value["status"] = "PASS"
        value["decision"] = "ALLOW"
        value["mutating"] = True
        value["completion_invalidated"] = True
        value["reason_codes"] = []
        value["hook_output"] = _hook_output(
            "PreToolUse",
            "ALLOW",
            "repository-owned successor first-action control plane",
        )
    if current_root_action_advance_pretool or current_root_review_submission_pretool:
        mutating = True
        value["status"] = "PASS"
        value["decision"] = "ALLOW"
        value["mutating"] = True
        value["completion_invalidated"] = True
        value["reason_codes"] = []
        value["hook_output"] = _hook_output(
            "PreToolUse",
            "ALLOW",
            (
                (
                    "repository-owned bootstrap review submission"
                    if bootstrap_review_submission_input_exact
                    else "repository-owned successor review submission"
                )
                if current_root_review_submission_pretool
                else (
                    "repository-owned bootstrap action-observation control plane"
                    if bootstrap_action_advance_input_exact
                    else "repository-owned successor action-observation control plane"
                )
            ),
        )
    canonical_read_only_tools = canonical_policy.get("read_only_tools")
    canonically_mutating = bool(
        tool_event
        and (
            not isinstance(canonical_read_only_tools, list)
            or tool_name not in canonical_read_only_tools
        )
    )
    native_tool = tool_name == "functions.exec"
    guarded_tool_event = bool(
        tool_event
        and not bootstrap_safe_tool_event
        and (mutating or native_tool or canonically_mutating)
    )
    if guarded_tool_event and canonically_mutating:
        mutating = True
        value["mutating"] = True
        value["completion_invalidated"] = True
    matched = False
    clean_terminal_successor_startup = bool(
        event_name == "SessionStart"
        and event.get("source") == "startup"
        and clean_terminal_successor_context
    )
    qualification_owner_startup = bool(
        event_name == "SessionStart"
        and event.get("source") == "startup"
        and qualification_owner_context_valid
    )
    if event_name == "SessionStart":
        if (
            event.get("session_id") != binding.get("root_session_id")
            and not clean_terminal_successor_startup
            and not qualification_owner_startup
        ):
            _issue(issues, "native_controller:root_session_mismatch")
        if (
            event.get("model") != binding.get("root_model")
            and not clean_terminal_successor_startup
            and not qualification_owner_startup
        ):
            _issue(issues, "native_controller:root_model_mismatch")
        if status == "BLOCKED":
            _issue(issues, "native_controller:pending_intent_outcome_unknown")
    elif guarded_tool_event:
        if (
            event_name == "PostToolUse"
            and event.get("tool_use_id") != lifecycle.get("tool_use_id")
        ):
            _issue(issues, "native_controller:tool_use_id_mismatch")
        matched = bool(
            not issues
            and status == "ACTIVE"
            and event.get("session_id") == binding.get("root_session_id")
            and event.get("model") == binding.get("root_model")
            and event.get("agent_id") is None
            and _canonical_native_tool_name(event.get("tool_name"))
            == _canonical_native_tool_name(action.get("tool_name"))
            and _sha(event.get("tool_input", {}))
            == action.get("tool_input_sha256")
        )
        if not matched:
            _issue(issues, "native_controller:exact_action_required")
    elif event_name == "Stop" and qualification_owner_context_valid:
        value["status"] = "PASS"
        value["decision"] = "STOP_ALLOWED"
        value["completion_invalidated"] = False
        value["reason_codes"] = [
            "native_controller:qualification_owner_read_only"
        ]
        value["hook_output"] = _hook_output(
            "Stop",
            "STOP_ALLOWED",
            "qualification owner read-only turn yielded",
        )
    elif event_name == "Stop" and clean_terminal_successor_context:
        _issue(
            value.setdefault("reason_codes", []),
            "native_controller:successor_not_activated",
        )
        value["status"] = "PASS"
        value["decision"] = "STOP_ALLOWED"
        reason = "; ".join(value["reason_codes"])
        value["hook_output"] = _hook_output("Stop", "STOP_ALLOWED", reason)
    elif (
        event_name == "SubagentStop"
        and not issues
        and _text(event.get("agent_id"))
        and status in {"ACTIVE", "WAITING"}
        and lifecycle.get("terminal") is False
        and lifecycle.get("pending_intent") is False
        and lifecycle.get("cleanup_required") is False
    ):
        value["status"] = "PASS"
        value["decision"] = "STOP_ALLOWED"
        value["hook_output"] = _hook_output(
            "SubagentStop",
            "STOP_ALLOWED",
            "controller-bound subagent turn yielded without terminal claim",
        )
    elif event_name in {"Stop", "SubagentStop"}:
        completion = (
            state_record.get("program", {}).get("completion")
            if isinstance(state_record, Mapping)
            and isinstance(state_record.get("program"), Mapping)
            else {}
        )
        if (
            status != "TERMINAL"
            or lifecycle.get("terminal") is not True
            or lifecycle.get("terminal_qualified") is not True
            or completion.get("final_verification_sha256")
            != lifecycle.get("terminal_evidence_sha256")
        ):
            _issue(issues, "native_controller:terminal_state_required")

    if issues and event_name == "SessionStart":
        decision = "READ_ONLY"
        value["status"] = "BLOCKED"
        value["decision"] = decision
        value["session_health"] = None
        reason = "; ".join(issues)
        value["hook_output"] = _hook_output(
            "SessionStart", decision, reason, health=None
        )
    elif issues and event_name == "PreToolUse" and guarded_tool_event:
        decision = "DENY"
        value["status"] = "BLOCKED"
        value["decision"] = decision
        value["completion_invalidated"] = False
        reason = "; ".join(issues)
        value["hook_output"] = _hook_output("PreToolUse", decision, reason)
    elif issues and event_name == "PostToolUse" and guarded_tool_event:
        value["status"] = "BLOCKED"
        reason = "; ".join(issues)
        value["hook_output"] = _hook_output("PostToolUse", "OBSERVED", reason)
    elif issues and event_name in {"Stop", "SubagentStop"}:
        value["status"] = "BLOCKED"
        value["decision"] = "CONTINUE"
        reason = "; ".join(issues)
        value["hook_output"] = _hook_output(event_name, "CONTINUE", reason)
    for issue in issues:
        _issue(value.setdefault("reason_codes", []), issue)
    value["native_controller"] = {
        "present": True,
        "controller_id": binding.get("controller_id") or (owner or {}).get("controller_id"),
        "controller_seq": binding.get("controller_seq"),
        "status": status,
        "action_id": action.get("action_id") if isinstance(action, Mapping) else None,
        "matched": matched,
        "grant_state": lifecycle.get("grant_state") if matched else None,
    }
    if qualification_owner_context_valid:
        value["qualification_owner_context_sha256"] = (
            qualification_owner_context.get("report_sha256")
        )
        value["qualification_owner_compatible_controller_issues"] = (
            qualification_owner_compatible_controller_issues
        )
    value.pop("report_sha256", None)
    value["report_sha256"] = _sha(value)
    return value


__all__ = [
    "ALL_COVERAGE_CLASSES",
    "GATEWAY_ONLY_CLASSES",
    "HOOK_EVENTS",
    "HOOK_STATE_SCHEMA",
    "NATIVE_CONTROLLER_HOOK_SCHEMA",
    "POLICY_VERSION",
    "QUALIFICATION_OWNER_COMPATIBLE_CONTROLLER_ISSUES",
    "PROGRAM_SCHEMA",
    "QUALIFICATION_OWNER_CONTEXT_SCHEMA",
    "REQUIRED_PROTECTED_RESOURCES",
    "REPORT_SCHEMA",
    "SESSION_HEALTH_SCHEMA",
    "SUPPORTED_PRETOOL_CLASSES",
    "build_session_health",
    "classify_tool",
    "evaluate_project_ground_enforcement",
    "enforce_native_controller_hook",
    "normalize_hook_input",
    "program_from_hook_state",
]
