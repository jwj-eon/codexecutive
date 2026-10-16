#!/usr/bin/env python3
"""Structural zero-tool transport for live-sweep measurement lanes.

Issue 133 is deliberately downstream of :mod:`orch_dork_live_sweep`.  The
controller continues to own campaign, grant, reservation, and settlement
state; this module owns only one model-call boundary:

* build and revalidate an exact OpenAI Responses request with a fixed logical
  route/wire-model mapping, no tools, ``tool_choice: none``, one bounded opaque
  hidden-reasoning envelope at most, no inherited response, and strict JSON
  output;
* optionally send that body once to a literal loopback ``/v1/responses``
  endpoint, with no redirect, retry, fallback, or replacement;
* validate one bounded response and project allow-listed facts into the
  existing ``session-runtime-observation/v1`` contract, or retain one closed
  privacy-safe transport-failure record for a non-200 response.

Request envelopes and raw response bodies are owner-only local execution
artifacts. Receipts, runtime observations, and transport-failure records expose
only allow-listed facts and hashes. Builders and observers are provider-free.
The two ``invoke_*_loopback_once`` wrappers share the only live-call-capable
boundary in this module and grant no authority by themselves.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from copy import deepcopy
import base64
import binascii
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Iterator
from urllib.parse import urlsplit

import orch_dork_adaptive_contracts as adaptive_contracts
import orch_dork_live_sweep as live_sweep
import orch_dork_routing_verify as routing
import orch_dork_worker_default as worker_default


REQUEST_SCHEMA_V1 = "orch-dork/live-zero-tool-request/v1"
REQUEST_SCHEMA_V2 = "orch-dork/live-zero-tool-request/v2"
# New requests use the OpenCodex 2.35 hidden-reasoning envelope contract.
# V1 remains accepted for immutable historical evidence and replay.
REQUEST_SCHEMA = REQUEST_SCHEMA_V2
ROUTE_PREFLIGHT_REQUEST_SCHEMA = (
    "orch-dork/route-preflight-zero-tool-request/v1"
)
REQUEST_VALIDATION_SCHEMA = "orch-dork/live-zero-tool-request-validation/v1"
ROUTE_PREFLIGHT_REQUEST_VALIDATION_SCHEMA = (
    "orch-dork/route-preflight-zero-tool-request-validation/v1"
)
RECEIPT_SCHEMA = "orch-dork/live-zero-tool-receipt/v1"
ROUTE_PREFLIGHT_RECEIPT_SCHEMA = (
    "orch-dork/route-preflight-zero-tool-receipt/v1"
)
OBSERVATION_REPORT_SCHEMA = "orch-dork/live-zero-tool-observation-report/v1"
ROUTE_PREFLIGHT_OBSERVATION_REPORT_SCHEMA = (
    "orch-dork/route-preflight-zero-tool-observation-report/v1"
)
INVOCATION_REPORT_SCHEMA = "orch-dork/live-zero-tool-invocation-report/v2"
TRANSPORT_FAILURE_SCHEMA = "orch-dork/live-zero-tool-transport-failure/v1"
TRANSPORT = "openai-responses/v1"

REQUEST_MODEL = "qwen-local/qwen-smart"
RESPONSE_WIRE_MODEL = "qwen-smart"
# Public compatibility name used by the existing routing/runtime contracts.
REQUIRED_MODEL = REQUEST_MODEL
REQUIRED_EFFORT = "xhigh"
REQUIRED_CONTEXT_POLICY = "none"
RESPONSES_PATH = "/v1/responses"
HIDDEN_REASONING_ENVELOPE_PREFIX = "ocxr1:"

MAX_OUTPUT_TOKENS = 32_768
MAX_TOTAL_TOKENS = 1_000_000
MAX_RESPONSE_BYTES = 262_144
MAX_TIMEOUT_MS = 600_000
ROUTE_PREFLIGHT_TOOL_CALL_BUDGET = 1

# Historical zero-tool evidence used the local-Qwen route above.  A current
# qualification host may seal a different forward worker route in its
# environment.  Keep the historical default when no route was explicitly
# supplied, while letting one bounded rehearsal pin the same route as its
# frozen plan.
_PINNED_ROUTE: dict[str, str] = {}
_RESPONSE_WIRE_MODELS = {
    REQUEST_MODEL: RESPONSE_WIRE_MODEL,
    worker_default.DEFAULT_WORKER_MODEL: "qwen/qwen3.8-27b",
    # The selected MiniMax qualification worker reports its upstream label.
    "minimax/MiniMax-M3": "MiniMax-M3",
    # The Local lineup's worker: OpenCodex's qwen-local provider reports the
    # served model name (observed 2026-10-12, Issue 201 generation 84).
    "qwen-local/qwen-fast": "qwen-fast",
}


def _route_model() -> str:
    return (
        _PINNED_ROUTE.get("model")
        or os.environ.get(worker_default.WORKER_MODEL_ENV)
        or REQUEST_MODEL
    )


def _route_effort() -> str:
    return (
        _PINNED_ROUTE.get("effort")
        or os.environ.get(worker_default.WORKER_EFFORT_ENV)
        or REQUIRED_EFFORT
    )


def response_wire_model(request_model: str | None = None) -> str:
    """Return the exact response label for one supported logical route."""

    model = request_model or _route_model()
    try:
        return _RESPONSE_WIRE_MODELS[model]
    except KeyError as error:
        raise LiveZeroToolError("route:wire_model_unavailable") from error


def _observed_wire_model(logical_model: Any, issues: list[str]) -> str | None:
    """Resolve one supported route without turning an unknown route into None."""

    try:
        return response_wire_model(
            logical_model if isinstance(logical_model, str) else ""
        )
    except LiveZeroToolError:
        _issue(issues, "route:wire_model_unavailable")
        return None


@contextmanager
def pinned_route(*, model: str, effort: str) -> Iterator[None]:
    """Temporarily bind builders and validators to one frozen worker route."""

    if not model.strip() or not effort.strip():
        raise LiveZeroToolError("route:pin_invalid")
    previous = dict(_PINNED_ROUTE)
    _PINNED_ROUTE.update(model=model.strip(), effort=effort.strip())
    try:
        yield
    finally:
        _PINNED_ROUTE.clear()
        _PINNED_ROUTE.update(previous)

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SAFE_REASON = re.compile(r"\A[a-z][a-z0-9_]{0,63}:[a-z0-9_]{1,63}\Z")
_PUBLIC_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/octet-stream",
        "application/problem+json",
        "text/html",
        "text/plain",
    }
)

_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "request_id",
        "transport",
        "bindings",
        "route",
        "limits",
        "assignment",
        "output_schema_sha256",
        "body",
        "request_sha256",
    }
)
_ROUTE_PREFLIGHT_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "request_id",
        "transport",
        "bindings",
        "route",
        "limits",
        "task_spec",
        "candidate",
        "output_schema_sha256",
        "body",
        "request_sha256",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "campaign_sha256",
        "grant_sha256",
        "reservation_sha256",
        "lane_id",
        "assignment_sha256",
        "evidence_scope_sha256",
    }
)
_AUTHORITY_BINDING_FIELDS = frozenset(
    {"campaign_sha256", "grant_sha256", "reservation_sha256"}
)
_ROUTE_PREFLIGHT_BINDING_FIELDS = frozenset(
    {
        "attempt_sha256",
        "live_preflight_sha256",
        "task_spec_sha256",
        "candidate_sha256",
        "preflight_id",
        "evidence_scope_sha256",
    }
)
_ROUTE_PREFLIGHT_AUTHORITY_BINDING_FIELDS = frozenset(
    {"attempt_sha256", "live_preflight_sha256"}
)
_ROUTE_PREFLIGHT_CANDIDATE_FIELDS = frozenset(
    {
        "schema",
        "preflight_id",
        "task_spec_sha256",
        "capability_profile",
        "handoff_receipt",
    }
)
_ROUTE_FIELDS = frozenset(
    {"model", "effort", "context_policy", "inherited_history"}
)
_LIMIT_FIELDS = frozenset(
    {
        "max_output_tokens",
        "max_total_tokens",
        "max_response_bytes",
        "timeout_ms",
    }
)
_BODY_FIELDS_V1 = frozenset(
    {
        "model",
        "input",
        "reasoning",
        "include_reasoning",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "text",
        "max_output_tokens",
        "stream",
        "store",
    }
)
_BODY_FIELDS_V2 = _BODY_FIELDS_V1 - {"include_reasoning"}
_HIDDEN_REASONING_FIELDS = frozenset(
    {"id", "type", "summary", "encrypted_content"}
)
_TERMINAL_FIELDS = frozenset(
    {
        "schema",
        "lane_id",
        "request_sha256",
        "assignment_sha256",
        "findings",
        "unknowns",
    }
)
_TOOL_OUTPUT_TYPES = frozenset(
    {
        "function_call",
        "custom_tool_call",
        "mcp_tool_call",
        "local_shell_call",
        "web_search_call",
        "computer_call",
        "code_interpreter_call",
        "file_search_call",
        "image_generation_call",
    }
)


class LiveZeroToolError(ValueError):
    """Stable refusal raised by explicit helper boundaries."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def build_route_preflight_task_spec(template: Any) -> dict[str, Any]:
    """Seal the accounting-only TaskSpec for one structural zero-tool canary."""

    if not isinstance(template, Mapping):
        raise LiveZeroToolError("route_preflight:task_spec_template_invalid")
    candidate = deepcopy(dict(template))
    candidate.pop("task_spec_sha256", None)
    candidate["input_refs"] = []
    candidate["allowed_tools"] = []
    budgets = candidate.get("budgets")
    if not isinstance(budgets, Mapping):
        raise LiveZeroToolError("route_preflight:task_spec_budgets_invalid")
    candidate["budgets"] = {
        **deepcopy(dict(budgets)),
        "tool_calls": ROUTE_PREFLIGHT_TOOL_CALL_BUDGET,
        "retries": 0,
    }
    try:
        return adaptive_contracts.seal_task_spec(candidate)
    except adaptive_contracts.ContractValidationError as error:
        raise LiveZeroToolError(
            "route_preflight:task_spec_template_invalid"
        ) from error


def _route_preflight_task_spec_valid(report: Any) -> bool:
    normalized = (
        report.get("normalized") if isinstance(report, Mapping) else None
    )
    budgets = (
        normalized.get("budgets")
        if isinstance(normalized, Mapping)
        and isinstance(normalized.get("budgets"), Mapping)
        else {}
    )
    return bool(
        isinstance(report, Mapping)
        and report.get("valid") is True
        and normalized.get("allowed_tools") == []
        and budgets.get("tool_calls") == ROUTE_PREFLIGHT_TOOL_CALL_BUDGET
        and budgets.get("retries") == 0
    )


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _safe_reason(error: BaseException, fallback: str) -> str:
    value = str(error)
    return value if _SAFE_REASON.fullmatch(value) is not None else fallback


def _http_failure_category(status: int) -> str:
    if 300 <= status <= 399:
        return "redirect_refused"
    if status in {401, 403}:
        return "credential_rejected"
    if status == 404:
        return "route_not_found"
    if status == 429:
        return "rate_limited"
    if status in {400, 422}:
        return "request_rejected"
    if 400 <= status <= 499:
        return "client_failure"
    if 500 <= status <= 599:
        return "server_failure"
    return "unexpected_status"


def _exact(value: Any, fields: frozenset[str], label: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, f"{label}:shape_invalid")
        return {}
    if set(value) != fields:
        _issue(issues, f"{label}:shape_invalid")
    return value


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _is_identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _positive_int(value: Any, *, maximum: int) -> bool:
    return type(value) is int and 0 < value <= maximum


def _required_route(*, session_id: str | None = None) -> dict[str, Any]:
    route: dict[str, Any] = {
        "model": _route_model(),
        "effort": _route_effort(),
        "context_policy": REQUIRED_CONTEXT_POLICY,
        "inherited_history": False,
    }
    if session_id is not None:
        route = {"session_id": session_id, **route}
    return route


def _evidence_root(value: str | os.PathLike[str] | Path) -> Path:
    root = Path(value)
    if not root.is_absolute():
        raise LiveZeroToolError("evidence_root:absolute_required")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise LiveZeroToolError("evidence_root:unavailable") from exc
    if root.is_symlink() or resolved != root or not resolved.is_dir():
        raise LiveZeroToolError("evidence_root:invalid")
    return resolved


def evidence_scope_sha256(value: str | os.PathLike[str] | Path) -> str:
    """Return the path-hiding digest bound into one response evidence scope."""

    root = _evidence_root(value)
    return _sha256(
        {"schema": "orch-dork/live-zero-tool-evidence-scope/v1", "root": str(root)}
    )


def _assignment_item_ids(assignment: Mapping[str, Any]) -> list[str]:
    task = assignment.get("task")
    items = task.get("items") if isinstance(task, Mapping) else None
    if not isinstance(items, list):
        raise LiveZeroToolError("assignment:items_invalid")
    result: list[str] = []
    for item in items:
        identifier = item.get("id") if isinstance(item, Mapping) else None
        if not _is_identifier(identifier) or identifier in result:
            raise LiveZeroToolError("assignment:item_id_invalid")
        result.append(str(identifier))
    if not result:
        raise LiveZeroToolError("assignment:items_empty")
    return sorted(result)


def _output_schema(assignment: Mapping[str, Any]) -> dict[str, Any]:
    item_ids = _assignment_item_ids(assignment)
    # vLLM's xgrammar backend rejects JSON Schema ``uniqueItems``. The response
    # observer below independently requires each list to equal its sorted set,
    # so transport compatibility does not weaken semantic uniqueness.
    item_list = {
        "type": "array",
        "items": {"type": "string", "enum": item_ids},
        "maxItems": len(item_ids),
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_TERMINAL_FIELDS),
        "properties": {
            "schema": {"type": "string", "const": live_sweep.LIVE_LANE_RESULT_SCHEMA},
            "lane_id": {"type": "string", "const": assignment["lane_id"]},
            "request_sha256": {
                "type": "string",
                "const": assignment["request_sha256"],
            },
            "assignment_sha256": {
                "type": "string",
                "const": assignment["assignment_sha256"],
            },
            "findings": deepcopy(item_list),
            "unknowns": deepcopy(item_list),
        },
    }


def _response_format(assignment: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "type": "json_schema",
        "name": "orch_dork_live_sweep_lane_result",
        "strict": True,
        "schema": _output_schema(assignment),
    }


def _request_body(
    assignment: Mapping[str, Any],
    max_output_tokens: int,
    request_schema: str,
) -> dict[str, Any]:
    body = {
        "model": _route_model(),
        "input": live_sweep.render_live_lane_prompt(assignment),
        "reasoning": {"effort": _route_effort(), "summary": "none"},
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": False,
        "text": {"format": _response_format(assignment)},
        "max_output_tokens": max_output_tokens,
        "stream": False,
        "store": False,
    }
    if request_schema == REQUEST_SCHEMA_V1:
        body["include_reasoning"] = False
    return body


def _closed_shape_schema(value: Any) -> dict[str, Any]:
    """Derive a strict JSON shape without trusting model-authored values."""

    if isinstance(value, Mapping):
        return {
            "type": "object",
            "additionalProperties": False,
            "required": sorted(str(key) for key in value),
            "properties": {
                str(key): _closed_shape_schema(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            },
        }
    if isinstance(value, list):
        item_schema = (
            _closed_shape_schema(value[0]) if value else {"type": "string"}
        )
        return {
            "type": "array",
            "items": item_schema,
            "minItems": len(value),
            "maxItems": len(value),
        }
    if value is None:
        return {"type": "null"}
    if type(value) is bool:
        return {"type": "boolean"}
    if type(value) is int:
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    return {"type": "string"}


def _route_preflight_output_schema(candidate: Mapping[str, Any]) -> dict[str, Any]:
    schema = _closed_shape_schema(candidate)
    properties = schema["properties"]
    for field in (
        "schema",
        "preflight_id",
        "task_spec_sha256",
        "capability_profile",
    ):
        properties[field]["const"] = candidate[field]
    return schema


def _route_preflight_response_format(
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "type": "json_schema",
        "name": "orch_dork_route_preflight_candidate",
        "strict": True,
        "schema": _route_preflight_output_schema(candidate),
    }


def _route_preflight_request_body(
    candidate: Mapping[str, Any],
    max_output_tokens: int,
) -> dict[str, Any]:
    exact_output = _canonical_bytes(candidate).decode("utf-8")
    return {
        "model": _route_model(),
        "input": (
            "Return exactly the following JSON object and nothing else. "
            "The transport exposes no tools and permits no continuation.\n"
            + exact_output
        ),
        "reasoning": {"effort": _route_effort(), "summary": "none"},
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": False,
        "text": {"format": _route_preflight_response_format(candidate)},
        "max_output_tokens": max_output_tokens,
        "stream": False,
        "store": False,
    }


def build_live_zero_tool_request(
    assignment: Any,
    *,
    campaign_sha256: str,
    grant_sha256: str,
    reservation_sha256: str,
    request_id: str,
    max_output_tokens: int,
    max_total_tokens: int,
    max_response_bytes: int,
    timeout_ms: int,
    evidence_root: str | os.PathLike[str] | Path,
    request_schema: str = REQUEST_SCHEMA,
) -> dict[str, Any]:
    """Build one assignment-bound, structurally tool-free Responses request."""

    if request_schema not in {REQUEST_SCHEMA_V1, REQUEST_SCHEMA_V2}:
        raise LiveZeroToolError("request_schema:invalid")
    if not isinstance(assignment, Mapping):
        raise LiveZeroToolError("assignment:shape_invalid")
    copied = deepcopy(dict(assignment))
    try:
        live_sweep.render_live_lane_prompt(copied)
        _assignment_item_ids(copied)
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveZeroToolError("assignment:invalid") from exc
    if not _is_identifier(request_id):
        raise LiveZeroToolError("request_id:invalid")
    for label, value in (
        ("campaign_sha256", campaign_sha256),
        ("grant_sha256", grant_sha256),
        ("reservation_sha256", reservation_sha256),
    ):
        if not _is_sha(value):
            raise LiveZeroToolError(f"{label}:invalid")
    if not _positive_int(max_output_tokens, maximum=MAX_OUTPUT_TOKENS):
        raise LiveZeroToolError("limits:max_output_tokens_invalid")
    if not _positive_int(max_total_tokens, maximum=MAX_TOTAL_TOKENS):
        raise LiveZeroToolError("limits:max_total_tokens_invalid")
    if max_output_tokens > max_total_tokens:
        raise LiveZeroToolError("limits:output_exceeds_total")
    if not _positive_int(max_response_bytes, maximum=MAX_RESPONSE_BYTES):
        raise LiveZeroToolError("limits:max_response_bytes_invalid")
    if not _positive_int(timeout_ms, maximum=MAX_TIMEOUT_MS):
        raise LiveZeroToolError("limits:timeout_ms_invalid")
    evidence_scope = evidence_scope_sha256(evidence_root)

    body = _request_body(copied, max_output_tokens, request_schema)
    response_format = body["text"]["format"]
    core = {
        "schema": request_schema,
        "request_id": request_id,
        "transport": TRANSPORT,
        "bindings": {
            "campaign_sha256": campaign_sha256,
            "grant_sha256": grant_sha256,
            "reservation_sha256": reservation_sha256,
            "lane_id": copied["lane_id"],
            "assignment_sha256": copied["assignment_sha256"],
            "evidence_scope_sha256": evidence_scope,
        },
        "route": _required_route(),
        "limits": {
            "max_output_tokens": max_output_tokens,
            "max_total_tokens": max_total_tokens,
            "max_response_bytes": max_response_bytes,
            "timeout_ms": timeout_ms,
        },
        "assignment": copied,
        "output_schema_sha256": _sha256(response_format["schema"]),
        "body": body,
    }
    request = {**core, "request_sha256": _sha256(core)}
    report = validate_live_zero_tool_request(request)
    if not report["valid"]:
        raise LiveZeroToolError("request:builder_invalid")
    return request


def validate_live_zero_tool_request(value: Any) -> dict[str, Any]:
    """Re-derive the request and refuse prompt-only or caller-resealed tools."""

    issues: list[str] = []
    request = _exact(value, _REQUEST_FIELDS, "request", issues)
    request_schema = request.get("schema")
    if request_schema not in {REQUEST_SCHEMA_V1, REQUEST_SCHEMA_V2}:
        _issue(issues, "request:schema_invalid")
    if not _is_identifier(request.get("request_id")):
        _issue(issues, "request:id_invalid")
    if request.get("transport") != TRANSPORT:
        _issue(issues, "request:transport_invalid")

    bindings = _exact(request.get("bindings"), _BINDING_FIELDS, "request:bindings", issues)
    for field in (
        "campaign_sha256",
        "grant_sha256",
        "reservation_sha256",
        "assignment_sha256",
        "evidence_scope_sha256",
    ):
        if not _is_sha(bindings.get(field)):
            _issue(issues, f"request:{field}_invalid")
    if not _is_identifier(bindings.get("lane_id")):
        _issue(issues, "request:lane_id_invalid")

    route = _exact(request.get("route"), _ROUTE_FIELDS, "request:route", issues)
    expected_route = _required_route()
    if dict(route) != expected_route:
        _issue(issues, "request:route_mismatch")

    limits = _exact(request.get("limits"), _LIMIT_FIELDS, "request:limits", issues)
    if not _positive_int(limits.get("max_output_tokens"), maximum=MAX_OUTPUT_TOKENS):
        _issue(issues, "request:max_output_tokens_invalid")
    if not _positive_int(limits.get("max_total_tokens"), maximum=MAX_TOTAL_TOKENS):
        _issue(issues, "request:max_total_tokens_invalid")
    if (
        type(limits.get("max_output_tokens")) is int
        and type(limits.get("max_total_tokens")) is int
        and limits["max_output_tokens"] > limits["max_total_tokens"]
    ):
        _issue(issues, "request:output_exceeds_total")
    if not _positive_int(limits.get("max_response_bytes"), maximum=MAX_RESPONSE_BYTES):
        _issue(issues, "request:max_response_bytes_invalid")
    if not _positive_int(limits.get("timeout_ms"), maximum=MAX_TIMEOUT_MS):
        _issue(issues, "request:timeout_ms_invalid")

    assignment = request.get("assignment")
    expected_body: dict[str, Any] | None = None
    if not isinstance(assignment, Mapping):
        _issue(issues, "request:assignment_invalid")
    else:
        try:
            live_sweep.render_live_lane_prompt(assignment)
            _assignment_item_ids(assignment)
            output_limit = limits.get("max_output_tokens")
            if type(output_limit) is int:
                expected_body = _request_body(
                    assignment,
                    output_limit,
                    request_schema
                    if request_schema in {REQUEST_SCHEMA_V1, REQUEST_SCHEMA_V2}
                    else REQUEST_SCHEMA,
                )
        except (KeyError, TypeError, ValueError):
            _issue(issues, "request:assignment_invalid")
        if bindings.get("lane_id") != assignment.get("lane_id") or bindings.get(
            "assignment_sha256"
        ) != assignment.get("assignment_sha256"):
            _issue(issues, "request:assignment_binding_mismatch")

    raw_body = request.get("body")
    body_fields = (
        _BODY_FIELDS_V1
        if request_schema == REQUEST_SCHEMA_V1
        else _BODY_FIELDS_V2
    )
    if not isinstance(raw_body, Mapping) or set(raw_body) != body_fields:
        _issue(issues, "request:body_shape_invalid")
    body = _exact(raw_body, body_fields, "request:body", issues)
    if body.get("tools") != []:
        _issue(issues, "request:tools_not_empty")
    if body.get("tool_choice") != "none":
        _issue(issues, "request:tool_choice_not_none")
    if body.get("parallel_tool_calls") is not False:
        _issue(issues, "request:parallel_tools_not_disabled")
    if body.get("stream") is not False or body.get("store") is not False:
        _issue(issues, "request:single_response_not_bound")
    if body.get("model") != _route_model():
        _issue(issues, "request:model_mismatch")
    if (
        request_schema == REQUEST_SCHEMA_V1
        and body.get("include_reasoning") is not False
    ):
        _issue(issues, "request:reasoning_output_not_suppressed")
    if request_schema == REQUEST_SCHEMA_V2 and "include_reasoning" in body:
        _issue(issues, "request:obsolete_reasoning_control_present")
    if body.get("max_output_tokens") != limits.get("max_output_tokens"):
        _issue(issues, "request:output_limit_mismatch")
    text = body.get("text")
    response_format = text.get("format") if isinstance(text, Mapping) else None
    if (
        not isinstance(response_format, Mapping)
        or response_format.get("type") != "json_schema"
        or response_format.get("strict") is not True
        or response_format.get("name") != "orch_dork_live_sweep_lane_result"
        or not isinstance(response_format.get("schema"), Mapping)
    ):
        _issue(issues, "request:response_format_mismatch")
    elif request.get("output_schema_sha256") != _sha256(response_format["schema"]):
        _issue(issues, "request:output_schema_digest_mismatch")
    if expected_body is not None and dict(body) != expected_body:
        _issue(issues, "request:body_mismatch")

    if isinstance(request, Mapping):
        core = {key: deepcopy(item) for key, item in request.items() if key != "request_sha256"}
        if not _is_sha(request.get("request_sha256")) or request.get("request_sha256") != _sha256(core):
            _issue(issues, "request:digest_mismatch")

    return {
        "schema": REQUEST_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(issues),
        "request_sha256": request.get("request_sha256") if not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def build_route_preflight_zero_tool_request(
    candidate: Any,
    *,
    task_spec: Any,
    attempt_sha256: str,
    live_preflight_sha256: str,
    request_id: str,
    max_output_tokens: int,
    max_total_tokens: int,
    max_response_bytes: int,
    timeout_ms: int,
    evidence_root: str | os.PathLike[str] | Path,
) -> dict[str, Any]:
    """Build one exact observer-bound canary request with no tool catalog."""

    if not isinstance(candidate, Mapping) or set(candidate) != (
        _ROUTE_PREFLIGHT_CANDIDATE_FIELDS
    ):
        raise LiveZeroToolError("route_preflight:candidate_shape_invalid")
    task_report = adaptive_contracts.validate_task_spec(task_spec)
    candidate_report = adaptive_contracts.validate_handoff_preflight_candidate(
        candidate,
        task_spec=task_spec,
    )
    if not _route_preflight_task_spec_valid(task_report):
        raise LiveZeroToolError("route_preflight:task_spec_invalid")
    if not candidate_report.get("candidate_valid"):
        raise LiveZeroToolError("route_preflight:candidate_invalid")
    if not _is_identifier(request_id):
        raise LiveZeroToolError("request_id:invalid")
    for label, digest in (
        ("attempt_sha256", attempt_sha256),
        ("live_preflight_sha256", live_preflight_sha256),
    ):
        if not _is_sha(digest):
            raise LiveZeroToolError(f"{label}:invalid")
    if not _positive_int(max_output_tokens, maximum=MAX_OUTPUT_TOKENS):
        raise LiveZeroToolError("limits:max_output_tokens_invalid")
    if not _positive_int(max_total_tokens, maximum=MAX_TOTAL_TOKENS):
        raise LiveZeroToolError("limits:max_total_tokens_invalid")
    if max_output_tokens > max_total_tokens:
        raise LiveZeroToolError("limits:output_exceeds_total")
    if not _positive_int(max_response_bytes, maximum=MAX_RESPONSE_BYTES):
        raise LiveZeroToolError("limits:max_response_bytes_invalid")
    if not _positive_int(timeout_ms, maximum=MAX_TIMEOUT_MS):
        raise LiveZeroToolError("limits:timeout_ms_invalid")

    copied_spec = deepcopy(dict(task_spec))
    copied_candidate = deepcopy(dict(candidate))
    body = _route_preflight_request_body(copied_candidate, max_output_tokens)
    response_format = body["text"]["format"]
    core = {
        "schema": ROUTE_PREFLIGHT_REQUEST_SCHEMA,
        "request_id": request_id,
        "transport": TRANSPORT,
        "bindings": {
            "attempt_sha256": attempt_sha256,
            "live_preflight_sha256": live_preflight_sha256,
            "task_spec_sha256": task_report["digest"],
            "candidate_sha256": candidate_report["digest"],
            "preflight_id": copied_candidate["preflight_id"],
            "evidence_scope_sha256": evidence_scope_sha256(evidence_root),
        },
        "route": _required_route(),
        "limits": {
            "max_output_tokens": max_output_tokens,
            "max_total_tokens": max_total_tokens,
            "max_response_bytes": max_response_bytes,
            "timeout_ms": timeout_ms,
        },
        "task_spec": copied_spec,
        "candidate": copied_candidate,
        "output_schema_sha256": _sha256(response_format["schema"]),
        "body": body,
    }
    request = {**core, "request_sha256": _sha256(core)}
    report = validate_route_preflight_zero_tool_request(request)
    if not report["valid"]:
        raise LiveZeroToolError("route_preflight:builder_invalid")
    return request


def validate_route_preflight_zero_tool_request(value: Any) -> dict[str, Any]:
    """Re-derive the exact route canary and refuse any exposed tool surface."""

    issues: list[str] = []
    request = _exact(
        value,
        _ROUTE_PREFLIGHT_REQUEST_FIELDS,
        "request",
        issues,
    )
    if request.get("schema") != ROUTE_PREFLIGHT_REQUEST_SCHEMA:
        _issue(issues, "request:schema_invalid")
    if not _is_identifier(request.get("request_id")):
        _issue(issues, "request:id_invalid")
    if request.get("transport") != TRANSPORT:
        _issue(issues, "request:transport_invalid")

    bindings = _exact(
        request.get("bindings"),
        _ROUTE_PREFLIGHT_BINDING_FIELDS,
        "request:bindings",
        issues,
    )
    for field in (
        "attempt_sha256",
        "live_preflight_sha256",
        "task_spec_sha256",
        "candidate_sha256",
        "evidence_scope_sha256",
    ):
        if not _is_sha(bindings.get(field)):
            _issue(issues, f"request:{field}_invalid")
    if not _is_identifier(bindings.get("preflight_id")):
        _issue(issues, "request:preflight_id_invalid")

    route = _exact(
        request.get("route"),
        _ROUTE_FIELDS,
        "request:route",
        issues,
    )
    if dict(route) != _required_route():
        _issue(issues, "request:route_mismatch")

    limits = _exact(
        request.get("limits"),
        _LIMIT_FIELDS,
        "request:limits",
        issues,
    )
    if not _positive_int(
        limits.get("max_output_tokens"), maximum=MAX_OUTPUT_TOKENS
    ):
        _issue(issues, "request:max_output_tokens_invalid")
    if not _positive_int(
        limits.get("max_total_tokens"), maximum=MAX_TOTAL_TOKENS
    ):
        _issue(issues, "request:max_total_tokens_invalid")
    if (
        type(limits.get("max_output_tokens")) is int
        and type(limits.get("max_total_tokens")) is int
        and limits["max_output_tokens"] > limits["max_total_tokens"]
    ):
        _issue(issues, "request:output_exceeds_total")
    if not _positive_int(
        limits.get("max_response_bytes"), maximum=MAX_RESPONSE_BYTES
    ):
        _issue(issues, "request:max_response_bytes_invalid")
    if not _positive_int(limits.get("timeout_ms"), maximum=MAX_TIMEOUT_MS):
        _issue(issues, "request:timeout_ms_invalid")

    task_spec = request.get("task_spec")
    task_report = adaptive_contracts.validate_task_spec(task_spec)
    if not task_report.get("valid"):
        _issue(issues, "request:task_spec_invalid")
    elif not _route_preflight_task_spec_valid(task_report):
        _issue(issues, "request:task_spec_not_zero_tool")
    elif bindings.get("task_spec_sha256") != task_report.get("digest"):
        _issue(issues, "request:task_spec_binding_mismatch")

    candidate = request.get("candidate")
    if not isinstance(candidate, Mapping) or set(candidate) != (
        _ROUTE_PREFLIGHT_CANDIDATE_FIELDS
    ):
        _issue(issues, "request:candidate_shape_invalid")
        candidate = {}
    candidate_report = adaptive_contracts.validate_handoff_preflight_candidate(
        candidate,
        task_spec=task_spec,
    )
    if not candidate_report.get("candidate_valid"):
        _issue(issues, "request:candidate_invalid")
    else:
        if bindings.get("candidate_sha256") != candidate_report.get("digest"):
            _issue(issues, "request:candidate_binding_mismatch")
        if bindings.get("preflight_id") != candidate.get("preflight_id"):
            _issue(issues, "request:preflight_id_binding_mismatch")

    raw_body = request.get("body")
    body = _exact(raw_body, _BODY_FIELDS_V2, "request:body", issues)
    if body.get("tools") != []:
        _issue(issues, "request:tools_not_empty")
    if body.get("tool_choice") != "none":
        _issue(issues, "request:tool_choice_not_none")
    if body.get("parallel_tool_calls") is not False:
        _issue(issues, "request:parallel_tools_not_disabled")
    if body.get("stream") is not False or body.get("store") is not False:
        _issue(issues, "request:single_response_not_bound")
    if body.get("model") != _route_model():
        _issue(issues, "request:model_mismatch")
    if "include_reasoning" in body:
        _issue(issues, "request:obsolete_reasoning_control_present")
    if body.get("max_output_tokens") != limits.get("max_output_tokens"):
        _issue(issues, "request:output_limit_mismatch")
    expected_body = None
    output_limit = limits.get("max_output_tokens")
    if candidate and type(output_limit) is int:
        expected_body = _route_preflight_request_body(
            candidate,
            output_limit,
        )
    text = body.get("text")
    response_format = text.get("format") if isinstance(text, Mapping) else None
    if (
        not isinstance(response_format, Mapping)
        or response_format.get("type") != "json_schema"
        or response_format.get("strict") is not True
        or response_format.get("name")
        != "orch_dork_route_preflight_candidate"
        or not isinstance(response_format.get("schema"), Mapping)
    ):
        _issue(issues, "request:response_format_mismatch")
    elif request.get("output_schema_sha256") != _sha256(
        response_format["schema"]
    ):
        _issue(issues, "request:output_schema_digest_mismatch")
    if expected_body is not None and dict(body) != expected_body:
        _issue(issues, "request:body_mismatch")

    if isinstance(request, Mapping):
        core = {
            key: deepcopy(item)
            for key, item in request.items()
            if key != "request_sha256"
        }
        if not _is_sha(request.get("request_sha256")) or request.get(
            "request_sha256"
        ) != _sha256(core):
            _issue(issues, "request:digest_mismatch")

    return {
        "schema": ROUTE_PREFLIGHT_REQUEST_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(issues),
        "request_sha256": request.get("request_sha256") if not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _strict_json(raw: bytes) -> Any:
    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    text = raw.decode("utf-8", "strict")
    return json.loads(text, object_pairs_hook=closed_pairs)


def _hidden_reasoning_envelope(
    value: Any,
    *,
    maximum_response_bytes: Any,
    issues: list[str],
) -> None:
    """Validate one opaque OpenCodex envelope without retaining its payload."""

    if not isinstance(value, Mapping):
        _issue(issues, "response:reasoning_envelope_invalid")
        return
    if value.get("summary") != [] or "content" in value:
        _issue(issues, "response:reasoning_visible")
    if set(value) != _HIDDEN_REASONING_FIELDS:
        _issue(issues, "response:reasoning_envelope_invalid")
        return
    if value.get("type") != "reasoning" or not _is_identifier(value.get("id")):
        _issue(issues, "response:reasoning_envelope_invalid")
    encrypted = value.get("encrypted_content")
    if not isinstance(encrypted, str) or not encrypted.startswith(
        HIDDEN_REASONING_ENVELOPE_PREFIX
    ):
        _issue(issues, "response:reasoning_envelope_invalid")
        return
    if (
        type(maximum_response_bytes) is not int
        or not encrypted
        or len(encrypted.encode("utf-8")) > maximum_response_bytes
    ):
        _issue(issues, "response:reasoning_envelope_invalid")
        return
    encoded = encrypted[len(HIDDEN_REASONING_ENVELOPE_PREFIX) :]
    try:
        decoded = base64.b64decode(encoded, validate=True)
        envelope = _strict_json(decoded)
    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ):
        _issue(issues, "response:reasoning_envelope_invalid")
        return
    if (
        not isinstance(envelope, Mapping)
        or set(envelope) != {"txt"}
        or not isinstance(envelope.get("txt"), str)
        or not envelope["txt"]
    ):
        _issue(issues, "response:reasoning_envelope_invalid")


def _terminal_result(
    value: Any,
    assignment: Mapping[str, Any],
    issues: list[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _TERMINAL_FIELDS:
        _issue(issues, "terminal:schema_violation")
        return {}
    constants = {
        "schema": live_sweep.LIVE_LANE_RESULT_SCHEMA,
        "lane_id": assignment.get("lane_id"),
        "request_sha256": assignment.get("request_sha256"),
        "assignment_sha256": assignment.get("assignment_sha256"),
    }
    if any(value.get(field) != expected for field, expected in constants.items()):
        _issue(issues, "terminal:schema_violation")
    allowed = set(_assignment_item_ids(assignment))
    projected: dict[str, list[str]] = {}
    for field in ("findings", "unknowns"):
        items = value.get(field)
        if (
            not isinstance(items, list)
            or any(not isinstance(item, str) for item in items)
            or items != sorted(set(items))
            or not set(items).issubset(allowed)
        ):
            _issue(issues, "terminal:schema_violation")
            projected[field] = []
        else:
            projected[field] = list(items)
    if set(projected.get("findings", [])) & set(projected.get("unknowns", [])):
        _issue(issues, "terminal:schema_violation")
    return value


def _usage(value: Any, limits: Mapping[str, Any], issues: list[str]) -> dict[str, Any]:
    usage = value if isinstance(value, Mapping) else {}
    details_in = usage.get("input_tokens_details")
    details_out = usage.get("output_tokens_details")
    values = {
        "input_tokens": usage.get("input_tokens"),
        "cached_input_tokens": (
            details_in.get("cached_tokens") if isinstance(details_in, Mapping) else None
        ),
        "output_tokens": usage.get("output_tokens"),
        "reasoning_tokens": (
            details_out.get("reasoning_tokens") if isinstance(details_out, Mapping) else None
        ),
        "total_tokens": usage.get("total_tokens"),
    }
    if any(type(item) is not int or item < 0 for item in values.values()):
        _issue(issues, "usage:exact_components_required")
        return {}
    if (
        values["cached_input_tokens"] > values["input_tokens"]
        or values["reasoning_tokens"] > values["output_tokens"]
        or values["total_tokens"]
        != values["input_tokens"] + values["output_tokens"]
    ):
        _issue(issues, "usage:arithmetic_invalid")
    if values["output_tokens"] > limits.get("max_output_tokens", -1):
        _issue(issues, "usage:output_limit_exceeded")
    if values["total_tokens"] > limits.get("max_total_tokens", -1):
        _issue(issues, "usage:total_limit_exceeded")
    return {"status": "observed", **values, "tool_calls": 0}


def _runtime_observation(
    *,
    observer_id: str,
    response_id: str,
    response_sha256: str,
    terminal: Mapping[str, Any],
    usage: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "schema": routing.SESSION_RUNTIME_OBSERVATION_SCHEMA,
        "status": "PASS",
        "issues": [],
        "observer_id": observer_id,
        "source_pointer": f"session://{response_id}",
        "source_sha256": response_sha256,
        "route": _required_route(session_id=response_id),
        "terminal_schema": terminal["schema"],
        "terminal_json_sha256": _sha256(terminal),
        "terminal_record": {"line": 1, "sha256": response_sha256},
        "usage": dict(usage),
        "usage_record": {"line": 1, "sha256": response_sha256},
        "skipped_lines": 0,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "evidence_tier": "runtime-observed",
    }
    return {**core, "report_sha256": _sha256(core)}


def observe_live_zero_tool_response(
    request: Any,
    raw_response: Any,
    *,
    observer_id: str,
    expected_response_sha256: str | None = None,
) -> dict[str, Any]:
    """Observe one raw non-streaming response without retaining it publicly."""

    issues: list[str] = []
    validation = validate_live_zero_tool_request(request)
    if not validation["valid"]:
        issues.extend(validation["issues"])
    request_value = request if isinstance(request, Mapping) else {}
    limits = request_value.get("limits") if isinstance(request_value.get("limits"), Mapping) else {}
    assignment = request_value.get("assignment") if isinstance(request_value.get("assignment"), Mapping) else {}

    if not isinstance(raw_response, (bytes, bytearray)):
        _issue(issues, "response:bytes_required")
        raw = b""
    else:
        raw = bytes(raw_response)
    response_sha256 = _bytes_sha256(raw)
    maximum = limits.get("max_response_bytes")
    if type(maximum) is not int or len(raw) > maximum:
        _issue(issues, "response:too_large")
    if expected_response_sha256 is not None and (
        not _is_sha(expected_response_sha256) or expected_response_sha256 != response_sha256
    ):
        _issue(issues, "response:source_digest_mismatch")

    try:
        response = _strict_json(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _issue(issues, "response:json_invalid")
        response = {}
    if not isinstance(response, Mapping):
        _issue(issues, "response:shape_invalid")
        response = {}

    response_id = response.get("id")
    if not _is_identifier(response_id):
        _issue(issues, "response:id_invalid")
    if response.get("status") != "completed":
        _issue(issues, "response:not_completed")
    if response.get("object") != "response":
        _issue(issues, "response:object_invalid")
    if response.get("error") is not None:
        _issue(issues, "response:error_present")
    if response.get("incomplete_details") is not None:
        _issue(issues, "response:incomplete_details_present")
    logical_model = request_value.get("route", {}).get("model")
    expected_wire_model = _observed_wire_model(logical_model, issues)
    if response.get("model") != expected_wire_model:
        _issue(issues, "response:model_mismatch")
    if response.get("previous_response_id") is not None:
        _issue(issues, "response:continuation_forbidden")
    if response.get("tools") not in (None, []):
        _issue(issues, "response:tools_not_empty")
    if response.get("tool_choice") not in (None, "none"):
        _issue(issues, "response:tool_choice_mismatch")

    output = response.get("output")
    if isinstance(output, list) and any(
        isinstance(item, Mapping) and item.get("type") in _TOOL_OUTPUT_TYPES
        for item in output
    ):
        _issue(issues, "response:tool_output_forbidden")
    request_schema = request_value.get("schema")
    allowed_output_counts = (
        {1, 2} if request_schema == REQUEST_SCHEMA_V2 else {1}
    )
    if not isinstance(output, list) or len(output) not in allowed_output_counts:
        _issue(issues, "response:output_count_invalid")
        output = []
    message: Mapping[str, Any] | None = None
    if request_schema == REQUEST_SCHEMA_V2 and len(output) == 2:
        if not isinstance(output[0], Mapping) or output[0].get("type") != "reasoning":
            second_type = (
                output[1].get("type") if isinstance(output[1], Mapping) else None
            )
            _issue(
                issues,
                (
                    "response:reasoning_order_invalid"
                    if second_type == "reasoning"
                    else "response:output_count_invalid"
                ),
            )
        else:
            _hidden_reasoning_envelope(
                output[0],
                maximum_response_bytes=limits.get("max_response_bytes"),
                issues=issues,
            )
        if isinstance(output[1], Mapping):
            message = output[1]
    elif len(output) == 1 and isinstance(output[0], Mapping):
        message = output[0]

    terminal: Mapping[str, Any] = {}
    if message is not None:
        if (
            message.get("type") != "message"
            or message.get("status") != "completed"
            or message.get("role") != "assistant"
        ):
            if message.get("type") in _TOOL_OUTPUT_TYPES:
                _issue(issues, "response:tool_output_forbidden")
            else:
                _issue(issues, "response:message_invalid")
        content = message.get("content")
        if not isinstance(content, list) or len(content) != 1:
            _issue(issues, "response:content_count_invalid")
        elif not isinstance(content[0], Mapping) or content[0].get("type") != "output_text":
            _issue(issues, "response:content_invalid")
        else:
            text = content[0].get("text")
            if not isinstance(text, str):
                _issue(issues, "terminal:not_closed_json_object")
            else:
                try:
                    parsed_terminal = _strict_json(text.encode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    parsed_terminal = None
                if not isinstance(parsed_terminal, Mapping):
                    _issue(issues, "terminal:not_closed_json_object")
                else:
                    terminal = _terminal_result(parsed_terminal, assignment, issues)
    elif output:
        _issue(issues, "response:message_invalid")

    usage = _usage(response.get("usage"), limits, issues)
    if not _is_identifier(observer_id):
        _issue(issues, "observer:id_invalid")
    if observer_id == response_id:
        _issue(issues, "observer:not_independent")

    receipt = None
    runtime_observation = None
    if not issues:
        receipt_core = {
            "schema": RECEIPT_SCHEMA,
            "status": "PASS",
            "request_sha256": request_value["request_sha256"],
            "bindings": deepcopy(dict(request_value["bindings"])),
            "response_id": response_id,
            "response_sha256": response_sha256,
            "route": _required_route(session_id=str(response_id)),
            "terminal_schema": terminal["schema"],
            "terminal_json_sha256": _sha256(terminal),
            "usage": dict(usage),
            "request_tool_count": 0,
            "response_tool_count": 0,
            "continued": False,
        }
        receipt = {**receipt_core, "receipt_sha256": _sha256(receipt_core)}
        runtime_observation = _runtime_observation(
            observer_id=observer_id,
            response_id=str(response_id),
            response_sha256=response_sha256,
            terminal=terminal,
            usage=usage,
        )
        if not routing.validate_session_runtime_observation(runtime_observation)["valid"]:
            _issue(issues, "runtime:projection_invalid")
            receipt = None
            runtime_observation = None

    return {
        "schema": OBSERVATION_REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(issues),
        "request_sha256": request_value.get("request_sha256"),
        "response_sha256": response_sha256,
        "terminal_result": deepcopy(dict(terminal)) if not issues else None,
        "receipt": receipt,
        "runtime_observation": runtime_observation,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def observe_route_preflight_zero_tool_response(
    request: Any,
    raw_response: Any,
    *,
    observer_id: str,
    expected_response_sha256: str | None = None,
) -> dict[str, Any]:
    """Observe one exact route-canary response and bind it for wave v3."""

    issues: list[str] = []
    validation = validate_route_preflight_zero_tool_request(request)
    if not validation["valid"]:
        issues.extend(validation["issues"])
    request_value = request if isinstance(request, Mapping) else {}
    limits = (
        request_value.get("limits")
        if isinstance(request_value.get("limits"), Mapping)
        else {}
    )
    candidate = (
        request_value.get("candidate")
        if isinstance(request_value.get("candidate"), Mapping)
        else {}
    )
    task_spec = request_value.get("task_spec")

    if not isinstance(raw_response, (bytes, bytearray)):
        _issue(issues, "response:bytes_required")
        raw = b""
    else:
        raw = bytes(raw_response)
    response_sha256 = _bytes_sha256(raw)
    maximum = limits.get("max_response_bytes")
    if type(maximum) is not int or len(raw) > maximum:
        _issue(issues, "response:too_large")
    if expected_response_sha256 is not None and (
        not _is_sha(expected_response_sha256)
        or expected_response_sha256 != response_sha256
    ):
        _issue(issues, "response:source_digest_mismatch")

    try:
        response = _strict_json(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _issue(issues, "response:json_invalid")
        response = {}
    if not isinstance(response, Mapping):
        _issue(issues, "response:shape_invalid")
        response = {}

    response_id = response.get("id")
    if not _is_identifier(response_id):
        _issue(issues, "response:id_invalid")
    if response.get("status") != "completed":
        _issue(issues, "response:not_completed")
    if response.get("object") != "response":
        _issue(issues, "response:object_invalid")
    if response.get("error") is not None:
        _issue(issues, "response:error_present")
    if response.get("incomplete_details") is not None:
        _issue(issues, "response:incomplete_details_present")
    logical_model = request_value.get("route", {}).get("model")
    expected_wire_model = _observed_wire_model(logical_model, issues)
    if response.get("model") != expected_wire_model:
        _issue(issues, "response:model_mismatch")
    if response.get("previous_response_id") is not None:
        _issue(issues, "response:continuation_forbidden")
    if response.get("tools") not in (None, []):
        _issue(issues, "response:tools_not_empty")
    if response.get("tool_choice") not in (None, "none"):
        _issue(issues, "response:tool_choice_mismatch")

    output = response.get("output")
    if isinstance(output, list) and any(
        isinstance(item, Mapping) and item.get("type") in _TOOL_OUTPUT_TYPES
        for item in output
    ):
        _issue(issues, "response:tool_output_forbidden")
    if not isinstance(output, list) or len(output) not in {1, 2}:
        _issue(issues, "response:output_count_invalid")
        output = []
    message: Mapping[str, Any] | None = None
    if len(output) == 2:
        if not isinstance(output[0], Mapping) or output[0].get("type") != (
            "reasoning"
        ):
            second_type = (
                output[1].get("type") if isinstance(output[1], Mapping) else None
            )
            _issue(
                issues,
                (
                    "response:reasoning_order_invalid"
                    if second_type == "reasoning"
                    else "response:output_count_invalid"
                ),
            )
        else:
            _hidden_reasoning_envelope(
                output[0],
                maximum_response_bytes=limits.get("max_response_bytes"),
                issues=issues,
            )
        if isinstance(output[1], Mapping):
            message = output[1]
    elif len(output) == 1 and isinstance(output[0], Mapping):
        message = output[0]

    terminal: Mapping[str, Any] = {}
    if message is not None:
        if (
            message.get("type") != "message"
            or message.get("status") != "completed"
            or message.get("role") != "assistant"
        ):
            if message.get("type") in _TOOL_OUTPUT_TYPES:
                _issue(issues, "response:tool_output_forbidden")
            else:
                _issue(issues, "response:message_invalid")
        content = message.get("content")
        if not isinstance(content, list) or len(content) != 1:
            _issue(issues, "response:content_count_invalid")
        elif not isinstance(content[0], Mapping) or content[0].get("type") != (
            "output_text"
        ):
            _issue(issues, "response:content_invalid")
        else:
            text = content[0].get("text")
            if not isinstance(text, str):
                _issue(issues, "terminal:not_closed_json_object")
            else:
                try:
                    parsed_terminal = _strict_json(text.encode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    parsed_terminal = None
                if not isinstance(parsed_terminal, Mapping):
                    _issue(issues, "terminal:not_closed_json_object")
                elif dict(parsed_terminal) != dict(candidate):
                    _issue(issues, "terminal:candidate_mismatch")
                else:
                    candidate_report = (
                        adaptive_contracts.validate_handoff_preflight_candidate(
                            parsed_terminal,
                            task_spec=task_spec,
                        )
                    )
                    if not candidate_report.get("candidate_valid"):
                        _issue(issues, "terminal:candidate_invalid")
                    else:
                        terminal = parsed_terminal
    elif output:
        _issue(issues, "response:message_invalid")

    usage = _usage(response.get("usage"), limits, issues)
    if not _is_identifier(observer_id):
        _issue(issues, "observer:id_invalid")
    if observer_id == response_id:
        _issue(issues, "observer:not_independent")

    receipt = None
    runtime_observation = None
    if not issues:
        receipt_core = {
            "schema": ROUTE_PREFLIGHT_RECEIPT_SCHEMA,
            "status": "PASS",
            "request_sha256": request_value["request_sha256"],
            "bindings": deepcopy(dict(request_value["bindings"])),
            "response_id": response_id,
            "response_sha256": response_sha256,
            "route": _required_route(session_id=str(response_id)),
            "terminal_schema": terminal["schema"],
            "terminal_json_sha256": _sha256(terminal),
            "usage": dict(usage),
            "request_tool_count": 0,
            "response_tool_count": 0,
            "continued": False,
        }
        receipt = {**receipt_core, "receipt_sha256": _sha256(receipt_core)}
        runtime_observation = _runtime_observation(
            observer_id=observer_id,
            response_id=str(response_id),
            response_sha256=response_sha256,
            terminal=terminal,
            usage=usage,
        )
        if not routing.validate_session_runtime_observation(runtime_observation)[
            "valid"
        ]:
            _issue(issues, "runtime:projection_invalid")
            receipt = None
            runtime_observation = None

    return {
        "schema": ROUTE_PREFLIGHT_OBSERVATION_REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(issues),
        "request_sha256": request_value.get("request_sha256"),
        "response_sha256": response_sha256,
        "terminal_result": deepcopy(dict(terminal)) if not issues else None,
        "receipt": receipt,
        "runtime_observation": runtime_observation,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def validate_loopback_responses_endpoint(endpoint: Any) -> str:
    """Accept only a literal loopback HTTP ``/v1/responses`` endpoint."""

    if not isinstance(endpoint, str) or not endpoint:
        raise LiveZeroToolError("endpoint:invalid")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as exc:
        raise LiveZeroToolError("endpoint:invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or port is None
        or not 1 <= port <= 65_535
        or parsed.path != RESPONSES_PATH
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise LiveZeroToolError("endpoint:not_loopback_responses")
    host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
    return f"http://{host}:{port}{RESPONSES_PATH}"


def _http_post_once(
    endpoint: str,
    body: bytes,
    headers: Mapping[str, str],
    timeout_ms: int,
    max_response_bytes: int,
) -> dict[str, Any]:
    parsed = urlsplit(validate_loopback_responses_endpoint(endpoint))
    started = time.monotonic()
    connection = http.client.HTTPConnection(
        parsed.hostname,
        parsed.port,
        timeout=timeout_ms / 1000,
    )
    try:
        connection.request("POST", RESPONSES_PATH, body=body, headers=dict(headers))
        response = connection.getresponse()
        data = response.read(max_response_bytes + 1)
        if len(data) > max_response_bytes:
            raise LiveZeroToolError("transport:response_too_large")
        raw_content_type = response.getheader("Content-Type")
        content_type = (
            raw_content_type.split(";", 1)[0].strip().lower()
            if isinstance(raw_content_type, str)
            else ""
        )
        if not content_type:
            content_type = "unknown"
        elif content_type not in _PUBLIC_MEDIA_TYPES:
            content_type = "other"
        return {
            "http_status": response.status,
            "content_type": content_type,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "body": data,
        }
    except LiveZeroToolError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise LiveZeroToolError("transport:io_failure") from exc
    finally:
        connection.close()


def _invocation_report(
    *,
    status: str,
    issues: list[str],
    request_sha256: Any,
    attempted_requests: int,
    response_sha256: str | None = None,
    observation: Mapping[str, Any] | None = None,
    transport_failure: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    model_calls = (
        attempted_requests
        if attempted_requests == 0 or observation is not None
        else None
    )
    return {
        "schema": INVOCATION_REPORT_SCHEMA,
        "status": status,
        "issues": sorted(set(issues)),
        "request_sha256": request_sha256,
        "response_sha256": response_sha256,
        "attempted_requests": attempted_requests,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "response_persisted": response_sha256 is not None,
        "terminal_result": (
            deepcopy(observation.get("terminal_result")) if observation else None
        ),
        "receipt": deepcopy(observation.get("receipt")) if observation else None,
        "runtime_observation": (
            deepcopy(observation.get("runtime_observation")) if observation else None
        ),
        "transport_failure": (
            deepcopy(dict(transport_failure)) if transport_failure else None
        ),
        "provider_free": False,
        "model_calls": model_calls,
        "hosted_calls": 0,
    }


def _invoke_loopback_once(
    request: Any,
    *,
    endpoint: str,
    api_key: str,
    evidence_root: str | os.PathLike[str] | Path,
    response_path: str | os.PathLike[str] | Path,
    observer_id: str,
    authority_binding: Any,
    post_once: Callable[
        [str, bytes, Mapping[str, str], int, int],
        Mapping[str, Any],
    ]
    | None = None,
    request_validator: Callable[[Any], Mapping[str, Any]],
    authority_binding_fields: frozenset[str],
    response_observer: Callable[..., Mapping[str, Any]],
) -> dict[str, Any]:
    """Perform one exact structural POST and persist its body create-only.

    The caller remains responsible for obtaining and validating live campaign
    authority.  ``authority_binding`` only prevents a passing external gate
    from being cross-wired to another request.
    """

    request_value = request if isinstance(request, Mapping) else {}
    request_sha = request_value.get("request_sha256")
    validation = request_validator(request)
    if not validation["valid"]:
        return _invocation_report(
            status="FAIL",
            issues=list(validation["issues"]),
            request_sha256=request_sha,
            attempted_requests=0,
        )
    try:
        normalized_endpoint = validate_loopback_responses_endpoint(endpoint)
    except LiveZeroToolError as exc:
        return _invocation_report(
            status="FAIL",
            issues=[str(exc)],
            request_sha256=request_sha,
            attempted_requests=0,
        )
    if (
        not isinstance(api_key, str)
        or not api_key
        or len(api_key.encode("utf-8")) > 4_096
        or any(character in api_key for character in ("\x00", "\r", "\n"))
    ):
        return _invocation_report(
            status="FAIL",
            issues=["credential:dedicated_key_invalid"],
            request_sha256=request_sha,
            attempted_requests=0,
        )
    binding = _exact(
        authority_binding,
        authority_binding_fields,
        "authority:binding",
        binding_issues := [],
    )
    expected_binding = {
        key: request_value["bindings"][key] for key in authority_binding_fields
    }
    if binding_issues or dict(binding) != expected_binding:
        return _invocation_report(
            status="FAIL",
            issues=["authority:binding_mismatch"],
            request_sha256=request_sha,
            attempted_requests=0,
        )

    try:
        bound_root = _evidence_root(evidence_root)
    except LiveZeroToolError as exc:
        return _invocation_report(
            status="FAIL",
            issues=[str(exc)],
            request_sha256=request_sha,
            attempted_requests=0,
        )
    if evidence_scope_sha256(bound_root) != request_value["bindings"].get(
        "evidence_scope_sha256"
    ):
        return _invocation_report(
            status="FAIL",
            issues=["response_sink:evidence_root_mismatch"],
            request_sha256=request_sha,
            attempted_requests=0,
        )

    sink = Path(response_path)
    try:
        if not sink.is_absolute():
            raise LiveZeroToolError("response_sink:absolute_required")
        if sink.exists() or sink.is_symlink():
            raise LiveZeroToolError("response_sink:already_exists")
        if sink.parent.is_symlink():
            raise LiveZeroToolError("response_sink:parent_invalid")
        parent = sink.parent.resolve(strict=True)
        if not parent.is_dir() or parent.is_symlink():
            raise LiveZeroToolError("response_sink:parent_invalid")
        try:
            inside = os.path.commonpath((str(bound_root), str(parent))) == str(
                bound_root
            )
        except ValueError:
            inside = False
        if not inside:
            raise LiveZeroToolError("response_sink:outside_evidence_root")
    except FileNotFoundError:
        return _invocation_report(
            status="FAIL",
            issues=["response_sink:parent_invalid"],
            request_sha256=request_sha,
            attempted_requests=0,
        )
    except LiveZeroToolError as exc:
        return _invocation_report(
            status="FAIL",
            issues=[str(exc)],
            request_sha256=request_sha,
            attempted_requests=0,
        )

    sender = post_once or _http_post_once
    body = _canonical_bytes(request_value["body"])
    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    limits = request_value["limits"]
    try:
        transport_result = sender(
            normalized_endpoint,
            body,
            headers,
            limits["timeout_ms"],
            limits["max_response_bytes"],
        )
    except LiveZeroToolError as exc:
        return _invocation_report(
            status="FAIL",
            issues=[_safe_reason(exc, "transport:refused")],
            request_sha256=request_sha,
            attempted_requests=1,
        )
    except Exception as exc:  # defensive boundary; never reflect a secret-bearing message
        return _invocation_report(
            status="FAIL",
            issues=["transport:unexpected_" + type(exc).__name__],
            request_sha256=request_sha,
            attempted_requests=1,
        )
    if not isinstance(transport_result, Mapping):
        return _invocation_report(
            status="FAIL",
            issues=["transport:response_record_invalid"],
            request_sha256=request_sha,
            attempted_requests=1,
        )
    http_status = transport_result.get("http_status")
    content_type = transport_result.get("content_type")
    elapsed_ms = transport_result.get("elapsed_ms")
    raw = transport_result.get("body")
    if (
        type(http_status) is not int
        or not 100 <= http_status <= 599
        or not isinstance(content_type, str)
        or content_type not in _PUBLIC_MEDIA_TYPES | {"other", "unknown"}
        or type(elapsed_ms) is not int
        or elapsed_ms < 0
    ):
        return _invocation_report(
            status="FAIL",
            issues=["transport:response_record_invalid"],
            request_sha256=request_sha,
            attempted_requests=1,
        )
    if not isinstance(raw, (bytes, bytearray)):
        return _invocation_report(
            status="FAIL",
            issues=["transport:response_bytes_required"],
            request_sha256=request_sha,
            attempted_requests=1,
        )
    raw_bytes = bytes(raw)
    if len(raw_bytes) > limits["max_response_bytes"]:
        return _invocation_report(
            status="FAIL",
            issues=["transport:response_too_large"],
            request_sha256=request_sha,
            attempted_requests=1,
        )
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(sink, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(raw_bytes)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                sink.unlink()
            except OSError:
                pass
            raise
    except FileExistsError:
        return _invocation_report(
            status="FAIL",
            issues=["response_sink:already_exists_after_request"],
            request_sha256=request_sha,
            attempted_requests=1,
        )
    except OSError:
        return _invocation_report(
            status="FAIL",
            issues=["response_sink:write_failed"],
            request_sha256=request_sha,
            attempted_requests=1,
        )

    response_sha = _bytes_sha256(raw_bytes)
    if http_status != 200:
        failure = {
            "schema": TRANSPORT_FAILURE_SCHEMA,
            "http_status": http_status,
            "http_status_class": f"{http_status // 100}xx",
            "category": _http_failure_category(http_status),
            "content_type": content_type,
            "elapsed_ms": elapsed_ms,
            "response_bytes": len(raw_bytes),
            "response_sha256": response_sha,
        }
        return _invocation_report(
            status="FAIL",
            issues=["transport:http_status_non_200"],
            request_sha256=request_sha,
            attempted_requests=1,
            response_sha256=response_sha,
            transport_failure=failure,
        )
    observation = response_observer(
        request_value,
        raw_bytes,
        observer_id=observer_id,
        expected_response_sha256=response_sha,
    )
    return _invocation_report(
        status=observation["status"],
        issues=list(observation["issues"]),
        request_sha256=request_sha,
        attempted_requests=1,
        response_sha256=response_sha,
        observation=observation,
    )


def invoke_loopback_once(
    request: Any,
    *,
    endpoint: str,
    api_key: str,
    evidence_root: str | os.PathLike[str] | Path,
    response_path: str | os.PathLike[str] | Path,
    observer_id: str,
    authority_binding: Any,
    post_once: Callable[
        [str, bytes, Mapping[str, str], int, int],
        Mapping[str, Any],
    ]
    | None = None,
) -> dict[str, Any]:
    """Invoke one live-sweep request without retry, fallback, or replacement."""

    return _invoke_loopback_once(
        request,
        endpoint=endpoint,
        api_key=api_key,
        evidence_root=evidence_root,
        response_path=response_path,
        observer_id=observer_id,
        authority_binding=authority_binding,
        post_once=post_once,
        request_validator=validate_live_zero_tool_request,
        authority_binding_fields=_AUTHORITY_BINDING_FIELDS,
        response_observer=observe_live_zero_tool_response,
    )


def invoke_route_preflight_loopback_once(
    request: Any,
    *,
    endpoint: str,
    api_key: str,
    evidence_root: str | os.PathLike[str] | Path,
    response_path: str | os.PathLike[str] | Path,
    observer_id: str,
    authority_binding: Any,
    post_once: Callable[
        [str, bytes, Mapping[str, str], int, int],
        Mapping[str, Any],
    ]
    | None = None,
) -> dict[str, Any]:
    """Invoke one observer-bound route canary through the zero-tool adapter."""

    return _invoke_loopback_once(
        request,
        endpoint=endpoint,
        api_key=api_key,
        evidence_root=evidence_root,
        response_path=response_path,
        observer_id=observer_id,
        authority_binding=authority_binding,
        post_once=post_once,
        request_validator=validate_route_preflight_zero_tool_request,
        authority_binding_fields=_ROUTE_PREFLIGHT_AUTHORITY_BINDING_FIELDS,
        response_observer=observe_route_preflight_zero_tool_response,
    )


__all__ = [
    "REQUEST_SCHEMA",
    "REQUEST_SCHEMA_V1",
    "REQUEST_SCHEMA_V2",
    "ROUTE_PREFLIGHT_REQUEST_SCHEMA",
    "REQUEST_VALIDATION_SCHEMA",
    "ROUTE_PREFLIGHT_REQUEST_VALIDATION_SCHEMA",
    "RECEIPT_SCHEMA",
    "ROUTE_PREFLIGHT_RECEIPT_SCHEMA",
    "OBSERVATION_REPORT_SCHEMA",
    "ROUTE_PREFLIGHT_OBSERVATION_REPORT_SCHEMA",
    "INVOCATION_REPORT_SCHEMA",
    "TRANSPORT_FAILURE_SCHEMA",
    "TRANSPORT",
    "REQUEST_MODEL",
    "RESPONSE_WIRE_MODEL",
    "response_wire_model",
    "REQUIRED_MODEL",
    "REQUIRED_EFFORT",
    "REQUIRED_CONTEXT_POLICY",
    "RESPONSES_PATH",
    "HIDDEN_REASONING_ENVELOPE_PREFIX",
    "MAX_OUTPUT_TOKENS",
    "MAX_TOTAL_TOKENS",
    "MAX_RESPONSE_BYTES",
    "MAX_TIMEOUT_MS",
    "ROUTE_PREFLIGHT_TOOL_CALL_BUDGET",
    "LiveZeroToolError",
    "evidence_scope_sha256",
    "build_live_zero_tool_request",
    "build_route_preflight_task_spec",
    "build_route_preflight_zero_tool_request",
    "validate_live_zero_tool_request",
    "validate_route_preflight_zero_tool_request",
    "observe_live_zero_tool_response",
    "observe_route_preflight_zero_tool_response",
    "validate_loopback_responses_endpoint",
    "invoke_loopback_once",
    "invoke_route_preflight_loopback_once",
]
