#!/usr/bin/env python3
"""Fail-closed OpenCodex credential admission for frontier qualification.

Management authority and proxy admission are deliberately separate.  The
owner-local admin token may create, delete, and census exactly one ephemeral
data-plane key; the ephemeral key may run only the fixed invalid-JSON admission
probe.  Raw credentials and response bodies stay process-local.  The returned
record contains bounded statuses and digests only and never grants campaign
authority or dispatches a provider request.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping, Optional


LIFECYCLE_DRAFT_SCHEMA = "orch-dork/frontier-credential-lifecycle-draft/v1"
LIFECYCLE_SCHEMA = "orch-dork/frontier-credential-lifecycle/v1"
LIFECYCLE_VALIDATION_SCHEMA = (
    "orch-dork/frontier-credential-lifecycle-validation/v1"
)
ISSUE152_CREATE_RESPONSE_SHA256 = (
    "9d55a7be531d13a42ff1f94fe5e1411bc103821582f02a065c63fd6fe42fce31"
)

_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "key_name",
        "purpose",
        "endpoint",
        "runtime_identity_sha256",
        "timeout_ms",
        "lifecycle_timeout_ms",
        "max_response_bytes",
    }
)
_ENDPOINT_FIELDS = frozenset({"scheme", "host", "port"})
_PURPOSES = frozenset(
    {"frontier-credential-qualification", "frontier-campaign-session"}
)
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:+-]{0,79}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_ADMIN_TOKEN = re.compile(r"\Aocx_admin_[A-Za-z0-9_-]{43}\Z")
_DATA_KEY = re.compile(r"\Aocx_data_[0-9a-f]{40}\Z")
_KEY_ID = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)
_PROJECTED_ADMIN_TOKEN = re.compile(r"ocx_admin_[A-Za-z0-9_-]{43}")
_PROJECTED_DATA_KEY = re.compile(r"ocx_data_[0-9a-f]{40}")
_PROJECTED_KEY_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_FIXED_PROBE_BODY = b"{"
_Transport = Callable[
    [str, str, Optional[bytes], Mapping[str, str], int, int], Mapping[str, Any]
]


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


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_json(data: bytes) -> Any:
    if data.startswith(b"\xef\xbb\xbf") or b"\x00" in data:
        raise ValueError("json:encoding_invalid")
    text = data.decode("utf-8")
    decoder = json.JSONDecoder()
    value, end = decoder.raw_decode(text)
    if text[end:].strip():
        raise ValueError("json:trailing_data")
    return value


def _validate_draft(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(value, Mapping) or set(value) != _DRAFT_FIELDS:
        return None, ["draft:contract_invalid"]
    draft = deepcopy(dict(value))
    issues: list[str] = []
    if draft.get("schema") != LIFECYCLE_DRAFT_SCHEMA:
        issues.append("draft:schema_invalid")
    for field in ("campaign_id", "key_name"):
        if not isinstance(draft.get(field), str) or not _IDENTIFIER.fullmatch(
            draft[field]
        ):
            issues.append("draft:" + field + "_invalid")
    if draft.get("purpose") not in _PURPOSES:
        issues.append("draft:purpose_invalid")
    endpoint = draft.get("endpoint")
    if (
        not isinstance(endpoint, Mapping)
        or set(endpoint) != _ENDPOINT_FIELDS
        or endpoint.get("scheme") != "http"
        or endpoint.get("host") != "127.0.0.1"
        or endpoint.get("port") != 10100
    ):
        issues.append("draft:endpoint_invalid")
    if not isinstance(draft.get("runtime_identity_sha256"), str) or not _SHA256.fullmatch(
        draft["runtime_identity_sha256"]
    ):
        issues.append("draft:runtime_identity_invalid")
    if (
        type(draft.get("timeout_ms")) is not int
        or not 1_000 <= draft["timeout_ms"] <= 10_000
    ):
        issues.append("draft:timeout_invalid")
    if (
        type(draft.get("lifecycle_timeout_ms")) is not int
        or not 10_000 <= draft["lifecycle_timeout_ms"] <= 60_000
        or (
            type(draft.get("timeout_ms")) is int
            and 4 * draft["timeout_ms"] > draft["lifecycle_timeout_ms"]
        )
    ):
        issues.append("draft:lifecycle_timeout_invalid")
    if (
        type(draft.get("max_response_bytes")) is not int
        or not 1_024 <= draft["max_response_bytes"] <= 65_536
    ):
        issues.append("draft:response_budget_invalid")
    return (draft if not issues else None), sorted(set(issues))


def _response(
    value: Any, *, max_response_bytes: int
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(value, Mapping) or set(value) != {
        "status",
        "content_type",
        "elapsed_ms",
        "body",
    }:
        return None, "response:contract_invalid"
    status_code = value.get("status")
    elapsed_ms = value.get("elapsed_ms")
    body = value.get("body")
    content_type = value.get("content_type")
    if type(status_code) is not int or not 100 <= status_code <= 599:
        return None, "response:status_invalid"
    if type(elapsed_ms) is not int or elapsed_ms < 0:
        return None, "response:elapsed_invalid"
    if not isinstance(body, (bytes, bytearray)) or len(body) > max_response_bytes:
        return None, "response:body_invalid"
    if (
        not isinstance(content_type, str)
        or content_type.split(";", 1)[0].strip().lower() != "application/json"
    ):
        return None, "response:content_type_invalid"
    data = bytes(body)
    try:
        parsed = _strict_json(data)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        parsed = None
    return {
        "status": status_code,
        "elapsed_ms": elapsed_ms,
        "body": data,
        "body_sha256": _bytes_sha256(data),
        "parsed": parsed,
    }, None


def _base_state(draft: Mapping[str, Any] | None) -> dict[str, Any]:
    return {
        "issues": [],
        "campaign_id": draft.get("campaign_id") if draft else None,
        "purpose": draft.get("purpose") if draft else None,
        "endpoint": deepcopy(draft.get("endpoint")) if draft else None,
        "runtime_identity_sha256": (
            draft.get("runtime_identity_sha256") if draft else None
        ),
        "lifecycle_timeout_ms": draft.get("lifecycle_timeout_ms") if draft else None,
        "create_http_status": None,
        "create_response_sha256": None,
        "admission_probe_http_status": None,
        "admission_probe_response_sha256": None,
        "delete_http_status": None,
        "delete_response_sha256": None,
        "census_http_status": None,
        "census_response_sha256": None,
        "key_id_sha256": None,
        "key_sha256": None,
        "provider_dispatch_status": "NOT_ATTEMPTED",
        "cleanup_status": "NOT_STARTED",
        "credential_creations": 0,
        "credential_deletions": 0,
        "cleanup_observations": 0,
        "admission_requests": 0,
        "network_calls": 0,
        "elapsed_ms": 0,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _finish(state: Mapping[str, Any], *, refused: bool = False) -> dict[str, Any]:
    mutable = dict(state)
    issues = [str(issue) for issue in state["issues"]]
    timeout = state.get("lifecycle_timeout_ms")
    if type(timeout) is int and state["elapsed_ms"] > timeout:
        issues.append("lifecycle:deadline_exceeded")
        if mutable.get("cleanup_status") == "COMPLETE":
            mutable["cleanup_status"] = "UNKNOWN"
    issues = sorted(set(issues))
    core = {
        "schema": LIFECYCLE_SCHEMA,
        "status": "REFUSED" if refused else "PASS" if not issues else "FAIL",
        "issues": issues,
        "campaign_id": mutable["campaign_id"],
        "purpose": mutable["purpose"],
        "endpoint": deepcopy(mutable["endpoint"]),
        "runtime_identity_sha256": mutable["runtime_identity_sha256"],
        "lifecycle_timeout_ms": mutable["lifecycle_timeout_ms"],
        "issue152_create_response_sha256": ISSUE152_CREATE_RESPONSE_SHA256,
        "create_http_status": mutable["create_http_status"],
        "create_response_sha256": mutable["create_response_sha256"],
        "admission_probe_http_status": mutable["admission_probe_http_status"],
        "admission_probe_response_sha256": mutable[
            "admission_probe_response_sha256"
        ],
        "delete_http_status": mutable["delete_http_status"],
        "delete_response_sha256": mutable["delete_response_sha256"],
        "census_http_status": mutable["census_http_status"],
        "census_response_sha256": mutable["census_response_sha256"],
        "key_id_sha256": mutable["key_id_sha256"],
        "key_sha256": mutable["key_sha256"],
        "provider_dispatch_status": mutable["provider_dispatch_status"],
        "cleanup_status": mutable["cleanup_status"],
        "credential_creations": mutable["credential_creations"],
        "credential_deletions": mutable["credential_deletions"],
        "cleanup_observations": mutable["cleanup_observations"],
        "admission_requests": mutable["admission_requests"],
        "network_calls": mutable["network_calls"],
        "elapsed_ms": mutable["elapsed_ms"],
        "provider_free": True,
        "model_calls": mutable["model_calls"],
        "hosted_calls": mutable["hosted_calls"],
        "retries": 0,
        "fallbacks": 0,
        "repairs": 0,
        "replacements": 0,
    }
    return {**core, "lifecycle_sha256": _sha256(core)}


def load_owner_management_token(path_value: str | os.PathLike[str]) -> str:
    """Load one owner-only OpenCodex admin token without projecting its path."""

    descriptor: int | None = None
    try:
        path = Path(path_value)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("management_token:path_invalid")
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise ValueError("management_token:path_invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= 512:
            raise ValueError("management_token:path_invalid")
        if info.st_uid != os.getuid():
            raise ValueError("management_token:owner_invalid")
        mode = stat.S_IMODE(info.st_mode)
        if mode not in {0o400, 0o600}:
            raise ValueError("management_token:mode_invalid")
        data = os.read(descriptor, 513)
        if len(data) > 512 or os.read(descriptor, 1):
            raise ValueError("management_token:path_invalid")
        token = data.decode("utf-8").strip()
    except ValueError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ValueError("management_token:unavailable") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if not _ADMIN_TOKEN.fullmatch(token):
        raise ValueError("management_token:shape_invalid")
    return token


def _call(
    state: dict[str, Any],
    transport: _Transport,
    draft: Mapping[str, Any],
    method: str,
    path: str,
    body: bytes | None,
    headers: Mapping[str, str],
    stage: str,
) -> dict[str, Any] | None:
    state["network_calls"] += 1
    try:
        raw = transport(
            method,
            path,
            body,
            headers,
            draft["timeout_ms"],
            draft["max_response_bytes"],
        )
    except Exception:
        state["issues"].append(stage + ":transport_failure")
        return None
    response, issue = _response(
        raw, max_response_bytes=draft["max_response_bytes"]
    )
    if issue:
        state["issues"].append(stage + ":" + issue)
        return None
    state["elapsed_ms"] += response["elapsed_ms"]
    return response


def _cleanup(
    state: dict[str, Any],
    draft: Mapping[str, Any],
    transport: _Transport,
    admin_headers: Mapping[str, str],
    key_id: str,
) -> None:
    delete = _call(
        state,
        transport,
        draft,
        "DELETE",
        "/api/keys",
        _canonical_bytes({"id": key_id}),
        admin_headers,
        "credential:delete",
    )
    if delete is not None:
        state["delete_http_status"] = delete["status"]
        state["delete_response_sha256"] = delete["body_sha256"]
        if delete["status"] == 200 and delete["parsed"] == {"success": True}:
            state["credential_deletions"] = 1
        else:
            state["issues"].append("credential:delete_failed")

    census = _call(
        state,
        transport,
        draft,
        "GET",
        "/api/keys",
        None,
        admin_headers,
        "credential:census",
    )
    if census is None:
        state["cleanup_status"] = "UNKNOWN"
        return
    state["cleanup_observations"] = 1
    state["census_http_status"] = census["status"]
    state["census_response_sha256"] = census["body_sha256"]
    parsed = census["parsed"]
    keys = parsed.get("keys") if isinstance(parsed, Mapping) else None
    if census["status"] != 200 or not isinstance(keys, list):
        state["issues"].append("credential:census_failed")
        state["cleanup_status"] = "UNKNOWN"
        return
    present = any(
        isinstance(item, Mapping) and item.get("id") == key_id for item in keys
    )
    if present:
        state["issues"].append("credential:census_present")
        state["cleanup_status"] = "UNKNOWN"
        return
    state["cleanup_status"] = "COMPLETE"


def run_credential_lifecycle(
    draft_value: Any,
    *,
    management_token_loader: Callable[[], str],
    transport: _Transport,
) -> dict[str, Any]:
    """Create, admission-probe, delete, and census one ephemeral key once."""

    draft, draft_issues = _validate_draft(draft_value)
    state = _base_state(draft if draft is not None else None)
    if draft is None:
        state["issues"].extend(draft_issues)
        return _finish(state, refused=True)

    try:
        management_token = management_token_loader()
    except Exception:
        state["issues"].append("management_authority:unavailable")
        return _finish(state)
    if not isinstance(management_token, str) or not _ADMIN_TOKEN.fullmatch(
        management_token
    ):
        state["issues"].append("management_authority:invalid")
        return _finish(state)

    admin_headers = {
        "Content-Type": "application/json",
        "X-OpenCodex-API-Key": management_token,
    }
    create = _call(
        state,
        transport,
        draft,
        "POST",
        "/api/keys",
        _canonical_bytes({"name": draft["key_name"]}),
        admin_headers,
        "credential:create",
    )
    management_token = None
    if create is None:
        state["cleanup_status"] = "UNKNOWN"
        return _finish(state)
    state["create_http_status"] = create["status"]
    state["create_response_sha256"] = create["body_sha256"]
    if create["status"] in {400, 401, 403, 404, 409, 422}:
        state["issues"].append("credential:create_refused")
        state["cleanup_status"] = "NOT_CREATED"
        return _finish(state)
    if create["status"] != 201:
        state["issues"].append("credential:create_failed")
        state["cleanup_status"] = "UNKNOWN"
        return _finish(state)

    parsed = create["parsed"]
    key_id = parsed.get("id") if isinstance(parsed, Mapping) else None
    ephemeral_key = parsed.get("key") if isinstance(parsed, Mapping) else None
    create_valid = (
        isinstance(parsed, Mapping)
        and set(parsed) == {"id", "name", "key", "createdAt"}
        and isinstance(key_id, str)
        and _KEY_ID.fullmatch(key_id) is not None
        and parsed.get("name") == draft["key_name"]
        and isinstance(ephemeral_key, str)
        and _DATA_KEY.fullmatch(ephemeral_key) is not None
        and isinstance(parsed.get("createdAt"), str)
        and 1 <= len(parsed["createdAt"]) <= 64
    )
    if isinstance(key_id, str) and _KEY_ID.fullmatch(key_id):
        state["key_id_sha256"] = _sha256(key_id)
    if isinstance(ephemeral_key, str) and _DATA_KEY.fullmatch(ephemeral_key):
        state["key_sha256"] = _sha256(ephemeral_key)
    if not create_valid:
        state["issues"].append("credential:create_response_invalid")
        if isinstance(key_id, str) and _KEY_ID.fullmatch(key_id):
            _cleanup(state, draft, transport, admin_headers, key_id)
        else:
            state["cleanup_status"] = "UNKNOWN"
        ephemeral_key = None
        return _finish(state)
    state["credential_creations"] = 1

    probe_headers = {
        "Content-Type": "application/json",
        "X-OpenCodex-API-Key": ephemeral_key,
    }
    state["admission_requests"] = 1
    probe = _call(
        state,
        transport,
        draft,
        "POST",
        "/v1/responses",
        _FIXED_PROBE_BODY,
        probe_headers,
        "admission",
    )
    if probe is None:
        state["provider_dispatch_status"] = "UNKNOWN"
        state["model_calls"] = None
        state["hosted_calls"] = None
    else:
        state["admission_probe_http_status"] = probe["status"]
        state["admission_probe_response_sha256"] = probe["body_sha256"]
        parsed_probe = probe["parsed"]
        error = parsed_probe.get("error") if isinstance(parsed_probe, Mapping) else None
        expected_refusal = (
            probe["status"] == 400
            and isinstance(error, Mapping)
            and error.get("type") == "invalid_request_error"
            and error.get("message") == "Invalid JSON body"
        )
        if expected_refusal:
            state["provider_dispatch_status"] = "REFUSED_BEFORE_PROVIDER"
        elif probe["status"] in {401, 403}:
            state["provider_dispatch_status"] = "REFUSED_AT_ADMISSION"
            state["issues"].append("admission:credential_refused")
        else:
            state["provider_dispatch_status"] = "UNKNOWN"
            state["model_calls"] = None
            state["hosted_calls"] = None
            state["issues"].append("admission:provider_boundary_unknown")

    ephemeral_key = None
    _cleanup(state, draft, transport, admin_headers, key_id)
    return _finish(state)


class LoopbackCredentialTransport:
    """Exact-loopback HTTP adapter; it has no proxy, redirect, or retry path."""

    _ALLOWED = frozenset(
        {
            ("POST", "/api/keys"),
            ("DELETE", "/api/keys"),
            ("GET", "/api/keys"),
            ("POST", "/v1/responses"),
        }
    )

    def __init__(self, *, host: str, port: int) -> None:
        if host != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65_535:
            raise ValueError("transport:endpoint_invalid")
        self.host = host
        self.port = port

    def __call__(
        self,
        method: str,
        path: str,
        body: bytes | None,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> dict[str, Any]:
        if (method, path) not in self._ALLOWED:
            raise ValueError("transport:request_disallowed")
        if body is not None and not isinstance(body, bytes):
            raise ValueError("transport:body_invalid")
        started = __import__("time").monotonic()
        connection = http.client.HTTPConnection(
            self.host, self.port, timeout=timeout_ms / 1_000
        )
        try:
            connection.request(method, path, body=body, headers=dict(headers))
            response = connection.getresponse()
            data = response.read(max_response_bytes + 1)
            if len(data) > max_response_bytes:
                raise ValueError("transport:response_too_large")
            return {
                "status": response.status,
                "content_type": response.getheader("Content-Type") or "",
                "elapsed_ms": int(
                    (__import__("time").monotonic() - started) * 1_000
                ),
                "body": data,
            }
        finally:
            connection.close()


def run_live_loopback_credential_lifecycle(
    draft: Any,
    *,
    management_token_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Run the closed lifecycle against one exact local OpenCodex listener."""

    validated, _issues = _validate_draft(draft)
    if validated is None:
        return run_credential_lifecycle(
            draft,
            management_token_loader=lambda: "",
            transport=lambda *_args: {},
        )
    endpoint = validated["endpoint"]
    return run_credential_lifecycle(
        draft,
        management_token_loader=lambda: load_owner_management_token(
            management_token_path
        ),
        transport=LoopbackCredentialTransport(
            host=endpoint["host"], port=endpoint["port"]
        ),
    )


_LIFECYCLE_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "campaign_id",
        "purpose",
        "endpoint",
        "runtime_identity_sha256",
        "lifecycle_timeout_ms",
        "issue152_create_response_sha256",
        "create_http_status",
        "create_response_sha256",
        "admission_probe_http_status",
        "admission_probe_response_sha256",
        "delete_http_status",
        "delete_response_sha256",
        "census_http_status",
        "census_response_sha256",
        "key_id_sha256",
        "key_sha256",
        "provider_dispatch_status",
        "cleanup_status",
        "credential_creations",
        "credential_deletions",
        "cleanup_observations",
        "admission_requests",
        "network_calls",
        "elapsed_ms",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "retries",
        "fallbacks",
        "repairs",
        "replacements",
        "lifecycle_sha256",
    }
)


def validate_credential_lifecycle_report(value: Any) -> dict[str, Any]:
    """Validate a lifecycle receipt without trusting its disposition or seal."""

    issues: list[str] = []
    if not isinstance(value, Mapping) or set(value) != _LIFECYCLE_FIELDS:
        issues.append("report:contract_invalid")
        record: Mapping[str, Any] = value if isinstance(value, Mapping) else {}
    else:
        record = value
    if record.get("schema") != LIFECYCLE_SCHEMA:
        issues.append("report:schema_invalid")
    raw_issues = record.get("issues")
    if (
        not isinstance(raw_issues, list)
        or raw_issues != sorted(set(raw_issues))
        or any(not isinstance(item, str) or not item for item in raw_issues)
    ):
        issues.append("report:issues_invalid")
        raw_issues = []
    status_value = record.get("status")
    if status_value == "PASS":
        if raw_issues:
            issues.append("report:disposition_invalid")
    elif status_value in {"FAIL", "REFUSED"}:
        if not raw_issues:
            issues.append("report:disposition_invalid")
    else:
        issues.append("report:disposition_invalid")
    if record.get("issue152_create_response_sha256") != ISSUE152_CREATE_RESPONSE_SHA256:
        issues.append("report:issue152_binding_invalid")
    if record.get("provider_free") is not True:
        issues.append("report:provider_boundary_invalid")
    for field in (
        "credential_creations",
        "credential_deletions",
        "cleanup_observations",
        "admission_requests",
        "network_calls",
        "elapsed_ms",
        "retries",
        "fallbacks",
        "repairs",
        "replacements",
    ):
        if type(record.get(field)) is not int or record[field] < 0:
            issues.append("report:" + field + "_invalid")
    for field in (
        "credential_creations",
        "credential_deletions",
        "cleanup_observations",
        "admission_requests",
    ):
        if type(record.get(field)) is int and record[field] > 1:
            issues.append("report:" + field + "_invalid")
    if type(record.get("network_calls")) is int and record["network_calls"] > 4:
        issues.append("report:network_calls_invalid")
    for field in ("retries", "fallbacks", "repairs", "replacements"):
        if record.get(field) != 0:
            issues.append("report:" + field + "_nonzero")
    for field in ("model_calls", "hosted_calls"):
        if record.get(field) is not None and (
            type(record.get(field)) is not int or record[field] < 0
        ):
            issues.append("report:" + field + "_invalid")
    if record.get("provider_dispatch_status") not in {
        "NOT_ATTEMPTED",
        "REFUSED_AT_ADMISSION",
        "REFUSED_BEFORE_PROVIDER",
        "UNKNOWN",
    }:
        issues.append("report:provider_dispatch_status_invalid")
    if record.get("cleanup_status") not in {
        "NOT_STARTED",
        "NOT_CREATED",
        "COMPLETE",
        "UNKNOWN",
    }:
        issues.append("report:cleanup_status_invalid")
    for field in (
        "create_response_sha256",
        "admission_probe_response_sha256",
        "delete_response_sha256",
        "census_response_sha256",
        "key_id_sha256",
        "key_sha256",
    ):
        if record.get(field) is not None and (
            not isinstance(record.get(field), str)
            or not _SHA256.fullmatch(record[field])
        ):
            issues.append("report:" + field + "_invalid")
    for field in (
        "create_http_status",
        "admission_probe_http_status",
        "delete_http_status",
        "census_http_status",
    ):
        if record.get(field) is not None and (
            type(record.get(field)) is not int or not 100 <= record[field] <= 599
        ):
            issues.append("report:" + field + "_invalid")
    serialized = json.dumps(record, sort_keys=True, separators=(",", ":"))
    if (
        _PROJECTED_ADMIN_TOKEN.search(serialized)
        or _PROJECTED_DATA_KEY.search(serialized)
        or _PROJECTED_KEY_ID.search(serialized)
    ):
        issues.append("report:credential_projection")
    if status_value != "REFUSED":
        endpoint = record.get("endpoint")
        timeout = record.get("lifecycle_timeout_ms")
        if (
            not isinstance(record.get("campaign_id"), str)
            or not _IDENTIFIER.fullmatch(record["campaign_id"])
            or record.get("purpose") not in _PURPOSES
            or endpoint
            != {"scheme": "http", "host": "127.0.0.1", "port": 10100}
            or not _SHA256.fullmatch(str(record.get("runtime_identity_sha256", "")))
            or type(timeout) is not int
            or not 10_000 <= timeout <= 60_000
        ):
            issues.append("report:runtime_binding_invalid")
        if (
            type(record.get("elapsed_ms")) is int
            and type(timeout) is int
            and record["elapsed_ms"] > timeout
            and (
                "lifecycle:deadline_exceeded" not in raw_issues
                or record.get("cleanup_status") != "UNKNOWN"
            )
        ):
            issues.append("report:deadline_disposition_invalid")
    elif any(
        record.get(field) != 0
        for field in (
            "credential_creations",
            "credential_deletions",
            "cleanup_observations",
            "admission_requests",
            "network_calls",
        )
    ):
        issues.append("report:refusal_side_effect_invalid")
    if status_value == "PASS":
        timeout = record.get("lifecycle_timeout_ms")
        if (
            type(timeout) is not int
            or record.get("elapsed_ms", timeout + 1) > timeout
        ):
            issues.append("report:runtime_binding_invalid")
        passing = {
            "create_http_status": 201,
            "admission_probe_http_status": 400,
            "delete_http_status": 200,
            "census_http_status": 200,
            "provider_dispatch_status": "REFUSED_BEFORE_PROVIDER",
            "cleanup_status": "COMPLETE",
            "credential_creations": 1,
            "credential_deletions": 1,
            "cleanup_observations": 1,
            "admission_requests": 1,
            "network_calls": 4,
            "model_calls": 0,
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "repairs": 0,
            "replacements": 0,
        }
        if any(record.get(field) != expected for field, expected in passing.items()):
            issues.append("report:passing_contract_invalid")
    supplied = record.get("lifecycle_sha256")
    core = {
        key: deepcopy(item)
        for key, item in record.items()
        if key != "lifecycle_sha256"
    }
    if (
        not isinstance(supplied, str)
        or not _SHA256.fullmatch(supplied)
        or supplied != _sha256(core)
    ):
        issues.append("report:seal_invalid")
    validation_core = {
        "schema": LIFECYCLE_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(set(issues)),
        "lifecycle_status": status_value,
        "lifecycle_sha256": supplied if isinstance(supplied, str) and _SHA256.fullmatch(supplied) else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**validation_core, "report_sha256": _sha256(validation_core)}


__all__ = [
    "LIFECYCLE_DRAFT_SCHEMA",
    "LIFECYCLE_SCHEMA",
    "LIFECYCLE_VALIDATION_SCHEMA",
    "ISSUE152_CREATE_RESPONSE_SHA256",
    "LoopbackCredentialTransport",
    "load_owner_management_token",
    "run_credential_lifecycle",
    "run_live_loopback_credential_lifecycle",
    "validate_credential_lifecycle_report",
]


if __name__ == "__main__":
    raise SystemExit("Import the credential-admission lifecycle; no CLI is provided.")
