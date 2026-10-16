#!/usr/bin/env python3
"""Installed, provider-free qualification for frontier credential admission.

The qualification binds the complete Orch Dork runtime allowlist and complete
installed OpenCodex package closure, exercises deterministic lifecycle failure
cases, and runs the real OpenCodex management/auth route with synthetic tokens
inside the owned process boundary.  It never reads an owner credential or
contacts a provider.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_frontier_admission as admission  # noqa: E402
import orch_dork_process_containment as containment  # noqa: E402
import orch_dork_runtime_package as runtime_package  # noqa: E402


QUALIFICATION_SCHEMA = "orch-dork/frontier-admission-qualification/v1"
QUALIFICATION_VALIDATION_SCHEMA = (
    "orch-dork/frontier-admission-qualification-validation/v1"
)
RUNTIME_IDENTITY_SCHEMA = "orch-dork/frontier-admission-runtime-identity/v1"
PROBE_INPUT_SCHEMA = "orch-dork/frontier-admission-probe-input/v1"
PROBE_OUTPUT_SCHEMA = "orch-dork/frontier-admission-probe-output/v1"

_ADMIN_TOKEN = "ocx_admin_" + "A" * 43
_OTHER_ADMIN_TOKEN = "ocx_admin_" + "B" * 43
_DATA_KEY = "ocx_data_" + "a" * 40
_KEY_ID = "11111111-1111-4111-8111-111111111111"
_CREATED_AT = "2026-08-29T22:00:00.000Z"
_PROBE_RELATIVE = (
    "skills/orch-dork/scripts/orch_dork_frontier_admission_probe.ts"
)
_EXPECTED_PROBE_CHECKS = {
    "unauthenticated_create_refused": "PASS",
    "data_key_management_refused": "PASS",
    "admin_create": "PASS",
    "invalid_data_key_refused": "PASS",
    "admission_refused_before_provider": "PASS",
    "delete": "PASS",
    "absence_census": "PASS",
}
_EXPECTED_SYNTHETIC_CASES = (
    "bad_auth",
    "census_failure",
    "delete_failure",
    "duplicate",
    "malformed",
    "secret_leak",
    "success",
    "timeout",
)
_QUALIFICATION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "qualified",
        "issues",
        "issue152_create_response_sha256",
        "runtime_identity",
        "checks",
        "provider_free",
        "real_credential_reads",
        "synthetic_lifecycle_cases",
        "synthetic_route_credential_lifecycles",
        "loopback_network_calls",
        "provider_calls",
        "model_calls",
        "hosted_calls",
        "retries",
        "fallbacks",
        "repairs",
        "replacements",
        "qualification_sha256",
    }
)


@dataclass(frozen=True)
class AdmissionRuntime:
    """Exact installed roots whose content forms the qualification identity."""

    plugin_root: Path
    opencodex_root: Path


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
        if resolved != path or not path.is_dir():
            return None
        return path
    except (OSError, TypeError, ValueError):
        return None


def _file_row(root: Path, relative: str) -> dict[str, Any] | None:
    path = root.joinpath(*relative.split("/"))
    try:
        if path.is_symlink() or not path.is_file():
            return None
        resolved = path.resolve(strict=True)
        if os.path.commonpath((str(root), str(resolved))) != str(root):
            return None
        data = path.read_bytes()
    except (OSError, ValueError):
        return None
    return {
        "name": relative,
        "mode": stat.S_IMODE(path.stat().st_mode),
        "bytes": len(data),
        "sha256": _bytes_sha256(data),
    }


def _plugin_closure(root: Path) -> dict[str, Any] | None:
    rows: list[dict[str, Any]] = []
    for relative in runtime_package.RUNTIME_ALLOWLIST:
        row = _file_row(root, relative)
        if row is None:
            if relative in runtime_package.RUNTIME_OPTIONAL_PATHS and not (
                root.joinpath(*relative.split("/")).exists()
            ):
                continue
            return None
        rows.append(row)
    try:
        manifest = json.loads(
            (root / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("name") != "orch-dork"
        or not isinstance(manifest.get("version"), str)
        or not manifest["version"]
    ):
        return None
    core = {"schema": "orch-dork/runtime-allowlist-closure/v1", "files": rows}
    return {
        "name": manifest["name"],
        "version": manifest["version"],
        "file_count": len(rows),
        "bytes": sum(row["bytes"] for row in rows),
        "source_closure_sha256": _sha256(core),
    }


def _package_closure(root: Path) -> dict[str, Any] | None:
    """Hash every installed OpenCodex package node without exposing paths."""

    rows: list[dict[str, Any]] = []
    total_bytes = 0
    try:
        for base, directories, names in os.walk(root, topdown=True, followlinks=False):
            base_path = Path(base)
            directories.sort()
            names.sort()
            retained: list[str] = []
            for name in directories:
                path = base_path / name
                info = path.lstat()
                relative = path.relative_to(root).as_posix()
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(path).encode("utf-8")
                    resolved = path.resolve(strict=True)
                    if os.path.commonpath((str(root), str(resolved))) != str(root):
                        return None
                    rows.append(
                        {
                            "name": relative,
                            "kind": "symlink",
                            "mode": stat.S_IMODE(info.st_mode),
                            "bytes": len(target),
                            "sha256": _bytes_sha256(target),
                        }
                    )
                    total_bytes += len(target)
                elif stat.S_ISDIR(info.st_mode):
                    retained.append(name)
                else:
                    return None
            directories[:] = retained
            for name in names:
                path = base_path / name
                info = path.lstat()
                relative = path.relative_to(root).as_posix()
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(path).encode("utf-8")
                    resolved = path.resolve(strict=True)
                    if os.path.commonpath((str(root), str(resolved))) != str(root):
                        return None
                    rows.append(
                        {
                            "name": relative,
                            "kind": "symlink",
                            "mode": stat.S_IMODE(info.st_mode),
                            "bytes": len(target),
                            "sha256": _bytes_sha256(target),
                        }
                    )
                    total_bytes += len(target)
                elif stat.S_ISREG(info.st_mode):
                    data = path.read_bytes()
                    rows.append(
                        {
                            "name": relative,
                            "kind": "file",
                            "mode": stat.S_IMODE(info.st_mode),
                            "bytes": len(data),
                            "sha256": _bytes_sha256(data),
                        }
                    )
                    total_bytes += len(data)
                else:
                    return None
    except (OSError, UnicodeError, ValueError):
        return None
    rows.sort(key=lambda row: (row["name"], row["kind"]))
    if not rows:
        return None
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(package, Mapping)
        or package.get("name") != "@bitkyc08/opencodex"
        or not isinstance(package.get("version"), str)
        or not package["version"]
        or not (root / "node_modules/bun/bin/bun.exe").is_file()
        or not os.access(root / "node_modules/bun/bin/bun.exe", os.X_OK)
    ):
        return None
    core = {"schema": "orch-dork/opencodex-package-closure/v1", "nodes": rows}
    return {
        "name": package["name"],
        "version": package["version"],
        "file_count": sum(row["kind"] == "file" for row in rows),
        "symlink_count": sum(row["kind"] == "symlink" for row in rows),
        "bytes": total_bytes,
        "source_closure_sha256": _sha256(core),
    }


def _runtime_identity(
    runtime: Any, issues: list[str]
) -> tuple[dict[str, Any] | None, Path | None, Path | None]:
    if not isinstance(runtime, AdmissionRuntime):
        issues.append("runtime:type_invalid")
        return None, None, None
    plugin_root = _safe_root(runtime.plugin_root)
    opencodex_root = _safe_root(runtime.opencodex_root)
    if plugin_root is None:
        issues.append("runtime:plugin_root_invalid")
    if opencodex_root is None:
        issues.append("runtime:opencodex_root_invalid")
    if plugin_root is None or opencodex_root is None:
        return None, plugin_root, opencodex_root
    plugin = _plugin_closure(plugin_root)
    opencodex = _package_closure(opencodex_root)
    if plugin is None:
        issues.append("runtime:plugin_closure_unavailable")
    if opencodex is None:
        issues.append("runtime:opencodex_closure_unavailable")
    if plugin is None or opencodex is None:
        return None, plugin_root, opencodex_root
    core = {
        "schema": RUNTIME_IDENTITY_SCHEMA,
        "plugin": plugin,
        "opencodex": opencodex,
    }
    return (
        {**core, "runtime_identity_sha256": _sha256(core)},
        plugin_root,
        opencodex_root,
    )


class _SyntheticTransport:
    def __init__(self, case: str) -> None:
        self.case = case
        self.calls = 0
        self.key_present = False

    @staticmethod
    def _response(status: int, body: Any) -> dict[str, Any]:
        return {
            "status": status,
            "content_type": "application/json",
            "elapsed_ms": 1,
            "body": _canonical(body),
        }

    def __call__(
        self,
        method: str,
        path: str,
        body: bytes | None,
        headers: Mapping[str, str],
        timeout_ms: int,
        max_response_bytes: int,
    ) -> Mapping[str, Any]:
        del timeout_ms, max_response_bytes
        self.calls += 1
        if self.case == "timeout" and self.calls == 2:
            raise TimeoutError("synthetic")
        if path == "/api/keys":
            if headers.get("X-OpenCodex-API-Key") != _ADMIN_TOKEN:
                return self._response(
                    401, {"error": "opencodex admin token required"}
                )
            if method == "POST":
                if self.case == "duplicate":
                    return self._response(409, {"error": "duplicate"})
                self.key_present = True
                if self.case == "malformed":
                    return self._response(201, {"id": _KEY_ID})
                return self._response(
                    201,
                    {
                        "id": _KEY_ID,
                        "name": "issue153-installed-qualification",
                        "key": _DATA_KEY,
                        "createdAt": _CREATED_AT,
                    },
                )
            if method == "DELETE":
                if self.case == "delete_failure":
                    return self._response(500, {"error": "delete failed"})
                self.key_present = False
                return self._response(200, {"success": True})
            if method == "GET":
                if self.case == "census_failure":
                    return self._response(503, {"error": "census failed"})
                keys = [{"id": _KEY_ID}] if self.key_present else []
                return self._response(200, {"keys": keys})
        if path == "/v1/responses" and method == "POST":
            if headers.get("X-OpenCodex-API-Key") != _DATA_KEY:
                return self._response(401, {"error": "credential refused"})
            if body != b"{":
                raise AssertionError("probe body drift")
            if self.case == "secret_leak":
                return self._response(
                    500, {"admin": _ADMIN_TOKEN, "data": _DATA_KEY, "id": _KEY_ID}
                )
            return self._response(
                400,
                {
                    "error": {
                        "type": "invalid_request_error",
                        "message": "Invalid JSON body",
                    }
                },
            )
        raise AssertionError("synthetic route drift")


def _draft(runtime_identity_sha256: str) -> dict[str, Any]:
    return {
        "schema": admission.LIFECYCLE_DRAFT_SCHEMA,
        "campaign_id": "issue153-installed-qualification",
        "key_name": "issue153-installed-qualification",
        "purpose": "frontier-credential-qualification",
        "endpoint": {"scheme": "http", "host": "127.0.0.1", "port": 10100},
        "runtime_identity_sha256": runtime_identity_sha256,
        "timeout_ms": 10_000,
        "lifecycle_timeout_ms": 60_000,
        "max_response_bytes": 65_536,
    }


def _synthetic_case(case: str, runtime_sha256: str) -> dict[str, Any]:
    transport = _SyntheticTransport(case)
    token = _OTHER_ADMIN_TOKEN if case == "bad_auth" else _ADMIN_TOKEN
    report = admission.run_credential_lifecycle(
        _draft(runtime_sha256),
        management_token_loader=lambda: token,
        transport=transport,
    )
    validation = admission.validate_credential_lifecycle_report(report)
    expected: dict[str, tuple[Any, ...]] = {
        "success": ("PASS", (), "COMPLETE", 4, 0),
        "bad_auth": ("FAIL", ("credential:create_refused",), "NOT_CREATED", 1, 0),
        "malformed": (
            "FAIL",
            ("credential:create_response_invalid",),
            "COMPLETE",
            3,
            0,
        ),
        "duplicate": ("FAIL", ("credential:create_refused",), "NOT_CREATED", 1, 0),
        "timeout": (
            "FAIL",
            ("admission:transport_failure",),
            "COMPLETE",
            4,
            None,
        ),
        "delete_failure": (
            "FAIL",
            ("credential:census_present", "credential:delete_failed"),
            "UNKNOWN",
            4,
            0,
        ),
        "census_failure": (
            "FAIL",
            ("credential:census_failed",),
            "UNKNOWN",
            4,
            0,
        ),
        "secret_leak": (
            "FAIL",
            ("admission:provider_boundary_unknown",),
            "COMPLETE",
            4,
            None,
        ),
    }
    disposition, case_issues, cleanup, calls, model_calls = expected[case]
    serialized = json.dumps(report, sort_keys=True, separators=(",", ":"))
    accepted = (
        validation.get("status") == "PASS"
        and report.get("status") == disposition
        and tuple(report.get("issues", [])) == case_issues
        and report.get("cleanup_status") == cleanup
        and transport.calls == calls
        and report.get("model_calls") == model_calls
        and report.get("retries") == 0
        and report.get("fallbacks") == 0
        and report.get("repairs") == 0
        and report.get("replacements") == 0
        and _ADMIN_TOKEN not in serialized
        and _DATA_KEY not in serialized
        and _KEY_ID not in serialized
    )
    return {
        "status": "PASS" if accepted else "FAIL",
        "lifecycle_status": report.get("status"),
        "lifecycle_sha256": report.get("lifecycle_sha256"),
    }


def _report(
    *,
    issues: list[str],
    runtime_identity: Mapping[str, Any] | None,
    checks: Mapping[str, Any],
    probe: Mapping[str, Any] | None,
) -> dict[str, Any]:
    probe_valid = isinstance(probe, Mapping)
    synthetic_cases = checks.get("synthetic_cases")
    core = {
        "schema": QUALIFICATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "qualified": not issues,
        "issues": sorted(set(issues)),
        "issue152_create_response_sha256": admission.ISSUE152_CREATE_RESPONSE_SHA256,
        "runtime_identity": deepcopy(dict(runtime_identity)) if runtime_identity else None,
        "checks": deepcopy(dict(checks)),
        "provider_free": True,
        "real_credential_reads": 0,
        "synthetic_lifecycle_cases": (
            len(synthetic_cases) if isinstance(synthetic_cases, Mapping) else 0
        ),
        "synthetic_route_credential_lifecycles": 1 if probe_valid else 0,
        "loopback_network_calls": probe.get("loopback_network_calls") if probe_valid else None,
        "provider_calls": probe.get("provider_calls") if probe_valid else None,
        "model_calls": probe.get("model_calls") if probe_valid else None,
        "hosted_calls": probe.get("hosted_calls") if probe_valid else None,
        "retries": 0,
        "fallbacks": 0,
        "repairs": 0,
        "replacements": 0,
    }
    return {**core, "qualification_sha256": _sha256(core)}


def qualify_installed_credential_admission(
    runtime: Any,
    *,
    runner: Callable[..., Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Qualify one exact installed generation without reading real credentials."""

    issues: list[str] = []
    identity, plugin_root, opencodex_root = _runtime_identity(runtime, issues)
    checks: dict[str, Any] = {
        "synthetic_cases": {},
        "probe": {"status": "NOT_RUN", "reason": None, "cleanup_status": None, "probe_sha256": None},
    }
    if identity is None or plugin_root is None or opencodex_root is None:
        return _report(
            issues=issues,
            runtime_identity=identity,
            checks=checks,
            probe=None,
        )

    runtime_sha = identity["runtime_identity_sha256"]
    cases = {
        case: _synthetic_case(case, runtime_sha) for case in _EXPECTED_SYNTHETIC_CASES
    }
    checks["synthetic_cases"] = cases
    if any(case["status"] != "PASS" for case in cases.values()):
        issues.append("synthetic:case_mismatch")

    selected_runner = runner or containment.run_contained
    process = selected_runner(
        [
            str(opencodex_root / "node_modules/bun/bin/bun.exe"),
            str(plugin_root / _PROBE_RELATIVE),
        ],
        input_bytes=_canonical(
            {"schema": PROBE_INPUT_SCHEMA, "opencodex_root": str(opencodex_root)}
        ),
        expect_json=True,
        case_id="issue153-frontier-admission",
        surface="frontier-admission-probe",
    )
    process_status = process.get("status") if isinstance(process, Mapping) else None
    process_reason = process.get("reason") if isinstance(process, Mapping) else None
    cleanup_status = process.get("cleanup_status") if isinstance(process, Mapping) else None
    parsed = process.get("parsed_output") if isinstance(process, Mapping) else None
    probe = parsed if isinstance(parsed, Mapping) else None
    checks["probe"] = {
        "status": process_status,
        "reason": process_reason if isinstance(process_reason, str) else None,
        "cleanup_status": cleanup_status if isinstance(cleanup_status, str) else None,
        "probe_sha256": probe.get("probe_sha256") if probe else None,
    }
    if process_status != "PASS" or cleanup_status != "complete":
        issues.append("probe:process_invalid")
    if probe is None:
        issues.append("probe:output_invalid")
    else:
        supplied = probe.get("probe_sha256")
        probe_core = {
            key: deepcopy(item) for key, item in probe.items() if key != "probe_sha256"
        }
        expected_probe = {
            "schema": PROBE_OUTPUT_SCHEMA,
            "status": "PASS",
            "checks": _EXPECTED_PROBE_CHECKS,
            "cleanup_status": "COMPLETE",
            "provider_dispatch_status": "REFUSED_BEFORE_PROVIDER",
            "provider_free": True,
            "real_credential_reads": 0,
            "synthetic_credential_reads": 1,
            "loopback_network_calls": 7,
            "provider_calls": 0,
            "model_calls": 0,
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "repairs": 0,
            "replacements": 0,
        }
        if probe_core != expected_probe:
            issues.append("probe:contract_mismatch")
        if not _is_sha(supplied) or supplied != _sha256(probe_core):
            issues.append("probe:seal_mismatch")

    post_issues: list[str] = []
    post_identity, _plugin, _opencodex = _runtime_identity(runtime, post_issues)
    if post_issues or post_identity != identity:
        issues.append("runtime:changed_during_qualification")
    return _report(
        issues=issues,
        runtime_identity=identity,
        checks=checks,
        probe=probe,
    )


def validate_installed_credential_admission(
    value: Any, runtime: AdmissionRuntime | None = None
) -> dict[str, Any]:
    """Validate a qualification and optionally rederive its runtime identity."""

    issues: list[str] = []
    if not isinstance(value, Mapping) or set(value) != _QUALIFICATION_FIELDS:
        issues.append("qualification:contract_invalid")
        record: Mapping[str, Any] = value if isinstance(value, Mapping) else {}
    else:
        record = value
    if record.get("schema") != QUALIFICATION_SCHEMA:
        issues.append("qualification:schema_invalid")
    raw_issues = record.get("issues")
    if (
        not isinstance(raw_issues, list)
        or raw_issues != sorted(set(raw_issues))
        or any(not isinstance(item, str) or not item for item in raw_issues)
    ):
        issues.append("qualification:issues_invalid")
        raw_issues = []
    expected_status = "PASS" if not raw_issues else "FAIL"
    if (
        record.get("status") != expected_status
        or record.get("qualified") is not (not raw_issues)
    ):
        issues.append("qualification:disposition_invalid")
    if (
        record.get("issue152_create_response_sha256")
        != admission.ISSUE152_CREATE_RESPONSE_SHA256
    ):
        issues.append("qualification:issue152_binding_invalid")
    identity = record.get("runtime_identity")
    if not isinstance(identity, Mapping) or set(identity) != {
        "schema",
        "plugin",
        "opencodex",
        "runtime_identity_sha256",
    }:
        issues.append("qualification:runtime_identity_invalid")
    else:
        identity_core = {
            key: deepcopy(item)
            for key, item in identity.items()
            if key != "runtime_identity_sha256"
        }
        if (
            identity.get("schema") != RUNTIME_IDENTITY_SCHEMA
            or not _is_sha(identity.get("runtime_identity_sha256"))
            or identity.get("runtime_identity_sha256") != _sha256(identity_core)
        ):
            issues.append("qualification:runtime_identity_invalid")
        for label, expected_name, expected_fields in (
            (
                "plugin",
                "orch-dork",
                {"name", "version", "file_count", "bytes", "source_closure_sha256"},
            ),
            (
                "opencodex",
                "@bitkyc08/opencodex",
                {
                    "name",
                    "version",
                    "file_count",
                    "symlink_count",
                    "bytes",
                    "source_closure_sha256",
                },
            ),
        ):
            closure = identity.get(label)
            if (
                not isinstance(closure, Mapping)
                or set(closure) != expected_fields
                or closure.get("name") != expected_name
                or not isinstance(closure.get("version"), str)
                or not closure["version"]
                or type(closure.get("file_count")) is not int
                or closure["file_count"] < 1
                or type(closure.get("bytes")) is not int
                or closure["bytes"] < 1
                or not _is_sha(closure.get("source_closure_sha256"))
                or (
                    label == "opencodex"
                    and (
                        type(closure.get("symlink_count")) is not int
                        or closure["symlink_count"] < 0
                    )
                )
            ):
                issues.append("qualification:" + label + "_closure_invalid")
    if runtime is not None:
        runtime_issues: list[str] = []
        derived, _plugin, _opencodex = _runtime_identity(runtime, runtime_issues)
        if runtime_issues or derived != identity:
            issues.append("qualification:runtime_identity_mismatch")

    checks = record.get("checks")
    if not isinstance(checks, Mapping) or set(checks) != {
        "synthetic_cases",
        "probe",
    }:
        issues.append("qualification:checks_invalid")
        checks = {}
    cases = checks.get("synthetic_cases") if isinstance(checks, Mapping) else None
    if not isinstance(cases, Mapping) or set(cases) != set(_EXPECTED_SYNTHETIC_CASES):
        issues.append("qualification:synthetic_cases_invalid")
    elif any(
        not isinstance(case, Mapping)
        or set(case) != {"status", "lifecycle_status", "lifecycle_sha256"}
        or case.get("status") != "PASS"
        or case.get("lifecycle_status") not in {"PASS", "FAIL"}
        or not _is_sha(case.get("lifecycle_sha256"))
        for case in cases.values()
    ):
        issues.append("qualification:synthetic_cases_invalid")
    expected_probe_check = {
        "status": "PASS",
        "reason": None,
        "cleanup_status": "complete",
        "probe_sha256": (
            checks.get("probe", {}).get("probe_sha256")
            if isinstance(checks.get("probe"), Mapping)
            else None
        ),
    }
    if (
        not isinstance(checks.get("probe"), Mapping)
        or set(checks["probe"])
        != {"status", "reason", "cleanup_status", "probe_sha256"}
        or checks["probe"] != expected_probe_check
        or not _is_sha(checks["probe"].get("probe_sha256"))
    ):
        issues.append("qualification:probe_check_invalid")
    if record.get("provider_free") is not True or record.get("real_credential_reads") != 0:
        issues.append("qualification:credential_boundary_invalid")
    for field in (
        "synthetic_lifecycle_cases",
        "synthetic_route_credential_lifecycles",
    ):
        if type(record.get(field)) is not int or record[field] < 0:
            issues.append("qualification:" + field + "_invalid")
    for field in (
        "loopback_network_calls",
        "provider_calls",
        "model_calls",
        "hosted_calls",
    ):
        if record.get(field) is not None and (
            type(record.get(field)) is not int or record[field] < 0
        ):
            issues.append("qualification:" + field + "_invalid")
    for field in ("retries", "fallbacks", "repairs", "replacements"):
        if record.get(field) != 0:
            issues.append("qualification:" + field + "_nonzero")
    passing = {
        "provider_free": True,
        "real_credential_reads": 0,
        "synthetic_lifecycle_cases": 8,
        "synthetic_route_credential_lifecycles": 1,
        "loopback_network_calls": 7,
        "provider_calls": 0,
        "model_calls": 0,
        "hosted_calls": 0,
        "retries": 0,
        "fallbacks": 0,
        "repairs": 0,
        "replacements": 0,
    }
    if record.get("status") == "PASS" and any(
        record.get(field) != expected for field, expected in passing.items()
    ):
        issues.append("qualification:passing_contract_invalid")
    supplied = record.get("qualification_sha256")
    core = {
        key: deepcopy(item)
        for key, item in record.items()
        if key != "qualification_sha256"
    }
    if not _is_sha(supplied) or supplied != _sha256(core):
        issues.append("qualification:seal_invalid")
    validation_core = {
        "schema": QUALIFICATION_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(set(issues)),
        "qualification_status": record.get("status"),
        "qualification_sha256": supplied if _is_sha(supplied) else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**validation_core, "report_sha256": _sha256(validation_core)}


__all__ = [
    "AdmissionRuntime",
    "PROBE_INPUT_SCHEMA",
    "PROBE_OUTPUT_SCHEMA",
    "QUALIFICATION_SCHEMA",
    "QUALIFICATION_VALIDATION_SCHEMA",
    "RUNTIME_IDENTITY_SCHEMA",
    "qualify_installed_credential_admission",
    "validate_installed_credential_admission",
]


if __name__ == "__main__":
    raise SystemExit("Import the credential-admission qualification; no CLI is provided.")
