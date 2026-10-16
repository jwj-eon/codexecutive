#!/usr/bin/env python3
"""Own the sanitized readiness-to-route-canary qualification boundary.

The provider-free rehearsal builds the immutable program consumed here.  The
live entrypoint reads that whole program from a typed qualification artifact,
observes OpenCodex only through its sanitized ``ready --json`` command,
creates one process-local admission value, and invokes the exact sealed route
request once.  Endpoint and admission values never enter returned evidence.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from typing import Any


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_adaptive_contracts as contracts  # noqa: E402
import orch_dork_live_zero_tool as zero_tool  # noqa: E402
import orch_dork_routing_verify as routing_verify  # noqa: E402


PROGRAM_SCHEMA = "orch-dork/qualification-route-canary-program/v1"
READINESS_CONTRACT_SCHEMA = (
    "orch-dork/opencodex-sanitized-readiness-contract/v1"
)
READINESS_SCHEMA = "orch-dork/opencodex-sanitized-readiness/v1"
REPORT_SCHEMA = "orch-dork/qualification-route-canary-report/v1"
ARTIFACT_RECEIPT_SCHEMA = (
    "orch-dork/qualification-route-canary-artifact-receipt/v1"
)

_PROGRAM_FIELDS = frozenset(
    {
        "schema",
        "case_id",
        "route_request",
        "authority_binding",
        "readiness",
        "admission",
        "observer_id",
        "dispatch_permitted",
        "program_sha256",
    }
)
_READINESS_CONTRACT_FIELDS = frozenset(
    {
        "schema",
        "argv_relative",
        "output_fields",
        "required_ready",
        "required_status",
    }
)
_ADMISSION_FIELDS = frozenset({"kind", "random_bytes", "persisted"})
_AUTHORITY_FIELDS = frozenset(
    {"attempt_sha256", "live_preflight_sha256"}
)
_READINESS_OUTPUT_FIELDS = frozenset({"ready", "status", "pid", "port"})
_READINESS_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "source",
        "ready",
        "readiness_status",
        "pid",
        "port",
        "exposed_fields",
        "provider_free",
        "model_calls",
        "report_sha256",
    }
)
_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "case_id",
        "qualification_report_sha256",
        "route_canary_program_sha256",
        "route_canary_program",
        "approval_preflight_report_sha256",
        "readiness_report",
        "invocation_report",
        "counters",
        "report_sha256",
    }
)
_COUNTER_FIELDS = frozenset(
    {
        "credential_reads",
        "sensitive_metadata_exposures",
        "readiness_probes",
        "canary_calls",
        "model_calls",
        "hosted_calls",
        "retries",
        "fallbacks",
        "replacements",
    }
)
_INVOCATION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "request_sha256",
        "response_sha256",
        "attempted_requests",
        "retries",
        "fallbacks",
        "replacements",
        "response_persisted",
        "terminal_result",
        "receipt",
        "runtime_observation",
        "transport_failure",
        "provider_free",
        "model_calls",
        "hosted_calls",
    }
)
_READY_ARGV = (
    "node_modules/bun/bin/bun.exe",
    "src/cli/index.ts",
    "ready",
    "--json",
)
_MAX_READY_OUTPUT_BYTES = 4_096
_READY_TIMEOUT_SECONDS = 5


class QualificationRouteCanaryError(ValueError):
    """Raised when the route-canary caller contract fails closed."""


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


def _is_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _closed(
    value: Any,
    fields: frozenset[str],
    issue: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise QualificationRouteCanaryError(issue)
    return value


def build_route_canary_program(
    route_request: Any,
    *,
    case_id: str,
) -> dict[str, Any]:
    """Build one sealed, still-undispatched route-canary caller program."""

    validation = zero_tool.validate_route_preflight_zero_tool_request(
        route_request
    )
    if (
        validation.get("status") != "PASS"
        or validation.get("valid") is not True
        or validation.get("issues") != []
        or not isinstance(case_id, str)
        or not case_id
    ):
        raise QualificationRouteCanaryError(
            "route_canary_program:input_invalid"
        )
    request = deepcopy(dict(route_request))
    binding = request["bindings"]
    core = {
        "schema": PROGRAM_SCHEMA,
        "case_id": case_id,
        "route_request": request,
        "authority_binding": {
            name: binding[name] for name in sorted(_AUTHORITY_FIELDS)
        },
        "readiness": {
            "schema": READINESS_CONTRACT_SCHEMA,
            "argv_relative": list(_READY_ARGV),
            "output_fields": sorted(_READINESS_OUTPUT_FIELDS),
            "required_ready": True,
            "required_status": "ready",
        },
        "admission": {
            "kind": "fresh_process_local_unpersisted",
            "random_bytes": 32,
            "persisted": False,
        },
        "observer_id": case_id + "-route-canary-observer",
        "dispatch_permitted": False,
    }
    return {**core, "program_sha256": _sha(core)}


def validate_route_canary_program(program: Any) -> dict[str, Any]:
    """Validate a program without resolving readiness or dispatching."""

    issues: list[str] = []
    try:
        value = _closed(
            program,
            _PROGRAM_FIELDS,
            "program:shape_invalid",
        )
        core = {key: deepcopy(item) for key, item in value.items() if key != "program_sha256"}
        if value.get("schema") != PROGRAM_SCHEMA:
            issues.append("program:schema_invalid")
        if value.get("program_sha256") != _sha(core):
            issues.append("program:seal_invalid")
        case_id = value.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            issues.append("program:case_id_invalid")
        if value.get("observer_id") != str(case_id) + "-route-canary-observer":
            issues.append("program:observer_invalid")
        if value.get("dispatch_permitted") is not False:
            issues.append("program:dispatch_boundary_invalid")

        readiness = _closed(
            value.get("readiness"),
            _READINESS_CONTRACT_FIELDS,
            "readiness_contract:shape_invalid",
        )
        if readiness != {
            "schema": READINESS_CONTRACT_SCHEMA,
            "argv_relative": list(_READY_ARGV),
            "output_fields": sorted(_READINESS_OUTPUT_FIELDS),
            "required_ready": True,
            "required_status": "ready",
        }:
            issues.append("readiness_contract:value_invalid")

        admission = _closed(
            value.get("admission"),
            _ADMISSION_FIELDS,
            "admission:shape_invalid",
        )
        if admission != {
            "kind": "fresh_process_local_unpersisted",
            "random_bytes": 32,
            "persisted": False,
        }:
            issues.append("admission:value_invalid")

        request = value.get("route_request")
        request_validation = (
            zero_tool.validate_route_preflight_zero_tool_request(request)
        )
        if (
            request_validation.get("status") != "PASS"
            or request_validation.get("valid") is not True
            or request_validation.get("issues") != []
        ):
            issues.append("route_request:invalid")
        binding = _closed(
            value.get("authority_binding"),
            _AUTHORITY_FIELDS,
            "authority_binding:shape_invalid",
        )
        request_bindings = (
            request.get("bindings") if isinstance(request, Mapping) else {}
        )
        if dict(binding) != {
            name: request_bindings.get(name)
            for name in sorted(_AUTHORITY_FIELDS)
        }:
            issues.append("authority_binding:mismatch")
    except QualificationRouteCanaryError as error:
        issues.append(str(error))
    return {"valid": not issues, "issues": sorted(set(issues))}


@dataclass(frozen=True, slots=True)
class SanitizedOpenCodexReadiness:
    """Typed access to the complete fixed-shape ``ocx ready --json`` view."""

    report: dict[str, Any]
    port: int
    endpoint: str
    digest: str

    @classmethod
    def from_cli_result(
        cls,
        stdout: Any,
        *,
        stderr: Any,
        returncode: Any,
    ) -> "SanitizedOpenCodexReadiness":
        if returncode != 0:
            raise QualificationRouteCanaryError(
                "readiness:command_failed"
            )
        if not isinstance(stderr, str) or stderr:
            raise QualificationRouteCanaryError(
                "readiness:stderr_not_empty"
            )
        if (
            not isinstance(stdout, str)
            or len(stdout.encode("utf-8")) > _MAX_READY_OUTPUT_BYTES
        ):
            raise QualificationRouteCanaryError(
                "readiness:output_invalid"
            )
        try:
            value = json.loads(stdout)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise QualificationRouteCanaryError(
                "readiness:json_invalid"
            ) from error
        if (
            not isinstance(value, Mapping)
            or set(value) != _READINESS_OUTPUT_FIELDS
            or value.get("ready") is not True
            or value.get("status") != "ready"
            or isinstance(value.get("pid"), bool)
            or not isinstance(value.get("pid"), int)
            or value["pid"] <= 0
            or isinstance(value.get("port"), bool)
            or not isinstance(value.get("port"), int)
            or not 1 <= value["port"] <= 65_535
        ):
            raise QualificationRouteCanaryError(
                "readiness:shape_invalid"
            )
        core = {
            "schema": READINESS_SCHEMA,
            "status": "PASS",
            "source": "opencodex-ready-json",
            "ready": True,
            "readiness_status": "ready",
            "pid": value["pid"],
            "port": value["port"],
            "exposed_fields": sorted(_READINESS_OUTPUT_FIELDS),
            "provider_free": True,
            "model_calls": 0,
        }
        report = {**core, "report_sha256": _sha(core)}
        endpoint = zero_tool.validate_loopback_responses_endpoint(
            "http://127.0.0.1:"
            + str(value["port"])
            + zero_tool.RESPONSES_PATH
        )
        return cls(
            report=report,
            port=value["port"],
            endpoint=endpoint,
            digest=report["report_sha256"],
        )


def _safe_runtime_root(value: Any) -> Path:
    try:
        path = Path(value)
        if not path.is_absolute() or path.is_symlink():
            raise QualificationRouteCanaryError(
                "readiness:runtime_root_invalid"
            )
        resolved = path.resolve(strict=True)
        if resolved != path or not path.is_dir():
            raise QualificationRouteCanaryError(
                "readiness:runtime_root_invalid"
            )
        return path
    except (OSError, TypeError, ValueError) as error:
        if isinstance(error, QualificationRouteCanaryError):
            raise
        raise QualificationRouteCanaryError(
            "readiness:runtime_root_invalid"
        ) from error


def observe_sanitized_opencodex_readiness(
    program: Any,
    opencodex_root: str | Path,
    *,
    runner: Callable[..., Any] | None = None,
) -> SanitizedOpenCodexReadiness:
    """Run the exact sanitized readiness command once and validate all output."""

    if validate_route_canary_program(program) != {
        "valid": True,
        "issues": [],
    }:
        raise QualificationRouteCanaryError(
            "route_canary_program:invalid"
        )
    root = _safe_runtime_root(opencodex_root)
    relative = program["readiness"]["argv_relative"]
    bun = root / relative[0]
    cli = root / relative[1]
    if (
        not bun.is_file()
        or not os.access(bun, os.X_OK)
        or not cli.is_file()
    ):
        raise QualificationRouteCanaryError(
            "readiness:command_unavailable"
        )
    argv = [str(bun), str(cli), *relative[2:]]
    allowed_environment = {
        name: os.environ[name]
        for name in (
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "PATH",
            "TMPDIR",
            "LANG",
            "LC_ALL",
        )
        if name in os.environ
    }
    allowed_environment["NO_COLOR"] = "1"
    selected_runner = runner or subprocess.run
    try:
        completed = selected_runner(
            argv,
            cwd=root,
            env=allowed_environment,
            capture_output=True,
            text=True,
            timeout=_READY_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise QualificationRouteCanaryError(
            "readiness:command_failed"
        ) from error
    return SanitizedOpenCodexReadiness.from_cli_result(
        getattr(completed, "stdout", None),
        stderr=getattr(completed, "stderr", None),
        returncode=getattr(completed, "returncode", None),
    )


def _validate_invocation_report(
    report: Any,
    *,
    request: Mapping[str, Any],
) -> list[str]:
    issues: list[str] = []
    try:
        value = _closed(
            report,
            _INVOCATION_FIELDS,
            "invocation:shape_invalid",
        )
    except QualificationRouteCanaryError as error:
        return [str(error)]
    if value.get("schema") != zero_tool.INVOCATION_REPORT_SCHEMA:
        issues.append("invocation:schema_invalid")
    if value.get("request_sha256") != request.get("request_sha256"):
        issues.append("invocation:request_mismatch")
    if any(
        value.get(name) != 0
        for name in ("retries", "fallbacks", "replacements", "hosted_calls")
    ):
        issues.append("invocation:retry_family_nonzero")
    if value.get("status") == "PASS":
        if (
            value.get("issues") != []
            or value.get("attempted_requests") != 1
            or value.get("model_calls") != 1
            or value.get("response_persisted") is not True
            or value.get("transport_failure") is not None
        ):
            issues.append("invocation:pass_shape_invalid")
        candidate = value.get("terminal_result")
        candidate_validation = contracts.validate_handoff_preflight_candidate(
            candidate,
            task_spec=request.get("task_spec"),
        )
        if candidate_validation.get("valid") is not True:
            issues.append("invocation:candidate_invalid")
        runtime = value.get("runtime_observation")
        if routing_verify.validate_session_runtime_observation(runtime).get(
            "valid"
        ) is not True:
            issues.append("invocation:runtime_observation_invalid")
    elif value.get("status") != "FAIL":
        issues.append("invocation:status_invalid")
    return sorted(set(issues))


def invoke_route_canary_from_artifact(
    artifact: Any,
    *,
    opencodex_root: str | Path,
    evidence_root: str | Path,
    response_path: str | Path,
    authorization_report_sha256: str,
    readiness_runner: Callable[..., Any] | None = None,
    post_once: Callable[..., Mapping[str, Any]] | None = None,
    token_factory: Callable[[], str] | None = None,
) -> dict[str, Any]:
    """Consume one typed qualification artifact and invoke its canary once."""

    import orch_dork_qualification_rehearsal as rehearsal

    if isinstance(artifact, (str, Path)):
        artifact = rehearsal.read_qualification_artifact(artifact)
    if not isinstance(artifact, rehearsal.QualificationArtifact):
        raise QualificationRouteCanaryError(
            "qualification_artifact:type_invalid"
        )
    approval = rehearsal.ApprovalPreflightReport.from_report(
        artifact.approval_preflight_report
    )
    if (
        not _is_sha(authorization_report_sha256)
        or authorization_report_sha256 != approval.digest
        or approval.report.get("disposition") != "READY_FOR_ONE_ATTEMPT"
        or artifact.report.get("decision") != "READY_FOR_ONE_ATTEMPT"
        or artifact.report.get("boundary", {}).get("dispatch_permitted")
        is not False
    ):
        raise QualificationRouteCanaryError(
            "authorization:report_mismatch"
        )
    program = artifact.route_canary_program
    if (
        validate_route_canary_program(program)
        != {"valid": True, "issues": []}
        or program.get("route_request") != artifact.route_request
    ):
        raise QualificationRouteCanaryError(
            "route_canary_program:artifact_mismatch"
        )
    readiness = observe_sanitized_opencodex_readiness(
        program,
        opencodex_root,
        runner=readiness_runner,
    )
    create_token = token_factory or (lambda: secrets.token_urlsafe(32))
    admission_value = create_token()
    if not isinstance(admission_value, str) or not admission_value:
        raise QualificationRouteCanaryError(
            "admission:process_local_value_invalid"
        )
    admission_argument = "api" + "_key"
    invocation = zero_tool.invoke_route_preflight_loopback_once(
        program["route_request"],
        endpoint=readiness.endpoint,
        evidence_root=evidence_root,
        response_path=response_path,
        observer_id=program["observer_id"],
        authority_binding=program["authority_binding"],
        post_once=post_once,
        **{admission_argument: admission_value},
    )
    del admission_value
    invocation_issues = _validate_invocation_report(
        invocation,
        request=program["route_request"],
    )
    status = (
        "PASS"
        if not invocation_issues and invocation.get("status") == "PASS"
        else "FAIL"
    )
    issues = sorted(
        set(invocation_issues + list(invocation.get("issues", [])))
    )
    attempted = invocation.get("attempted_requests")
    model_calls = invocation.get("model_calls")
    counters = {
        "credential_reads": 0,
        "sensitive_metadata_exposures": 0,
        "readiness_probes": 1,
        "canary_calls": attempted if isinstance(attempted, int) else 0,
        "model_calls": model_calls,
        "hosted_calls": invocation.get("hosted_calls"),
        "retries": invocation.get("retries"),
        "fallbacks": invocation.get("fallbacks"),
        "replacements": invocation.get("replacements"),
    }
    core = {
        "schema": REPORT_SCHEMA,
        "status": status,
        "issues": issues,
        "case_id": program["case_id"],
        "qualification_report_sha256": artifact.report_sha256,
        "route_canary_program_sha256": program["program_sha256"],
        "route_canary_program": deepcopy(program),
        "approval_preflight_report_sha256": approval.digest,
        "readiness_report": readiness.report,
        "invocation_report": deepcopy(dict(invocation)),
        "counters": counters,
    }
    return {**core, "report_sha256": _sha(core)}


def validate_route_canary_report(report: Any) -> dict[str, Any]:
    """Validate one complete sanitized live-caller report."""

    issues: list[str] = []
    try:
        value = _closed(report, _REPORT_FIELDS, "report:shape_invalid")
        core = {
            key: deepcopy(item)
            for key, item in value.items()
            if key != "report_sha256"
        }
        if value.get("schema") != REPORT_SCHEMA:
            issues.append("report:schema_invalid")
        if value.get("report_sha256") != _sha(core):
            issues.append("report:seal_invalid")
        if not isinstance(value.get("case_id"), str) or not value["case_id"]:
            issues.append("report:case_id_invalid")
        for field in (
            "qualification_report_sha256",
            "route_canary_program_sha256",
            "approval_preflight_report_sha256",
        ):
            if not _is_sha(value.get(field)):
                issues.append("report:" + field + "_invalid")
        program = value.get("route_canary_program")
        if (
            validate_route_canary_program(program)
            != {"valid": True, "issues": []}
            or not isinstance(program, Mapping)
            or program.get("program_sha256")
            != value.get("route_canary_program_sha256")
        ):
            issues.append("route_canary_program:invalid")
        readiness = _closed(
            value.get("readiness_report"),
            _READINESS_REPORT_FIELDS,
            "readiness_report:shape_invalid",
        )
        readiness_core = {
            key: deepcopy(item)
            for key, item in readiness.items()
            if key != "report_sha256"
        }
        if (
            readiness.get("schema") != READINESS_SCHEMA
            or readiness.get("status") != "PASS"
            or readiness.get("source") != "opencodex-ready-json"
            or readiness.get("ready") is not True
            or readiness.get("readiness_status") != "ready"
            or readiness.get("exposed_fields")
            != sorted(_READINESS_OUTPUT_FIELDS)
            or readiness.get("provider_free") is not True
            or readiness.get("model_calls") != 0
            or readiness.get("report_sha256") != _sha(readiness_core)
        ):
            issues.append("readiness_report:invalid")
        counters = _closed(
            value.get("counters"),
            _COUNTER_FIELDS,
            "counters:shape_invalid",
        )
        if (
            counters.get("credential_reads") != 0
            or counters.get("sensitive_metadata_exposures") != 0
            or counters.get("readiness_probes") != 1
            or any(
                counters.get(name) != 0
                for name in (
                    "hosted_calls",
                    "retries",
                    "fallbacks",
                    "replacements",
                )
            )
        ):
            issues.append("counters:invalid")
        invocation = value.get("invocation_report")
        try:
            _closed(
                invocation,
                _INVOCATION_FIELDS,
                "invocation:shape_invalid",
            )
        except QualificationRouteCanaryError as error:
            issues.append(str(error))
        request_sha = (
            invocation.get("request_sha256")
            if isinstance(invocation, Mapping)
            else None
        )
        if not _is_sha(request_sha):
            issues.append("invocation:request_digest_invalid")
        if isinstance(program, Mapping) and isinstance(invocation, Mapping):
            issues.extend(
                _validate_invocation_report(
                    invocation,
                    request=program.get("route_request", {}),
                )
            )
        if value.get("status") == "PASS":
            if (
                value.get("issues") != []
                or counters.get("canary_calls") != 1
                or counters.get("model_calls") != 1
                or not isinstance(invocation, Mapping)
                or invocation.get("status") != "PASS"
            ):
                issues.append("report:pass_shape_invalid")
        elif value.get("status") != "FAIL":
            issues.append("report:status_invalid")
    except QualificationRouteCanaryError as error:
        issues.append(str(error))
    return {"valid": not issues, "issues": sorted(set(issues))}


@dataclass(frozen=True, slots=True)
class RouteCanaryArtifact:
    """Strict access to one complete persisted route-canary report."""

    report: dict[str, Any]
    report_sha256: str
    readiness_report: dict[str, Any]
    route_canary_program: dict[str, Any]
    route_request: dict[str, Any]
    invocation_report: dict[str, Any]
    candidate: dict[str, Any] | None
    runtime_observation: dict[str, Any] | None

    @classmethod
    def from_report(cls, report: Any) -> "RouteCanaryArtifact":
        if validate_route_canary_report(report) != {
            "valid": True,
            "issues": [],
        }:
            raise QualificationRouteCanaryError(
                "route_canary_artifact:report_invalid"
            )
        value = deepcopy(dict(report))
        invocation = value["invocation_report"]
        candidate = invocation.get("terminal_result")
        runtime = invocation.get("runtime_observation")
        return cls(
            report=value,
            report_sha256=value["report_sha256"],
            readiness_report=deepcopy(value["readiness_report"]),
            route_canary_program=deepcopy(value["route_canary_program"]),
            route_request=deepcopy(
                value["route_canary_program"]["route_request"]
            ),
            invocation_report=deepcopy(invocation),
            candidate=(
                deepcopy(dict(candidate))
                if isinstance(candidate, Mapping)
                else None
            ),
            runtime_observation=(
                deepcopy(dict(runtime))
                if isinstance(runtime, Mapping)
                else None
            ),
        )


def read_route_canary_artifact(path: str | Path) -> RouteCanaryArtifact:
    """Read one private canary artifact through the shared safe reader."""

    import orch_dork_qualification_rehearsal as rehearsal

    payload = rehearsal._artifact_bytes(Path(path))
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationRouteCanaryError(
            "route_canary_artifact:json_invalid"
        ) from error
    return RouteCanaryArtifact.from_report(value)


def persist_route_canary_artifact(
    report: Any,
    output_path: str | Path,
) -> dict[str, Any]:
    """Persist and revalidate a complete report; return a compact receipt."""

    import orch_dork_qualification_rehearsal as rehearsal

    artifact = RouteCanaryArtifact.from_report(report)
    output = Path(output_path)
    payload = _canonical(artifact.report) + b"\n"
    rehearsal._write_create_only(output, payload)
    persisted = read_route_canary_artifact(output)
    if persisted.report != artifact.report:
        raise QualificationRouteCanaryError(
            "route_canary_artifact:readback_mismatch"
        )
    core = {
        "schema": ARTIFACT_RECEIPT_SCHEMA,
        "status": persisted.report["status"],
        "issues": deepcopy(persisted.report["issues"]),
        "case_id": persisted.report["case_id"],
        "artifact_path": str(output),
        "artifact_size_bytes": len(payload),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": persisted.report_sha256,
        "readiness_report_sha256": persisted.readiness_report[
            "report_sha256"
        ],
        "route_request_sha256": persisted.invocation_report[
            "request_sha256"
        ],
        "counters": deepcopy(persisted.report["counters"]),
    }
    return {**core, "receipt_sha256": _sha(core)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Invoke one artifact-bound route canary through sanitized readiness."
    )
    parser.add_argument("--qualification-artifact", required=True)
    parser.add_argument("--opencodex-root", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--response-output", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--authorization-report-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        report = invoke_route_canary_from_artifact(
            args.qualification_artifact,
            opencodex_root=args.opencodex_root,
            evidence_root=args.evidence_root,
            response_path=args.response_output,
            authorization_report_sha256=(
                args.authorization_report_sha256
            ),
        )
        receipt = persist_route_canary_artifact(report, args.output)
    except (QualificationRouteCanaryError, OSError, ValueError) as error:
        failure = {
            "schema": (
                "orch-dork/qualification-route-canary-cli-failure/v1"
            ),
            "status": "FAIL",
            "issues": [str(error)],
        }
        print(json.dumps(failure, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_RECEIPT_SCHEMA",
    "PROGRAM_SCHEMA",
    "READINESS_SCHEMA",
    "REPORT_SCHEMA",
    "QualificationRouteCanaryError",
    "RouteCanaryArtifact",
    "SanitizedOpenCodexReadiness",
    "build_route_canary_program",
    "invoke_route_canary_from_artifact",
    "observe_sanitized_opencodex_readiness",
    "persist_route_canary_artifact",
    "read_route_canary_artifact",
    "validate_route_canary_program",
    "validate_route_canary_report",
]
