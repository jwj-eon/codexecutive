"""Onboarded model profiles (ADR 0012, FR68 as amended, Issue 203).

Any model Codex can spawn is eligible for any semantic role once one brief
onboarding probe has recorded its plumbing facts in one dated
orch-dork/onboarded-profile/v1.  This module owns that record: its closed
schema and seal, the host-local store the probe writes and the runtime reads,
the reuse rule, the family read from a model's name, the location read from
its route, and the classification of what the probe observed into named
findings.  It tests no capability and never refuses admission: a failed
observation is a finding on the profile.

It also owns the two decisions the profiles feed: where governed runs hold
the V1 surface (the user's own Codex or the governed runner's all-v1 catalog
overlay, and the confirmed opt-in that moves the user's own Codex to V1),
and governed admission (two different models that passed onboarding, the
default lineup, local-only projects, and the first error a real run records
on a profile).

Nothing here launches a process, opens a socket, or calls a model.  The probe
driver that runs Codex (racetrack/onboard.py) stays outside the runtime
allowlist until automatic onboarding ships; the installed runtime reads the
profiles it writes unchanged.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from types import MappingProxyType
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


def _load_sibling(name: str):
    """Load a sibling when this module itself was loaded by file path."""

    try:
        return __import__(name)
    except ImportError:
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


contracts = _load_sibling("orch_dork_adaptive_contracts")

PROFILE_SCHEMA = "orch-dork/onboarded-profile/v1"
ARTIFACT_SCHEMA = "orch-dork/onboarding-artifact/v1"
# The host-local store; the environment variable moves it for tests and for
# a second Codex home.
STORE_ENV = "ORCH_DORK_ONBOARDING_ROOT"
# Under the user's home: .local/state/orch-dork/onboarding.
DEFAULT_STORE_PARTS = (".local", "state", "orch-dork", "onboarding")

SURFACES = ("v1", "v2", "disabled")
V1_LOCATIONS = ("user_codex", "governed_runner")
LOCATIONS = ("local", "hosted")
# Why a route's location reads as it does.  Only a route whose final upstream
# is stated to be on this machine is local; anything uncertain is hosted.
LOCATION_BASES = ("loopback_upstream", "hosted_upstream", "hosted_direct", "uncertain")
ROUTE_VIA = ("opencodex", "direct")
REACHABILITY = (
    "reachable",
    "unreachable",
    "unauthorized",
    "model_unavailable",
    "chat_completions_only",
    "provider_error",
    "unknown",
)
TOOL_CALL_STATES = ("parsed", "absent", "unparsable", "unknown")
ARTIFACT_STATES = ("parsed", "missing", "unparsable", "schema_mismatch", "unknown")
CATALOG_SOURCES = ("model_catalog_json", "model_list", "absent")
FACT_SOURCES = ("catalog", "provider", "probe")
REDO_REASONS = (
    "model_changed",
    "catalog_entry_changed",
    "codex_version_changed",
    "first_run_error",
)

# The family of a model, read from its name only when the name makes it
# obvious (ADR 0012).  A name matching no family, or more than one, is an
# unknown family; nobody labels a model.  The first three are the registry's
# closed lineages.
FAMILY_MARKERS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "anthropic": ("claude", "anthropic"),
        "openai": ("gpt", "openai", "codex"),
        "qwen": ("qwen",),
        "google": ("gemini", "gemma"),
        "meta": ("llama",),
        "mistral": ("mistral", "mixtral", "codestral", "devstral", "magistral"),
        "deepseek": ("deepseek",),
        "xai": ("grok",),
        "moonshot": ("kimi", "moonshot"),
        "zhipu": ("glm", "zhipu"),
    }
)
FAMILIES = tuple(FAMILY_MARKERS)

# Every named finding the probe can record.  A finding never refuses
# admission; it is shown before freeze so the user decides.
FINDINGS: Mapping[str, str] = MappingProxyType(
    {
        "catalog_entry_absent": "Codex's catalog has no row for the model, so its metadata is unknown.",
        "dry_run_failed": "A dry run against the stand-in provider did not report the surface Codex assigns.",
        "route_unreachable": "The route did not answer; Codex was still waiting for the network.",
        "route_unauthorized": "The provider refused the credentials Codex sent.",
        "model_unavailable_to_account": "The provider reports that this account cannot use the model.",
        "provider_chat_completions_only": "The provider has no Responses endpoint; it speaks only Chat Completions.",
        "provider_error": "The provider returned an error the probe does not classify further.",
        "v1_unreachable": "Neither the user's Codex nor the governed runner assigns the model the V1 surface.",
        "live_surface_not_v1": "The live probe ran the model on a surface other than V1.",
        "v1_collaboration_tools_unobserved": "The live probe did not observe the model calling a V1 collaboration tool.",
        "v1_worker_spawn_unobserved": "The live probe did not observe the model spawned as a V1 worker.",
        "worker_failed": "The spawned worker did not complete its trivial task.",
        "tool_calls_absent": "The model made no tool call when the probe asked for one.",
        "tool_calls_unparsable": "Codex could not parse a tool call the model made.",
        "artifact_missing": "The worker wrote no onboarding artifact.",
        "artifact_unparsable": "The onboarding artifact is not one JSON object.",
        "artifact_schema_mismatch": "The onboarding artifact does not match the onboarding schema and nonce.",
        "probe_timeout": "The live probe did not finish within its time bound.",
    }
)
FINDING_CODES = tuple(FINDINGS)

_PROFILE_FIELDS = frozenset(
    {
        "schema",
        "model",
        "onboarded_at",
        "codex_version",
        "route",
        "family",
        "catalog",
        "surface",
        "reachability",
        "tool_calls",
        "artifact",
        "sample",
        "findings",
        "probe",
        "first_run_error",
        "profile_sha256",
    }
)
_ROUTE_FIELDS = frozenset(
    {
        "provider_id",
        "base_url",
        "via",
        "upstream_provider",
        "upstream_base_url",
        "location",
        "location_basis",
    }
)
_CATALOG_FIELDS = frozenset(
    {
        "source",
        "entry_sha256",
        "row_surface",
        "rewritten_from",
        "context_window",
        "max_output_tokens",
        "default_effort",
        "parallel_tool_calls",
    }
)
_SURFACE_FIELDS = frozenset(
    {
        "v2_feature_enabled",
        "user_codex",
        "governed_runner",
        "v1_location",
        "v1_unavailable",
        "live",
        "worker",
        "collaboration_tools_offered",
        "v1_worker_spawned",
    }
)
_V1_UNAVAILABLE_FIELDS = frozenset({"reason", "tried", "codex_reported"})
_SAMPLE_FIELDS = frozenset(
    {
        "effort",
        "effective_context_window",
        "first_output_ms",
        "root_turn_ms",
        "worker_turn_ms",
        "tokens",
    }
)
_TOKEN_FIELDS = frozenset({"input", "cached_input", "output", "total"})
_PROBE_FIELDS = frozenset({"spawns", "duration_ms", "dry_run_model_calls", "harness"})
_FIRST_ERROR_FIELDS = frozenset({"observed_at", "codex_error_info", "message"})
_FINDING_FIELDS = frozenset({"code", "detail"})
_V1_UNAVAILABLE_REASONS = ("catalog_row_not_v1", "dry_run_failed")
_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_MODEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_MAX_TEXT_BYTES = 1024
_MAX_FINDINGS = len(FINDINGS)
_MAX_PROFILE_BYTES = 65_536


def _sha256(value: Any) -> str:
    return hashlib.sha256(contracts.canonical_bytes(value)).hexdigest()


def seal(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of a profile carrying the digest of its other fields."""

    core = deepcopy(dict(value))
    core.pop("profile_sha256", None)
    return {**core, "profile_sha256": _sha256(core)}


def catalog_entry_sha256(row: Any) -> str | None:
    """The digest of one catalog row, which a profile is reused against."""

    if not isinstance(row, Mapping):
        return None
    return _sha256(row)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# Facts the catalog or provider states carry their value and source; facts
# nothing states are typed unknowns.


def stated(value: Any, source: str) -> dict[str, Any]:
    return {"status": "stated", "value": value, "source": source}


def unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def observed_surface(value: Any) -> dict[str, Any]:
    if value in SURFACES:
        return {"status": "observed", "value": value}
    return unknown("not_observed")


def family_for_model(model: Any) -> str | None:
    """The family a model's name makes obvious, or None when it does not."""

    if not isinstance(model, str):
        return None
    name = model.lower()
    matched = {
        family
        for family, markers in FAMILY_MARKERS.items()
        if any(marker in name for marker in markers)
    }
    return matched.pop() if len(matched) == 1 else None


def _loopback(url: Any) -> bool:
    if not isinstance(url, str):
        return False
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def classify_location(route: Mapping[str, Any]) -> tuple[str, str]:
    """Where a route's model runs, and why it reads that way.

    A model is local only when its route states an upstream on this machine,
    as an OpenCodex provider at a loopback address does.  A direct provider
    at a loopback address may itself forward to a hosted model, so its
    location is uncertain and therefore hosted; local-only work never reaches
    a model whose location is uncertain.
    """

    if route.get("via") == "opencodex":
        upstream = route.get("upstream_base_url")
        if not isinstance(upstream, str):
            return "hosted", "uncertain"
        if _loopback(upstream):
            return "local", "loopback_upstream"
        return "hosted", "hosted_upstream"
    base_url = route.get("base_url")
    if not isinstance(base_url, str) or _loopback(base_url):
        return "hosted", "uncertain"
    return "hosted", "hosted_direct"


def classify_provider_error(info: Any, message: Any) -> tuple[str, str]:
    """The finding and reachability a typed Codex turn error names.

    info is the turn error's codexErrorInfo; message is its text, which
    carries the provider's own error body.
    """

    text = message.lower() if isinstance(message, str) else ""
    status = None
    if isinstance(info, Mapping) and len(info) == 1:
        detail = next(iter(info.values()))
        if isinstance(detail, Mapping):
            status = detail.get("httpStatusCode")
    mentions_model = "model" in text and any(
        phrase in text
        for phrase in ("not found", "does not exist", "not available", "access", "not supported")
    )
    if info == "unauthorized" or status == 401:
        return "route_unauthorized", "unauthorized"
    if status == 403 or (mentions_model and status in (None, 400, 404)):
        return "model_unavailable_to_account", "model_unavailable"
    if status in (404, 405):
        return "provider_chat_completions_only", "chat_completions_only"
    if status is None and isinstance(info, Mapping) and "waiting for network" in text:
        return "route_unreachable", "unreachable"
    return "provider_error", "provider_error"


def classify_artifact(text: Any, *, model: str, nonce: str) -> str:
    """Whether the worker's artifact parsed in the onboarding schema."""

    if not isinstance(text, str):
        return "missing"
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return "unparsable"
    if not isinstance(value, dict):
        return "unparsable"
    expected = {"schema": ARTIFACT_SCHEMA, "model": model, "nonce": nonce}
    return "parsed" if value == expected else "schema_mismatch"


def _finding(code: str, detail: str) -> dict[str, str]:
    text = " ".join(detail.split())
    encoded = text.encode("utf-8")
    if len(encoded) > _MAX_TEXT_BYTES:
        text = encoded[: _MAX_TEXT_BYTES - 3].decode("utf-8", "ignore") + "..."
    return {"code": code, "detail": text or FINDINGS[code]}


def classify_probe(observation: Mapping[str, Any], *, model: str, nonce: str) -> dict[str, Any]:
    """Turn what one probe observed into the profile's verdict fields.

    observation is the driver's record of the dry runs and the live probe;
    the result carries reachability, tool-call and artifact states, the
    surface facts, and every named finding.  Nothing here refuses: the
    caller writes the profile whatever the findings are.
    """

    findings: list[dict[str, str]] = []
    if not observation.get("catalog_row_present"):
        findings.append(_finding("catalog_entry_absent", FINDINGS["catalog_entry_absent"]))

    dry_runs = observation.get("dry_runs") or {}
    surfaces = {}
    for location in V1_LOCATIONS:
        run = dry_runs.get(location) or {}
        surface = run.get("surface")
        surfaces[location] = surface if surface in SURFACES else None
        if surfaces[location] is None:
            findings.append(_finding(
                "dry_run_failed",
                location + ": " + str(run.get("error") or "no surface reported"),
            ))
    v1_location = next((name for name in V1_LOCATIONS if surfaces[name] == "v1"), None)
    v1_unavailable = None
    if v1_location is None:
        tried = list(V1_LOCATIONS)
        reported = "; ".join(
            name + "=" + (surfaces[name] or "unreported") for name in V1_LOCATIONS
        )
        reason = (
            "catalog_row_not_v1"
            if all(surfaces[name] is not None for name in V1_LOCATIONS)
            else "dry_run_failed"
        )
        v1_unavailable = {"reason": reason, "tried": tried, "codex_reported": reported}
        findings.append(_finding("v1_unreachable", "Codex reported " + reported + "."))

    turn = observation.get("turn") or {}
    output_seen = bool(observation.get("root_output"))
    reachability = "reachable" if output_seen else "unknown"
    if turn.get("interrupted_for") == "timeout":
        findings.append(_finding("probe_timeout", FINDINGS["probe_timeout"]))
    error_info = turn.get("error_info")
    error_message = turn.get("error_message")
    if turn.get("interrupted_for") == "unreachable" or error_info is not None or error_message:
        code, state = classify_provider_error(error_info, error_message)
        if turn.get("interrupted_for") == "unreachable":
            code, state = "route_unreachable", "unreachable"
        if not output_seen or state != "provider_error":
            # A route that answered stays reachable; its error is a finding.
            if not output_seen:
                reachability = state
            findings.append(_finding(code, str(error_message or FINDINGS[code])))

    root_surface = observation.get("root_surface")
    if output_seen and root_surface in SURFACES and root_surface != "v1":
        findings.append(_finding(
            "live_surface_not_v1", "The root turn ran on " + str(root_surface) + "."
        ))

    spawn = observation.get("spawn") or {}
    worker = observation.get("worker") or {}
    collaboration = True if spawn.get("called") else (None if not output_seen else False)
    worker_surface = worker.get("surface") if worker.get("found") else None
    spawned = bool(spawn.get("status") == "completed" and worker.get("found"))
    if output_seen and not spawn.get("called"):
        findings.append(_finding(
            "v1_collaboration_tools_unobserved", FINDINGS["v1_collaboration_tools_unobserved"]
        ))
    if not spawned:
        detail = spawn.get("detail") or FINDINGS["v1_worker_spawn_unobserved"]
        if output_seen or spawn.get("called"):
            findings.append(_finding("v1_worker_spawn_unobserved", str(detail)))
        spawned_value = False if (output_seen or spawn.get("called")) else None
    else:
        spawned_value = worker_surface == "v1"
        if worker_surface != "v1":
            findings.append(_finding(
                "live_surface_not_v1", "The worker ran on " + str(worker_surface) + "."
            ))
        if worker.get("status") != "completed":
            findings.append(_finding(
                "worker_failed", str(worker.get("detail") or FINDINGS["worker_failed"])
            ))

    calls = int(observation.get("root_tool_calls") or 0) + int(worker.get("tool_calls") or 0)
    parse_errors = int(observation.get("root_tool_parse_errors") or 0) + int(
        worker.get("tool_parse_errors") or 0
    )
    if parse_errors:
        tool_calls = "unparsable"
        findings.append(_finding(
            "tool_calls_unparsable", str(parse_errors) + " tool call(s) did not parse."
        ))
    elif calls:
        tool_calls = "parsed"
    elif output_seen:
        tool_calls = "absent"
        findings.append(_finding("tool_calls_absent", FINDINGS["tool_calls_absent"]))
    else:
        tool_calls = "unknown"

    artifact_state = classify_artifact(observation.get("artifact_text"), model=model, nonce=nonce)
    if not spawned and artifact_state == "missing":
        artifact_state = "unknown" if not output_seen else "missing"
    if artifact_state in ("missing", "unparsable", "schema_mismatch") and (output_seen or spawned):
        findings.append(_finding("artifact_" + artifact_state, FINDINGS["artifact_" + artifact_state]))

    unique: dict[tuple[str, str], dict[str, str]] = {}
    for row in findings:
        unique.setdefault((row["code"], row["detail"]), row)
    return {
        "reachability": reachability,
        "tool_calls": tool_calls,
        "artifact": artifact_state,
        "surfaces": surfaces,
        "v1_location": v1_location,
        "v1_unavailable": v1_unavailable,
        "live_surface": root_surface if root_surface in SURFACES else None,
        "worker_surface": worker_surface if worker_surface in SURFACES else None,
        "collaboration_tools_offered": collaboration,
        "v1_worker_spawned": spawned_value,
        "findings": sorted(unique.values(), key=lambda row: (row["code"], row["detail"])),
    }


def build_profile(
    *,
    model: str,
    onboarded_at: str,
    codex_version: str,
    route: Mapping[str, Any],
    catalog: Mapping[str, Any],
    v2_feature_enabled: bool,
    verdict: Mapping[str, Any],
    sample: Mapping[str, Any],
    probe: Mapping[str, Any],
) -> dict[str, Any]:
    """Assemble and seal one profile from the driver's facts and the verdict."""

    family = family_for_model(model)
    surfaces = verdict["surfaces"]
    profile = {
        "schema": PROFILE_SCHEMA,
        "model": model,
        "onboarded_at": onboarded_at,
        "codex_version": codex_version,
        "route": dict(route),
        "family": (
            {"status": "inferred", "value": family}
            if family is not None
            else unknown("name_not_obvious")
        ),
        "catalog": dict(catalog),
        "surface": {
            "v2_feature_enabled": bool(v2_feature_enabled),
            "user_codex": observed_surface(surfaces.get("user_codex")),
            "governed_runner": observed_surface(surfaces.get("governed_runner")),
            "v1_location": verdict["v1_location"],
            "v1_unavailable": verdict["v1_unavailable"],
            "live": observed_surface(verdict["live_surface"]),
            "worker": observed_surface(verdict["worker_surface"]),
            "collaboration_tools_offered": verdict["collaboration_tools_offered"],
            "v1_worker_spawned": verdict["v1_worker_spawned"],
        },
        "reachability": verdict["reachability"],
        "tool_calls": verdict["tool_calls"],
        "artifact": verdict["artifact"],
        "sample": dict(sample),
        "findings": [dict(row) for row in verdict["findings"]],
        "probe": dict(probe),
        "first_run_error": None,
    }
    sealed = seal(profile)
    issues = validate_profile(sealed)
    if issues:
        raise ValueError(",".join(issues))
    return sealed


def _closed(value: Any, fields: frozenset[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        issues.append(path + ":not_object")
        return False
    keys = set(value)
    for key in sorted(str(item) for item in keys - fields):
        issues.append(path + ":unknown:" + key)
    for key in sorted(fields - keys):
        issues.append(path + ":missing:" + key)
    return keys == fields


def _text(value: Any, *, nullable: bool = False) -> bool:
    if value is None:
        return nullable
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= _MAX_TEXT_BYTES
    )


def _count(value: Any) -> bool:
    return value is None or (type(value) is int and value >= 0)


def _fact_issues(value: Any, path: str, issues: list[str], kinds: tuple[type, ...]) -> None:
    if not isinstance(value, Mapping):
        issues.append(path + ":not_object")
        return
    if value.get("status") == "stated":
        if set(value) != {"status", "value", "source"}:
            issues.append(path + ":shape_invalid")
        elif value["source"] not in FACT_SOURCES or type(value["value"]) not in kinds:
            issues.append(path + ":stated_invalid")
    elif value.get("status") == "unknown":
        if set(value) != {"status", "reason"} or not _text(value.get("reason")):
            issues.append(path + ":unknown_invalid")
    else:
        issues.append(path + ":status_invalid")


def _surface_issues(value: Any, path: str, issues: list[str]) -> None:
    if not isinstance(value, Mapping):
        issues.append(path + ":not_object")
    elif value.get("status") == "observed":
        if set(value) != {"status", "value"} or value.get("value") not in SURFACES:
            issues.append(path + ":observed_invalid")
    elif value.get("status") == "unknown":
        if set(value) != {"status", "reason"} or not _text(value.get("reason")):
            issues.append(path + ":unknown_invalid")
    else:
        issues.append(path + ":status_invalid")


def validate_profile(value: Any) -> list[str]:
    """Return every reason value is not one sealed onboarded profile."""

    issues: list[str] = []
    if not _closed(value, _PROFILE_FIELDS, "profile", issues):
        return sorted(set(issues))
    try:
        size = len(contracts.canonical_bytes(value))
    except (TypeError, ValueError, OverflowError, RecursionError):
        return ["profile:hostile_or_non_json_input"]
    if size > _MAX_PROFILE_BYTES:
        issues.append("profile:too_large")
    if value["schema"] != PROFILE_SCHEMA:
        issues.append("profile:schema_invalid")
    if not isinstance(value["model"], str) or not _MODEL.fullmatch(value["model"]):
        issues.append("profile:model_invalid")
    if not isinstance(value["onboarded_at"], str) or not _TIMESTAMP.fullmatch(value["onboarded_at"]):
        issues.append("profile:onboarded_at_invalid")
    if not _text(value["codex_version"]):
        issues.append("profile:codex_version_invalid")

    route = value["route"]
    if _closed(route, _ROUTE_FIELDS, "profile.route", issues):
        if not _text(route["provider_id"]):
            issues.append("profile.route:provider_id_invalid")
        for field in ("base_url", "upstream_provider", "upstream_base_url"):
            if not _text(route[field], nullable=True):
                issues.append("profile.route:" + field + "_invalid")
        if route["via"] not in ROUTE_VIA:
            issues.append("profile.route:via_invalid")
        if route["via"] == "direct" and (route["upstream_provider"], route["upstream_base_url"]) != (None, None):
            issues.append("profile.route:upstream_without_proxy")
        if route["location"] not in LOCATIONS or route["location_basis"] not in LOCATION_BASES:
            issues.append("profile.route:location_invalid")
        elif (route["location"], route["location_basis"]) != classify_location(route):
            issues.append("profile.route:location_inconsistent")

    family = value["family"]
    expected_family = family_for_model(value["model"])
    if family != (
        {"status": "inferred", "value": expected_family}
        if expected_family is not None
        else unknown("name_not_obvious")
    ):
        issues.append("profile:family_inconsistent")

    catalog = value["catalog"]
    if _closed(catalog, _CATALOG_FIELDS, "profile.catalog", issues):
        if catalog["source"] not in CATALOG_SOURCES:
            issues.append("profile.catalog:source_invalid")
        digest = catalog["entry_sha256"]
        if digest is not None and (not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
            issues.append("profile.catalog:entry_sha256_invalid")
        if catalog["source"] == "absent" and digest is not None:
            issues.append("profile.catalog:entry_without_source")
        if catalog["row_surface"] is not None and catalog["row_surface"] not in SURFACES:
            issues.append("profile.catalog:row_surface_invalid")
        if not _text(catalog["rewritten_from"], nullable=True):
            issues.append("profile.catalog:rewritten_from_invalid")
        _fact_issues(catalog["context_window"], "profile.catalog.context_window", issues, (int,))
        _fact_issues(catalog["max_output_tokens"], "profile.catalog.max_output_tokens", issues, (int,))
        _fact_issues(catalog["default_effort"], "profile.catalog.default_effort", issues, (str,))
        _fact_issues(catalog["parallel_tool_calls"], "profile.catalog.parallel_tool_calls", issues, (bool,))

    surface = value["surface"]
    if _closed(surface, _SURFACE_FIELDS, "profile.surface", issues):
        if type(surface["v2_feature_enabled"]) is not bool:
            issues.append("profile.surface:v2_feature_enabled_invalid")
        for field in ("user_codex", "governed_runner", "live", "worker"):
            _surface_issues(surface[field], "profile.surface." + field, issues)
        location = surface["v1_location"]
        unavailable = surface["v1_unavailable"]
        if location is not None and location not in V1_LOCATIONS:
            issues.append("profile.surface:v1_location_invalid")
        if (location is None) == (unavailable is None):
            issues.append("profile.surface:v1_location_and_reason_exclusive")
        if unavailable is not None and _closed(
            unavailable, _V1_UNAVAILABLE_FIELDS, "profile.surface.v1_unavailable", issues
        ):
            if unavailable["reason"] not in _V1_UNAVAILABLE_REASONS:
                issues.append("profile.surface.v1_unavailable:reason_invalid")
            tried = unavailable["tried"]
            if not isinstance(tried, list) or not tried or any(item not in V1_LOCATIONS for item in tried):
                issues.append("profile.surface.v1_unavailable:tried_invalid")
            if not _text(unavailable["codex_reported"]):
                issues.append("profile.surface.v1_unavailable:codex_reported_invalid")
        if location is not None and surface[location] != {"status": "observed", "value": "v1"}:
            issues.append("profile.surface:v1_location_unobserved")
        for field in ("collaboration_tools_offered", "v1_worker_spawned"):
            if surface[field] not in (True, False, None):
                issues.append("profile.surface:" + field + "_invalid")

    if value["reachability"] not in REACHABILITY:
        issues.append("profile:reachability_invalid")
    if value["tool_calls"] not in TOOL_CALL_STATES:
        issues.append("profile:tool_calls_invalid")
    if value["artifact"] not in ARTIFACT_STATES:
        issues.append("profile:artifact_invalid")

    sample = value["sample"]
    if _closed(sample, _SAMPLE_FIELDS, "profile.sample", issues):
        if not _text(sample["effort"]):
            issues.append("profile.sample:effort_invalid")
        for field in ("effective_context_window", "first_output_ms", "root_turn_ms", "worker_turn_ms"):
            if not _count(sample[field]):
                issues.append("profile.sample:" + field + "_invalid")
        tokens = sample["tokens"]
        if _closed(tokens, _TOKEN_FIELDS, "profile.sample.tokens", issues):
            if not all(_count(tokens[field]) for field in _TOKEN_FIELDS):
                issues.append("profile.sample.tokens:invalid")

    findings = value["findings"]
    if not isinstance(findings, list) or len(findings) > _MAX_FINDINGS * 4:
        issues.append("profile:findings_invalid")
    else:
        keys = []
        for index, row in enumerate(findings):
            path = "profile.findings[" + str(index) + "]"
            if not _closed(row, _FINDING_FIELDS, path, issues):
                continue
            if row["code"] not in FINDINGS:
                issues.append(path + ":code_invalid")
            if not _text(row["detail"]):
                issues.append(path + ":detail_invalid")
            keys.append((str(row["code"]), str(row["detail"])))
        if keys != sorted(set(keys)):
            issues.append("profile:findings_unsorted_or_duplicate")

    probe = value["probe"]
    if _closed(probe, _PROBE_FIELDS, "profile.probe", issues):
        if type(probe["spawns"]) is not int or probe["spawns"] not in (0, 1):
            issues.append("profile.probe:spawns_invalid")
        if type(probe["duration_ms"]) is not int or probe["duration_ms"] < 0:
            issues.append("profile.probe:duration_ms_invalid")
        if probe["dry_run_model_calls"] != 0:
            issues.append("profile.probe:dry_run_model_calls_invalid")
        if not _text(probe["harness"]):
            issues.append("profile.probe:harness_invalid")

    first_error = value["first_run_error"]
    if first_error is not None and _closed(
        first_error, _FIRST_ERROR_FIELDS, "profile.first_run_error", issues
    ):
        if not isinstance(first_error["observed_at"], str) or not _TIMESTAMP.fullmatch(first_error["observed_at"]):
            issues.append("profile.first_run_error:observed_at_invalid")
        if not _text(first_error["message"]):
            issues.append("profile.first_run_error:message_invalid")

    digest = value["profile_sha256"]
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest) or digest != _sha256(
        {key: item for key, item in value.items() if key != "profile_sha256"}
    ):
        issues.append("profile:seal_invalid")
    return sorted(set(issues))


def redo_reasons(
    profile: Mapping[str, Any],
    *,
    model: str,
    catalog_entry: Any,
    codex_version: str,
) -> list[str]:
    """Why a stored profile must be redone; empty when it is reused.

    A profile is reused until the model's name or catalog entry, the Codex
    version, or a first error on a real run changes.  A user asking for
    onboarding again is the caller's to honor.
    """

    reasons = []
    if profile.get("model") != model:
        reasons.append("model_changed")
    if profile.get("catalog", {}).get("entry_sha256") != catalog_entry_sha256(catalog_entry):
        reasons.append("catalog_entry_changed")
    if profile.get("codex_version") != codex_version:
        reasons.append("codex_version_changed")
    if profile.get("first_run_error") is not None:
        reasons.append("first_run_error")
    return reasons


def store_root(root: Any = None) -> Path:
    """The host-local profile store: root, the environment's, or the default."""

    if root is not None:
        return Path(root).expanduser()
    configured = os.environ.get(STORE_ENV)
    if configured:
        return Path(configured).expanduser()
    return Path.home().joinpath(*DEFAULT_STORE_PARTS)


def profile_name(model: str) -> str:
    """The file name of a model's profile: readable, and unique by digest."""

    readable = re.sub(r"[^A-Za-z0-9._-]+", "_", model).strip("._-")[:80] or "model"
    return readable + "--" + hashlib.sha256(model.encode("utf-8")).hexdigest()[:16] + ".json"


def profile_path(model: str, root: Any = None) -> Path:
    return store_root(root) / "profiles" / profile_name(model)


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def read_profile(model: str, root: Any = None) -> dict[str, Any] | None:
    """The stored profile for model, or None; an invalid record raises ValueError."""

    path = profile_path(model, root)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    if len(data) > _MAX_PROFILE_BYTES:
        raise ValueError("profile:too_large")
    value = json.loads(data.decode("utf-8"))
    issues = validate_profile(value)
    if issues:
        raise ValueError(",".join(issues))
    if value["model"] != model:
        raise ValueError("profile:model_mismatch")
    return value


def onboarded(model: Any, root: Any = None) -> dict[str, Any] | None:
    """The model's valid stored profile, or None; this never raises."""

    if not isinstance(model, str) or not _MODEL.fullmatch(model):
        return None
    try:
        return read_profile(model, root)
    except (OSError, ValueError, UnicodeDecodeError):
        return None


# Why a root's live task reports another surface than V1, named for the
# governed-activation refusal: the drift since a profile that reached V1,
# the reason a profile records for V1 being unavailable, or no profile.
V1_REFUSAL_REASONS = ("drift_since_onboarding", *_V1_UNAVAILABLE_REASONS, "not_onboarded")


def v1_refusal_reason(profile: Mapping[str, Any] | None) -> str:
    """The reason a task off V1 refuses, read from the model's profile."""

    if profile is None:
        return "not_onboarded"
    unavailable = profile["surface"]["v1_unavailable"]
    if unavailable is None:
        return "drift_since_onboarding"
    return unavailable["reason"]


def write_profile(profile: Mapping[str, Any], root: Any = None) -> Path:
    """Store a sealed profile, keeping the one it replaces in history."""

    issues = validate_profile(profile)
    if issues:
        raise ValueError(",".join(issues))
    base = store_root(root)
    profiles = base / "profiles"
    history = base / "history" / profile_name(profile["model"])[: -len(".json")]
    _private_directory(base)
    _private_directory(profiles)
    path = profiles / profile_name(profile["model"])
    if path.exists():
        _private_directory(history)
        previous = path.read_bytes()
        stamp = hashlib.sha256(previous).hexdigest()[:16]
        target = history / (stamp + ".json")
        if not target.exists():
            _create_private(target, previous)
    data = contracts.canonical_bytes(profile) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".profile-", dir=profiles)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return path


def list_profiles(root: Any = None) -> list[dict[str, Any]]:
    """Every valid stored profile, ordered by model."""

    directory = store_root(root) / "profiles"
    found = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else ():
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not validate_profile(value) and path.name == profile_name(value["model"]):
            found.append(value)
    return sorted(found, key=lambda row: row["model"])


# ---------------------------------------------------------------- V1 location
#
# Every governed run uses the V1 collaboration surface (ADR 0012), settled
# once at enrollment.  Governed runs use the user's own Codex when its V2
# feature is off and every catalog row states v1; otherwise they use the
# governed runner, a second app server launched with the user's login, the
# V2 feature off and an all-v1 copy of the catalog the server would otherwise
# load (an overlay replaces the whole catalog, so the copy keeps every other
# model the user has).  Making the user's own Codex run every model on V1 is
# an opt-in that changes nothing until the user confirms the exact plan.

V1_LOCATION_SCHEMA = "orch-dork/v1-location/v1"
USER_CODEX_V1_PLAN_SCHEMA = "orch-dork/user-codex-v1-change-plan/v1"
USER_CODEX_V1_REPORT_SCHEMA = "orch-dork/user-codex-v1-change-report/v1"
USER_CODEX_V1_KINDS = ("opencodex_multi_agent_mode", "catalog_overlay")
# The overlay the opt-in writes beside the user's Codex configuration.
USER_CODEX_V1_OVERLAY_NAME = "orch-dork-v1-catalog.json"
_TOML_TABLE = re.compile(r"\A\s*\[")
_TOML_KEY = re.compile(r"\A\s*([A-Za-z0-9_.\"-]+?)\s*=\s*(.*?)\s*\Z")


def catalog_rows(value: Any) -> list[Mapping[str, Any]]:
    """The rows of a Codex catalog ({"models": [...]}) or of a model/list page."""

    rows = value.get("models", value.get("data")) if isinstance(value, Mapping) else value
    if not isinstance(rows, list):
        raise ValueError("catalog:rows_invalid")
    return [row for row in rows if isinstance(row, Mapping)]


def row_model(row: Mapping[str, Any]) -> str | None:
    """The model a catalog row or model/list entry names."""

    for key in ("slug", "model", "id"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def row_surface(row: Mapping[str, Any]) -> str | None:
    """The surface a catalog row (multi_agent_version) or model/list entry
    (multiAgentVersion) states, or None."""

    value = row.get("multi_agent_version", row.get("multiAgentVersion"))
    return value if value in SURFACES else None


def v1_location(rows: Any, *, v2_feature_enabled: bool) -> dict[str, Any]:
    """Where governed runs hold V1, read from every catalog row and the V2 feature.

    The user's own Codex when its V2 feature is off and every row states v1;
    otherwise the governed runner.  A row stating no surface is not v1.
    """

    listed = catalog_rows(rows)
    off_v1 = sorted({row_model(row) or "<unnamed>" for row in listed if row_surface(row) != "v1"})
    location = (
        "user_codex" if listed and not off_v1 and v2_feature_enabled is False else "governed_runner"
    )
    core = {
        "schema": V1_LOCATION_SCHEMA,
        "location": location,
        "v2_feature_enabled": v2_feature_enabled is True,
        "rows": len(listed),
        "rows_not_v1": off_v1,
    }
    return {**core, "report_sha256": _sha256(core)}


def all_v1_catalog(catalog: Any) -> dict[str, Any]:
    """A copy of a Codex catalog with every row set to v1 and nothing else changed."""

    if not isinstance(catalog, Mapping) or not isinstance(catalog.get("models"), list):
        raise ValueError("catalog:invalid")
    copy = json.loads(json.dumps(catalog, allow_nan=False))
    for row in copy["models"]:
        if isinstance(row, dict):
            row["multi_agent_version"] = "v1"
    return copy


def _catalog_bytes(catalog: Any) -> bytes:
    return (json.dumps(catalog, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _create_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def write_all_v1_overlay(catalog: Any, path: Any) -> str:
    """Write the governed runner's all-v1 catalog create-only; return its sha256."""

    data = _catalog_bytes(all_v1_catalog(catalog))
    _create_private(Path(path), data)
    return hashlib.sha256(data).hexdigest()


def governed_runner_overrides(overlay_path: Any) -> list[str]:
    """The app-server configuration that holds every model on V1.

    A task's own configuration can switch the V2 feature off but cannot
    replace the catalog, which an app server reads when it starts, so the
    overlay is named on the app server's command line.
    """

    return [
        "-c",
        "model_catalog_json=" + json.dumps(str(overlay_path)),
        "-c",
        "features.multi_agent_v2.enabled=false",
    ]


def _replace_atomically(path: Path, data: bytes) -> None:
    mode = os.stat(path).st_mode & 0o777
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _toml_unquoted(key: str) -> str:
    return ".".join(part.strip().strip('"') for part in key.split("."))


def configured_catalog_path(codex_home: Any) -> Path | None:
    """The catalog file a Codex configuration names at its top level, or None.

    Only the top-level model_catalog_json setting is read; nothing else in
    the configuration is.
    """

    try:
        text = (Path(codex_home).expanduser() / "config.toml").read_text(encoding="utf-8")
    except (FileNotFoundError, NotADirectoryError):
        return None
    for line in text.splitlines():
        if _TOML_TABLE.match(line):
            return None
        match = _TOML_KEY.match(line)
        if not match or _toml_unquoted(match.group(1)) != "model_catalog_json":
            continue
        raw = match.group(2)
        try:
            if raw.startswith('"'):
                value, _end = json.JSONDecoder().raw_decode(raw)
            elif raw.startswith("'"):
                value = raw[1:raw.index("'", 1)]
            else:
                return None
        except ValueError:
            return None
        return Path(value).expanduser() if isinstance(value, str) and value else None
    return None


def _toml_with_catalog(text: str, overlay: Path) -> str:
    """config.toml text whose top-level model_catalog_json names overlay.

    An existing top-level setting is replaced in place; otherwise the line
    ends the top-level block, before the first table.
    """

    line = "model_catalog_json = " + json.dumps(str(overlay))
    lines = text.splitlines()
    first_table = next((index for index, row in enumerate(lines) if _TOML_TABLE.match(row)), len(lines))
    for index in range(first_table):
        match = _TOML_KEY.match(lines[index])
        if match and _toml_unquoted(match.group(1)) == "model_catalog_json":
            lines[index] = line
            break
    else:
        position = first_table
        while position > 0 and not lines[position - 1].strip():
            position -= 1
        lines.insert(position, line)
    return "\n".join(lines) + "\n"


def _toml_without_v2(text: str) -> tuple[str, str | None]:
    """config.toml text with the V2 feature switched off, and why it is not.

    The reason is v2_feature_setting_unrecognized when the setting is written
    in a form this edit does not recognize, v2_feature_setting_not_found when
    no setting it recognizes switches the feature on, and None once the text
    switches the feature off.
    """

    lines = text.splitlines()
    table = ""
    changed = False
    for index, row in enumerate(lines):
        if _TOML_TABLE.match(row):
            table = _toml_unquoted(row.strip().strip("[]"))
            continue
        match = _TOML_KEY.match(row)
        if not match:
            continue
        key = _toml_unquoted(match.group(1))
        full = (table + "." + key) if table else key
        value = match.group(2).split("#", 1)[0].strip()
        if full in ("features", "features.multi_agent_v2") and value.startswith("{") and (
            full == "features.multi_agent_v2" or "multi_agent_v2" in value
        ):
            return text, "v2_feature_setting_unrecognized"
        if full in ("features.multi_agent_v2", "features.multi_agent_v2.enabled"):
            if value == "true":
                lines[index] = match.group(1) + " = false"
                changed = True
            elif value != "false":
                return text, "v2_feature_setting_unrecognized"
    if not changed:
        return text, "v2_feature_setting_not_found"
    return "\n".join(lines) + "\n", None


def _opencodex_mode(path: Path) -> tuple[Any, bytes] | None:
    try:
        data = path.read_bytes()
        value = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("providers"), dict):
        return None
    return value, data


def _planned_change(
    home: Path, catalog: Any, v2_feature_enabled: bool, opencodex_config: Any
) -> dict[str, Any]:
    """Everything the opt-in would write, read from the current files once.

    The plan seals the kind, status, edits and issues; applying writes the
    exact bytes computed here, so nothing is derived a second time.
    """

    config_path = home / "config.toml"
    try:
        config_bytes: bytes | None = config_path.read_bytes()
    except FileNotFoundError:
        config_bytes = None
    config_text = (config_bytes or b"").decode("utf-8")
    edits: list[dict[str, Any]] = []
    issues: list[str] = []
    status = None
    opencodex_path = Path(opencodex_config).expanduser() if opencodex_config is not None else None
    opencodex = _opencodex_mode(opencodex_path) if opencodex_path is not None else None
    kind = "opencodex_multi_agent_mode" if opencodex is not None else "catalog_overlay"
    rows_v1 = all(row_surface(row) == "v1" for row in catalog_rows(catalog))
    opencodex_value = None
    overlay_catalog = None
    if rows_v1 and not v2_feature_enabled:
        status = "NO_CHANGE"
    elif opencodex is not None and opencodex[0].get("multiAgentMode") != "v1":
        opencodex_value = {**opencodex[0], "multiAgentMode": "v1"}
        edits.append({
            "path": str(opencodex_path),
            "before_sha256": hashlib.sha256(opencodex[1]).hexdigest(),
            "change": "multiAgentMode=v1",
        })
    elif opencodex is not None:
        if not rows_v1:
            # OpenCodex rewrites its catalog when it restarts.
            status = "RESTART_REQUIRED"
    elif not rows_v1:
        overlay = home / USER_CODEX_V1_OVERLAY_NAME
        if overlay.exists():
            issues.append("overlay_exists")
        overlay_catalog = all_v1_catalog(catalog)
        edits.append({
            "path": str(overlay),
            "before_sha256": None,
            "change": "create:all_v1_catalog:" + hashlib.sha256(_catalog_bytes(overlay_catalog)).hexdigest(),
        })
        config_text = _toml_with_catalog(config_text, overlay)
    if v2_feature_enabled and status is None:
        config_text, reason = _toml_without_v2(config_text)
        if reason is not None:
            issues.append(reason)
    new_config = config_text.encode("utf-8")
    if new_config != (config_bytes or b""):
        edits.append({
            "path": str(config_path),
            "before_sha256": hashlib.sha256(config_bytes).hexdigest() if config_bytes is not None else None,
            "change": "config:" + hashlib.sha256(new_config).hexdigest(),
        })
    if issues:
        status = "MANUAL_CHANGE_REQUIRED"
    elif status is None:
        status = "CONFIRMATION_REQUIRED" if edits else "NO_CHANGE"
    return {
        "kind": kind,
        "status": status,
        "edits": edits,
        "issues": sorted(issues),
        "config_path": config_path,
        "config_bytes": new_config,
        "config_existed": config_bytes is not None,
        "opencodex_value": opencodex_value,
        "overlay_catalog": overlay_catalog,
    }


def _sealed_plan(home: Path, change: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        "schema": USER_CODEX_V1_PLAN_SCHEMA,
        "status": change["status"],
        "kind": change["kind"],
        "codex_home": str(home),
        "edits": change["edits"],
        "issues": change["issues"],
        "restart_required": change["status"] in ("CONFIRMATION_REQUIRED", "RESTART_REQUIRED"),
    }
    return {**core, "plan_sha256": _sha256(core)}


def plan_user_codex_v1_change(
    *,
    codex_home: Any,
    catalog: Any,
    v2_feature_enabled: bool,
    opencodex_config: Any = None,
) -> dict[str, Any]:
    """The opt-in change that makes the user's own Codex run every model on V1.

    When OpenCodex writes the catalog the user's Codex loads, its
    multiAgentMode is set to v1; otherwise an all-v1 copy of catalog (the
    catalog the app server would otherwise load) is written beside
    config.toml and model_catalog_json names it.  A V2 feature that is on is
    switched off.  The plan names the files and their current digests and
    changes nothing; apply_user_codex_v1_change applies it only when given
    the plan's digest as the user's confirmation.  Credentials never enter
    the plan.  A Codex already running every model on V1 needs no change;
    an OpenCodex already set to v1 whose catalog still states another
    surface needs only its restart.
    """

    home = Path(codex_home).expanduser()
    return _sealed_plan(home, _planned_change(home, catalog, v2_feature_enabled, opencodex_config))


def apply_user_codex_v1_change(
    plan: Any,
    *,
    confirmation: Any,
    codex_home: Any,
    catalog: Any,
    v2_feature_enabled: bool,
    opencodex_config: Any = None,
) -> dict[str, Any]:
    """Apply a planned V1 change after the user confirmed it, and only then.

    confirmation is the plan's digest.  The plan is recomputed from the
    current files; when anything changed since it was shown, nothing is
    written.  After the change the user's app server restarts once no work
    is active.
    """

    def report(status: str, applied: list[str], issues: list[str]) -> dict[str, Any]:
        core = {
            "schema": USER_CODEX_V1_REPORT_SCHEMA,
            "status": status,
            "plan_sha256": plan.get("plan_sha256") if isinstance(plan, Mapping) else None,
            "applied": applied,
            "issues": issues,
            "restart_required": status == "APPLIED",
        }
        return {**core, "report_sha256": _sha256(core)}

    if not isinstance(plan, Mapping) or confirmation != plan.get("plan_sha256"):
        return report("CONFIRMATION_REQUIRED", [], ["confirmation_missing"])
    home = Path(codex_home).expanduser()
    change = _planned_change(home, catalog, v2_feature_enabled, opencodex_config)
    if _sealed_plan(home, change) != dict(plan):
        return report("REFUSED", [], ["changed_since_plan"])
    if plan["status"] != "CONFIRMATION_REQUIRED":
        return report("REFUSED", [], ["plan_not_applicable:" + str(plan["status"])])
    applied = []
    for edit in plan["edits"]:
        path = Path(edit["path"])
        if edit["change"] == "multiAgentMode=v1":
            _replace_atomically(path, (json.dumps(change["opencodex_value"], indent=2) + "\n").encode("utf-8"))
        elif edit["change"].startswith("create:"):
            _create_private(path, _catalog_bytes(change["overlay_catalog"]))
        elif change["config_existed"]:
            _replace_atomically(change["config_path"], change["config_bytes"])
        else:
            _create_private(change["config_path"], change["config_bytes"])
        applied.append(str(path))
    return report("APPLIED", applied, [])


# ---------------------------------------------------------------- admission
#
# No governed run starts until two different models have passed onboarding
# (ADR 0012): a model cannot independently review its own work, and a third
# model adds nothing a run requires.  A model has passed when its route
# answered, it reaches V1, and its profile is current.  Below the minimum the
# advisory features keep working and governed runs refuse with the reasons
# the profiles record.

ADMISSION_SCHEMA = "orch-dork/onboarded-admission/v1"
LINEUP_SCHEMA = "orch-dork/onboarded-lineup/v1"
MINIMUM_GOVERNED_MODELS = 2


def not_passed_reasons(
    profile: Mapping[str, Any],
    *,
    codex_version: str | None = None,
    catalog: Any = None,
) -> list[str]:
    """Why a profile has not passed onboarding; empty when it has.

    A profile passes when its route answered and the model reaches V1, and
    stays current until the redo rule fires: a first error on a real run,
    another Codex version than the one it was onboarded on, or a catalog
    entry that changed since.  The cheap facts are re-observed only when the
    caller supplies them: the installed Codex version, and the catalog the
    app server loads, compared for a profile read from a catalog file.
    """

    reasons = []
    if profile["reachability"] != "reachable":
        reasons.append("reachability:" + str(profile["reachability"]))
    unavailable = profile["surface"]["v1_unavailable"]
    if unavailable is not None:
        reasons.append("v1_unavailable:" + str(unavailable["reason"]))
    if profile["first_run_error"] is not None:
        reasons.append("redo_required:first_run_error")
    if codex_version is not None and profile["codex_version"] != codex_version:
        reasons.append("redo_required:codex_version_changed")
    if catalog is not None and profile["catalog"]["source"] == "model_catalog_json":
        row = next(
            (row for row in catalog_rows(catalog) if row_model(row) == profile["model"]), None
        )
        if catalog_entry_sha256(row) != profile["catalog"]["entry_sha256"]:
            reasons.append("redo_required:catalog_entry_changed")
    return reasons


def governed_admission(
    models: Sequence[str],
    *,
    local_only: bool = False,
    codex_version: str | None = None,
    catalog: Any = None,
    root: Any = None,
) -> dict[str, Any]:
    """Whether a governed run naming models may start.

    It may once two different models have passed onboarding and every model
    it names has passed.  A project kept on this machine counts and admits
    only local models.  Each refusal names the model and the reason its
    profile records; the report binds the digest of every profile it read.
    codex_version and catalog re-observe the cheap facts on this dispatch.
    """

    def reasons(profile: Mapping[str, Any]) -> list[str]:
        return not_passed_reasons(profile, codex_version=codex_version, catalog=catalog)

    def counted(profile: Mapping[str, Any]) -> bool:
        return not reasons(profile) and (
            not local_only or profile["route"]["location"] == "local"
        )

    passed = [profile["model"] for profile in list_profiles(root) if counted(profile)]
    issues = []
    if len(passed) < MINIMUM_GOVERNED_MODELS:
        issues.append("onboarding_minimum_unmet:" + str(len(passed)))
    named = []
    for model in sorted(set(models)):
        profile = onboarded(model, root)
        if profile is None:
            issues.append("model_not_onboarded:" + model)
            continue
        for reason in reasons(profile):
            issues.append("model_not_passed:" + model + ":" + reason)
        if local_only and profile["route"]["location"] != "local":
            issues.append("model_not_local:" + model)
        named.append({
            "model": model,
            "profile_sha256": profile["profile_sha256"],
            "family": profile["family"].get("value"),
            "location": profile["route"]["location"],
            "v1_location": profile["surface"]["v1_location"],
        })
    core = {
        "schema": ADMISSION_SCHEMA,
        "status": "REFUSED" if issues else "ADMITTED",
        "local_only": bool(local_only),
        "passed_models": sorted(passed),
        "models": named,
        "issues": sorted(issues),
    }
    return {**core, "report_sha256": _sha256(core)}


def default_lineup(
    chat_model: str,
    *,
    local_only: bool = False,
    codex_version: str | None = None,
    root: Any = None,
) -> dict[str, Any]:
    """The default governed lineup over the onboarded profiles.

    The model the user chats with plans and reviews; a second model that has
    passed onboarding writes the code, from a different family than the chat
    model's when one has passed.  The reviewer therefore always differs from
    the model that wrote the code; a review of the same or an unknown family
    is labeled, never refused.
    """

    admission = governed_admission(
        [chat_model], local_only=local_only, codex_version=codex_version, root=root
    )
    candidates = [model for model in admission["passed_models"] if model != chat_model]
    chat_family = family_for_model(chat_model)
    # Prefer, in model order, a second model of a known family other than
    # the chat model's; otherwise the first other model that passed.
    other_family = [
        model
        for model in candidates
        if chat_family is not None and family_for_model(model) not in (None, chat_family)
    ]
    if other_family:
        implementer = other_family[0]
    elif candidates:
        implementer = candidates[0]
    else:
        implementer = None
    issues = list(admission["issues"])
    if implementer is None and not any(item.startswith("onboarding_minimum_unmet") for item in issues):
        issues.append("second_model_unavailable")
    label = None
    if implementer is not None:
        implementer_family = family_for_model(implementer)
        if chat_family is None or implementer_family is None:
            label = "family_unknown"
        elif chat_family == implementer_family:
            label = "same_family"
    core = {
        "schema": LINEUP_SCHEMA,
        "status": "REFUSED" if issues else "READY",
        "planner": chat_model,
        "reviewer": chat_model,
        "implementer": implementer if not issues else None,
        "review_label": label if not issues else None,
        "admission_sha256": admission["report_sha256"],
        "issues": sorted(issues),
    }
    return {**core, "report_sha256": _sha256(core)}


def record_first_run_error(
    model: str,
    *,
    message: str,
    codex_error_info: Any = None,
    observed_at: str | None = None,
    root: Any = None,
) -> dict[str, Any] | None:
    """Record a model's first typed provider error on a real run, once.

    The profile is re-sealed with the error and must be redone before the
    model passes onboarding again.  A model with no profile, or one whose
    first error is already recorded, is left unchanged.
    """

    profile = onboarded(model, root)
    if profile is None or profile["first_run_error"] is not None:
        return None
    text = " ".join(str(message).split()) or "provider error"
    encoded = text.encode("utf-8")
    if len(encoded) > _MAX_TEXT_BYTES:
        text = encoded[: _MAX_TEXT_BYTES - 3].decode("utf-8", "ignore") + "..."
    try:
        contracts.canonical_bytes(codex_error_info)
    except (TypeError, ValueError, OverflowError, RecursionError):
        codex_error_info = None
    updated = seal({
        **profile,
        "first_run_error": {
            "observed_at": observed_at or utc_now(),
            "codex_error_info": codex_error_info,
            "message": text,
        },
    })
    write_profile(updated, root)
    return updated
