"""Agent Lifecycle Map publication and next-invocation projection (FR64, section 11).

This module is a navigation aid over the existing public surface, not a second
controller. It publishes one closed orch-dork/agent-lifecycle-map/v1 inventory
as bounded read-only MCP resources and derives one compact
orch-dork/agent-next-invocation/v1 projection beside lifecycle-bearing tool
results. It never changes a canonical report, supplies tool input, grants
authority, or counts as evidence or a receipt. A map that drifts from the
live tool catalogue, skill, references, scenarios, or schemas refuses
publication by name instead of guessing.
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

_SCRIPTS_DIR = Path(__file__).resolve().parent
_SKILL_DIR = _SCRIPTS_DIR.parent
_PLUGIN_ROOT = _SKILL_DIR.parents[1]

MAP_PATH = _SKILL_DIR / "runtime" / "agent-lifecycle-map-v1.json"
SKILL_PATH = _SKILL_DIR / "SKILL.md"
REFERENCES_DIR = _SKILL_DIR / "references"
RUNTIME_DIR = _SKILL_DIR / "runtime"
MANIFEST_PATH = _PLUGIN_ROOT / ".codex-plugin" / "plugin.json"

MAP_SCHEMA = "orch-dork/agent-lifecycle-map/v1"
MAP_GENERATION = "agent-lifecycle-map/v1"
INDEX_SCHEMA = "orch-dork/agent-lifecycle-index/v1"
JOURNEY_SCHEMA = "orch-dork/agent-lifecycle-journey/v1"
PROJECTION_SCHEMA = "orch-dork/agent-next-invocation/v1"
AUTHORITY = "navigation_only"
URI_ROOT = "orch-dork://lifecycle"
DISPOSITIONS = ("INVOKE", "AWAIT_EVIDENCE", "AWAIT_DECISION", "STOP", "TERMINAL")

MAX_TEXT_CHARS = 600
MAX_RESOURCE_BYTES = 16_384
MAX_PROJECTION_BYTES = 4_096
MAX_CODES = 16
MAX_CODE_CHARS = 120
MAX_REFS = 8

_MAP_FIELDS = frozenset(
    {"schema", "map_generation", "authority", "journeys", "projections", "scenario_projection"}
)
_JOURNEY_FIELDS = frozenset(
    {
        "id",
        "title",
        "trigger_class",
        "when",
        "prerequisites",
        "report_schemas",
        "terminal_statuses",
        "typed_stops",
        "skill_sections",
        "references",
        "entry",
        "steps",
        "evidence_boundary",
        "primary_tools",
        "supporting_tools",
        "scenarios",
    }
)
_ENTRY_FIELDS = frozenset({"tool", "operation", "input_schema"})
_STEP_FIELDS = frozenset({"tool", "purpose"})
_PROJECTION_RULE_FIELDS = frozenset({"status_paths", "rules"})
_JOURNEY_ID = re.compile(r"\A[a-z][a-z0-9-]{1,47}\Z")
_TRIGGER = re.compile(r"\A[a-z][a-z0-9_]{1,47}\Z")
MAX_PREREQUISITES = 6
_IDENTIFIER = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")
_STATUS = re.compile(r"\A[A-Z][A-Z0-9_]{1,63}\Z")
_PATH = re.compile(r"\A[a-z_]+(?:\.[a-z_]+){0,3}\Z")
_SCHEMA_ID = re.compile(r"\Aorch-dork/[a-z0-9-]+/v[0-9]+\Z")
_REFERENCE = re.compile(r"\A[a-z0-9-]+\.md\Z")
_SCENARIO = re.compile(r"\A[a-z0-9-]+/[a-z0-9-]+\.json\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_HOST_PATH = re.compile(r"(?:\A|[\s:'\"=(\[])(?:/(?:home|Users|tmp|var|etc|root|private|opt|srv|mnt)/|[A-Za-z]:\\)")
_SECRET = re.compile(r"(?:\b(?:sk|pk|rk|ghp|gho|ghs|xox[abprs]|AKIA)[-_A-Za-z0-9]{16,}|PRIVATE KEY)")

_SCHEMA_CACHE: dict[str, frozenset[str]] = {}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _private(text: str) -> bool:
    return bool(_HOST_PATH.search(text) or _SECRET.search(text))


def _tool_catalog() -> list[Mapping[str, Any]]:
    """The live public tool catalogue; the policy server passes it explicitly."""

    policy = sys.modules.get("orch_dork_policy")
    if policy is None:
        spec = importlib.util.spec_from_file_location(
            "orch_dork_policy", _SCRIPTS_DIR / "orch_dork_policy.py"
        )
        policy = importlib.util.module_from_spec(spec)
        sys.modules["orch_dork_policy"] = policy
        spec.loader.exec_module(policy)
    return list(policy.list_tools())


_SCHEMA_CONSTANT = re.compile(
    r'^[A-Z][A-Z0-9_]*\s*=\s*\(?\s*"(orch-dork/[a-z0-9-]+/v[0-9]+)"', re.MULTILINE
)


def _defined_schemas() -> frozenset[str]:
    """Schema identifiers the runtime package defines as module constants."""

    cached = _SCHEMA_CACHE.get("defined")
    if cached is None:
        cached = frozenset(
            match
            for path in sorted(_SCRIPTS_DIR.glob("*.py"))
            for match in _SCHEMA_CONSTANT.findall(path.read_text(encoding="utf-8"))
        )
        _SCHEMA_CACHE["defined"] = cached
    return cached


def _schema_known(schema: str) -> bool:
    return schema in _defined_schemas()


def _skill_sections() -> set[str]:
    return {
        line[3:].strip()
        for line in SKILL_PATH.read_text(encoding="utf-8").splitlines()
        if line.startswith("## ")
    }


def _issue(issues: list[str], path: str, code: str) -> None:
    issues.append("agent_lifecycle:" + path + ":" + code)


def _items(value: Any, path: str, issues: list[str], *, empty: bool = True) -> list[Any]:
    if not isinstance(value, list) or (not empty and not value):
        _issue(issues, path, "invalid")
        return []
    return value


def _text_issues(value: Any, path: str, issues: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        _issue(issues, path, "text_invalid")
    elif len(value) > MAX_TEXT_CHARS:
        _issue(issues, path, "text_oversized")
    elif _private(value):
        _issue(issues, path, "text_private")


def _exact(value: Any, fields: frozenset[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping) or set(value) != fields:
        _issue(issues, path, "shape_invalid")
        return False
    return True


def _tool_list(value: Any, tools: set[str], path: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list) or len(value) != len(set(map(str, value))):
        _issue(issues, path, "invalid")
        return []
    for name in value:
        if name not in tools:
            _issue(issues, path, "tool_unknown:" + str(name)[:64])
    return [name for name in value if isinstance(name, str)]


def _validate_journey(
    journey: Any, index: int, tools: set[str], sections: set[str], issues: list[str]
) -> tuple[str | None, list[str]]:
    path = "journeys[" + str(index) + "]"
    if not _exact(journey, _JOURNEY_FIELDS, path, issues):
        return None, []
    journey_id = journey.get("id")
    if not isinstance(journey_id, str) or not _JOURNEY_ID.fullmatch(journey_id):
        _issue(issues, path, "id_invalid")
        journey_id = None
    if not isinstance(journey.get("trigger_class"), str) or not _TRIGGER.fullmatch(journey["trigger_class"]):
        _issue(issues, path, "trigger_class_invalid")
    for field in ("title", "when", "evidence_boundary"):
        _text_issues(journey.get(field), path + "." + field, issues)
    prerequisites = _items(journey.get("prerequisites"), path + ".prerequisites", issues, empty=False)
    if len(prerequisites) > MAX_PREREQUISITES:
        _issue(issues, path + ".prerequisites", "oversized")
    for item_index, item in enumerate(prerequisites):
        _text_issues(item, path + ".prerequisites[" + str(item_index) + "]", issues)
    for schema in _items(journey.get("report_schemas"), path + ".report_schemas", issues, empty=False):
        if not _schema_valid(schema):
            _issue(issues, path + ".report_schemas", "schema_unknown:" + str(schema)[:64])
    for field in ("terminal_statuses", "typed_stops"):
        for status in _items(journey.get(field), path + "." + field, issues):
            if not isinstance(status, str) or not _STATUS.fullmatch(status):
                _issue(issues, path + "." + field, "status_invalid")
    for section in _items(journey.get("skill_sections"), path + ".skill_sections", issues, empty=False):
        if not isinstance(section, str) or section not in sections:
            _issue(issues, path, "skill_section_missing:" + str(section)[:64])
    for reference in _items(journey.get("references"), path + ".references", issues):
        if (
            not isinstance(reference, str)
            or not _REFERENCE.fullmatch(reference)
            or not (REFERENCES_DIR / reference).is_file()
        ):
            _issue(issues, path, "reference_missing:" + str(reference)[:64])
    for scenario in _items(journey.get("scenarios"), path + ".scenarios", issues):
        if (
            not isinstance(scenario, str)
            or not _SCENARIO.fullmatch(scenario)
            or not (RUNTIME_DIR / scenario).is_file()
        ):
            _issue(issues, path, "scenario_missing:" + str(scenario)[:64])
    entry = journey.get("entry")
    if _exact(entry, _ENTRY_FIELDS, path + ".entry", issues):
        if entry.get("tool") not in tools:
            _issue(issues, path + ".entry", "tool_unknown")
        _operation_issues(entry.get("operation"), path + ".entry", issues)
        schema = entry.get("input_schema")
        if schema is not None and not _schema_valid(schema):
            _issue(issues, path + ".entry", "schema_unknown")
    for step_index, step in enumerate(_items(journey.get("steps"), path + ".steps", issues, empty=False)):
        step_path = path + ".steps[" + str(step_index) + "]"
        if _exact(step, _STEP_FIELDS, step_path, issues):
            if step.get("tool") not in tools:
                _issue(issues, step_path, "tool_unknown")
            _text_issues(step.get("purpose"), step_path + ".purpose", issues)
    primary = _tool_list(journey.get("primary_tools"), tools, path + ".primary_tools", issues)
    supporting = _tool_list(journey.get("supporting_tools"), tools, path + ".supporting_tools", issues)
    if set(primary) & set(supporting):
        _issue(issues, path, "supporting_tool_is_primary")
    return journey_id, primary


def _operation_issues(operation: Any, path: str, issues: list[str]) -> None:
    if operation is not None and (not isinstance(operation, str) or not _IDENTIFIER.fullmatch(operation)):
        _issue(issues, path, "operation_invalid")


def _schema_valid(schema: Any) -> bool:
    return isinstance(schema, str) and bool(_SCHEMA_ID.fullmatch(schema)) and _schema_known(schema)


def _validate_rule_set(entry: Any, path: str, tools: set[str], issues: list[str]) -> None:
    if not _exact(entry, _PROJECTION_RULE_FIELDS, path, issues):
        return
    paths = entry.get("status_paths")
    if (
        not isinstance(paths, list)
        or not paths
        or any(not isinstance(item, str) or not _PATH.fullmatch(item) for item in paths)
    ):
        _issue(issues, path, "status_paths_invalid")
    rules = entry.get("rules")
    if not isinstance(rules, Mapping) or not rules:
        _issue(issues, path, "rules_invalid")
        return
    for status in sorted(rules):
        rule = rules[status]
        rule_path = path + "." + str(status)[:64]
        if not isinstance(status, str) or not _STATUS.fullmatch(status):
            _issue(issues, rule_path, "status_invalid")
        if not isinstance(rule, Mapping) or set(rule) - {"disposition", "next"} or "disposition" not in rule:
            _issue(issues, rule_path, "rule_invalid")
            continue
        disposition = rule.get("disposition")
        if disposition not in DISPOSITIONS:
            _issue(issues, rule_path, "disposition_invalid")
            continue
        target = rule.get("next")
        if disposition != "INVOKE":
            if target is not None:
                _issue(issues, rule_path, "next_without_invoke")
            continue
        if not _exact(target, _ENTRY_FIELDS, rule_path + ".next", issues):
            continue
        if target.get("tool") not in tools:
            _issue(issues, rule_path + ".next", "tool_unknown")
        _operation_issues(target.get("operation"), rule_path + ".next", issues)
        if not _schema_valid(target.get("input_schema")):
            _issue(issues, rule_path + ".next", "schema_unknown")


def _validate_projections(value: Any, tools: set[str], issues: list[str]) -> None:
    if not isinstance(value, Mapping):
        _issue(issues, "projections", "invalid")
        return
    for tool in sorted(value):
        path = "projections." + str(tool)[:64]
        if tool not in tools:
            _issue(issues, path, "tool_unknown")
        _validate_rule_set(value[tool], path, tools, issues)


def _journey_rules(value: Mapping[str, Any], journey: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Rule tables that can produce a disposition inside one journey."""

    projections = value.get("projections") if isinstance(value.get("projections"), Mapping) else {}
    members = set(journey.get("primary_tools") or []) | set(journey.get("supporting_tools") or [])
    tables = [
        projections[tool].get("rules")
        for tool in sorted(members)
        if tool in projections and isinstance(projections[tool], Mapping)
    ]
    scenario = value.get("scenario_projection")
    if journey.get("scenarios") and isinstance(scenario, Mapping):
        tables.append(scenario.get("rules"))
    return [table for table in tables if isinstance(table, Mapping)]


def _validate_journey_outcomes(value: Mapping[str, Any], issues: list[str]) -> None:
    for index, journey in enumerate(value.get("journeys") or []):
        if not isinstance(journey, Mapping):
            continue
        path = "journeys[" + str(index) + "]"
        tables = _journey_rules(value, journey)
        for field, disposition in (("terminal_statuses", "TERMINAL"), ("typed_stops", "STOP")):
            statuses = journey.get(field) if isinstance(journey.get(field), list) else []
            for status in statuses:
                if not any(
                    isinstance(table.get(status), Mapping)
                    and table[status].get("disposition") == disposition
                    for table in tables
                ):
                    _issue(issues, path + "." + field, "not_" + disposition.lower() + ":" + str(status)[:64])


def validate_map(value: Any, tool_catalog: Sequence[Mapping[str, Any]] | None = None) -> list[str]:
    """Every reason value cannot be published in this contract generation."""

    issues: list[str] = []
    if not isinstance(value, Mapping) or set(value) != _MAP_FIELDS:
        return ["agent_lifecycle:map_shape_invalid"]
    if value.get("schema") != MAP_SCHEMA:
        issues.append("agent_lifecycle:map_schema_invalid")
    if value.get("map_generation") != MAP_GENERATION:
        issues.append("agent_lifecycle:map_generation_stale")
    if value.get("authority") != AUTHORITY:
        issues.append("agent_lifecycle:authority_invalid")
    catalog = list(tool_catalog) if tool_catalog is not None else _tool_catalog()
    tools = {str(tool.get("name")) for tool in catalog if isinstance(tool, Mapping)}
    sections = _skill_sections()
    journeys = _items(value.get("journeys"), "journeys", issues, empty=False)
    identifiers: list[str] = []
    assignments: dict[str, int] = {}
    for index, journey in enumerate(journeys):
        journey_id, primary = _validate_journey(journey, index, tools, sections, issues)
        if journey_id is not None:
            identifiers.append(journey_id)
        for name in primary:
            assignments[name] = assignments.get(name, 0) + 1
    if len(identifiers) != len(set(identifiers)):
        issues.append("agent_lifecycle:journey_duplicate")
    for name in sorted(tools):
        count = assignments.get(name, 0)
        if count == 0:
            issues.append("agent_lifecycle:tool_unassigned:" + name)
        elif count > 1:
            issues.append("agent_lifecycle:tool_assigned_twice:" + name)
    _validate_projections(value.get("projections"), tools, issues)
    _validate_rule_set(value.get("scenario_projection"), "scenario_projection", tools, issues)
    _validate_journey_outcomes(value, issues)
    return sorted(set(issues))


def _load_map() -> Any:
    return json.loads(MAP_PATH.read_text(encoding="utf-8"))


def _plugin_version() -> str | None:
    try:
        version = json.loads(MANIFEST_PATH.read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError, AttributeError):
        return None
    return version if isinstance(version, str) and len(version) <= 128 else None


def _contract_generation(value: Mapping[str, Any], catalog: Sequence[Mapping[str, Any]]) -> str:
    references = sorted({ref for journey in value["journeys"] for ref in journey["references"]})
    scenarios = sorted({ref for journey in value["journeys"] for ref in journey["scenarios"]})
    return _sha256(
        {
            "map": value,
            "tools": sorted(
                [str(tool.get("name")), _sha256(tool.get("inputSchema"))] for tool in catalog
            ),
            "skill_sha256": _file_sha256(SKILL_PATH),
            "references": {ref: _file_sha256(REFERENCES_DIR / ref) for ref in references},
            "scenarios": {ref: _file_sha256(RUNTIME_DIR / ref) for ref in scenarios},
        }
    )


def publication(
    *, map_value: Any = None, tool_catalog: Sequence[Mapping[str, Any]] | None = None
) -> tuple[dict[str, Any] | None, list[str]]:
    """The publishable map with its contract generation, or the refusal reasons."""

    try:
        value = _load_map() if map_value is None else map_value
    except (OSError, ValueError):
        return None, ["agent_lifecycle:map_unavailable"]
    catalog = list(tool_catalog) if tool_catalog is not None else _tool_catalog()
    issues = validate_map(value, catalog)
    if issues:
        return None, issues
    return {
        "map": deepcopy(value),
        "contract_generation_sha256": _contract_generation(value, catalog),
        "plugin_version": _plugin_version(),
    }, []


def _render(value: Any) -> str:
    return _canonical(value).decode("utf-8")


def list_resources(
    *, map_value: Any = None, tool_catalog: Sequence[Mapping[str, Any]] | None = None
) -> tuple[list[dict[str, Any]] | None, list[str]]:
    """Bounded resource metadata: the index and one entry per journey."""

    published, issues = publication(map_value=map_value, tool_catalog=tool_catalog)
    if published is None:
        return None, issues
    rows = [
        {
            "uri": URI_ROOT,
            "name": "agent-lifecycle-index",
            "title": "Orch Dork lifecycle journeys",
            "description": "Choose one journey, then read only that journey's resource.",
            "mimeType": "application/json",
        }
    ]
    for journey in sorted(published["map"]["journeys"], key=lambda row: row["id"]):
        rows.append(
            {
                "uri": URI_ROOT + "/" + journey["id"],
                "name": "agent-lifecycle-" + journey["id"],
                "title": journey["title"],
                "description": journey["when"][:280],
                "mimeType": "application/json",
            }
        )
    return rows, []


def read_resource(
    uri: Any,
    *,
    map_value: Any = None,
    tool_catalog: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]] | None, list[str]]:
    """The contents of exactly one lifecycle resource, or a named refusal."""

    published, issues = publication(map_value=map_value, tool_catalog=tool_catalog)
    if published is None:
        return None, issues
    journeys = {journey["id"]: journey for journey in published["map"]["journeys"]}
    common = {
        "authority": AUTHORITY,
        "contract_generation_sha256": published["contract_generation_sha256"],
        "map_schema": MAP_SCHEMA,
        "plugin_version": published["plugin_version"],
    }
    if uri == URI_ROOT:
        view = {
            **common,
            "schema": INDEX_SCHEMA,
            "journeys": [
                {
                    "id": journey["id"],
                    "title": journey["title"],
                    "trigger_class": journey["trigger_class"],
                    "when": journey["when"],
                    "uri": URI_ROOT + "/" + journey["id"],
                }
                for journey in sorted(journeys.values(), key=lambda row: row["id"])
            ],
        }
    elif isinstance(uri, str) and uri.startswith(URI_ROOT + "/") and uri[len(URI_ROOT) + 1 :] in journeys:
        journey = journeys[uri[len(URI_ROOT) + 1 :]]
        projections = published["map"]["projections"]
        view = {
            **common,
            "schema": JOURNEY_SCHEMA,
            "journey": journey,
            "projected_tools": sorted(
                tool
                for tool in projections
                if tool in journey["primary_tools"] or tool in journey["supporting_tools"]
            ),
        }
    else:
        return None, ["agent_lifecycle:resource_unknown"]
    text = _render(view)
    if len(text.encode("utf-8")) > MAX_RESOURCE_BYTES:
        return None, ["agent_lifecycle:resource_oversized"]
    return [{"uri": uri, "mimeType": "application/json", "text": text}], []


def _resolve(report: Any, dotted: str) -> Any:
    value: Any = report
    for part in dotted.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _first(report: Mapping[str, Any], paths: Sequence[str], kind: type) -> Any:
    for path in paths:
        value = _resolve(report, path)
        if isinstance(value, kind):
            return value
    return None


def _codes(values: Sequence[Any], limit: int = MAX_CODES) -> tuple[list[str], bool]:
    kept: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or len(value) > MAX_CODE_CHARS or _private(value):
            continue
        if value not in kept:
            kept.append(value)
    return kept[:limit], len(kept) > limit


def _list_field(report: Mapping[str, Any], *paths: str) -> list[Any]:
    rows: list[Any] = []
    for path in paths:
        value = _resolve(report, path)
        if isinstance(value, list):
            rows.extend(value)
    return rows


def _receipt_refs(report: Mapping[str, Any]) -> list[dict[str, str]]:
    refs = []
    for scope in (report, report.get("result") if isinstance(report.get("result"), Mapping) else {}):
        for field in sorted(scope):
            value = scope[field]
            if (
                field.endswith("_sha256")
                and field != "report_sha256"
                and isinstance(value, str)
                and _SHA256.fullmatch(value)
                and {"field": field, "sha256": value} not in refs
            ):
                refs.append({"field": field, "sha256": value})
    return refs[:MAX_REFS]


# Canonical evidence fields read, never inferred: the first boolean or string
# found on these paths is carried verbatim; absent fields stay null.
_CLAIM_PATHS = (
    "claim_permitted",
    "terminal_claim_permitted",
    "result.claim_permitted",
    "displayed_result.claim_permitted",
)
_TIER_PATHS = ("evidence_tier", "result.evidence_tier")
_UNKNOWN_PATHS = (
    "evidence_unknowns",
    "unknowns",
    "cleanup_unknown",
    "result.unknowns",
    "displayed_result.unknown_claims",
)
_CONTRADICTION_PATHS = (
    "contradictions",
    "evidence_contradictions",
    "displayed_result.contradictory_claims",
)
_REASON_PATHS = (
    "issues",
    "reason_codes",
    "invalidation_reasons",
    "result.reason_codes",
    "result.issues",
    "displayed_result.issues",
)
_TRUNCATED = "agent_lifecycle:reason_codes_truncated"


def _canonical_summary(report: Mapping[str, Any], status: Any, extra_codes: list[str]) -> dict[str, Any]:
    digest = report.get("report_sha256")
    tier = _first(report, _TIER_PATHS, str)
    unknowns, _ = _codes(_list_field(report, *_UNKNOWN_PATHS))
    contradictions, _ = _codes(_list_field(report, *_CONTRADICTION_PATHS))
    codes, truncated = _codes(extra_codes + _list_field(report, *_REASON_PATHS), MAX_CODES - 1)
    if truncated:
        codes.append(_TRUNCATED)
    return {
        "report_schema": report.get("schema") if isinstance(report.get("schema"), str) else None,
        "report_sha256": digest if isinstance(digest, str) and _SHA256.fullmatch(digest) else None,
        "status": status if isinstance(status, str) and _STATUS.fullmatch(status) else None,
        "evidence_tier": tier if isinstance(tier, str) and len(tier) <= 64 and not _private(tier) else None,
        "claim_permitted": _first(report, _CLAIM_PATHS, bool),
        "unknowns": unknowns,
        "contradictions": contradictions,
        "reason_codes": codes,
        "receipt_refs": _receipt_refs(report),
    }


def _primary_journey(published: Mapping[str, Any], tool: str) -> str | None:
    for journey in published["map"]["journeys"]:
        if tool in journey["primary_tools"]:
            return journey["id"]
    return None


def _project(
    published: Mapping[str, Any] | None,
    rule_set: Any,
    journey_id: str | None,
    report: Any,
) -> dict[str, Any]:
    if not isinstance(report, Mapping):
        report = {}
    status = None
    disposition = "STOP"
    target = None
    guidance = "REFUSED"
    extra: list[str] = []
    if published is None:
        extra.append("agent_lifecycle:publication_refused")
    else:
        for path in rule_set["status_paths"]:
            value = _resolve(report, path)
            if isinstance(value, str):
                status = value
                if value in rule_set["rules"]:
                    break
        rule = rule_set["rules"].get(status) if isinstance(status, str) else None
        if rule is None:
            extra.append("agent_lifecycle:status_unmapped")
        else:
            disposition = rule["disposition"]
            target = deepcopy(rule.get("next"))
            guidance = "MAPPED"
    projection = {
        "schema": PROJECTION_SCHEMA,
        "journey_id": journey_id,
        "contract_generation_sha256": (
            published["contract_generation_sha256"] if published is not None else None
        ),
        "guidance_status": guidance,
        "disposition": disposition,
        "next": target,
        "canonical": _canonical_summary(report, status, extra),
    }
    while len(_canonical(projection)) > MAX_PROJECTION_BYTES and len(projection["canonical"]["reason_codes"]) > 1:
        codes = projection["canonical"]["reason_codes"]
        projection["canonical"]["reason_codes"] = [code for code in codes[:-2] if code != _TRUNCATED] + [_TRUNCATED]
    return projection


def project_next_invocation(
    tool: str,
    report: Any,
    *,
    map_value: Any = None,
    tool_catalog: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """The compact next-step projection for one lifecycle-bearing tool result.

    Returns None for a tool the map does not mark lifecycle-bearing. Any map,
    rule, or status that cannot be resolved yields STOP with guidance_status
    REFUSED; the canonical report is only read, never changed.
    """

    try:
        candidate = _load_map() if map_value is None else map_value
    except (OSError, ValueError):
        candidate = None
    projections = candidate.get("projections") if isinstance(candidate, Mapping) else None
    if not isinstance(projections, Mapping) or tool not in projections:
        return None
    published, _issues = publication(map_value=candidate, tool_catalog=tool_catalog)
    rule_set = published["map"]["projections"][tool] if published is not None else None
    journey_id = _primary_journey(published, tool) if published is not None else None
    return _project(published, rule_set, journey_id, report)


def project_scenario_replay(
    journey_id: str,
    scenario: str,
    report: Any,
    *,
    map_value: Any = None,
    tool_catalog: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Project one replayed gallery scenario the named journey references."""

    published, _issues = publication(map_value=map_value, tool_catalog=tool_catalog)
    if published is not None:
        journeys = {journey["id"]: journey for journey in published["map"]["journeys"]}
        if journey_id not in journeys or scenario not in journeys[journey_id]["scenarios"]:
            published = None
    rule_set = published["map"]["scenario_projection"] if published is not None else None
    return _project(published, rule_set, journey_id if published is not None else None, report)


def contains_projection(value: Any, *, depth: int = 0) -> bool:
    """Whether a tool argument carries a projection, which is never input."""

    if depth > 32:
        return False
    if isinstance(value, Mapping):
        if value.get("schema") == PROJECTION_SCHEMA:
            return True
        return any(contains_projection(item, depth=depth + 1) for item in value.values())
    if isinstance(value, list):
        return any(contains_projection(item, depth=depth + 1) for item in value)
    return False
