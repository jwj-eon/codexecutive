#!/usr/bin/env python3
"""Provider-free Orch Dork skill-contract inventory and forward evaluation."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


CONTRACT_SCHEMA = "orch-dork/skill-contract/v1"
TRIGGER_MATRIX_SCHEMA = "orch-dork/trigger-matrix/v2"
SUPPORTED_TRIGGER_MATRIX_SCHEMAS = frozenset(
    {"orch-dork/trigger-matrix/v1", TRIGGER_MATRIX_SCHEMA}
)
CASE_RESULT_SCHEMA = "orch-dork/skill-forward-evaluation-case/v1"
REPORT_SCHEMA = "orch-dork/skill-forward-evaluation-report/v1"
MAX_JSON_BYTES = 262_144
MAX_SKILL_LINES = 499

# Issue 198: the first load is exactly SKILL.md.  The budget is recorded in
# bytes because bytes are what this host can measure exactly. No tokenizer
# is run and no token estimate or bound is claimed.
MAX_FIRST_LOAD_BYTES = 32_768


STOP_CODES = frozenset(
    {
        "UNKNOWN_MISSING_FRONTMATTER",
        "UNKNOWN_MALFORMED_FRONTMATTER",
        "UNKNOWN_BROKEN_DIRECT_REFERENCE",
        "REFUSED_STALE_CONTRACT_GENERATION",
        "REFUSED_STALE_TRIGGER_MATRIX",
        "REFUSED_FIRST_LOAD_BUDGET_EXCEEDED",
        "READ_ONLY_SOURCE_INSTALLED_MISMATCH",
        "UNKNOWN_EVALUATOR_UNAVAILABLE",
        "READ_ONLY_ACTIVE_TASK_OLDER_GENERATION",
    }
)

_REFERENCE_LINK = re.compile(r"\[[^\]]+\]\((references/[A-Za-z0-9._/-]+\.md)(?:#[^)]+)?\)")
_NAME = re.compile(r"\A[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_REQUEST_PATTERNS = (
    ("EXPLICIT_ORCHESTRATE_REQUEST", re.compile(r"\b(?:please\s+)?orchestrate\b", re.I)),
    ("EXPLICIT_DELEGATE_REQUEST", re.compile(r"\b(?:please\s+)?delegate\b", re.I)),
    ("EXPLICIT_PARALLELIZE_REQUEST", re.compile(r"\b(?:please\s+)?parallel(?:ize|ise)\b", re.I)),
    (
        "EXPLICIT_SUBAGENT_REQUEST",
        re.compile(r"\b(?:please\s+)?use\s+(?:the\s+)?(?:subagents?|\$orch-dork|orch dork)\b", re.I),
    ),
    (
        "EXPLICIT_DEFAULT_REQUEST",
        re.compile(r"\bmake\s+orchestration\s+(?:the\s+)?default\b", re.I),
    ),
    (
        "EXPLICIT_TRACE_INSPECTION_REQUEST",
        re.compile(r"\b(?:inspect|audit|review)\s+(?:(?:an?|the|this)\s+)?orchestration\s+trace\b", re.I),
    ),
    (
        "EXPLICIT_TICKET_LIST_REQUEST",
        re.compile(r"\bwork\s+(?:through\s+)?(?:the|my|our|this)\s+ticket\s+list\b", re.I),
    ),
    (
        "EXPLICIT_GOVERNED_RUN_REQUEST",
        re.compile(r"\b(?:as|in|under)\s+a\s+governed\s+run\b|\bstart\s+a\s+governed\s+run\b", re.I),
    ),
)

# A keyword used as a word, rather than as a request, never triggers the skill.
_BARE_MENTION = (
    re.compile(r"\b(?:the\s+)?(?:word|term|phrase)\s+[\"'\u201c]?(?:orchestrat|delegat|parallel|subagent)", re.I),
    re.compile(r"\bwhat\s+(?:does|do)\b[^;.?!\n]*\bmean\b", re.I),
    re.compile(r"\b(?:explain|define|describe)\b[^,;.?!\n]*\b(?:words?|terms?|phrases?|means?|meaning)\b[^,;.?!\n]*", re.I),
)
_EXPECTED_LEAK = re.compile(
    r"\b(?:ATOMIC_ADMITTED|ORCHESTRATION_PLAN_REQUIRED|RECLASSIFICATION_REQUIRED|SKILL_NOT_TRIGGERED|REFUSED_[A-Z0-9_]+)\b"
)


class ContractError(ValueError):
    """A stable fail-closed contract error."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical(value))


def _strict_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ContractError("UNKNOWN_BROKEN_DIRECT_REFERENCE", f"fixture is not a regular file: {path.name}")
    raw = path.read_bytes()
    if len(raw) > MAX_JSON_BYTES:
        raise ContractError("UNKNOWN_BROKEN_DIRECT_REFERENCE", "fixture exceeds the JSON byte bound")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ContractError("UNKNOWN_BROKEN_DIRECT_REFERENCE", "fixture is not strict UTF-8") from exc

    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ContractError("UNKNOWN_BROKEN_DIRECT_REFERENCE", f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except ContractError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise ContractError("UNKNOWN_BROKEN_DIRECT_REFERENCE", "fixture is not canonical finite JSON") from exc


def _frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        raise ContractError("UNKNOWN_MISSING_FRONTMATTER", "SKILL.md has no leading frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ContractError("UNKNOWN_MALFORMED_FRONTMATTER", "SKILL.md frontmatter is not terminated")
    rows: dict[str, str] = {}
    for raw in text[4:end].splitlines():
        if not raw.strip() or ":" not in raw:
            raise ContractError("UNKNOWN_MALFORMED_FRONTMATTER", "frontmatter contains a malformed row")
        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key in rows or not key or not value:
            raise ContractError("UNKNOWN_MALFORMED_FRONTMATTER", "frontmatter keys must be unique and non-empty")
        rows[key] = value.strip('"\'')
    if set(rows) != {"name", "description"}:
        raise ContractError("UNKNOWN_MALFORMED_FRONTMATTER", "frontmatter must contain exactly name and description")
    if not _NAME.fullmatch(rows["name"]) or not rows["description"]:
        raise ContractError("UNKNOWN_MALFORMED_FRONTMATTER", "frontmatter values are invalid")
    return rows


def contract_inventory(
    skill_root: str | Path,
    *,
    expected_generation: str | None = None,
    active_generation: str | None = None,
    evaluator_available: bool = True,
) -> dict[str, Any]:
    root = Path(skill_root).resolve()
    skill = root / "SKILL.md"
    if not evaluator_available:
        return _stop("UNKNOWN_EVALUATOR_UNAVAILABLE", "the provider-free evaluator is unavailable")
    if skill.is_symlink() or not skill.is_file():
        return _stop("UNKNOWN_MISSING_FRONTMATTER", "SKILL.md is missing or not a regular file")
    try:
        raw = skill.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        frontmatter = _frontmatter(text)
        line_count = len(text.splitlines())
        if line_count > MAX_SKILL_LINES:
            raise ContractError("UNKNOWN_MALFORMED_FRONTMATTER", "SKILL.md exceeds the 499-line contract bound")
        refs = sorted(set(_REFERENCE_LINK.findall(text)))
        if not refs:
            raise ContractError("UNKNOWN_BROKEN_DIRECT_REFERENCE", "SKILL.md has no direct contract references")
        rows = [_inventory_row(root, skill)]
        for relative in refs:
            candidate = root / relative
            resolved = candidate.resolve()
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise ContractError("UNKNOWN_BROKEN_DIRECT_REFERENCE", f"reference escapes the skill root: {relative}") from exc
            if candidate.is_symlink() or not candidate.is_file():
                raise ContractError("UNKNOWN_BROKEN_DIRECT_REFERENCE", f"direct reference is missing: {relative}")
            ref_text = candidate.read_text(encoding="utf-8", errors="strict")
            if len(ref_text.splitlines()) > 100 and "## Contents" not in ref_text:
                raise ContractError("UNKNOWN_BROKEN_DIRECT_REFERENCE", f"long reference has no contents section: {relative}")
            rows.append(_inventory_row(root, candidate))
    except ContractError as exc:
        return _stop(exc.code, exc.detail)
    except (OSError, UnicodeError) as exc:
        return _stop("UNKNOWN_BROKEN_DIRECT_REFERENCE", f"contract bytes are unavailable: {type(exc).__name__}")

    inventory = {
        "schema": CONTRACT_SCHEMA,
        "frontmatter": frontmatter,
        "skill_lines": line_count,
        "files": rows,
    }
    first_load = _first_load_record(len(raw), line_count, rows)
    inventory["first_load"] = first_load
    generation = _sha256_json(inventory)
    result = {
        "schema": CONTRACT_SCHEMA,
        "status": "PASS",
        "disposition": "CONTRACT_CURRENT",
        "contract_generation": generation,
        "skill_lines": line_count,
        "first_load": first_load,
        "frontmatter_keys": sorted(frontmatter),
        "direct_references": refs,
        "inventory": rows,
        "issues": [],
        "provider_free": True,
    }
    if not first_load["within_budget"]:
        return _stop(
            "REFUSED_FIRST_LOAD_BUDGET_EXCEEDED",
            "SKILL.md exceeds the recorded first-load byte budget",
            generation,
        )
    if expected_generation is not None and expected_generation != generation:
        return _stop("REFUSED_STALE_CONTRACT_GENERATION", "the expected contract generation is stale", generation)
    if active_generation is not None and active_generation != generation:
        return _stop("READ_ONLY_ACTIVE_TASK_OLDER_GENERATION", "the active task loaded an older contract", generation)
    return result


def _first_load_record(skill_bytes: int, skill_lines: int, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Record what a fresh task loads before it reads any reference.

    The byte count is measured exactly. Token counts require a tokenizer and
    cannot be inferred as an upper bound by dividing a byte count.
    """

    lazy_bytes = sum(int(row["bytes"]) for row in rows[1:])
    return {
        "path": "SKILL.md",
        "bytes": skill_bytes,
        "lines": skill_lines,
        "bytes_measured": True,
        "budget_bytes": MAX_FIRST_LOAD_BYTES,
        "within_budget": skill_bytes <= MAX_FIRST_LOAD_BYTES,
        "tokens_measured": False,
        "lazy_reference_count": len(rows) - 1,
        "lazy_reference_bytes": lazy_bytes,
    }


def _inventory_row(root: Path, path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {
        "path": path.resolve().relative_to(root).as_posix(),
        "bytes": len(raw),
        "sha256": _sha256_bytes(raw),
    }


def _stop(code: str, detail: str, generation: str | None = None) -> dict[str, Any]:
    if code not in STOP_CODES:
        raise ValueError(f"unknown contract stop code: {code}")
    status = "UNKNOWN" if code.startswith("UNKNOWN_") else "FAIL"
    return {
        "schema": CONTRACT_SCHEMA,
        "status": status,
        "disposition": code,
        "contract_generation": generation,
        "issues": [code],
        "detail": detail,
        "provider_free": True,
    }


def compare_contract_copies(source_root: str | Path, other_root: str | Path) -> dict[str, Any]:
    source = contract_inventory(source_root)
    other = contract_inventory(other_root)
    if source.get("status") != "PASS" or other.get("status") != "PASS":
        return {
            "schema": CONTRACT_SCHEMA,
            "status": "FAIL",
            "disposition": "READ_ONLY_SOURCE_INSTALLED_MISMATCH",
            "source": source,
            "other": other,
            "provider_free": True,
        }
    same = source["contract_generation"] == other["contract_generation"]
    return {
        "schema": CONTRACT_SCHEMA,
        "status": "PASS" if same else "FAIL",
        "disposition": "CONTRACT_COPIES_MATCH" if same else "READ_ONLY_SOURCE_INSTALLED_MISMATCH",
        "source_generation": source["contract_generation"],
        "other_generation": other["contract_generation"],
        "source_inventory": source["inventory"],
        "other_inventory": other["inventory"],
        "provider_free": True,
    }


def _definition_spans(prompt: str) -> list[tuple[int, int]]:
    """Keep comma-separated word lists inside their definition, not commands.

    A continuation must consist only of individual terms, quoted phrases or
    the request phrases the fixture matcher knows. A command with an object
    such as "delegate the CLI fix" ends that list and stays an explicit request.
    """
    spans = []
    for pattern in _BARE_MENTION:
        for match in pattern.finditer(prompt):
            start, end = match.span()
            while end < len(prompt) and prompt[end] == ",":
                boundary = re.search(r"[,;.?!\n]", prompt[end + 1:])
                stop = end + 1 + boundary.start() if boundary else len(prompt)
                continuation = re.sub(r"^\s*(?:and|or)\s+", "", prompt[end + 1:stop], flags=re.I)
                terms = re.split(r"\s+(?:and|or)\s+", continuation.strip(), flags=re.I)
                if not all(_definition_term(term) for term in terms):
                    break
                end = stop
            spans.append((start, end))
    return spans


def _definition_term(term: str) -> bool:
    quoted = len(term) > 2 and (term[0], term[-1]) in {("'", "'"), ('"', '"'), ('`', '`'), ('“', '”')}
    word = term.strip("\"'`“”")
    return quoted or bool(re.fullmatch(r"[\w$-]+", word)) or (
        not re.match(r"please\s+", word, re.I)
        and any(pattern.fullmatch(word) for _, pattern in _REQUEST_PATTERNS)
    )


def trigger_selection(
    prompt: str,
    *,
    policy_requires_observable_delegation: bool,
    judgment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Decide whether a new request loads the skill at all (Issue 198).

    Exactly three things trigger it: an explicit request, an applicable
    instruction that requires observable delegation, or Codex's own declared
    judgment that the work is worth splitting or worth substantive independent
    verification. The judgment is recorded as a declaration, never as model
    inference evidence, and it is accepted only when the declaration carries
    the topology or checks it claims.
    """

    declared = _judgment_record(judgment)
    mentions = _definition_spans(prompt)
    suppressed = False
    if policy_requires_observable_delegation:
        return _trigger(True, "APPLICABLE_POLICY_REQUIRES_OBSERVABLE_DELEGATION", declared, False)
    for reason, pattern in _REQUEST_PATTERNS:
        for match in pattern.finditer(prompt):
            if any(match.start() < end and start < match.end() for start, end in mentions):
                suppressed = True
            else:
                return _trigger(True, reason, declared, suppressed)
    if declared["accepted"]:
        return _trigger(True, str(declared["reason"]), declared, suppressed)
    return _trigger(False, "NO_EXPLICIT_OR_APPLICABLE_TRIGGER", declared, suppressed)


def _trigger(triggered: bool, reason: str, judgment: dict[str, Any], suppressed: bool) -> dict[str, Any]:
    return {
        "triggered": triggered,
        "reason": reason,
        "judgment": judgment,
        "suppressed_bare_mention": suppressed,
    }


def _judgment_record(judgment: Mapping[str, Any] | None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "declared": judgment is not None,
        "source": "codex_declared_judgment",
        "is_model_inference_evidence": False,
        "worth_splitting": False,
        "worth_independent_verification": False,
        "declared_lane_count": 0,
        "declared_check_count": 0,
        "substantive_change": False,
        "accepted": False,
        "reason": None,
        "rejected": "JUDGMENT_NOT_DECLARED",
    }
    if judgment is None:
        return record
    if not isinstance(judgment, Mapping):
        raise ValueError("codex_judgment must be an object")
    allowed = {
        "worth_splitting",
        "worth_independent_verification",
        "substantive_change",
        "declared_lanes",
        "declared_checks",
    }
    if set(judgment) - allowed:
        raise ValueError("codex_judgment contains an unknown field")
    for field in ("worth_splitting", "worth_independent_verification", "substantive_change"):
        state = judgment.get(field, False)
        if not isinstance(state, bool):
            raise ValueError("codex_judgment flags must be boolean")
        record[field] = state
    lanes = _declared_lanes(judgment.get("declared_lanes", []))
    checks = judgment.get("declared_checks", [])
    if not isinstance(checks, list) or any(not isinstance(item, str) or not item for item in checks):
        raise ValueError("codex_judgment.declared_checks must be an array of names")
    record["declared_lane_count"] = len(lanes)
    record["declared_check_count"] = len(checks)
    if record["worth_splitting"]:
        if len(lanes) < 2:
            record["rejected"] = "JUDGMENT_WITHOUT_TWO_DECLARED_LANES"
            return record
        if _writes_overlap(lanes):
            record["rejected"] = "JUDGMENT_LANES_SHARE_DECLARED_WRITES"
            return record
        record.update({"accepted": True, "reason": "CODEX_JUDGED_WORTH_SPLITTING", "rejected": None})
        return record
    if record["worth_independent_verification"]:
        if not record["substantive_change"] or not checks:
            record["rejected"] = "JUDGMENT_WITHOUT_SUBSTANTIVE_CHANGE_AND_CHECK"
            return record
        record.update(
            {
                "accepted": True,
                "reason": "CODEX_JUDGED_WORTH_INDEPENDENT_VERIFICATION",
                "rejected": None,
            }
        )
        return record
    record["rejected"] = "JUDGMENT_CLAIMS_NEITHER_SPLITTING_NOR_VERIFICATION"
    return record


def _declared_lanes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("codex_judgment.declared_lanes must be an array")
    lanes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if isinstance(item, str):
            lane: dict[str, Any] = {"id": item, "writes": []}
        elif isinstance(item, Mapping) and set(item) <= {"id", "writes"}:
            writes = item.get("writes", [])
            if not isinstance(writes, list) or any(not isinstance(path, str) or not path for path in writes):
                raise ValueError("declared lane writes must be an array of paths")
            lane = {"id": item.get("id"), "writes": list(writes)}
        else:
            raise ValueError("declared lane must be an id or an object with id and writes")
        if not isinstance(lane["id"], str) or not lane["id"] or lane["id"] in seen:
            raise ValueError("declared lane ids must be unique non-empty strings")
        seen.add(str(lane["id"]))
        lanes.append(lane)
    return lanes


def _writes_overlap(lanes: list[dict[str, Any]]) -> bool:
    claimed: set[str] = set()
    for lane in lanes:
        paths = set(lane["writes"])
        if paths & claimed:
            return True
        claimed |= paths
    return False


def evaluate_fresh_context(case_input: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(case_input))
    prompt = value.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("case input requires a non-empty prompt")
    policy_trigger = value.get("policy_requires_observable_delegation", False)
    if not isinstance(policy_trigger, bool):
        raise ValueError("policy trigger must be boolean")
    trigger = trigger_selection(
        prompt,
        policy_requires_observable_delegation=policy_trigger,
        judgment=value.get("codex_judgment"),
    )
    governed_requested = bool(value.get("governed_requested", False))
    project_policy_requires_ground = value.get(
        "project_policy_requires_ground", False
    )
    if not isinstance(project_policy_requires_ground, bool):
        raise ValueError("project ground policy must be boolean")
    execution_mode = "governed" if governed_requested else "advisory"
    base = {
        "schema": CASE_RESULT_SCHEMA,
        "trigger": trigger,
        "classification": None,
        "reason": trigger["reason"],
        "root_owned": True,
        "worker_count": 0,
        "trace_disposition": "not_applicable",
        "mutation_permitted": False,
        "required_gates": [],
        "unknowns": [],
        "forbidden_action_checks": _forbidden_checks(value),
        "terminally_qualified": False,
        "execution_mode": execution_mode,
        "execution_profile": (
            "governed_v3" if governed_requested else "compatibility_advisory"
        ),
        "requires_external_controller": governed_requested,
        "requires_wave_v3": governed_requested,
        "requires_execution_readiness": governed_requested,
        "requires_project_ground": (
            governed_requested or project_policy_requires_ground
        ),
        "completion_evidence": (
            "independent_terminal" if governed_requested else "submitted"
        ),
    }
    if not trigger["triggered"]:
        base["decision"] = "SKILL_NOT_TRIGGERED"
        return base

    if governed_requested and not bool(value.get("external_controller_available", False)):
        return _refused(base, "REFUSED_GOVERNED_CONTROLLER_UNAVAILABLE")

    for field, label in (
        ("authority", "REQUIRED_AUTHORITY"),
        ("model", "REQUIRED_MODEL"),
        ("evidence", "REQUIRED_EVIDENCE"),
        ("safe_ownership", "SAFE_RESOURCE_OWNERSHIP"),
    ):
        state = value.get(field, "available")
        if state not in {"available", "missing", "unknown"}:
            raise ValueError(f"invalid {field} state")
        if state == "missing":
            return _refused(base, f"REFUSED_{label}_UNAVAILABLE")
        if state == "unknown":
            base["unknowns"].append(field)
            return _refused(base, f"REFUSED_{label}_UNKNOWN")

    admission = value.get("admission", "fresh")
    if admission != "fresh":
        base["decision"] = "RECLASSIFICATION_REQUIRED"
        base["classification"] = "refused"
        base["reason"] = "STALE_OR_MISSING_TICKET_ADMISSION"
        return base

    if not all(base["forbidden_action_checks"].values()):
        return _refused(base, "REFUSED_FORBIDDEN_ACTION_OBSERVED")

    lanes = value.get("independent_lanes", [])
    if not isinstance(lanes, list) or any(not isinstance(item, str) or not item for item in lanes):
        raise ValueError("independent_lanes must be an array of identifiers")
    explicit_atomic = bool(value.get("explicit_atomic", False))
    strict_serial = bool(value.get("strict_serial_dependency", False))
    shared_mutable_core = bool(value.get("shared_mutable_core", False))

    if 2 <= len(lanes) <= 4 and not explicit_atomic and not strict_serial and not shared_mutable_core:
        base.update(
            {
                "decision": "ORCHESTRATION_PLAN_REQUIRED",
                "classification": "orchestrated",
                "reason": "TWO_TO_FOUR_INDEPENDENTLY_OWNABLE_LANES",
                "root_owned": False,
                "trace_disposition": "required_after_execution",
                "required_gates": [
                    "ticket_admission",
                    "frozen_plan",
                    "acceptance_resource_closure",
                    "ownership",
                    "capacity",
                    "worker_lifecycle",
                    "spawn_wave",
                    "release_and_integration_owner",
                ],
            }
        )
    else:
        base.update(
            {
                "decision": "ATOMIC_ADMITTED",
                "classification": "atomic",
                "reason": "ONE_COHERENT_OR_STRICTLY_SERIAL_OPERATION",
                "required_gates": ["ticket_admission"],
                "mutation_permitted": True,
            }
        )

    if value.get("submitted_trace_pass") is True and value.get("independent_terminal_observer") is not True:
        base["terminally_qualified"] = False
    return base


def _refused(base: dict[str, Any], reason: str) -> dict[str, Any]:
    base.update({"decision": "REFUSED", "classification": "refused", "reason": reason})
    return base


def _forbidden_checks(value: Mapping[str, Any]) -> dict[str, bool]:
    actions = value.get("forbidden_actions", {})
    if not isinstance(actions, Mapping):
        raise ValueError("forbidden_actions must be an object")
    checks = {}
    for name in ("workers_before_gates", "retries", "replacements", "fallbacks", "nesting"):
        amount = actions.get(name, 0)
        checks[name] = type(amount) is int and amount == 0
    retained = value.get("retained_material", {})
    if not isinstance(retained, Mapping):
        raise ValueError("retained_material must be an object")
    for name in ("credentials", "session_body", "prompt_body", "private_reasoning", "chain_of_thought"):
        checks[f"no_{name}"] = retained.get(name) in {None, False, "", 0}
    advisory = value.get("invocation_mode", "advisory")
    checks["no_advisory_to_governed_promotion"] = advisory != "advisory" or not bool(value.get("effective_governed", False))
    return checks


def evaluate_matrix(matrix_path: str | Path, skill_root: str | Path) -> dict[str, Any]:
    matrix = _strict_json(Path(matrix_path))
    if not isinstance(matrix, Mapping) or matrix.get("schema") not in SUPPORTED_TRIGGER_MATRIX_SCHEMAS:
        raise ContractError("REFUSED_STALE_TRIGGER_MATRIX", "trigger matrix schema is missing or stale")
    cases = matrix.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ContractError("REFUSED_STALE_TRIGGER_MATRIX", "trigger matrix has no cases")
    contract = contract_inventory(skill_root)
    if contract.get("status") != "PASS":
        return {
            "schema": REPORT_SCHEMA,
            "status": "FAIL",
            "contract": contract,
            "issues": list(contract.get("issues", [])),
            "provider_free": True,
        }

    results: list[dict[str, Any]] = []
    issues: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(cases):
        if not isinstance(raw, Mapping):
            issues.append(f"case[{index}]:not_object")
            continue
        case_id = raw.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            issues.append(f"case[{index}]:id_invalid_or_duplicate")
            continue
        seen.add(case_id)
        case_input = raw.get("input")
        expected = raw.get("expected")
        if not isinstance(case_input, Mapping) or not isinstance(expected, Mapping):
            issues.append(f"{case_id}:input_or_expected_invalid")
            continue
        prompt = case_input.get("prompt")
        if not isinstance(prompt, str) or _EXPECTED_LEAK.search(prompt):
            issues.append(f"{case_id}:expected_answer_leaked_into_prompt")
            continue
        try:
            actual = evaluate_fresh_context(copy.deepcopy(case_input))
        except (TypeError, ValueError) as exc:
            issues.append(f"{case_id}:evaluation_error:{type(exc).__name__}")
            continue
        mismatches = _expected_mismatches(expected, actual)
        if mismatches:
            issues.extend(f"{case_id}:{item}" for item in mismatches)
        results.append(
            {
                "id": case_id,
                "status": "PASS" if not mismatches else "FAIL",
                "triggered": actual["trigger"]["triggered"],
                "trigger_reason": actual["trigger"]["reason"],
                "judgment_declared": actual["trigger"]["judgment"]["declared"],
                "judgment_accepted": actual["trigger"]["judgment"]["accepted"],
                "judgment_rejected": actual["trigger"]["judgment"]["rejected"],
                "judgment_source": actual["trigger"]["judgment"]["source"],
                "judgment_is_model_inference_evidence": actual["trigger"]["judgment"][
                    "is_model_inference_evidence"
                ],
                "suppressed_bare_mention": actual["trigger"]["suppressed_bare_mention"],
                "decision": actual["decision"],
                "classification": actual["classification"],
                "reason": actual["reason"],
                "root_owned": actual["root_owned"],
                "worker_count": actual["worker_count"],
                "trace_disposition": actual["trace_disposition"],
                "mutation_permitted": actual["mutation_permitted"],
                "terminally_qualified": actual["terminally_qualified"],
                "unknowns": actual["unknowns"],
                "forbidden_actions_pass": all(actual["forbidden_action_checks"].values()),
            }
        )

    matrix_generation = _sha256_json(matrix)
    return {
        "schema": REPORT_SCHEMA,
        "status": "PASS" if not issues and len(results) == len(cases) else "FAIL",
        "contract_generation": contract["contract_generation"],
        "first_load": contract["first_load"],
        "trigger_matrix_generation": matrix_generation,
        "trigger_matrix_schema": matrix["schema"],
        "fixture_ids": [row["id"] for row in results],
        "case_count": len(results),
        "passed": sum(row["status"] == "PASS" for row in results),
        "failed": sum(row["status"] != "PASS" for row in results),
        "cases": results,
        "issues": sorted(set(issues)),
        "judgment_inputs_are_declarations": True,
        "model_inference_evidence": False,
        "prompts_retained": False,
        "session_bodies_retained": False,
        "private_reasoning_retained": False,
        "credentials_retained": False,
        "hosted_calls": 0,
        "model_calls": 0,
        "workers": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "provider_free": True,
    }


def _expected_mismatches(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> list[str]:
    mismatches = []
    trigger = actual.get("trigger") if isinstance(actual.get("trigger"), Mapping) else None
    for key, value in expected.items():
        if trigger is not None and key == "triggered":
            observed = trigger["triggered"]
        elif trigger is not None and key == "trigger_reason":
            observed = trigger["reason"]
        elif trigger is not None and key in {"judgment_accepted", "judgment_rejected", "judgment_declared"}:
            observed = trigger["judgment"][key.split("_", 1)[1]]
        elif trigger is not None and key == "suppressed_bare_mention":
            observed = trigger["suppressed_bare_mention"]
        else:
            observed = actual.get(key)
        if observed != value:
            mismatches.append(f"expected_{key}_mismatch")
    return mismatches


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inventory = sub.add_parser("inventory")
    inventory.add_argument("--skill-root", required=True)
    inventory.add_argument("--expected-generation")
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--skill-root", required=True)
    evaluate.add_argument("--matrix", required=True)
    compare = sub.add_parser("compare")
    compare.add_argument("--source-root", required=True)
    compare.add_argument("--other-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inventory":
            report = contract_inventory(args.skill_root, expected_generation=args.expected_generation)
        elif args.command == "evaluate":
            report = evaluate_matrix(args.matrix, args.skill_root)
        else:
            report = compare_contract_copies(args.source_root, args.other_root)
    except ContractError as exc:
        report = _stop(exc.code, exc.detail)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CASE_RESULT_SCHEMA",
    "CONTRACT_SCHEMA",
    "MAX_FIRST_LOAD_BYTES",
    "MAX_SKILL_LINES",
    "REPORT_SCHEMA",
    "STOP_CODES",
    "SUPPORTED_TRIGGER_MATRIX_SCHEMAS",
    "TRIGGER_MATRIX_SCHEMA",
    "compare_contract_copies",
    "contract_inventory",
    "evaluate_fresh_context",
    "evaluate_matrix",
    "main",
    "trigger_selection",
]
