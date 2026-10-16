#!/usr/bin/env python3
"""Two-stage architecture ingestion, stage one: digest a proposal into a draft.

ADR 0010, FR68 and section 15 (Issue 184).  An external model lineup enters
Orch Dork only as one canonical orch-dork/architecture-draft/v1 that names the
inferred roles, the registered profile proposed for each, independence and
escalation rules, every missing decision as a typed question, every
assumption, and every conflict with the specification.  The draft is
untrusted until the Owner seals it create-only by digest; compile
(orch_dork_model_profile_registry.compile_routing_policy) consumes only a
draft together with that seal.

The one digest operation, digest(), takes three inputs:

* a structured proposal (orch-dork/architecture-proposal/v1) digests here,
  provider-free and deterministically;
* prose cannot be digested here.  digest() returns a sealed requirement whose
  bounded orch-dork/task-spec/v2 an ordinary task runs under existing
  authority, mirroring ID-17's strong-planning rule; the requirement grants
  nothing;
* the structured proposal that task returns digests only with the task's
  complete handoff receipt, which binds the exact task spec and carries the
  proposal's content digest.

Nothing here selects, substitutes, or falls back to a model, reads the
environment, or calls a model, dispatcher, capacity ledger, credential store,
or authority path.  A proposal's fallback or quota rule becomes a conflict
entry and is never executed; an unknown role becomes a typed question and is
never dropped or invented.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence


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
registry = _load_sibling("orch_dork_model_profile_registry")

PROPOSAL_SCHEMA = "orch-dork/architecture-proposal/v1"
REQUIREMENT_SCHEMA = "orch-dork/architecture-digest-requirement/v1"
MAX_PROPOSAL_BYTES = 262_144
MAX_PROSE_BYTES = 262_144
MAX_APPROVAL_BYTES = 65_536
# The command line reads one JSON or text file at a time.
MAX_INPUT_BYTES = 1_048_576
_MAX_ROLES = 32
_MAX_RULES = 64
_MAX_NAME_BYTES = 128
_MAX_TEXT_BYTES = 1024
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_PROPOSAL_REQUIRED = frozenset({"schema", "proposal_id", "roles"})
_PROPOSAL_OPTIONAL = frozenset({"privacy_envelope", "rules"})
_ROLE_REQUIRED = frozenset({"name"})
_ROLE_OPTIONAL = frozenset(
    {"model", "effort", "purpose", "privacy_class", "independent", "reviews"}
)
_RULE_FIELDS = {
    "escalation": frozenset({"kind", "from", "to", "trigger"}),
    "fallback": frozenset({"kind", "role", "use", "trigger"}),
    "quota_exhaustion": frozenset({"kind", "action"}),
}
_REQUIREMENT_FIELDS = frozenset(
    {
        "schema",
        "task_spec",
        "prose_sha256",
        "proposal_id",
        "registry_generation",
        "registry_sha256",
        "privacy_class",
        "authority_class",
        "requirement_sha256",
    }
)
# Roles whose work the reviewer reviews when a proposal does not say.
_DEFAULT_REVIEWED_ROLES = ("implementer", "trivial")
_PROPOSAL_MEDIA_TYPE = "application/json"
_PROSE_MEDIA_TYPE = "text/plain"
_ACCEPTANCE_CHECK = "proposal-schema"
# task-spec/v2 requires every budget except retries to be positive, so one
# tool call is its floor; the empty allowed_tools list is what grants none.
_TASK_BUDGETS = {
    "context_tokens": 32_768,
    "output_tokens": 8_192,
    "handoff_tokens": 1_024,
    "tool_calls": 1,
    "retries": 0,
}


class IngestionError(ValueError):
    """A named refusal from the approval record store or the command line."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: Any) -> str:
    return _sha256_bytes(contracts.canonical_bytes(value))


def _normal(name: str) -> str:
    return " ".join(name.strip().lower().split())


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", _normal(name)).strip("-")[:64] or "role"


def _bounded(value: Any, limit: int = _MAX_TEXT_BYTES) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= limit
    )


def _closed(
    value: Any,
    required: frozenset[str],
    optional: frozenset[str],
    path: str,
    issues: list[str],
) -> bool:
    if not isinstance(value, Mapping):
        issues.append(path + ":not_object")
        return False
    keys = set(value)
    for key in sorted(str(item) for item in keys - required - optional):
        issues.append(path + ":unknown:" + key)
    for key in sorted(required - keys):
        issues.append(path + ":missing:" + key)
    return required <= keys <= required | optional


def proposal_issues(proposal: Any) -> list[str]:
    """Return every reason proposal is not a structured architecture proposal."""

    issues: list[str] = []
    if not _closed(proposal, _PROPOSAL_REQUIRED, _PROPOSAL_OPTIONAL, "proposal", issues):
        return sorted(set(issues))
    try:
        size = len(contracts.canonical_bytes(proposal))
    except (TypeError, ValueError, OverflowError, RecursionError):
        return ["proposal:hostile_or_non_json_input"]
    if size > MAX_PROPOSAL_BYTES:
        issues.append("proposal:too_large")
    if proposal["schema"] != PROPOSAL_SCHEMA:
        issues.append("proposal:schema_invalid")
    if not isinstance(proposal["proposal_id"], str) or not _IDENTIFIER.fullmatch(
        proposal["proposal_id"]
    ):
        issues.append("proposal:proposal_id_invalid")
    if "privacy_envelope" in proposal:
        envelope = proposal["privacy_envelope"]
        if (
            not isinstance(envelope, list)
            or not envelope
            or any(item not in registry.PRIVACY_CLASSES for item in envelope)
            or len(envelope) != len(set(envelope))
        ):
            issues.append("proposal:privacy_envelope_invalid")
    roles = proposal["roles"]
    if not isinstance(roles, list) or not roles or len(roles) > _MAX_ROLES:
        issues.append("proposal:roles_invalid")
        roles = []
    names: list[str] = []
    for index, role in enumerate(roles):
        path = "proposal.roles[" + str(index) + "]"
        if not _closed(role, _ROLE_REQUIRED, _ROLE_OPTIONAL, path, issues):
            continue
        if not _bounded(role["name"], _MAX_NAME_BYTES):
            issues.append(path + ":name_invalid")
            continue
        name = _normal(role["name"])
        names.append(name)
        for field in ("model", "effort"):
            if field in role and (
                not isinstance(role[field], str) or not _IDENTIFIER.fullmatch(role[field])
            ):
                issues.append(path + ":" + field + "_invalid")
        if "purpose" in role and not _bounded(role["purpose"]):
            issues.append(path + ":purpose_invalid")
        if "privacy_class" in role and role["privacy_class"] not in registry.PRIVACY_CLASSES:
            issues.append(path + ":privacy_class_invalid")
        if ("independent" in role or "reviews" in role) and name != "reviewer":
            issues.append(path + ":review_fields_outside_reviewer")
        if "independent" in role and type(role["independent"]) is not bool:
            issues.append(path + ":independent_invalid")
        if "reviews" in role:
            reviews = role["reviews"]
            if (
                not isinstance(reviews, list)
                or any(not _bounded(item, _MAX_NAME_BYTES) for item in reviews)
                or len({_normal(item) for item in reviews}) != len(reviews)
            ):
                issues.append(path + ":reviews_invalid")
    if len(names) != len(set(names)):
        issues.append("proposal:role_duplicate")
    unknown = [name for name in names if name not in registry.ROLES]
    if len({_slug(name) for name in unknown}) != len(set(unknown)):
        issues.append("proposal:role_name_collision")
    present = set(names)
    for index, role in enumerate(roles):
        if isinstance(role, Mapping) and isinstance(role.get("reviews"), list):
            for item in role["reviews"]:
                if not isinstance(item, str) or _normal(item) not in present & set(registry.ROLES):
                    issues.append("proposal.roles[" + str(index) + "]:reviews_unknown")
    rules = proposal.get("rules", [])
    if not isinstance(rules, list) or len(rules) > _MAX_RULES:
        issues.append("proposal:rules_invalid")
        rules = []
    for index, rule in enumerate(rules):
        path = "proposal.rules[" + str(index) + "]"
        fields = _RULE_FIELDS.get(rule.get("kind")) if isinstance(rule, Mapping) else None
        if fields is None:
            issues.append(path + ":kind_invalid")
            continue
        if not _closed(rule, fields, frozenset(), path, issues):
            continue
        if any(not _bounded(rule[field]) for field in sorted(fields - {"kind"})):
            issues.append(path + ":text_invalid")
            continue
        if rule["kind"] == "escalation" and any(
            _normal(rule[field]) not in present & set(registry.ROLES) for field in ("from", "to")
        ):
            issues.append(path + ":role_unknown")
        if rule["kind"] == "fallback" and _normal(rule["role"]) not in present:
            issues.append(path + ":role_unknown")
    return sorted(set(issues))


def _question(kind: str, subject: str, label: str, prompt: str, options: Sequence[str]) -> dict[str, Any]:
    return {
        "question_id": registry.question_id(kind, subject),
        "kind": kind,
        "subject": label,
        "prompt": prompt,
        "options": list(options),
    }


def _assumption(assumption_id: str, subject: str, statement: str) -> dict[str, str]:
    return {"assumption_id": assumption_id, "subject": subject, "statement": statement}


def _conflict(conflict_id: str, subject: str, rule: str, statement: str) -> dict[str, str]:
    return {
        "conflict_id": conflict_id,
        "subject": subject,
        "rule": rule,
        "statement": statement + " " + registry.CONFLICT_RULES[rule],
    }


def _route_question(role: str, model: Any, effort: Any, candidates: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    options = [profile["profile_id"] for profile in candidates] + [registry.UNRESOLVED_ROUTE]
    if model is None:
        named = "names no model for the " + role + " role and the registry has no default profile for it"
    else:
        named = "routes the " + role + " role to " + model
        if effort is not None:
            named += " at effort " + effort
        named += ", which no registered " + role + " profile binds"
    return _question(
        "unregistered_route",
        role,
        role,
        "The proposal " + named + ". Choose a registered " + role
        + " profile or leave the role unresolved; compile refuses an unresolved role by name.",
        options,
    )


def _proposed_profile(
    role: str, entry: Mapping[str, Any], view: Any
) -> tuple[str | None, dict[str, Any] | None, dict[str, str] | None]:
    """The registered profile a proposal's role entry names, or the question it raises."""

    candidates = sorted(
        (profile for profile in view.profiles.values() if profile["role"] == role),
        key=lambda profile: profile["profile_id"],
    )
    model = entry.get("model")
    effort = entry.get("effort")
    if model is None:
        default = view.default_profile_id(role)
        if default is None:
            return None, _route_question(role, None, None, candidates), None
        return default, None, _assumption(
            "default_profile:" + role,
            role,
            "The proposal names no model for the " + role
            + " role; the draft proposes its registered default profile " + default + ".",
        )
    matches = [
        profile
        for profile in candidates
        if profile["model_binding"] != "root_executes"
        and profile["default_model"] == model
        and (effort is None or profile["default_effort"] == effort)
    ]
    if len(matches) != 1:
        onboarded_id = registry.onboarded_profile_id(role, model)
        onboarded = registry.onboarded_capability_profile(onboarded_id)
        if onboarded is not None and effort is not None and onboarded["default_effort"] != effort:
            # The proposal names an effort the catalog default does not
            # match: the onboarded identifier pins it.
            onboarded_id = registry.onboarded_profile_id(role, model, effort)
            onboarded = registry.onboarded_capability_profile(onboarded_id)
        if onboarded is not None:
            # ADR 0012: an onboarded model fills the role without a registry
            # entry, at the effort its onboarded profile records.
            return onboarded_id, None, _assumption(
                "onboarded_route:" + role,
                role,
                "The proposal routes the " + role + " role to " + model
                + ", which has an onboarded profile; the draft proposes " + onboarded_id
                + " at effort " + str(onboarded["default_effort"]) + ".",
            )
        return None, _route_question(role, model, effort, candidates), None
    profile = matches[0]
    assumption = None
    if effort is None:
        assumption = _assumption(
            "registered_effort:" + role,
            role,
            "The proposal names no effort for the " + role + " role; the draft uses the effort "
            + str(profile["default_effort"]) + " that profile " + profile["profile_id"]
            + " registers.",
        )
    return profile["profile_id"], None, assumption


def _privacy_conflict(role: str, requested: str, profile: Mapping[str, Any] | None) -> dict[str, str] | None:
    """The conflict a role's requested privacy class raises when it is broader than allowed."""

    registered = profile["privacy_class"] if profile is not None else "local_only"
    if registry.PRIVACY_CLASSES.index(requested) <= registry.PRIVACY_CLASSES.index(registered):
        return None
    if profile is not None:
        detail = "its registered class is " + registered + " and the draft keeps it."
    else:
        detail = "no registered profile is proposed for it, and a proposal cannot assign a privacy class."
    return _conflict(
        "registered_privacy_class:" + role,
        role,
        "FR68/registered-privacy-class",
        "The proposal asks to run the " + role + " role at privacy class " + requested + "; " + detail,
    )


def _draft(
    proposal: Mapping[str, Any],
    view: Any,
    *,
    kind: str,
    prose_sha256: str | None = None,
    requirement_sha256: str | None = None,
) -> dict[str, Any]:
    entries = {_normal(role["name"]): role for role in proposal["roles"]}
    known = [role for role in registry.ROLES if role in entries]
    unknown = sorted(name for name in entries if name not in registry.ROLES)
    roles: list[dict[str, Any]] = []
    questions: list[dict[str, Any]] = []
    assumptions: list[dict[str, str]] = []
    conflicts: list[dict[str, str]] = []
    for role in known:
        profile_id, question, assumption = _proposed_profile(role, entries[role], view)
        roles.append({"role": role, "profile_id": profile_id})
        if question is not None:
            questions.append(question)
        if assumption is not None:
            assumptions.append(assumption)
        requested = entries[role].get("privacy_class")
        if requested is not None:
            profile = view.profiles[profile_id] if profile_id is not None else None
            conflict = _privacy_conflict(role, requested, profile)
            if conflict is not None:
                conflicts.append(conflict)

    if "privacy_envelope" in proposal:
        envelope = sorted(set(proposal["privacy_envelope"]), key=registry.PRIVACY_CLASSES.index)
    else:
        envelope = ["local_only"]
        assumptions.append(_assumption(
            "privacy_envelope",
            "privacy envelope",
            "The proposal names no privacy envelope; the draft admits only local_only, the narrowest class.",
        ))

    for name in unknown:
        questions.append(_question(
            "unknown_role",
            _slug(name),
            name,
            "The proposal names the role '" + name + "', which is outside the closed vocabulary "
            + registry.ROLE_VOCABULARY_VERSION + ". Fold its responsibilities into one of the "
            "draft's roles, which adds no route, or exclude it; no role is invented.",
            [registry.EXCLUDE_ROLE, *known],
        ))

    independence_rules: list[dict[str, Any]] = []
    if "reviewer" in entries:
        entry = entries["reviewer"]
        if "reviews" in entry:
            reviews = sorted({_normal(item) for item in entry["reviews"]})
        else:
            reviews = [role for role in _DEFAULT_REVIEWED_ROLES if role in entries]
            assumptions.append(_assumption(
                "reviewer_scope",
                "reviewer",
                "The proposal does not say what the reviewer reviews; the draft assumes it reviews "
                + (", ".join(reviews) if reviews else "no executing role") + ".",
            ))
        if "independent" in entry:
            independence = "required" if entry["independent"] else "not_required"
        else:
            independence = "undecided"
            questions.append(_question(
                "reviewer_independence",
                "reviewer",
                "reviewer",
                "The proposal does not say whether the reviewer must be independent of the work "
                "it reviews. Required refuses a reviewer route that shares the executor or model "
                "lineage of a reviewed role (FR68).",
                registry.INDEPENDENCE_OPTIONS,
            ))
        independence_rules.append(
            {"reviewer_role": "reviewer", "reviews": reviews, "independence": independence}
        )

    escalation_rules: set[tuple[str, str, str]] = set()
    quota_actions: set[str] = set()
    for index, rule in enumerate(proposal.get("rules", [])):
        if rule["kind"] == "escalation":
            escalation_rules.add((_normal(rule["from"]), _normal(rule["to"]), rule["trigger"].strip()))
        elif rule["kind"] == "fallback":
            conflicts.append(_conflict(
                "runtime_fallback:" + str(index),
                _normal(rule["role"]),
                "FR68/no-runtime-selection",
                "The proposal asks the " + _normal(rule["role"]) + " role to use " + rule["use"].strip()
                + " when " + rule["trigger"].strip() + "; the draft records the rule and never executes it.",
            ))
        else:
            action = rule["action"].strip()
            if action in registry.QUOTA_EXHAUSTION_OPTIONS:
                quota_actions.add(action)
            else:
                conflicts.append(_conflict(
                    "quota_exhaustion:" + str(index),
                    "exhausted or unavailable route",
                    "FR68/no-runtime-selection",
                    "The proposal's quota-exhaustion action '" + action
                    + "' would change a route under a running plan; the draft records it and never executes it.",
                ))
    if len(quota_actions) == 1:
        assumptions.append(_assumption(
            "quota_exhaustion_policy",
            "exhausted or unavailable route",
            "The proposal states the admissible quota-exhaustion action " + next(iter(quota_actions)) + ".",
        ))
    else:
        questions.append(_question(
            "quota_exhaustion_policy",
            "run",
            "exhausted or unavailable route",
            "The proposal leaves open what happens when a route is exhausted or unavailable during a "
            "run. Choose a typed failure, or a typed failure followed by one Owner-approved N+1 "
            "revision; nothing substitutes a model at runtime (FR68).",
            registry.QUOTA_EXHAUSTION_OPTIONS,
        ))
    if "escalation" in entries or escalation_rules:
        assumptions.append(_assumption(
            "escalation_entry",
            "escalation",
            "Escalation triggers are recorded for planning only: a route changes only before freeze "
            "or through one Owner-approved N+1 revision, and no trigger is evaluated at runtime.",
        ))

    proposal_sha256 = _digest(proposal)
    return registry.seal(
        {
            "schema": registry.DRAFT_SCHEMA,
            "draft_id": "architecture-draft-" + proposal_sha256[:16],
            "registry_generation": view.generation,
            "registry_sha256": view.sha256,
            "source": {
                "kind": kind,
                "proposal_id": proposal["proposal_id"],
                "proposal_sha256": proposal_sha256,
                "prose_sha256": prose_sha256,
                "requirement_sha256": requirement_sha256,
            },
            "privacy_envelope": envelope,
            "roles": sorted(roles, key=lambda row: row["role"]),
            "independence_rules": independence_rules,
            "escalation_rules": [
                {"from_role": source, "to_role": target, "trigger": trigger}
                for source, target, trigger in sorted(escalation_rules)
            ],
            "questions": sorted(questions, key=lambda row: row["question_id"]),
            "assumptions": sorted(assumptions, key=lambda row: row["assumption_id"]),
            "conflicts": sorted(conflicts, key=lambda row: row["conflict_id"]),
        },
        "draft_sha256",
    )


def _prose_requirement(prose: str, view: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Seal the bounded task an ordinary task runs to restate prose as a proposal."""

    data = prose.encode("utf-8")
    if not data.strip() or len(data) > MAX_PROSE_BYTES:
        return None, ["prose:size_invalid"]
    executor_profile = view.default_profile_id("orchestrator")
    if executor_profile is None:
        return None, ["prose:orchestrator_unregistered"]
    prose_sha256 = _sha256_bytes(data)
    proposal_id = "prose-" + prose_sha256[:24]
    prose_ref = contracts.seal_artifact_ref(
        {
            "schema": contracts.ARTIFACT_REF_SCHEMA,
            "uri": "artifact://sha256/" + prose_sha256,
            "sha256": prose_sha256,
            "size_bytes": len(data),
            "media_type": _PROSE_MEDIA_TYPE,
        }
    )
    # The Owner's ordinary root task restates the prose: no worker is
    # admitted, no project file is read or written, and no tool is allowed.
    task_spec = contracts.seal_task_spec(
        {
            "schema": contracts.TASK_SPEC_SCHEMA,
            "id": "architecture-digest-" + prose_sha256[:16],
            "kind": "execute",
            "goal": (
                "Restate the referenced prose architecture proposal as one " + PROPOSAL_SCHEMA
                + " document whose proposal_id is " + proposal_id + "."
            ),
            "rationale": (
                "FR68 digests a prose proposal only through a bounded model-assisted task under "
                "existing authority; its proposal stays untrusted until it is digested against "
                "this requirement and the task's handoff."
            ),
            "non_goals": [
                "Choose, rank, or substitute a model",
                "Approve or seal the draft",
                "Grant authority or write project files",
            ],
            "dependencies": [],
            "input_refs": [prose_ref],
            "read_scope": [],
            "write_scope": [],
            "deliverable": {
                "schema": PROPOSAL_SCHEMA,
                "media_type": _PROPOSAL_MEDIA_TYPE,
                "description": (
                    "One structured proposal that restates only what the prose states, leaves "
                    "undecided matters unstated so they surface as typed questions, keeps any "
                    "role name outside the closed vocabulary as written, and records every "
                    "fallback, substitution, or quota rule as a rule."
                ),
            },
            "acceptance_checks": [
                {
                    "id": _ACCEPTANCE_CHECK,
                    "description": (
                        "The deliverable validates as " + PROPOSAL_SCHEMA
                        + " and carries proposal_id " + proposal_id
                    ),
                    "required": True,
                }
            ],
            "executor": "root_task",
            "model_profile": executor_profile,
            "allowed_tools": [],
            "risk": {"level": "low", "reasons": ["untrusted_until_digested"]},
            "budgets": dict(_TASK_BUDGETS),
            "may_request_decomposition": False,
            "failure_policy": {
                "on_blocked": "return_receipt",
                "on_failed": "return_receipt",
                "on_budget_exhausted": "return_receipt",
            },
        }
    )
    requirement = registry.seal(
        {
            "schema": REQUIREMENT_SCHEMA,
            "task_spec": task_spec,
            "prose_sha256": prose_sha256,
            "proposal_id": proposal_id,
            "registry_generation": view.generation,
            "registry_sha256": view.sha256,
            "privacy_class": "local_only",
            "authority_class": "none",
        },
        "requirement_sha256",
    )
    return requirement, []


def requirement_issues(requirement: Any, view: Any) -> list[str]:
    """Return every reason requirement is not a sealed, current digest requirement."""

    if not isinstance(requirement, Mapping) or set(requirement) != _REQUIREMENT_FIELDS:
        return ["requirement:shape_invalid"]
    issues: list[str] = []
    if requirement["schema"] != REQUIREMENT_SCHEMA:
        issues.append("requirement:schema_invalid")
    if not registry.seal_valid(requirement, "requirement_sha256"):
        issues.append("requirement:seal_invalid")
    if (requirement["privacy_class"], requirement["authority_class"]) != ("local_only", "none"):
        issues.append("requirement:authority_invalid")
    if (requirement["registry_generation"], requirement["registry_sha256"]) != (
        view.generation,
        view.sha256,
    ):
        issues.append("requirement:registry_stale")
    prose_sha256 = requirement["prose_sha256"]
    if not isinstance(prose_sha256, str) or not _SHA256.fullmatch(prose_sha256):
        issues.append("requirement:prose_sha256_invalid")
        prose_sha256 = ""
    if requirement["proposal_id"] != "prose-" + prose_sha256[:24]:
        issues.append("requirement:proposal_id_invalid")
    report = contracts.validate_task_spec(requirement["task_spec"])
    if report.get("status") != "PASS" or report["normalized"] != requirement["task_spec"]:
        issues.append("requirement:task_spec_invalid")
    else:
        spec = requirement["task_spec"]
        if (
            spec["deliverable"]["schema"] != PROPOSAL_SCHEMA
            or spec["deliverable"]["media_type"] != _PROPOSAL_MEDIA_TYPE
            or spec["write_scope"]
            or spec["allowed_tools"]
            or [ref["sha256"] for ref in spec["input_refs"]] != [prose_sha256]
            or [check["id"] for check in spec["acceptance_checks"]] != [_ACCEPTANCE_CHECK]
        ):
            issues.append("requirement:task_spec_unbound")
    return sorted(set(issues))


def handoff_issues(handoff: Any, requirement: Mapping[str, Any], proposal: Any) -> list[str]:
    """Return every reason handoff is not the complete receipt that returned proposal."""

    report = contracts.validate_handoff_receipt(handoff, task_spec=requirement["task_spec"])
    if report.get("status") != "PASS":
        # Nothing in a receipt that fails its own contract can be read.
        return ["handoff:invalid"]
    receipt = report["normalized"]
    issues: list[str] = []
    if receipt["disposition"] != "complete":
        issues.append("handoff:not_complete")
    data = contracts.canonical_bytes(proposal)
    digest_value = _sha256_bytes(data)
    if not any(
        ref["sha256"] == digest_value
        and ref["size_bytes"] == len(data)
        and ref["media_type"] == _PROPOSAL_MEDIA_TYPE
        for ref in receipt["artifact_refs"]
    ):
        issues.append("handoff:proposal_artifact_missing")
    return issues


def _result(status: str, **fields: Any) -> dict[str, Any]:
    result = {"status": status, "draft": None, "requirement": None, "reasons": []}
    result.update(fields)
    return result


def digest(value: Any, *, requirement: Any = None, handoff: Any = None) -> dict[str, Any]:
    """The one digest operation.

    A structured proposal digests to {"status": "DRAFTED", "draft": ...}.
    Prose returns {"status": "MODEL_ASSISTED_DIGEST_REQUIRED", "requirement":
    ...}: an ordinary task runs the requirement's bounded task spec, and the
    proposal it returns digests with requirement= and that task's complete
    handoff=.  Anything else is {"status": "REFUSED", "reasons": [...]}.
    Every draft is untrusted until the Owner seals it.
    """

    view = registry.registry_view()
    if isinstance(value, str):
        if requirement is not None or handoff is not None:
            return _result("REFUSED", reasons=["prose:requirement_unexpected"])
        sealed, issues = _prose_requirement(value, view)
        if issues:
            return _result("REFUSED", reasons=issues)
        return _result("MODEL_ASSISTED_DIGEST_REQUIRED", requirement=sealed)
    issues = proposal_issues(value)
    if (requirement is None) != (handoff is None):
        issues.append("proposal:requirement_and_handoff_required_together")
    elif requirement is not None:
        issues.extend(requirement_issues(requirement, view))
        if not issues:
            if value["proposal_id"] != requirement["proposal_id"]:
                issues.append("proposal:requirement_mismatch")
            issues.extend(handoff_issues(handoff, requirement, value))
    if issues:
        return _result("REFUSED", reasons=sorted(set(issues)))
    if requirement is None:
        draft = _draft(value, view, kind="structured")
    else:
        draft = _draft(
            value,
            view,
            kind="model_assisted",
            prose_sha256=requirement["prose_sha256"],
            requirement_sha256=requirement["requirement_sha256"],
        )
    problems = registry.validate_draft(draft)
    if problems:
        return _result("REFUSED", reasons=["draft:" + issue for issue in problems])
    return _result("DRAFTED", draft=draft)


def _directory(root: Any) -> int:
    try:
        return os.open(Path(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise IngestionError("approval:root_unavailable") from error


def seal_approval(
    approvals_root: Any,
    draft: Any,
    *,
    decisions: Mapping[str, str],
    acknowledged_conflicts: Sequence[str],
) -> dict[str, Any]:
    """Record the Owner's seal of one draft create-only, named by its digest.

    The approval answers every typed question from its own options and
    acknowledges every conflict; an approval for that digest that already
    exists is never replaced.  Returns the sealed approval.
    """

    try:
        approval = registry.approve_draft(
            draft, decisions=decisions, acknowledged_conflicts=acknowledged_conflicts
        )
    except ValueError as error:
        raise IngestionError(str(error)) from error
    data = contracts.canonical_bytes(approval) + b"\n"
    directory = _directory(approvals_root)
    try:
        try:
            descriptor = os.open(
                approval["draft_sha256"] + ".json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
        except FileExistsError as error:
            raise IngestionError("approval:exists") from error
        except OSError as error:
            raise IngestionError("approval:unwritable") from error
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)
    finally:
        os.close(directory)
    return approval


def read_approval(approvals_root: Any, draft_sha256: Any) -> dict[str, Any] | None:
    """The Owner's recorded approval of the draft with this digest, or None."""

    if not isinstance(draft_sha256, str) or not _SHA256.fullmatch(draft_sha256):
        raise IngestionError("approval:draft_sha256_invalid")
    directory = _directory(approvals_root)
    try:
        try:
            descriptor = os.open(
                draft_sha256 + ".json",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=directory,
            )
        except FileNotFoundError:
            return None
        except OSError as error:
            raise IngestionError("approval:unreadable") from error
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_APPROVAL_BYTES:
                raise IngestionError("approval:not_regular")
            data = os.read(descriptor, MAX_APPROVAL_BYTES + 1)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise IngestionError("approval:duplicate_key")
            result[key] = item
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IngestionError("approval:invalid_json") from error
    if not isinstance(value, dict):
        raise IngestionError("approval:not_object")
    return value


def compile_sealed(approvals_root: Any, draft: Any, catalog: Any) -> dict[str, Any]:
    """Compile a draft with the Owner's recorded approval of its exact digest."""

    digest_value = draft.get("draft_sha256") if isinstance(draft, Mapping) else None
    approval = None
    if isinstance(digest_value, str) and _SHA256.fullmatch(digest_value):
        approval = read_approval(approvals_root, digest_value)
    return registry.compile_routing_policy(draft, catalog, approval=approval)


def _read_input(path: str) -> bytes:
    data = Path(path).read_bytes()
    if len(data) > MAX_INPUT_BYTES:
        raise IngestionError("input:too_large")
    return data


def _load_json(path: str) -> Any:
    return json.loads(_read_input(path).decode("utf-8"))


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Digest, approve, and compile architecture drafts (Issue 184).")
    commands = parser.add_subparsers(dest="command", required=True)
    digest_command = commands.add_parser("digest", help="digest a proposal into an untrusted draft")
    source = digest_command.add_mutually_exclusive_group(required=True)
    source.add_argument("--proposal", help="path to a structured proposal JSON")
    source.add_argument("--prose", help="path to a prose proposal text file")
    digest_command.add_argument("--requirement", help="path to the sealed requirement a returned proposal answers")
    digest_command.add_argument("--handoff", help="path to the requirement task's complete handoff receipt")
    approve_command = commands.add_parser("approve", help="record the Owner's create-only approval of a draft")
    approve_command.add_argument("--draft", required=True, help="path to the draft JSON")
    approve_command.add_argument("--approvals-root", required=True, help="directory of approval records")
    approve_command.add_argument(
        "--decisions", required=True, help="path to a JSON object mapping question_id to answer"
    )
    approve_command.add_argument("--acknowledge", action="append", default=[], metavar="CONFLICT_ID")
    compile_command = commands.add_parser("compile", help="compile a sealed draft into a routing policy")
    compile_command.add_argument("--draft", required=True, help="path to the draft JSON")
    compile_command.add_argument("--approvals-root", required=True, help="directory of approval records")
    compile_command.add_argument("--catalog", required=True, help="path to the runtime catalog JSON")
    args = parser.parse_args(argv)
    try:
        if args.command == "digest":
            if args.prose is not None:
                result = digest(_read_input(args.prose).decode("utf-8"))
            else:
                result = digest(
                    _load_json(args.proposal),
                    requirement=_load_json(args.requirement) if args.requirement else None,
                    handoff=_load_json(args.handoff) if args.handoff else None,
                )
            status = 1 if result["status"] == "REFUSED" else 0
        elif args.command == "approve":
            result = {
                "status": "APPROVED",
                "approval": seal_approval(
                    args.approvals_root,
                    _load_json(args.draft),
                    decisions=_load_json(args.decisions),
                    acknowledged_conflicts=args.acknowledge,
                ),
            }
            status = 0
        else:
            result = compile_sealed(args.approvals_root, _load_json(args.draft), _load_json(args.catalog))
            status = 1 if result["status"] == "REFUSED" else 0
    except IngestionError as error:
        result = {"status": "REFUSED", "reasons": str(error).split(",")}
        status = 1
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        result = {"status": "REFUSED", "reasons": ["input:unreadable"]}
        status = 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(_main())
