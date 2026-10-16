"""Closed, content-addressed model-profile registry (ADR 0010, FR68, section 15).

A semantic role is a planning concept; the executor group stays the runtime
concept. This module maps the closed role vocabulary to registered capability
profiles and provides one provider-free compile operation that turns an
architecture draft the Owner sealed, plus the runtime catalog, into a sealed
routing policy or a refusal naming every unresolved role and unqualified route.
The draft schema and the Owner's approval record are closed here; the digest
stage that produces a draft lives in orch_dork_architecture_ingestion.

Generation v2 is the contract step of the migration (Issue 185). The three
per-node profile values of the expand step keep their exact resolution
semantics as aliases of the implementer, escalation, and root-labor reviewer
profiles, and alias acceptance is confined to historical replay adapters.
The closed root-model/surface matrix is a registry entry: every root model a
validator may accept is an orchestrator profile whose surface names the
collaboration backend the live turn context must report, and adding a root
route requires a registry entry plus qualification, never an environment
override. Every profile that binds a model carries a closed model lineage so
a reviewer whose independence is required can refuse, by name, a route that
shares the executor or lineage of the node it reviews. Nothing here selects,
substitutes, or falls back at runtime, reads the environment, or calls a
model, dispatcher, capacity ledger, credential store, or authority path.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
from types import MappingProxyType
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
worker_default = _load_sibling("orch_dork_worker_default")
onboarded_profiles = _load_sibling("orch_dork_onboarded_profiles")

# The registry's field set is unchanged since v1; the generation below is
# what a draft binds and what turns stale when the profile contract moves.
REGISTRY_SCHEMA = "orch-dork/model-profile-registry/v1"
PROFILE_SCHEMA = "orch-dork/capability-profile/v2"
DRAFT_SCHEMA = "orch-dork/architecture-draft/v1"
POLICY_SCHEMA = "orch-dork/routing-policy/v2"
REFUSAL_SCHEMA = "orch-dork/routing-policy-refusal/v1"
CAPABILITY_SCHEMA = "orch-dork/executor-capability/v1"
REGISTRY_GENERATION = "model-profile-registry/v2"
ROLE_VOCABULARY_VERSION = "semantic-roles/v1"

ROLES = (
    "orchestrator",
    "planner",
    "implementer",
    "reviewer",
    "trivial",
    "escalation",
)
PRIVACY_CLASSES = ("local_only", "hosted_restricted", "hosted_standard")
QUALIFICATION_STATES = ("qualified", "unqualified")
# How a profile is bound to a model.  "governed_worker_default" and
# "strong_default" resolve through the worker and strong-integrator ladders
# of orch_dork_worker_default before freeze; "profile_model" is the profile's
# own exact model and effort with no ladder; "root_executes" is root labor;
# "root_model" is the orchestrator binding: the profile names the exact root
# model and effort a task runs as, and its surface is the collaboration
# backend Codex pins to that task.
MODEL_BINDINGS = (
    "governed_worker_default",
    "strong_default",
    "profile_model",
    "root_executes",
    "root_model",
)
ADAPTERS = ("native_subagent", "root_labor", "root_task")
SURFACES = ("multi_agent_v1", "multi_agent_v2", "root_turn")
# A model's provenance, closed.  Two routes of one lineage are not independent
# of each other even when their executors differ.
LINEAGES = ("openai", "anthropic", "qwen")
# The registry's surface vocabulary for the collaboration backends, mapped to
# the exact "multi_agent_version" the current-turn route observer reads from
# the live turn context.  Codex pins the backend when a task starts: native
# Sol/Astra need classic V1 so routed worker tasks remain plaintext, routed
# Opus uses V2, and the routed Fable root was observed on V1.
ROOT_SURFACE_OBSERVED = MappingProxyType({"multi_agent_v1": "v1", "multi_agent_v2": "v2"})
# The collaboration backends a native-subagent worker binding may name.
BACKEND_SURFACES = frozenset(ROOT_SURFACE_OBSERVED)
# Each role's default profile: the profile a plan resolves through when it
# names the role without a profile, and the root a provider-free Control
# Tower plans under when no observed root is injected.  A default changes
# only as a Challenger that passes the whole promotion path (ADR 0010,
# FR60); role_default_change names why a proposed change refuses (Issue 186).
DEFAULT_PROFILE_IDS = MappingProxyType({
    "escalation": "escalation.strong-worker/v1",
    "implementer": "implementer.governed-worker/v1",
    "orchestrator": "orchestrator.sol/v1",
    "reviewer": "reviewer.root-labor/v1",
})

# The v50 promotion-qualification receipt (Issue 170) that qualified the root
# route gpt-5.6-sol/xhigh with governed workers openrouter/qwen-qwen3.8-27b/xhigh.
_V50_QUALIFICATION_RECEIPT_SHA256 = (
    "6baee4a469112291e1f599f7a1d0eea39db932cbb60e768f4e595531b0e3ca45"
)
# The root the v50 receipt proved, written here as the exact literal the
# receipt bound rather than borrowed from the strong-worker default: a
# change to that default must not re-point a qualified root.  The registry
# is the one product module that names root models.
_SOL_ROOT_MODEL = "gpt-5.6-sol"
_SOL_ROOT_EFFORT = "xhigh"
# Registered root models that have no qualification receipt yet.  Each becomes
# qualified only through one fresh-task qualification whose receipt digest is
# bound here in the following generation.
_ASTRA_ROOT_MODEL = "gpt-6-astra"
_OPUS_ROOT_MODEL = "anthropic/claude-opus-5"
_FABLE_ROOT_MODEL = "anthropic/claude-fable-5-1"
_FABLE_ROOT_EFFORT = "xhigh"
# Issue 187's Owner-selected reviewer route: the independent Opus reviewer
# worker through opencodex.  Registered unqualified until its one attempt.
_INDEPENDENT_REVIEWER_MODEL = "anthropic/claude-opus-5-5"
_INDEPENDENT_REVIEWER_EFFORT = "xhigh"
# The local vLLM worker route retired from qualification (AGENTS.md) and
# kept for pinned historical replay: a second, unqualified implementer
# profile, so a plan can route two ordinary nodes to two distinct
# implementer profiles and compile refuses the unqualified one by name.
_LOCAL_IMPLEMENTER_MODEL = "qwen-local/qwen-smart"
_LOCAL_IMPLEMENTER_EFFORT = "medium"

_REGISTRY_FIELDS = frozenset(
    {"schema", "generation", "role_vocabulary", "profiles", "registry_sha256"}
)
_VOCABULARY_FIELDS = frozenset({"version", "roles"})
_PROFILE_FIELDS = frozenset(
    {
        "schema",
        "profile_id",
        "role",
        "aliases",
        "model_binding",
        "lineage",
        "default_model",
        "default_effort",
        "surface",
        "adapter",
        "independence_required",
        "privacy_class",
        "qualification",
        "profile_sha256",
    }
)
_UNQUALIFIED = {"state": "unqualified", "tuple": None, "receipt_sha256": None}
_QUALIFICATION_FIELDS = frozenset({"state", "tuple", "receipt_sha256"})
# A qualification binds the exact route it proved: model, effort, surface, and
# adapter.  A profile that changes any of them is no longer qualified by it.
_TUPLE_FIELDS = frozenset({"model", "effort", "surface", "adapter"})
_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "draft_id",
        "registry_generation",
        "registry_sha256",
        "source",
        "privacy_envelope",
        "roles",
        "independence_rules",
        "escalation_rules",
        "questions",
        "assumptions",
        "conflicts",
        "draft_sha256",
    }
)
_DRAFT_ROLE_FIELDS = frozenset({"role", "profile_id"})
_DRAFT_SOURCE_FIELDS = frozenset(
    {"kind", "proposal_id", "proposal_sha256", "prose_sha256", "requirement_sha256"}
)
# "structured" drafts come from a structured proposal digested provider-free;
# "model_assisted" drafts come from the structured proposal an ordinary,
# bounded task returned for a prose proposal and its sealed requirement.
DRAFT_SOURCE_KINDS = ("model_assisted", "structured")
_INDEPENDENCE_RULE_FIELDS = frozenset({"reviewer_role", "reviews", "independence"})
INDEPENDENCE_STATES = ("not_required", "required", "undecided")
_ESCALATION_RULE_FIELDS = frozenset({"from_role", "to_role", "trigger"})
_QUESTION_FIELDS = frozenset({"question_id", "kind", "subject", "prompt", "options"})
# Every missing decision is one of these closed kinds, and every answer is one
# of the question's own options: the Owner decides, the draft never guesses.
QUESTION_KINDS = (
    "quota_exhaustion_policy",
    "reviewer_independence",
    "unknown_role",
    "unregistered_route",
)
_ASSUMPTION_FIELDS = frozenset({"assumption_id", "subject", "statement"})
_CONFLICT_FIELDS = frozenset({"conflict_id", "subject", "rule", "statement"})
# The rules a proposal can conflict with, each citing the specification text
# it violates.  A conflicting rule is recorded in the draft and never executed.
CONFLICT_RULES = MappingProxyType({
    "FR68/no-runtime-selection": (
        "Nothing selects, substitutes, or falls back to a model at runtime; an "
        "unavailable or exhausted route is a typed failure and, at the Owner's "
        "choice, one explicit N+1 revision."
    ),
    "FR68/registered-privacy-class": (
        "A privacy class is a registered profile attribute admitted only inside "
        "the plan's privacy envelope; a proposal cannot widen it."
    ),
})
QUOTA_EXHAUSTION_OPTIONS = ("typed_failure", "typed_failure_and_owner_revision")
INDEPENDENCE_OPTIONS = ("not_required", "required")
# The answer that leaves a role without a route: compile refuses it by name.
UNRESOLVED_ROUTE = "unresolved"
# The answer that keeps an out-of-vocabulary role out of the draft.
EXCLUDE_ROLE = "exclude"
APPROVAL_SCHEMA = "orch-dork/architecture-draft-approval/v1"
APPROVER = "owner"
_APPROVAL_FIELDS = frozenset(
    {
        "schema",
        "draft_sha256",
        "approver",
        "decisions",
        "acknowledged_conflicts",
        "approval_sha256",
    }
)
_DECISION_FIELDS = frozenset({"question_id", "answer"})
_MAX_DRAFT_ITEMS = 64
_MAX_DRAFT_TEXT_BYTES = 2048
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


def _sha256(value: Any) -> str:
    return hashlib.sha256(contracts.canonical_bytes(value)).hexdigest()


def seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    """Return a copy of value carrying the canonical digest of its other fields."""

    core = deepcopy(dict(value))
    core.pop(field, None)
    return {**core, field: _sha256(core)}


def seal_valid(value: Any, field: str) -> bool:
    """Whether value carries a correct canonical digest in field."""

    if not isinstance(value, Mapping) or field not in value:
        return False
    digest = value.get(field)
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        return False
    core = dict(value)
    core.pop(field, None)
    return digest == _sha256(core)


def _profile(
    profile_id: str,
    *,
    role: str,
    alias: str | None,
    model_binding: str,
    lineage: str | None,
    default_model: str | None,
    default_effort: str | None,
    surface: str,
    adapter: str,
    qualification: Mapping[str, Any],
    independence_required: bool = False,
) -> dict[str, Any]:
    return seal(
        {
            "schema": PROFILE_SCHEMA,
            "profile_id": profile_id,
            "role": role,
            "aliases": [] if alias is None else [alias],
            "model_binding": model_binding,
            "lineage": lineage,
            "default_model": default_model,
            "default_effort": default_effort,
            "surface": surface,
            "adapter": adapter,
            "independence_required": independence_required,
            "privacy_class": "local_only",
            "qualification": dict(qualification),
        },
        "profile_sha256",
    )


def _orchestrator(
    profile_id: str,
    *,
    model: str,
    effort: str,
    lineage: str,
    surface: str,
    receipt_sha256: str | None,
) -> dict[str, Any]:
    qualification: dict[str, Any] = dict(_UNQUALIFIED)
    if receipt_sha256 is not None:
        qualification = {
            "state": "qualified",
            "tuple": {
                "model": model,
                "effort": effort,
                "surface": surface,
                "adapter": "root_task",
            },
            "receipt_sha256": receipt_sha256,
        }
    return _profile(
        profile_id,
        role="orchestrator",
        alias=None,
        model_binding="root_model",
        lineage=lineage,
        default_model=model,
        default_effort=effort,
        surface=surface,
        adapter="root_task",
        qualification=qualification,
    )


def _builtin_registry() -> dict[str, Any]:
    profiles = [
        _profile(
            "escalation.strong-worker/v1",
            role="escalation",
            alias="strong_integrator",
            model_binding="strong_default",
            lineage="openai",
            default_model=worker_default.DEFAULT_STRONG_MODEL,
            default_effort=worker_default.DEFAULT_STRONG_EFFORT,
            surface="multi_agent_v1",
            adapter="native_subagent",
            qualification=_UNQUALIFIED,
        ),
        _profile(
            "implementer.governed-worker/v1",
            role="implementer",
            alias="qwen_executor",
            model_binding="governed_worker_default",
            lineage="qwen",
            default_model=worker_default.DEFAULT_WORKER_MODEL,
            default_effort=worker_default.DEFAULT_WORKER_EFFORT,
            surface="multi_agent_v1",
            adapter="native_subagent",
            qualification={
                "state": "qualified",
                "tuple": {
                    "model": worker_default.DEFAULT_WORKER_MODEL,
                    "effort": worker_default.DEFAULT_WORKER_EFFORT,
                    "surface": "multi_agent_v1",
                    "adapter": "native_subagent",
                },
                "receipt_sha256": _V50_QUALIFICATION_RECEIPT_SHA256,
            },
        ),
        _profile(
            "implementer.local-qwen/v1",
            role="implementer",
            alias=None,
            model_binding="profile_model",
            lineage="qwen",
            default_model=_LOCAL_IMPLEMENTER_MODEL,
            default_effort=_LOCAL_IMPLEMENTER_EFFORT,
            surface="multi_agent_v1",
            adapter="native_subagent",
            qualification=_UNQUALIFIED,
        ),
        _orchestrator(
            "orchestrator.astra/v1",
            model=_ASTRA_ROOT_MODEL,
            effort=worker_default.DEFAULT_STRONG_EFFORT,
            lineage="openai",
            surface="multi_agent_v1",
            receipt_sha256=None,
        ),
        _orchestrator(
            "orchestrator.fable/v1",
            model=_FABLE_ROOT_MODEL,
            effort=_FABLE_ROOT_EFFORT,
            lineage="anthropic",
            surface="multi_agent_v1",
            receipt_sha256=None,
        ),
        _orchestrator(
            "orchestrator.opus/v1",
            model=_OPUS_ROOT_MODEL,
            effort=worker_default.DEFAULT_STRONG_EFFORT,
            lineage="anthropic",
            surface="multi_agent_v2",
            receipt_sha256=None,
        ),
        _orchestrator(
            "orchestrator.sol/v1",
            model=_SOL_ROOT_MODEL,
            effort=_SOL_ROOT_EFFORT,
            lineage="openai",
            surface="multi_agent_v1",
            receipt_sha256=_V50_QUALIFICATION_RECEIPT_SHA256,
        ),
        _profile(
            "reviewer.independent-opus/v1",
            role="reviewer",
            alias=None,
            model_binding="profile_model",
            lineage="anthropic",
            default_model=_INDEPENDENT_REVIEWER_MODEL,
            default_effort=_INDEPENDENT_REVIEWER_EFFORT,
            surface="multi_agent_v1",
            adapter="native_subagent",
            qualification=_UNQUALIFIED,
            independence_required=True,
        ),
        _profile(
            "reviewer.root-labor/v1",
            role="reviewer",
            alias="sol_verifier",
            model_binding="root_executes",
            lineage=None,
            default_model=None,
            default_effort=None,
            surface="root_turn",
            adapter="root_labor",
            qualification={
                "state": "qualified",
                "tuple": {
                    "model": worker_default.DEFAULT_STRONG_MODEL,
                    "effort": worker_default.DEFAULT_STRONG_EFFORT,
                    "surface": "root_turn",
                    "adapter": "root_labor",
                },
                "receipt_sha256": _V50_QUALIFICATION_RECEIPT_SHA256,
            },
        ),
    ]
    return seal(
        {
            "schema": REGISTRY_SCHEMA,
            "generation": REGISTRY_GENERATION,
            "role_vocabulary": {
                "version": ROLE_VOCABULARY_VERSION,
                "roles": list(ROLES),
            },
            "profiles": profiles,
        },
        "registry_sha256",
    )


def _exact(value: Any, fields: frozenset[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        issues.append(path + ":not_object")
        return False
    for key in sorted(set(value) - fields):
        issues.append(path + ":unknown:" + str(key))
    for key in sorted(fields - set(value)):
        issues.append(path + ":missing:" + key)
    return set(value) == fields


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_qualification(value: Any, path: str, issues: list[str]) -> None:
    if not _exact(value, _QUALIFICATION_FIELDS, path, issues):
        return
    state = value.get("state")
    if state not in QUALIFICATION_STATES:
        issues.append(path + ":state_invalid")
        return
    tuple_value = value.get("tuple")
    receipt = value.get("receipt_sha256")
    if state == "qualified":
        if not isinstance(receipt, str) or _SHA256.fullmatch(receipt) is None:
            issues.append(path + ":receipt_invalid")
        if not _exact(tuple_value, _TUPLE_FIELDS, path + ".tuple", issues):
            return
        if any(not _text(tuple_value.get(field)) for field in sorted(_TUPLE_FIELDS)):
            issues.append(path + ".tuple:invalid")
    elif tuple_value is not None or receipt is not None:
        issues.append(path + ":unqualified_binds_evidence")


def _validate_profile(value: Any, path: str, issues: list[str]) -> None:
    if not _exact(value, _PROFILE_FIELDS, path, issues):
        return
    if value.get("schema") != PROFILE_SCHEMA:
        issues.append(path + ":schema_invalid")
    if not isinstance(value.get("profile_id"), str) or not _IDENTIFIER.fullmatch(
        value["profile_id"]
    ):
        issues.append(path + ":profile_id_invalid")
    if value.get("role") not in ROLES:
        issues.append(path + ":role_invalid")
    aliases = value.get("aliases")
    if (
        not isinstance(aliases, list)
        or any(not isinstance(alias, str) or not _IDENTIFIER.fullmatch(alias) for alias in aliases)
        or len(aliases) != len(set(aliases))
        or any(alias in ROLES for alias in aliases)
    ):
        issues.append(path + ":aliases_invalid")
    binding = value.get("model_binding")
    if binding not in MODEL_BINDINGS:
        issues.append(path + ":model_binding_invalid")
    elif binding == "root_executes":
        if value.get("default_model") is not None or value.get("default_effort") is not None:
            issues.append(path + ":root_binding_names_model")
        if value.get("adapter") != "root_labor" or value.get("surface") != "root_turn":
            issues.append(path + ":root_binding_adapter_invalid")
        # Root labor runs on whichever root the plan declares, so its
        # lineage is the root's and is resolved when a plan is routed.
        if value.get("lineage") is not None:
            issues.append(path + ":root_binding_names_lineage")
    elif binding == "root_model":
        if not _text(value.get("default_model")) or not _text(value.get("default_effort")):
            issues.append(path + ":default_route_invalid")
        if value.get("adapter") != "root_task" or value.get("surface") not in ROOT_SURFACE_OBSERVED:
            issues.append(path + ":orchestrator_binding_adapter_invalid")
        if value.get("lineage") not in LINEAGES:
            issues.append(path + ":lineage_invalid")
    else:
        if not _text(value.get("default_model")) or not _text(value.get("default_effort")):
            issues.append(path + ":default_route_invalid")
        if value.get("adapter") != "native_subagent" or value.get("surface") not in BACKEND_SURFACES:
            issues.append(path + ":worker_binding_adapter_invalid")
        if value.get("lineage") not in LINEAGES:
            issues.append(path + ":lineage_invalid")
    # The orchestrator role and the root_model binding imply each other: the
    # root matrix is exactly the set of orchestrator profiles.
    if (value.get("role") == "orchestrator") != (binding == "root_model"):
        issues.append(path + ":orchestrator_binding_mismatch")
    if value.get("surface") not in SURFACES:
        issues.append(path + ":surface_invalid")
    if value.get("adapter") not in ADAPTERS:
        issues.append(path + ":adapter_invalid")
    if not isinstance(value.get("independence_required"), bool):
        issues.append(path + ":independence_required_invalid")
    if value.get("privacy_class") not in PRIVACY_CLASSES:
        issues.append(path + ":privacy_class_invalid")
    qualification = value.get("qualification")
    _validate_qualification(qualification, path + ".qualification", issues)
    proved = qualification.get("tuple") if isinstance(qualification, Mapping) else None
    if isinstance(proved, Mapping) and (
        proved.get("surface") != value.get("surface")
        or proved.get("adapter") != value.get("adapter")
        or (
            binding != "root_executes"
            and (proved.get("model"), proved.get("effort"))
            != (value.get("default_model"), value.get("default_effort"))
        )
    ):
        issues.append(path + ":qualification_route_mismatch")
    if not seal_valid(value, "profile_sha256"):
        issues.append(path + ":seal_invalid")


def validate_registry(value: Any) -> list[str]:
    """Return every reason value is not an acceptable registry; empty means valid."""

    issues: list[str] = []
    if not _exact(value, _REGISTRY_FIELDS, "registry", issues):
        return sorted(set(issues))
    if value.get("schema") != REGISTRY_SCHEMA:
        issues.append("registry:schema_invalid")
    if value.get("generation") != REGISTRY_GENERATION:
        issues.append("registry:generation_unsupported")
    vocabulary = value.get("role_vocabulary")
    if _exact(vocabulary, _VOCABULARY_FIELDS, "registry.role_vocabulary", issues):
        if (
            vocabulary.get("version") != ROLE_VOCABULARY_VERSION
            or vocabulary.get("roles") != list(ROLES)
        ):
            issues.append("registry.role_vocabulary:unsupported")
    profiles = value.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        issues.append("registry:profiles_invalid")
        profiles = []
    profile_ids: list[str] = []
    aliases: list[str] = []
    for index, profile in enumerate(profiles):
        path = "registry:profiles[" + str(index) + "]"
        _validate_profile(profile, path, issues)
        if isinstance(profile, Mapping):
            if isinstance(profile.get("profile_id"), str):
                profile_ids.append(profile["profile_id"])
            if isinstance(profile.get("aliases"), list):
                aliases.extend(str(alias) for alias in profile["aliases"])
    if len(profile_ids) != len(set(profile_ids)):
        issues.append("registry:profile_duplicate")
    if profile_ids != sorted(profile_ids):
        issues.append("registry:profiles_not_canonical")
    if len(aliases) != len(set(aliases)):
        issues.append("registry:alias_duplicate")
    if set(aliases) & set(profile_ids):
        issues.append("registry:alias_shadows_profile")
    root_models = [
        profile.get("default_model")
        for profile in profiles
        if isinstance(profile, Mapping) and profile.get("model_binding") == "root_model"
    ]
    if len(root_models) != len(set(root_models)):
        issues.append("registry:root_model_duplicate")
    lineages: dict[Any, set[str]] = {}
    for profile in profiles:
        if isinstance(profile, Mapping) and isinstance(profile.get("lineage"), str):
            lineages.setdefault(profile.get("default_model"), set()).add(profile["lineage"])
    if any(len(found) > 1 for found in lineages.values()):
        issues.append("registry:model_lineage_conflict")
    if not seal_valid(value, "registry_sha256"):
        issues.append("registry:seal_invalid")
    return sorted(set(issues))


_REGISTRY = _builtin_registry()
_REGISTRY_ISSUES = validate_registry(_REGISTRY)
if _REGISTRY_ISSUES:
    raise RuntimeError("model-profile registry invalid: " + ",".join(_REGISTRY_ISSUES))
_ALIASES = {
    alias: profile
    for profile in _REGISTRY["profiles"]
    for alias in profile["aliases"]
}


class _RegistryView:
    """Lookup tables over one sealed registry: the active one, or a private copy."""

    __slots__ = ("value", "profiles", "root_profiles")

    def __init__(self, value: Mapping[str, Any]) -> None:
        self.value = value
        self.profiles = {profile["profile_id"]: profile for profile in value["profiles"]}
        self.root_profiles = {
            profile["default_model"]: profile
            for profile in value["profiles"]
            if profile["model_binding"] == "root_model"
        }

    @property
    def generation(self) -> str:
        return self.value["generation"]

    @property
    def sha256(self) -> str:
        return self.value["registry_sha256"]

    def lineage(self, model: Any) -> str | None:
        for profile in self.value["profiles"]:
            if profile["default_model"] == model and profile["lineage"] is not None:
                return profile["lineage"]
        return None

    def default_profile_id(self, role: Any) -> str | None:
        profile_id = DEFAULT_PROFILE_IDS.get(role) if isinstance(role, str) else None
        profile = self.profiles.get(profile_id) if profile_id is not None else None
        return profile_id if profile is not None and profile["role"] == role else None


_ACTIVE = _RegistryView(_REGISTRY)
_PROFILES = _ACTIVE.profiles
_ROOT_PROFILES = _ACTIVE.root_profiles
for _role, _profile_id in DEFAULT_PROFILE_IDS.items():
    if _role not in ROLES or _PROFILES.get(_profile_id, {}).get("role") != _role:
        raise RuntimeError("model-profile registry invalid: default_profile:" + _role)
del _role, _profile_id


def role_default_change(
    defaults: Mapping[str, str],
    role: Any,
    profile_id: Any,
    promotion: Any = None,
) -> dict[str, Any]:
    """Refuse a change to one role's default profile, naming every reason.

    A role's default changes only as a Challenger that passes the whole
    FR60 promotion path: offline evaluation, shadow observation, a
    separately authorized canary, and forward activation.  promotion is
    {"request", "decision"}: the sealed inputs of one decide_role_default
    program, which carry the Challenger record, and the sealed decision it
    produced.  The decision is replayed from those inputs here, and it must
    retain offline exactly this change, from the role's current default, in
    this registry generation, to a profile whose exact tuple a release
    qualification passed.  Only the offline stage is recorded today, so even
    a decision that satisfies all of that refuses as
    role_default:promotion_path_incomplete, and no default changes.
    """

    reasons: list[str] = []
    if role not in ROLES:
        reasons.append("role_default:role_unknown")
    profile = _PROFILES.get(profile_id) if isinstance(profile_id, str) else None
    if profile is None:
        reasons.append("role_default:profile_unregistered")
    elif profile["role"] != role:
        reasons.append("role_default:profile_role_mismatch")
    elif defaults.get(role) == profile_id:
        reasons.append("role_default:unchanged")
    elif profile["qualification"]["state"] != "qualified":
        # A role-default Challenger still requires a release qualification of
        # its exact tuple (FR68, ADR 0012); filling a role never does.
        reasons.append("role_default:challenger_profile_unqualified")
    request = promotion.get("request") if isinstance(promotion, Mapping) else None
    decision = promotion.get("decision") if isinstance(promotion, Mapping) else None
    has_challenger = isinstance(request, Mapping) and isinstance(
        request.get("challenger"), Mapping
    )
    if not has_challenger:
        reasons.append("role_default:challenger_record_missing")
    if not isinstance(decision, Mapping):
        reasons.append("role_default:promotion_decision_missing")
    elif has_challenger:
        champion_challenger = _load_sibling("orch_dork_champion_challenger")
        replay = champion_challenger.replay_role_default_promotion(request, decision)
        if replay["status"] != "PASS":
            reasons.append("role_default:promotion_replay_mismatch")
        else:
            if decision.get("decision") != "OFFLINE_RETAINED":
                reasons.append("role_default:challenger_not_retained")
            if decision.get("role") != role:
                reasons.append("role_default:promotion_role_mismatch")
            if decision.get("champion_profile_id") != defaults.get(role):
                reasons.append("role_default:champion_default_mismatch")
            if decision.get("challenger_profile_id") != profile_id:
                reasons.append("role_default:challenger_default_mismatch")
            if decision.get("registry_generation") != _ACTIVE.generation:
                reasons.append("role_default:registry_generation_stale")
            # No decision records shadow observation, the canary, or forward
            # activation yet (FR60).
            reasons.append("role_default:promotion_path_incomplete")
    return {"status": "REFUSED", "reasons": sorted(set(reasons))}


def registry_view() -> _RegistryView:
    """A private copy of the active registry's lookup tables.

    The digest stage proposes profiles from the same registry compile resolves
    against.  The copy keeps the sealed registry unchanged by any caller, the
    way every other accessor here returns copies.
    """

    return _RegistryView(deepcopy(_ACTIVE.value))


def question_id(kind: str, subject: str) -> str:
    """The identifier of the typed question of one kind about one subject.

    The digest stage names questions with it and compile reads the Owner's
    answers with it, so the two can never disagree about an identifier.
    """

    return kind + ":" + subject


def registry() -> dict[str, Any]:
    """The active sealed registry."""

    return deepcopy(_REGISTRY)


def aliases() -> frozenset[str]:
    """Every alias identifier the historical replay adapters accept."""

    return frozenset(_ALIASES)


def resolve_alias(alias: Any) -> dict[str, Any] | None:
    """The registered profile behind a legacy per-node profile value.

    This is the historical replay adapter for the three expand-step alias
    values.  New plans name a profile by its exact `profile_id`; no product
    path names an alias.
    """

    profile = _ALIASES.get(alias) if isinstance(alias, str) else None
    return deepcopy(profile) if profile is not None else None


def resolve_profile(profile_id: Any) -> dict[str, Any] | None:
    """The registered profile with this exact identifier."""

    profile = _PROFILES.get(profile_id) if isinstance(profile_id, str) else None
    return deepcopy(profile) if profile is not None else None


def resolve_node_profile(value: Any) -> dict[str, Any] | None:
    """The profile a plan node's `model_profile` value names.

    An exact profile identifier resolves first; a legacy alias resolves
    through :func:`resolve_alias` so historical frozen plans replay; an
    onboarded identifier resolves to the capability profile its onboarded
    model fills the role with (ADR 0012).  An orchestrator profile is not a
    node profile and resolves to nothing.
    """

    profile = resolve_profile(value)
    if profile is None:
        profile = resolve_alias(value)
    if profile is None:
        profile = onboarded_capability_profile(value)
    if profile is None or profile["role"] == "orchestrator":
        return None
    return profile


def node_profile_ids() -> frozenset[str]:
    """Every profile identifier a plan node may name."""

    return frozenset(
        profile["profile_id"]
        for profile in _REGISTRY["profiles"]
        if profile["role"] != "orchestrator"
    )


# ADR 0012: any onboarded model fills any node role through one identifier,
# "<role>.onboarded:<model>", or "<role>.onboarded.<effort>:<model>" to run
# it at an explicit effort.  The capability profile behind it is synthesized
# from the model's onboarded profile, and its digest covers that profile's
# digest, so a routing policy naming it binds the exact profile a plan froze
# with.  No registry entry is added and no capability is tested.
ONBOARDED_MARKER = ".onboarded"
ONBOARDED_NODE_ROLES = tuple(role for role in ROLES if role != "orchestrator")
ONBOARDED_EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra")


def onboarded_profile_id(role: str, model: str, effort: str | None = None) -> str:
    """The node profile identifier through which an onboarded model fills a role.

    Without an effort the model runs at the effort its catalog states (else
    the one its probe ran); an explicit effort pins it.
    """

    return role + ONBOARDED_MARKER + ("." + effort if effort is not None else "") + ":" + model


def _onboarded_target(value: Any) -> tuple[str, str, str | None] | None:
    if not isinstance(value, str):
        return None
    head, separator, model = value.partition(":")
    role, marker, rest = head.partition(ONBOARDED_MARKER)
    if not separator or not marker or role not in ONBOARDED_NODE_ROLES or not model:
        return None
    if not rest:
        return role, model, None
    if rest[:1] == "." and rest[1:] in ONBOARDED_EFFORTS:
        return role, model, rest[1:]
    return None


def is_node_profile_id(value: Any) -> bool:
    """Whether a node's `model_profile` value names a profile by identifier."""

    return value in node_profile_ids() or _onboarded_target(value) is not None


def onboarding_required(value: Any) -> str | None:
    """The model an onboarded identifier names when it has no profile yet, else None."""

    target = _onboarded_target(value)
    if target is None or onboarded_profiles.onboarded(target[1]) is not None:
        return None
    return target[1]


def onboarded_v1_refusal(value: Any) -> str | None:
    """Why an onboarded identifier's model cannot run governed, or None.

    Every governed task runs on V1 (ADR 0012).  A model whose profile records
    that neither the user's Codex nor the governed runner reaches V1 refuses
    with the reason its profile records.
    """

    target = _onboarded_target(value)
    record = onboarded_profiles.onboarded(target[1]) if target is not None else None
    if record is None or record["surface"]["v1_unavailable"] is None:
        return None
    return str(record["surface"]["v1_unavailable"]["reason"])


def onboarded_capability_profile(value: Any) -> dict[str, Any] | None:
    """The capability profile an onboarded identifier names, or None.

    It runs on the V1 surface as a native subagent at the identifier's
    effort, else the effort the catalog states for the model, else the
    probe's; carries the model's family as its lineage and the privacy class
    its location implies; and requires independence when it reviews.  Its
    qualification state stays unqualified: qualification binds only Orch
    Dork's own release receipts.
    """

    target = _onboarded_target(value)
    if target is None:
        return None
    role, model, explicit_effort = target
    record = onboarded_profiles.onboarded(model)
    if record is None:
        return None
    effort = record["catalog"]["default_effort"]
    if explicit_effort is not None:
        effort = {"status": "stated", "value": explicit_effort}
    family = record["family"]
    return seal(
        {
            "schema": PROFILE_SCHEMA,
            "profile_id": value,
            "role": role,
            "aliases": [],
            "model_binding": "profile_model",
            "lineage": family["value"] if family["status"] == "inferred" else None,
            "default_model": model,
            "default_effort": (
                effort["value"] if effort["status"] == "stated" else record["sample"]["effort"]
            ),
            "surface": "multi_agent_v1",
            "adapter": "native_subagent",
            "independence_required": role == "reviewer",
            "privacy_class": (
                "local_only" if record["route"]["location"] == "local" else "hosted_standard"
            ),
            "qualification": {"state": "unqualified", "tuple": None, "receipt_sha256": None},
            "onboarded_profile_sha256": record["profile_sha256"],
        },
        "profile_sha256",
    )


def profiles_for_role(role: Any) -> list[dict[str, Any]]:
    """Every registered profile of one role, in registry order."""

    return [
        deepcopy(profile)
        for profile in _REGISTRY["profiles"]
        if profile["role"] == role
    ]


def default_profile(role: Any) -> dict[str, Any] | None:
    """The registered default profile of a role, or None for a role without one."""

    profile_id = DEFAULT_PROFILE_IDS.get(role) if isinstance(role, str) else None
    return deepcopy(_PROFILES[profile_id]) if profile_id is not None else None


def default_root_model() -> str:
    """The orchestrator role's default root model."""

    return _PROFILES[DEFAULT_PROFILE_IDS["orchestrator"]]["default_model"]


def root_models() -> tuple[str, ...]:
    """Every registered orchestrator's model, in registry order.

    Since ADR 0012 this is no longer the closed set of admissible roots:
    :func:`root_admitted` also admits any model with an onboarded profile.
    The order carries no default semantics; :func:`default_root_model` is
    the only default.
    """

    return tuple(_ROOT_PROFILES)


def root_admitted(model: Any) -> bool:
    """Whether a root model may plan and run a governed task (ADR 0012).

    A registered orchestrator stays admitted as the provider-free planning
    default; any other model is admitted once it has an onboarded profile.
    The environment admits nothing.
    """

    if not isinstance(model, str) or not model:
        return False
    return model in _ROOT_PROFILES or onboarded_profiles.onboarded(model) is not None


def root_profile(model: Any) -> dict[str, Any] | None:
    """The orchestrator profile registered for this exact root model."""

    profile = _ROOT_PROFILES.get(model) if isinstance(model, str) else None
    return deepcopy(profile) if profile is not None else None


def root_surface_matrix() -> dict[str, str]:
    """Each registered root model's surface under ADR 0010, for historical replay.

    ADR 0012 retired this matrix from live routing: every live governed task
    runs on V1.  Only a replay that pins the era of its evidence reads it.
    """

    return {
        model: ROOT_SURFACE_OBSERVED[profile["surface"]]
        for model, profile in _ROOT_PROFILES.items()
    }


def model_lineage(model: Any) -> str | None:
    """The closed lineage of a model any registered profile binds, else None.

    Registry validation refuses two profiles binding one model to different
    lineages, so the first match is the only answer.
    """

    return _ACTIVE.lineage(model)


def _qualified_route(profile: Mapping[str, Any], model: Any, effort: Any) -> bool:
    qualification = profile["qualification"]
    if qualification["state"] != "qualified":
        return False
    proved = qualification["tuple"]
    if (proved["surface"], proved["adapter"]) != (profile["surface"], profile["adapter"]):
        return False
    if profile["model_binding"] == "root_executes":
        return True
    return (proved["model"], proved["effort"]) == (model, effort)


def _route_lineage(
    profile: Mapping[str, Any],
    model: Any,
    root_model: Any,
) -> str | None:
    if profile["model_binding"] == "root_executes":
        root = _ACTIVE.root_profiles.get(root_model) if isinstance(root_model, str) else None
        return root["lineage"] if root is not None else None
    if model == profile["default_model"]:
        return profile["lineage"]
    return _ACTIVE.lineage(model)


def _role_route(
    profile: Mapping[str, Any],
    model: Any,
    effort: Any,
    *,
    root_model: Any = None,
) -> dict[str, Any]:
    return {
        "role": profile["role"],
        "profile_id": profile["profile_id"],
        "profile_sha256": profile["profile_sha256"],
        "model": model,
        "effort": effort,
        "lineage": _route_lineage(profile, model, root_model),
        "surface": profile["surface"],
        "adapter": profile["adapter"],
        "independence_required": profile["independence_required"],
        "privacy_class": profile["privacy_class"],
        "qualification_state": profile["qualification"]["state"],
        "qualified_route": _qualified_route(profile, model, effort),
    }


def _policy(
    *,
    origin: str,
    draft_sha256: str | None,
    plan_core_sha256: str | None,
    routes: Mapping[str, Mapping[str, Any]],
    nodes: Mapping[str, Mapping[str, str]],
    approval_sha256: str | None = None,
    review_labels: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    roles: dict[str, list[str]] = {}
    for profile_id in sorted(routes):
        roles.setdefault(routes[profile_id]["role"], []).append(profile_id)
    core = {
        "schema": POLICY_SCHEMA,
        "origin": origin,
        "registry_generation": _ACTIVE.generation,
        "registry_sha256": _ACTIVE.sha256,
        "draft_sha256": draft_sha256,
        # The digest of the routed plan's core (the plan without its
        # routing-policy binding); None for a compiled draft.
        "plan_core_sha256": plan_core_sha256,
        # Every distinct route the policy resolves, keyed by profile; the
        # roles table lists the profiles behind each role and the nodes
        # table names the role and profile behind every node.
        "routes": {profile_id: dict(routes[profile_id]) for profile_id in sorted(routes)},
        "roles": {role: roles[role] for role in sorted(roles)},
        "nodes": {node: dict(nodes[node]) for node in sorted(nodes)},
    }
    if approval_sha256 is not None:
        # A compiled policy names the Owner's approval whose answers decided
        # it; a plan's policy keeps the byte layout its frozen digest binds.
        core["approval_sha256"] = approval_sha256
    if review_labels:
        # A review whose independence is required and whose family matches
        # or is unknown runs labeled, never refused (ADR 0012).  Plans that
        # earlier froze had no such review, so their bytes are unchanged.
        core["review_labels"] = {
            reviewer: {reviewed: labels[reviewed] for reviewed in sorted(labels)}
            for reviewer, labels in sorted(review_labels.items())
        }
    return seal(core, "policy_sha256")


def _executor_key(route: Mapping[str, Any]) -> tuple[str, ...]:
    if route["adapter"] in ("root_labor", "root_task"):
        return ("root",)
    return ("native_subagent", str(route["model"]), str(route["effort"]))


def _transitive_dependencies(
    node_id: str, dependencies: Mapping[str, Sequence[str]]
) -> set[str]:
    """Every node the given node depends on, directly or through others."""

    reviewed: set[str] = set()
    frontier = [str(item) for item in dependencies.get(node_id, ())]
    while frontier:
        current = frontier.pop()
        if current in reviewed or current == node_id:
            continue
        reviewed.add(current)
        frontier.extend(str(item) for item in dependencies.get(current, ()))
    return reviewed


def _review_labels(
    node_id: str,
    route: Mapping[str, Any],
    dependencies: Mapping[str, Sequence[str]],
    node_routes: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    """How a route whose independence is required relates to each node it reviews.

    The node under review is every node the independent node depends on,
    directly or transitively.  A reviewed route of another family carries
    no label; one sharing the reviewer's executor or family is labeled
    same_family and one whose family is unknown family_unknown.  ADR 0012
    never refuses such a review: it runs in a fresh context, labeled.
    """

    labels: dict[str, str] = {}
    for reviewed_id in sorted(_transitive_dependencies(node_id, dependencies)):
        reviewed = node_routes.get(reviewed_id)
        if reviewed is None:
            continue
        label = _review_label(route, reviewed)
        if label is not None:
            labels[reviewed_id] = label
    return labels


def _review_label(
    route: Mapping[str, Any], reviewed: Mapping[str, Any]
) -> str | None:
    """The label a review whose independence is required carries, or None.

    A shared executor or family is same_family; an unknown family on either
    side is family_unknown; another family needs no label.
    """

    if _executor_key(route) == _executor_key(reviewed):
        return "same_family"
    if route["lineage"] is None or reviewed["lineage"] is None:
        return "family_unknown"
    if route["lineage"] == reviewed["lineage"]:
        return "same_family"
    return None


def plan_routing_policy(
    plan_core_sha256: str,
    node_routes: Mapping[str, Mapping[str, Any]],
    *,
    root_model: Any,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Seal the registry resolution of one validated plan as a routing policy.

    node_routes maps each node to the registered profile it resolved through
    (its exact `profile_id`, or the legacy `alias` a historical replay
    adapter accepted, or an onboarded identifier), the exact model and effort
    the plan validator resolved for it, and the node's `dependencies`.
    root_model is the plan's declared root, which gives root labor its
    lineage.  Two nodes of one role may resolve to two distinct profiles; one
    profile resolving to two different routes within a plan, or an onboarded
    identifier whose model has no profile, is returned as a named issue with
    no policy.  A review whose independence is required and whose family
    matches or is unknown is labeled in the policy, never refused (ADR 0012).
    """

    routes: dict[str, dict[str, Any]] = {}
    nodes: dict[str, dict[str, str]] = {}
    resolved: dict[str, dict[str, Any]] = {}
    issues: list[str] = []
    for node_id in sorted(node_routes):
        entry = node_routes[node_id]
        profile = _PROFILES.get(entry.get("profile_id"))
        if profile is None:
            profile = _ALIASES.get(entry.get("alias"))
        if profile is None:
            profile = onboarded_capability_profile(entry.get("profile_id"))
        if profile is None and onboarding_required(entry.get("profile_id")) is not None:
            issues.append("routing_policy:model_not_onboarded:" + str(node_id))
            continue
        v1_refusal = onboarded_v1_refusal(entry.get("profile_id"))
        if v1_refusal is not None:
            issues.append("routing_policy:model_cannot_reach_v1:" + str(node_id) + ":" + v1_refusal)
            continue
        if profile is None:
            issues.append("routing_policy:profile_unregistered:" + str(node_id))
            continue
        route = _role_route(
            profile, entry.get("model"), entry.get("effort"), root_model=root_model
        )
        previous = routes.get(profile["profile_id"])
        if previous is not None and previous != route:
            issues.append("routing_policy:profile_route_divergent:" + profile["profile_id"])
            continue
        routes[profile["profile_id"]] = route
        nodes[node_id] = {"role": profile["role"], "profile_id": profile["profile_id"]}
        resolved[node_id] = route
    dependency_sets = {
        node_id: list(node_routes[node_id].get("dependencies") or ())
        for node_id in node_routes
    }
    review_labels: dict[str, dict[str, str]] = {}
    for node_id in sorted(resolved):
        route = resolved[node_id]
        if not route["independence_required"]:
            continue
        labels = _review_labels(node_id, route, dependency_sets, resolved)
        if labels:
            review_labels[node_id] = labels
    if issues:
        return None, sorted(set(issues))
    return _policy(
        origin="plan_alias_resolution",
        draft_sha256=None,
        plan_core_sha256=plan_core_sha256,
        routes=routes,
        nodes=nodes,
        review_labels=review_labels,
    ), []


def _refusal(
    draft_sha256: Any,
    rows: list[tuple[str | None, str]],
    approval_sha256: str | None = None,
) -> dict[str, Any]:
    """A compile refusal; it names the approval once one has validated."""

    ordered = sorted(set(rows), key=lambda row: ("" if row[0] is None else row[0], row[1]))
    return {
        "status": "REFUSED",
        "policy": None,
        "refusal": seal(
            {
                "schema": REFUSAL_SCHEMA,
                "registry_generation": _ACTIVE.generation,
                "registry_sha256": _ACTIVE.sha256,
                "draft_sha256": draft_sha256 if isinstance(draft_sha256, str) else None,
                "approval_sha256": approval_sha256,
                "reasons": [{"role": role, "reason": reason} for role, reason in ordered],
            },
            "refusal_sha256",
        ),
    }


def _catalog_routes(catalog: Any, rows: list[tuple[str | None, str]]) -> list[Mapping[str, Any]]:
    if not isinstance(catalog, Sequence) or isinstance(catalog, (str, bytes)):
        rows.append((None, "catalog_invalid"))
        return []
    accepted = []
    for entry in catalog:
        identity = entry.get("runtime_identity") if isinstance(entry, Mapping) else None
        privacy = entry.get("privacy_classes") if isinstance(entry, Mapping) else None
        if (
            not isinstance(entry, Mapping)
            or entry.get("schema") != CAPABILITY_SCHEMA
            or not seal_valid(entry, "capability_sha256")
            or not isinstance(identity, Mapping)
            or not _text(identity.get("logical_model_id"))
            or not isinstance(privacy, list)
            or any(item not in PRIVACY_CLASSES for item in privacy)
        ):
            rows.append((None, "catalog_entry_invalid"))
            continue
        accepted.append(entry)
    return accepted


def _digest_text(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _bounded_text(value: Any) -> bool:
    return _text(value) and len(value.encode("utf-8")) <= _MAX_DRAFT_TEXT_BYTES


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _draft_items(
    value: Any,
    fields: frozenset[str],
    key: str,
    path: str,
    issues: list[str],
) -> list[Mapping[str, Any]]:
    """The closed entries of one draft list, in canonical order by key."""

    if not isinstance(value, list) or len(value) > _MAX_DRAFT_ITEMS:
        issues.append(path + ":invalid")
        return []
    rows: list[Mapping[str, Any]] = []
    for index, entry in enumerate(value):
        if _exact(entry, fields, path + "[" + str(index) + "]", issues):
            rows.append(entry)
    keys = [row[key] for row in rows]
    if len(rows) == len(value) and (
        any(not _identifier(item) for item in keys) or keys != sorted(set(keys))
    ):
        issues.append(path + ":not_canonical")
    return rows


def validate_draft(value: Any) -> list[str]:
    """Return every reason value is not a well-formed architecture draft.

    Shape only: the closed field sets and vocabularies, canonical ordering,
    and the draft's own seal (reported as "draft:seal_invalid").  Whether the
    roles resolve to qualified routes is compile's question.
    """

    if not isinstance(value, Mapping):
        return ["draft:not_object"]
    issues: list[str] = []
    core = {key: item for key, item in value.items() if key != "draft_sha256"}
    if not _exact(core, _DRAFT_FIELDS - {"draft_sha256"}, "draft", issues):
        return sorted(set(issues))
    if core["schema"] != DRAFT_SCHEMA:
        issues.append("draft:schema_invalid")
    if not _identifier(core["draft_id"]):
        issues.append("draft:draft_id_invalid")
    if not _text(core["registry_generation"]):
        issues.append("draft:registry_generation_invalid")
    if not _digest_text(core["registry_sha256"]):
        issues.append("draft:registry_sha256_invalid")
    source = core["source"]
    if _exact(source, _DRAFT_SOURCE_FIELDS, "draft.source", issues):
        if source["kind"] not in DRAFT_SOURCE_KINDS:
            issues.append("draft.source:kind_invalid")
        if not _identifier(source["proposal_id"]):
            issues.append("draft.source:proposal_id_invalid")
        if not _digest_text(source["proposal_sha256"]):
            issues.append("draft.source:proposal_sha256_invalid")
        bound = (source["prose_sha256"], source["requirement_sha256"])
        if source["kind"] == "structured" and bound != (None, None):
            issues.append("draft.source:structured_binds_requirement")
        if source["kind"] == "model_assisted" and not all(_digest_text(item) for item in bound):
            issues.append("draft.source:requirement_unbound")
    envelope = core["privacy_envelope"]
    if (
        not isinstance(envelope, list)
        or not envelope
        or any(item not in PRIVACY_CLASSES for item in envelope)
        or envelope != sorted(set(envelope), key=PRIVACY_CLASSES.index)
    ):
        issues.append("draft:privacy_envelope_invalid")
    for entry in _draft_items(core["roles"], _DRAFT_ROLE_FIELDS, "role", "draft.roles", issues):
        profile_id = entry["profile_id"]
        if profile_id is not None and not _identifier(profile_id):
            issues.append("draft.roles:profile_id_invalid")
    for rule in _draft_items(
        core["independence_rules"],
        _INDEPENDENCE_RULE_FIELDS,
        "reviewer_role",
        "draft.independence_rules",
        issues,
    ):
        reviews = rule["reviews"]
        if (
            not isinstance(reviews, list)
            or any(not _identifier(item) for item in reviews)
            or reviews != sorted(set(reviews))
        ):
            issues.append("draft.independence_rules:reviews_invalid")
        if rule["independence"] not in INDEPENDENCE_STATES:
            issues.append("draft.independence_rules:independence_invalid")
    escalations = core["escalation_rules"]
    if not isinstance(escalations, list) or len(escalations) > _MAX_DRAFT_ITEMS:
        issues.append("draft.escalation_rules:invalid")
    else:
        keys = []
        for index, rule in enumerate(escalations):
            path = "draft.escalation_rules[" + str(index) + "]"
            if not _exact(rule, _ESCALATION_RULE_FIELDS, path, issues):
                continue
            if not _identifier(rule["from_role"]) or not _identifier(rule["to_role"]):
                issues.append(path + ":role_invalid")
            if not _bounded_text(rule["trigger"]):
                issues.append(path + ":trigger_invalid")
            keys.append((str(rule["from_role"]), str(rule["to_role"]), str(rule["trigger"])))
        if keys != sorted(set(keys)):
            issues.append("draft.escalation_rules:not_canonical")
    for question in _draft_items(
        core["questions"], _QUESTION_FIELDS, "question_id", "draft.questions", issues
    ):
        options = question["options"]
        if question["kind"] not in QUESTION_KINDS:
            issues.append("draft.questions:kind_invalid")
        if not _bounded_text(question["subject"]) or not _bounded_text(question["prompt"]):
            issues.append("draft.questions:text_invalid")
        if (
            not isinstance(options, list)
            or not options
            or len(options) > _MAX_DRAFT_ITEMS
            or any(not _identifier(option) for option in options)
            or len(options) != len(set(options))
        ):
            issues.append("draft.questions:options_invalid")
    for assumption in _draft_items(
        core["assumptions"], _ASSUMPTION_FIELDS, "assumption_id", "draft.assumptions", issues
    ):
        if not _bounded_text(assumption["subject"]) or not _bounded_text(assumption["statement"]):
            issues.append("draft.assumptions:text_invalid")
    for conflict in _draft_items(
        core["conflicts"], _CONFLICT_FIELDS, "conflict_id", "draft.conflicts", issues
    ):
        if conflict["rule"] not in CONFLICT_RULES:
            issues.append("draft.conflicts:rule_invalid")
        if not _bounded_text(conflict["subject"]) or not _bounded_text(conflict["statement"]):
            issues.append("draft.conflicts:text_invalid")
    if not seal_valid(value, "draft_sha256"):
        issues.append("draft:seal_invalid")
    return sorted(set(issues))


def validate_approval(approval: Any, draft: Any) -> list[str]:
    """Return every reason approval is not the Owner's seal of exactly this draft.

    The seal answers every question from that question's own options,
    acknowledges every conflict, names the draft by digest, and carries its
    own digest.  An empty result means valid.
    """

    if validate_draft(draft):
        return ["approval:draft_invalid"]
    issues: list[str] = []
    if not _exact(approval, _APPROVAL_FIELDS, "approval", issues):
        return sorted(set(issues))
    if approval["schema"] != APPROVAL_SCHEMA:
        issues.append("approval:schema_invalid")
    if approval["approver"] != APPROVER:
        issues.append("approval:approver_invalid")
    if approval["draft_sha256"] != draft["draft_sha256"]:
        issues.append("approval:draft_mismatch")
    questions = {question["question_id"]: question for question in draft["questions"]}
    decisions = approval["decisions"]
    if not isinstance(decisions, list) or len(decisions) > _MAX_DRAFT_ITEMS:
        issues.append("approval:decisions_invalid")
        decisions = []
    answered: list[Any] = []
    for index, decision in enumerate(decisions):
        if not _exact(decision, _DECISION_FIELDS, "approval.decisions[" + str(index) + "]", issues):
            continue
        question_id = decision["question_id"]
        answered.append(question_id)
        question = questions.get(question_id) if isinstance(question_id, str) else None
        if question is None:
            issues.append("approval:question_unknown:" + str(question_id))
        elif decision["answer"] not in question["options"]:
            issues.append("approval:answer_invalid:" + question_id)
    if any(not isinstance(item, str) for item in answered) or answered != sorted(
        set(item for item in answered if isinstance(item, str))
    ):
        issues.append("approval:decisions_not_canonical")
    for question_id in sorted(set(questions) - set(answered)):
        issues.append("approval:question_unanswered:" + question_id)
    acknowledged = approval["acknowledged_conflicts"]
    conflicts = sorted(conflict["conflict_id"] for conflict in draft["conflicts"])
    if (
        not isinstance(acknowledged, list)
        or any(not isinstance(item, str) for item in acknowledged)
        or acknowledged != sorted(set(acknowledged))
    ):
        issues.append("approval:acknowledged_conflicts_invalid")
    else:
        for conflict_id in sorted(set(conflicts) - set(acknowledged)):
            issues.append("approval:conflict_unacknowledged:" + conflict_id)
        for conflict_id in sorted(set(acknowledged) - set(conflicts)):
            issues.append("approval:conflict_unknown:" + conflict_id)
    if not seal_valid(approval, "approval_sha256"):
        issues.append("approval:seal_invalid")
    return sorted(set(issues))


def approve_draft(
    draft: Any,
    *,
    decisions: Mapping[str, str],
    acknowledged_conflicts: Sequence[str],
) -> dict[str, Any]:
    """Return the Owner's sealed approval of one draft.

    Every question must be answered from its own options and every conflict
    acknowledged by identifier; anything else raises ValueError naming each
    issue.  Pure: the create-only record on disk is the ingestion module's.
    """

    if not isinstance(decisions, Mapping) or any(not isinstance(key, str) for key in decisions):
        raise ValueError("approval:decisions_invalid")
    if isinstance(acknowledged_conflicts, (str, bytes)) or not isinstance(
        acknowledged_conflicts, Sequence
    ):
        raise ValueError("approval:acknowledged_conflicts_invalid")
    draft_issues = validate_draft(draft)
    if draft_issues:
        raise ValueError(",".join(draft_issues))
    approval = seal(
        {
            "schema": APPROVAL_SCHEMA,
            "draft_sha256": draft["draft_sha256"],
            "approver": APPROVER,
            "decisions": [
                {"question_id": question_id, "answer": decisions[question_id]}
                for question_id in sorted(decisions)
            ],
            "acknowledged_conflicts": sorted(set(acknowledged_conflicts)),
        },
        "approval_sha256",
    )
    issues = validate_approval(approval, draft)
    if issues:
        raise ValueError(",".join(issues))
    return approval


def compile_routing_policy(draft: Any, catalog: Any, *, approval: Any = None) -> dict[str, Any]:
    """Compile an Owner-sealed draft and the runtime catalog into a policy or a refusal.

    Deterministic and provider-free: the result depends only on the draft,
    the Owner's approval, the catalog, and the active registry.  An
    unapproved, altered, or stale draft refuses by digest before any role
    resolves; otherwise a refusal names every unresolved role, unregistered
    or unavailable route, and route outside the privacy envelope, and carries
    no partial policy.  Any onboarded model may fill a role through its
    onboarded identifier; qualification and reviewer independence never
    refuse (ADR 0012): a required review whose family matches or is unknown
    is labeled in the policy.  The approval's answers decide routes and
    independence, so a policy, and a refusal reached after the approval
    validates, names the approval by digest.  A
    conflicting proposal rule is never compiled.
    """

    rows: list[tuple[str | None, str]] = []
    draft_sha256 = draft.get("draft_sha256") if isinstance(draft, Mapping) else None
    draft_issues = validate_draft(draft)
    if any(issue != "draft:seal_invalid" for issue in draft_issues):
        return _refusal(draft_sha256, [(None, "draft_shape_invalid")])
    if draft_issues:
        rows.append((None, "draft_seal_invalid"))
    if (draft["registry_generation"], draft["registry_sha256"]) != (
        _ACTIVE.generation,
        _ACTIVE.sha256,
    ):
        rows.append((None, "draft_registry_generation_stale"))
    if approval is None:
        rows.append((None, "draft_unapproved"))
    elif not draft_issues:
        approval_issues = validate_approval(approval, draft)
        if "approval:draft_mismatch" in approval_issues:
            rows.append((None, "approval_draft_mismatch"))
        elif approval_issues:
            rows.append((None, "approval_invalid"))
    if rows:
        return _refusal(draft_sha256, rows)

    approval_sha256 = approval["approval_sha256"]
    decisions = {row["question_id"]: row["answer"] for row in approval["decisions"]}
    envelope = draft["privacy_envelope"]
    entries = draft["roles"]
    if not entries:
        rows.append((None, "draft_roles_invalid"))
    catalog_entries = _catalog_routes(catalog, rows)

    selected: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        role = entry["role"]
        if role not in ROLES:
            rows.append((role, "role_unknown"))
            continue
        profile_id = decisions.get(question_id("unregistered_route", role), entry["profile_id"])
        if profile_id is None or profile_id == UNRESOLVED_ROUTE:
            rows.append((role, "role_unresolved"))
            continue
        profile = _ACTIVE.profiles.get(profile_id) or onboarded_capability_profile(profile_id)
        if profile is None:
            rows.append((role, "profile_unregistered"))
            continue
        v1_refusal = onboarded_v1_refusal(profile_id)
        if v1_refusal is not None:
            rows.append((role, "model_cannot_reach_v1:" + v1_refusal))
            continue
        if profile["role"] != role:
            rows.append((role, "profile_role_mismatch"))
            continue
        selected[role] = profile
    orchestrator = selected.get("orchestrator")
    root_model = orchestrator["default_model"] if orchestrator is not None else None

    routes: dict[str, dict[str, Any]] = {}
    role_routes: dict[str, dict[str, Any]] = {}
    for role in sorted(selected):
        profile = selected[role]
        role_rows: list[tuple[str | None, str]] = []
        if profile["privacy_class"] not in envelope:
            role_rows.append((role, "profile_outside_privacy_envelope"))
        model = profile["default_model"]
        effort = profile["default_effort"]
        if profile["model_binding"] == "root_executes":
            model = None
            effort = None
        elif profile["model_binding"] != "root_model" and not any(
            capability["runtime_identity"]["logical_model_id"] == model
            and set(envelope) <= set(capability["privacy_classes"])
            for capability in catalog_entries
        ):
            role_rows.append((role, "route_unavailable"))
        if role_rows:
            rows.extend(role_rows)
            continue
        route = _role_route(profile, model, effort, root_model=root_model)
        routes[profile["profile_id"]] = route
        role_routes[role] = route

    review_labels: dict[str, dict[str, str]] = {}
    for rule in draft["independence_rules"]:
        reviewer_role = rule["reviewer_role"]
        independence = rule["independence"]
        if independence == "undecided":
            independence = decisions.get(question_id("reviewer_independence", reviewer_role))
        if independence != "required":
            continue
        reviewer = role_routes.get(reviewer_role)
        if reviewer is None:
            continue
        for reviewed_role in rule["reviews"]:
            reviewed = role_routes.get(reviewed_role)
            if reviewed is None:
                continue
            label = _review_label(reviewer, reviewed)
            if label is not None:
                review_labels.setdefault(reviewer_role, {})[reviewed_role] = label

    if rows:
        return _refusal(draft_sha256, rows, approval_sha256)
    return {
        "status": "COMPILED",
        "policy": _policy(
            origin="compiled_draft",
            draft_sha256=draft_sha256,
            plan_core_sha256=None,
            routes=routes,
            nodes={},
            approval_sha256=approval_sha256,
            review_labels=review_labels,
        ),
        "refusal": None,
    }
