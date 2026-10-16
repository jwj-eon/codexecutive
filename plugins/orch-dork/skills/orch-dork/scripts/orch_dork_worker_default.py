#!/usr/bin/env python3
"""The single source of truth for the default subagent worker model.

The worker model used to be a literal `gpt-5.6-luna` duplicated across the
policy, receipt, v1 observer, v2 observer, and efficiency governor. Changing it
meant editing five files and hoping they agreed; a missed one produced routing
refusals with no obvious cause. This module holds the value once.

Resolution is most-specific-wins:

1. A frozen plan's own `children.model`. A plan that names its worker model is
   authoritative, because that is the value the qualifier checks the observed
   run against.
2. `ORCH_DORK_WORKER_MODEL` in the environment, for a host or run that routes
   somewhere else without editing source.
3. `DEFAULT_WORKER_MODEL` below.

The environment override deserves a note, because Orch Dork otherwise refuses
substitution and fallback. It is admissible here for one reason: the override
is resolved *before* plan freeze, and the frozen plan then records the exact
model it resolved to. Nothing downstream infers routing from an environment
variable, and the evidence chain still names one exact model per lane. An
override that changed routing *after* freeze would be the thing the contract
forbids, and this is not that.
"""

from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import sys
from typing import Any, Iterator, Mapping

# Forward worker lanes use the exact hosted OpenRouter selector. OpenRouter's
# own upstream provider selection remains automatic; Orch Dork does not pin an
# upstream provider. Historical evidence pins its original route through
# :func:`pinned` and remains replayable after this forward-only default change.
DEFAULT_WORKER_MODEL = "openrouter/qwen-qwen3.8-27b"
# The qualified forward route explicitly pins xhigh even when a host catalog
# also advertises it as the default. This prevents an ambient/default change
# from silently lowering worker reasoning effort.
DEFAULT_WORKER_EFFORT = "xhigh"

WORKER_MODEL_ENV = "ORCH_DORK_WORKER_MODEL"
WORKER_EFFORT_ENV = "ORCH_DORK_WORKER_EFFORT"
# The qualification reviewer route (Issue 203): the owner request names it,
# the qualification host seals it into the app server's environment, and the
# successor pre-turn routes the qualification plan's standards lane to the
# reviewer's onboarded identifier.  Unset, every lane stays on the worker
# route, exactly as earlier attempts froze.
REVIEWER_MODEL_ENV = "ORCH_DORK_REVIEWER_MODEL"
REVIEWER_EFFORT_ENV = "ORCH_DORK_REVIEWER_EFFORT"

# Set only through :func:`pinned`, which always restores the previous value.
_PINNED: dict[str, str] = {}


def _clean(value: Any) -> str | None:
    """Return a usable identifier, or None. Blank is not a choice."""

    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


@contextmanager
def pinned(*, model: Any = None, effort: Any = None) -> Iterator[None]:
    """Hold the governed default fixed for the duration of a block.

    Evidence outlives defaults. A sealed bundle recorded last month has to be
    verified against the worker model that was in force when it ran, not
    against whatever the default is today, or swapping the default would
    retroactively invalidate every archived run. This is the seam that lets a
    replay say which default applies to it.

    A pin is more specific than the environment, because it is a deliberate
    statement about one block rather than an ambient setting for the process.
    It is always restored, including on an exception.
    """

    previous = dict(_PINNED)
    cleaned_model = _clean(model)
    cleaned_effort = _clean(effort)
    if cleaned_model is not None:
        _PINNED["model"] = cleaned_model
    if cleaned_effort is not None:
        _PINNED["effort"] = cleaned_effort
    try:
        yield
    finally:
        _PINNED.clear()
        _PINNED.update(previous)


def configured_worker_model(env: Mapping[str, str] | None = None) -> str:
    """The default worker model before any plan is consulted."""

    pin = _clean(_PINNED.get("model"))
    if pin is not None:
        return pin
    source = os.environ if env is None else env
    return _clean(source.get(WORKER_MODEL_ENV)) or DEFAULT_WORKER_MODEL


def configured_worker_effort(env: Mapping[str, str] | None = None) -> str:
    """The default worker effort before any plan is consulted."""

    pin = _clean(_PINNED.get("effort"))
    if pin is not None:
        return pin
    source = os.environ if env is None else env
    return _clean(source.get(WORKER_EFFORT_ENV)) or DEFAULT_WORKER_EFFORT


def configured_reviewer_route(env: Mapping[str, str] | None = None) -> tuple[str, str] | None:
    """The sealed qualification reviewer route, or None when none is named.

    The host seals the model and effort together; one without the other is
    a refusal, never a silent return to the worker route.
    """

    source = os.environ if env is None else env
    model = _clean(source.get(REVIEWER_MODEL_ENV))
    effort = _clean(source.get(REVIEWER_EFFORT_ENV))
    if model is None and effort is None:
        return None
    if model is None or effort is None:
        raise ValueError("worker_default:reviewer_route_incomplete")
    return model, effort


def resolve_worker_model(
    planned: Any = None, *, env: Mapping[str, str] | None = None
) -> str:
    """Resolve the worker model a plan should be checked against.

    ``planned`` is the plan's own ``children.model`` when it declares one. A
    declared value always wins: the qualifier must check an observed run
    against what that run's plan actually froze, not against whatever the
    current default happens to be. Otherwise a plan frozen last week would
    start failing the moment someone swapped the default.
    """

    return _clean(planned) or configured_worker_model(env)


def resolve_worker_effort(
    planned: Any = None, *, env: Mapping[str, str] | None = None
) -> str:
    """Resolve the worker effort a plan should be checked against."""

    return _clean(planned) or configured_worker_effort(env)


# The strong-integrator executor: a high-judgment node (semantic join,
# cross-lane synthesis) that should not run on the cheap worker model but is
# not the root either.  Same resolution ladder as the worker default.
DEFAULT_STRONG_MODEL = "gpt-5.6-sol"
DEFAULT_STRONG_EFFORT = "xhigh"

STRONG_MODEL_ENV = "ORCH_DORK_STRONG_MODEL"
STRONG_EFFORT_ENV = "ORCH_DORK_STRONG_EFFORT"


def configured_strong_model(env: Mapping[str, str] | None = None) -> str:
    """The strong-integrator model before any plan is consulted."""

    pin = _clean(_PINNED.get("strong_model"))
    if pin is not None:
        return pin
    source = os.environ if env is None else env
    return _clean(source.get(STRONG_MODEL_ENV)) or DEFAULT_STRONG_MODEL


def configured_strong_effort(env: Mapping[str, str] | None = None) -> str:
    """The strong-integrator effort before any plan is consulted."""

    pin = _clean(_PINNED.get("strong_effort"))
    if pin is not None:
        return pin
    source = os.environ if env is None else env
    return _clean(source.get(STRONG_EFFORT_ENV)) or DEFAULT_STRONG_EFFORT


# The planner/root identity used to be the literal sol model name pinned at
# four separate validator sites (logical-plan planner, replan persisted_root,
# replan request author, rollover checkpoint routing).  A truthful plan
# authored by any other root could not validate without claiming the sol
# identity.  The invariant was never that the root is named sol; it is that
# the plan names one exact root model and the evidence proves the observed
# root matched it.  A plan-declared root model is authoritative for that
# plan, exactly as children.model is for workers.
#
# ADR 0012 (Issue 203) retired the closed root gate and the per-model
# root/surface matrix.  A root is admitted when it is a registered
# orchestrator, the provider-free planning default, or when it has an
# onboarded profile; and every live governed task runs on the V1
# collaboration surface.  The registry's matrix and the pin seams below
# remain for historical replay only: a replay pins the root set or matrix in
# force when its evidence was recorded.  The ORCH_DORK_ROOT_MODELS and
# ORCH_DORK_ROOT_SURFACES variables stay ignored, so the environment can
# neither admit a root nor assign a surface.  Callers must verify the live
# turn_context rather than treating the expected surface as evidence.
ROOT_SURFACES = ("v1", "v2")
GOVERNED_SURFACE = "v1"


def _registry():
    """The sealed model-profile registry, loaded when a root is first judged.

    The registry imports this module for the worker defaults, so the root
    reads import it lazily and share whichever module object the process
    already loaded.
    """

    name = "orch_dork_model_profile_registry"
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


def accepted_root_models() -> tuple[str, ...]:
    """The registered root models, or a historical replay's pinned set."""

    pin = _clean(_PINNED.get("root_models"))
    if pin is not None:
        return tuple(part for part in (p.strip() for p in pin.split(",")) if part)
    return _registry().root_models()


def replay_pinned() -> bool:
    """Whether a historical replay pins the root set or the surface matrix."""

    return any(
        _clean(_PINNED.get(key)) is not None for key in ("root_models", "root_surfaces")
    )


def root_model_accepted(candidate: Any, *, declared: Any = None) -> bool:
    """Whether candidate is a permissible root model for validation.

    declared is the plan-declared root/planner model when the caller holds a
    frozen plan; a declared value is authoritative for that plan exactly as
    children.model is for workers.  Without a declaration the candidate must
    be admitted: a registered orchestrator or a model with an onboarded
    profile (ADR 0012), or under a historical replay pin one of the pinned
    roots.  The environment cannot admit one.
    """

    cleaned = _clean(candidate)
    if cleaned is None:
        return False
    declared_clean = _clean(declared)
    if declared_clean is not None:
        return cleaned == declared_clean
    if replay_pinned():
        return cleaned in accepted_root_models()
    return _registry().root_admitted(cleaned)


def _parse_root_surfaces(raw: str, accepted: tuple[str, ...]) -> dict[str, str]:
    routes: dict[str, str] = {}
    for part in raw.split(","):
        entry = part.strip()
        if not entry:
            continue
        model, separator, surface = entry.partition("=")
        model, surface = model.strip(), surface.strip()
        if (
            not separator
            or not model
            or surface not in ROOT_SURFACES
            or model in routes
            or model not in accepted
        ):
            raise ValueError("root_surfaces:invalid")
        routes[model] = surface
    return routes


def root_surface_routes() -> dict[str, str]:
    """The historical root/surface matrix: the registry's, under a replay pin.

    Raises ``ValueError("root_surfaces:invalid")`` when a replay pin is
    malformed: an entry without ``=``, an unknown surface, a model named
    twice, or a model :func:`accepted_root_models` does not admit.  A pin
    reassigns surfaces for replay; it never widens the closed accepted-root
    set, and the environment is not consulted.
    """

    pin = _clean(_PINNED.get("root_surfaces"))
    accepted = accepted_root_models()
    # Under a replay pin of the accepted roots the matrix is narrowed to
    # them, so a pinned replay never sees a root its own era did not admit.
    matrix = {
        model: surface
        for model, surface in _registry().root_surface_matrix().items()
        if model in accepted
    }
    if pin is not None:
        return {**matrix, **_parse_root_surfaces(pin, accepted)}
    return matrix


def expected_root_surface(candidate: Any) -> str | None:
    """The surface a root's governed task must report.

    V1 for every live root (ADR 0012); under a historical replay pin, the
    pinned era's matrix entry, or None for a root that era did not admit.
    This is policy, not runtime evidence: the current-turn adapter must still
    observe the exact ``multi_agent_version`` recorded by Codex.  Propagates
    :func:`root_surface_routes`'s refusal of a malformed replay pin.
    """

    cleaned = _clean(candidate)
    if cleaned is None:
        return None
    if replay_pinned():
        return root_surface_routes().get(cleaned)
    return GOVERNED_SURFACE


def onboarded_profile(candidate: Any) -> dict[str, Any] | None:
    """The candidate model's onboarded profile, or None (ADR 0012)."""

    cleaned = _clean(candidate)
    if cleaned is None:
        return None
    return _registry().onboarded_profiles.onboarded(cleaned)


def registered_root(candidate: Any) -> bool:
    """Whether candidate is a registered orchestrator's model."""

    cleaned = _clean(candidate)
    return cleaned is not None and cleaned in _registry().root_models()
