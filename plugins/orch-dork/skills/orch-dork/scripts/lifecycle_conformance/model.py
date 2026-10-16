"""Pure reference-model interface for the shared lifecycle contract (Issue 165).

The public seam defined here -- initialize, reduce, validate_state,
validate_stimulus -- is the one every future campaign slice (166-169)
reduces through. Exactly one successor and exactly one directive come out
of one reduction; the foundation itself registers no transitions, so the
transition provider passed to reduce is the seam future slices fill with
the complete two-lane graph.
"""

from __future__ import annotations

from dataclasses import dataclass

from lifecycle_conformance import values
from lifecycle_conformance import registries

STIMULUS_KINDS = ("transition_reference", "observation", "injection")

TERMINAL_PHASES = ("terminal",)

_STATE_FIELDS = ("id", "phase", "generation", "result")
_STIMULUS_FIELDS = ("kind", "reference", "phrase", "evidence")
_PHASE_HEADS = ("spec", "standards", "controller", "process", "shared")


@dataclass(frozen=True)
class Reduction:
    """One pure reduction: exactly one successor and one directive."""

    successor: dict
    directive: dict
    transition_id: str


def _case_id_of(state: dict) -> str:
    result = state.get("result")
    if not isinstance(result, dict) or "case" not in result:
        raise values.LifecycleContractError("model:invalid_state")
    case_id = result["case"]
    if (
        isinstance(case_id, str)
        and case_id
        and not values._CASE_ID.match(case_id)
    ):
        raise values.LifecycleContractError("model:invalid_state")
    if not isinstance(case_id, str) or not case_id:
        raise values.LifecycleContractError("model:invalid_state")
    return case_id


def _id(item: object) -> None:
    if not values.is_item_id(item):
        raise values.LifecycleContractError("model:invalid_state")


def _is_stable_string(value: object) -> bool:
    """True for a closed token or a closed registry item identifier."""
    if not isinstance(value, str) or not value:
        return False
    return bool(values._TOKEN.match(value) or values.is_item_id(value))


def _check_phrase(phrase: object) -> None:
    if not isinstance(phrase, str) or ":" not in phrase:
        raise values.LifecycleContractError("model:invalid_stimulus")
    head = phrase.split(":", 1)[0]
    if head not in _PHASE_HEADS:
        raise values.LifecycleContractError("model:invalid_stimulus")
    rest = phrase.split(":", 1)[1]
    if not rest or not values._TOKEN.match(rest):
        raise values.LifecycleContractError("model:invalid_stimulus")


def _check_evidence(evidence: object) -> None:
    if evidence is None:
        return
    if not isinstance(evidence, dict):
        raise values.LifecycleContractError("model:invalid_evidence")
    for key, value in evidence.items():
        if not isinstance(key, str) or not isinstance(value, (str, int, bool, float)):
            raise values.LifecycleContractError("model:invalid_evidence")
        if isinstance(value, float) and not values._is_finite(value):
            raise values.LifecycleContractError("model:invalid_evidence")
        if isinstance(value, str) and not _is_stable_string(value):
            raise values.LifecycleContractError("model:invalid_evidence")


def _check_result_shape(result: object) -> None:
    if not isinstance(result, dict):
        raise values.LifecycleContractError("model:invalid_state")
    if not set(result) <= {"case", "item"}:
        raise values.LifecycleContractError("model:invalid_state")
    for key, value in result.items():
        if not isinstance(value, str) or not _is_stable_string(value):
            raise values.LifecycleContractError("model:invalid_state")
        if key == "case" and not values._CASE_ID.match(value):
            raise values.LifecycleContractError("model:invalid_state")
        if key == "item" and not values.is_item_id(value):
            raise values.LifecycleContractError("model:invalid_state")


def validate_state(state: object) -> None:
    """Fail closed unless state matches the closed modeled-state shape."""
    if not isinstance(state, dict) or set(state) != {"id", "phase", "generation", "result"}:
        raise values.LifecycleContractError("model:invalid_state")
    if state["phase"] not in values.LIFECYCLE_PHASES:
        raise values.LifecycleContractError("model:invalid_state")
    if not isinstance(state["generation"], int) or isinstance(state["generation"], bool):
        raise values.LifecycleContractError("model:invalid_state")
    if state["generation"] < 0:
        raise values.LifecycleContractError("model:invalid_state")
    _id(state["id"])
    _check_result_shape(state["result"])
    _case_id_of(state)


def validate_stimulus(stimulus: object) -> None:
    """Fail closed unless stimulus matches the closed typed-stimulus shape."""
    if not isinstance(stimulus, dict) or set(stimulus) != {"kind", "reference", "phrase", "evidence"}:
        raise values.LifecycleContractError("model:invalid_stimulus")
    if stimulus["kind"] not in STIMULUS_KINDS:
        raise values.LifecycleContractError("model:invalid_stimulus")
    if not isinstance(stimulus["reference"], str):
        raise values.LifecycleContractError("model:invalid_stimulus")
    if not values.is_item_id(stimulus["reference"]):
        raise values.LifecycleContractError("model:invalid_stimulus")
    _check_phrase(stimulus["phrase"])
    _check_evidence(stimulus["evidence"])


def initial_state(case_id: str) -> dict:
    """One closed pre-turn initial state for a content-addressed case."""
    if (
        isinstance(case_id, str)
        and case_id
        and not values._CASE_ID.match(case_id)
    ):
        raise values.LifecycleContractError("model:invalid_case_id")
    if not isinstance(case_id, str) or not case_id:
        raise values.LifecycleContractError("model:invalid_case_id")
    item_id = "lc-state:" + case_id + ":init"
    return {
        "id": item_id,
        "phase": "pre_turn",
        "generation": 0,
        "result": {"case": case_id, "item": item_id},
    }


def _lookup_transition(provider: object, transition_id: str) -> dict | None:
    """Resolve one transition record by id, from a mapping or a registry.

    A plain mapping resolves id to record directly. A registry store holds
    transitions under the closed lc-trans kind; the trace is generated from
    that registry view, never a private helper.
    """
    if isinstance(provider, dict):
        return provider.get(transition_id)
    if isinstance(provider, registries.RegistryStore):
        return provider.items_of(registries.TRANSITIONS_KIND).get(transition_id)
    raise values.LifecycleContractError("model:invalid_provider")


def reduce(
    state: dict, stimulus: dict, transition_provider: object
) -> Reduction:
    """Reduce one immutable state plus one typed stimulus to one successor.

    The transition provider is either a plain id-to-record mapping or a
    registry store; the campaign passes a registry view so the trace is
    generated from the registry, not hard-coded. The foundation validates
    shapes and guards; it never fabricates a transition.
    """
    validate_state(state)
    validate_stimulus(stimulus)
    transition_id = stimulus["reference"]
    transition = _lookup_transition(transition_provider, transition_id)
    if transition is None:
        raise values.LifecycleContractError("model:stale_reference")
    if not isinstance(transition, dict):
        raise values.LifecycleContractError("model:invalid_reference")
    for field in ("from", "to", "trigger"):
        if not isinstance(transition.get(field), str) or not transition.get(field):
            raise values.LifecycleContractError("model:invalid_reference")
    if transition["from"] not in values.LIFECYCLE_PHASES:
        raise values.LifecycleContractError("model:invalid_reference")
    if transition["to"] not in values.LIFECYCLE_PHASES:
        raise values.LifecycleContractError("model:invalid_reference")
    if transition["from"] != state["phase"]:
        raise values.LifecycleContractError("model:guard_failed")
    case_id = _case_id_of(state)
    generation = state["generation"] + 1
    successor_id = "lc-state:" + case_id + ":" + str(generation)
    successor = {
        "id": successor_id,
        "phase": transition["to"],
        "generation": generation,
        "result": {"case": case_id, "item": successor_id},
    }
    # The directive evidence is bound to the registered transition that
    # produced it, never a re-typed caller value, so it validates against
    # the registration unchanged.
    evidence = {"case": case_id, "item": transition_id}
    _check_evidence(evidence)
    if successor["phase"] in TERMINAL_PHASES:
        directive = {
            "kind": "terminal_closure",
            "payload": {"detail": "terminal", "evidence": evidence},
        }
    else:
        directive = {
            "kind": "wait_for_observation",
            "payload": {"detail": successor["phase"], "evidence": evidence},
        }
    return Reduction(successor=successor, directive=directive, transition_id=transition_id)
