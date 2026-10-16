"""Complete Issue166 lifecycle interface, retaining the tested readiness seed.

This module seeds the two-lane readiness graph on top of the unchanged
Issue 165 kernel. One closed rich state carries exactly the kernel state
plus a readiness map; exactly three registered edges exist: the shared
pre-turn to host-readiness edge and one self-loop per lane, each of which
requires shared readiness and its own false readiness fact and changes only
its own lane. Readiness itself prevents duplicate edges; there is no
consumed-edge ledger and no history.

The model never speaks for a live host: it reduces through the unchanged
pure kernel, binds its own closed envelope before the kernel runs, and
hands completed readiness to the finite protocol at generation 3. The protocol
models activation through verified owner rotation, including explicit unresolved
external evidence. No physical authority or cleanup is claimed.
"""

from __future__ import annotations

from lifecycle_conformance import protocol
from lifecycle_conformance import model
from lifecycle_conformance import reference_values
from lifecycle_conformance import registries
from lifecycle_conformance import values

PHASE_PRE_TURN = "pre_turn"
PHASE_HOST_READINESS = "host_readiness"

LANES = ("spec", "standards")
TARGETS = ("shared", "spec", "standards")

STIMULUS_KIND = "transition_reference"

# The closed per-edge contract: from/to phase, trigger, accepted kind and
# the one exact phrase that edge accepts. Frozen at module load so no
# decoded mutable definition is ever retained; every reader below takes a
# fresh detached projection.
EDGE_SPECS = reference_values.freeze({
    "shared": [
        "pre_turn",
        "host_readiness",
        "host_readiness_observed",
        "shared:host_readiness",
    ],
    "spec": [
        "host_readiness",
        "host_readiness",
        "spec_readiness_observed",
        "spec:lane_readiness",
    ],
    "standards": [
        "host_readiness",
        "host_readiness",
        "standards_readiness_observed",
        "standards:lane_readiness",
    ],
})

_EDGE_ORDER = ("shared", "spec", "standards")
_TERMINAL_GENERATION = 3

_KERNEL_KEYS = frozenset({"id", "phase", "generation", "result"})
_STATE_KEYS = frozenset(_KERNEL_KEYS | {"readiness"})
_LANES_KEYS = frozenset(LANES)
_READINESS_KEYS = frozenset({"shared", "lanes"})
_STIMULUS_KEYS = frozenset(
    {"case", "generation", "transition", "target", "kind", "phrase"}
)


class _Refusal(Exception):
    """Closed internal refusal; only its code survives to the public API."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _refuse(code: str) -> None:
    raise _Refusal(code)


def _raise(code: str) -> None:
    raise values.LifecycleContractError(code)


def _refuse_reason(err: _Refusal) -> str:
    return "reference_model:" + err.code


def _plain(frozen: reference_values.FrozenValue) -> object:
    """One transient decode; the caller must not retain the result."""
    if not isinstance(frozen, reference_values.FrozenValue):
        _refuse("state_mismatch")
    return frozen.to_plain()


def _state_case(state: dict) -> str:
    result = state.get("result")
    if not isinstance(result, dict) or isinstance(result, bool):
        _refuse("state_mismatch")
    case_id = result.get("case")
    if (
        not isinstance(case_id, str)
        or not case_id
        or not values._CASE_ID.match(case_id)
    ):
        _refuse("state_mismatch")
    return case_id


def _check_case(case_id: object) -> str:
    if (
        not isinstance(case_id, str)
        or not case_id
        or not values._CASE_ID.match(case_id)
    ):
        _refuse("case_id")
    return case_id


def _check_readiness(readiness: object) -> None:
    if not isinstance(readiness, dict) or isinstance(readiness, bool):
        _refuse("readiness")
    if not set(readiness) == _READINESS_KEYS:
        _refuse("readiness")
    if not isinstance(readiness.get("shared"), bool):
        _refuse("readiness")
    lanes = readiness.get("lanes")
    if not isinstance(lanes, dict) or isinstance(lanes, bool):
        _refuse("readiness")
    if not set(lanes) == _LANES_KEYS:
        _refuse("readiness")
    for lane in LANES:
        if not isinstance(lanes.get(lane), bool):
            _refuse("readiness")


def _check_rich_state(state: object) -> None:
    """Fail closed unless state is one closed rich modeled state."""
    if not isinstance(state, dict) or isinstance(state, bool):
        _refuse("state_mismatch")
    if not set(state) == _STATE_KEYS:
        _refuse("state_mismatch")
    # Bind result.case, state.id and result.item exactly before the base
    # kernel runs: lc-state:<case>:init at generation 0 and
    # lc-state:<case>:<generation> thereafter.
    case_peek = state.get("result")
    if not isinstance(case_peek, dict) or isinstance(case_peek, bool):
        _refuse("state_mismatch")
    peek_case = case_peek.get("case")
    if (
        not isinstance(peek_case, str)
        or not peek_case
        or not values._CASE_ID.match(peek_case)
    ):
        _refuse("state_mismatch")
    peek_generation = state.get("generation")
    if not isinstance(peek_generation, int) or isinstance(peek_generation, bool):
        _refuse("state_mismatch")
    expected_id = "lc-state:" + peek_case + (":init" if peek_generation == 0 else ":" + str(peek_generation))
    if state.get("id") != expected_id:
        _refuse("state_mismatch")
    if case_peek.get("item") != expected_id:
        _refuse("state_mismatch")
    # The readiness key is this module's addition; the kernel projection
    # (the four original fields) must itself be a closed kernel state.
    model.validate_state({key: state[key] for key in _KERNEL_KEYS})
    case_id = _state_case(state)
    if state["result"].get("item") != state.get("id"):
        _refuse("state_mismatch")
    generation = state.get("generation")
    phase = state.get("phase")
    if phase not in (PHASE_PRE_TURN, PHASE_HOST_READINESS):
        _refuse("state_mismatch")
    if phase == PHASE_PRE_TURN and generation != 0:
        _refuse("state_mismatch")
    if phase == PHASE_HOST_READINESS and generation not in (1, 2, 3):
        _refuse("state_mismatch")
    _check_readiness(state.get("readiness"))
    readiness = state["readiness"]
    if generation == 0:
        if (
            readiness["shared"]
            or readiness["lanes"]["spec"]
            or readiness["lanes"]["standards"]
        ):
            _refuse("state_mismatch")
    elif generation == 1:
        if (
            not readiness["shared"]
            or readiness["lanes"]["spec"]
            or readiness["lanes"]["standards"]
        ):
            _refuse("state_mismatch")
    elif generation == 2:
        if not readiness["shared"]:
            _refuse("state_mismatch")
        ready = [lane for lane in LANES if readiness["lanes"][lane]]
        if len(ready) != 1:
            _refuse("state_mismatch")
    else:
        if (
            not readiness["shared"]
            or not readiness["lanes"]["spec"]
            or not readiness["lanes"]["standards"]
        ):
            _refuse("state_mismatch")


def transition_id(case_id: str, target: str) -> str:
    """The closed registry identity of one of the three edges."""
    _check_case(case_id)
    if target not in TARGETS:
        _refuse("invalid_target")
    return "lc-trans:" + case_id + ":" + target


def _transition_record(case_id: str, target: str) -> dict:
    if target not in EDGE_SPECS.to_plain():
        _refuse("invalid_target")
    from_phase, to_phase, trigger, _phrase = EDGE_SPECS.to_plain()[target]
    return {
        "from": from_phase,
        "to": to_phase,
        "trigger": trigger,
        "evidence": {
            "case": case_id,
            "item": "lc-state:" + case_id + ":init",
        },
    }


def fresh_registry(case_id: str) -> registries.RegistryStore:
    """One fresh deterministic store holding exactly the three edges."""
    _check_case(case_id)
    store = registries.RegistryStore()
    for target in _EDGE_ORDER:
        store.add(
            "lc-trans",
            transition_id(case_id, target),
            case_id,
            _transition_record(case_id, target),
        )
    return store


def _readiness_snapshot(state: reference_values.FrozenValue) -> reference_values.FrozenValue:
    """Deterministic detached frozen snapshot of exactly the three edges."""
    try:
        state_plain = _plain(state)
        _check_rich_state(state_plain)
        case_id = _state_case(state_plain)
        store = fresh_registry(case_id)
        payload = {
            transition_id(case_id, target): store.get(
                "lc-trans", transition_id(case_id, target)
            )
            for target in _EDGE_ORDER
        }
        return reference_values.freeze(payload)
    except _Refusal as err:
        _raise(_refuse_reason(err))


def _edge_identities(case_id: str, generation: int, targets) -> list[dict]:
    identities = []
    for target in targets:
        identities.append(
            {
                "case": case_id,
                "generation": generation,
                "kind": STIMULUS_KIND,
                "phrase": EDGE_SPECS.to_plain()[target][3],
                "target": target,
                "transition": transition_id(case_id, target),
            }
        )
    return identities


def _legal_targets(state_plain: dict) -> list[str]:
    readiness = state_plain["readiness"]
    if not readiness["shared"]:
        return ["shared"]
    return [lane for lane in LANES if not readiness["lanes"][lane]]


def _wait_directive(state_plain: dict) -> dict:
    case_id = _state_case(state_plain)
    generation = state_plain["generation"]
    return {
        "kind": "wait_for_observation",
        "payload": {
            "detail": state_plain["phase"],
            "evidence": {
                "case": case_id,
                "item": state_plain["id"],
            },
            "stimuli": _edge_identities(case_id, generation, _legal_targets(state_plain)),
        },
    }


def _directive_for_state(state_plain: dict) -> dict:
    if state_plain["generation"] == _TERMINAL_GENERATION:
        return protocol.legal_directive(reference_values.freeze(state_plain)).to_plain()
    return _wait_directive(state_plain)


def _readiness_directive(state: reference_values.FrozenValue) -> reference_values.FrozenValue:
    """The single directive legal to issue from one closed rich state."""
    try:
        state_plain = _plain(state)
        _check_rich_state(state_plain)
        return reference_values.freeze(_directive_for_state(state_plain))
    except _Refusal as err:
        _raise(_refuse_reason(err))


def _readiness_outgoing(state: reference_values.FrozenValue) -> reference_values.FrozenValue:
    """The finite, closed list of stimulus identities legal right now."""
    try:
        state_plain = _plain(state)
        _check_rich_state(state_plain)
        case_id = _state_case(state_plain)
        generation = state_plain["generation"]
        if generation >= _TERMINAL_GENERATION:
            return reference_values.freeze([])
        return reference_values.freeze(
            _edge_identities(case_id, generation, _legal_targets(state_plain))
        )
    except _Refusal as err:
        _raise(_refuse_reason(err))


def _check_phrase(phrase: object, target: str) -> None:
    if not isinstance(phrase, str):
        _refuse("unknown_phrase")
    if ":" not in phrase:
        _refuse("unknown_phrase")
    head, _, rest = phrase.partition(":")
    if head not in TARGETS or not rest or not values._TOKEN.match(rest):
        _refuse("unknown_phrase")
    if head != target:
        _refuse("cross_lane")
    if phrase != EDGE_SPECS.to_plain()[target][3]:
        _refuse("unknown_phrase")


def _check_stimulus(envelope: object, state_plain: dict) -> str:
    """Validate the closed envelope; return the legal target."""
    if not isinstance(envelope, dict) or isinstance(envelope, bool):
        _refuse("invalid_stimulus")
    if not set(envelope) == _STIMULUS_KEYS:
        _refuse("invalid_stimulus")
    kind = envelope.get("kind")
    if not isinstance(kind, str) or kind != STIMULUS_KIND:
        _refuse("unknown_kind")
    case_id = envelope.get("case")
    if (
        not isinstance(case_id, str)
        or not case_id
        or not values._CASE_ID.match(case_id)
    ):
        _refuse("case_mismatch")
    if case_id != _state_case(state_plain):
        _refuse("case_mismatch")
    generation = envelope.get("generation")
    if not isinstance(generation, int) or isinstance(generation, bool):
        _refuse("invalid_generation")
    if generation != state_plain["generation"]:
        _refuse("stale_generation")
    target = envelope.get("target")
    if not isinstance(target, str) or target not in TARGETS:
        _refuse("invalid_target")
    transition = envelope.get("transition")
    if not isinstance(transition, str) or not values.is_item_id(transition):
        _refuse("unknown_transition")
    if transition != transition_id(case_id, target):
        _refuse("unknown_transition")
    _check_phrase(envelope.get("phrase"), target)
    return target


def _kernel_stimulus(case_id: str, target: str) -> dict:
    return {
        "kind": STIMULUS_KIND,
        "reference": transition_id(case_id, target),
        "phrase": EDGE_SPECS.to_plain()[target][3],
        "evidence": None,
    }


def _apply_readiness(kernel_successor: dict, pre_readiness: dict, target: str) -> dict:
    successor = dict(kernel_successor)
    readiness = {
        "shared": bool(pre_readiness["shared"]),
        "lanes": {
            lane: bool(pre_readiness["lanes"][lane]) for lane in LANES
        },
    }
    if target == "shared":
        readiness["shared"] = True
    else:
        readiness["lanes"][target] = True
    successor["readiness"] = readiness
    return successor


def _readiness_reduce(
    state: reference_values.FrozenValue,
    stimulus: object,
) -> reference_values.FrozenValue:
    """Reduce one closed rich state plus one legal envelope through the kernel.

    State must be an exact FrozenValue; stimulus must be an exact dict
    envelope or an exact FrozenValue decoding to one (decoded before the
    existing validation). Every other outer type, including a subclass, is
    refused with a stable contract error before the unchanged kernel runs,
    so a refused input performs zero base reductions and leaves both inputs
    unchanged. Every legal edge rebuilds a fresh deterministic registry from
    the three immutable definitions and runs the unchanged kernel reducer
    exactly once; the kernel binds case, phase, generation and successor id,
    while this module alone binds the readiness fact. The result is one
    exact FrozenValue holding only the plain JSON successor and directive
    plus the edge transition id. The seed hands off to protocol activation.

    The selected transition is resolved from the actual fresh registry
    view (items_of, not only store.get) and re-checked after the
    reduction; the actual returned Reduction is validated field by field
    before any projection, so a corrupted view or output is refused with
    a stable, non-reflecting reason.
    """
    try:
        if type(state) is not reference_values.FrozenValue:
            _refuse("state_mismatch")
        state_plain = _plain(state)
        _check_rich_state(state_plain)
        # Require the exact outer type before any decode: only an exact
        # dict envelope or an exact FrozenValue decoding to one. Any
        # subclass or other outer type is refused before its decoder
        # or the kernel ever runs.
        if isinstance(stimulus, reference_values.FrozenValue):
            if type(stimulus) is not reference_values.FrozenValue:
                _refuse("invalid_stimulus")
            stimulus = stimulus.to_plain()
        if type(stimulus) is not dict:
            _refuse("invalid_stimulus")
        case_id = _state_case(state_plain)
        target = _check_stimulus(stimulus, state_plain)

        def _strict_equal(a: object, b: object) -> bool:
            """Closed type-sensitive equality; True==1 and 1.0==1 stay apart."""
            if isinstance(a, bool) or isinstance(b, bool):
                return type(a) is bool and type(b) is bool and a is b
            if isinstance(a, (int, float)) or isinstance(b, (int, float)):
                return type(a) is type(b) and a == b
            if type(a) is not type(b):
                return False
            if type(a) is dict:
                if set(a) != set(b):
                    return False
                return all(_strict_equal(a[k], b[k]) for k in a)
            if type(a) is list:
                return len(a) == len(b) and all(
                    _strict_equal(x, y) for x, y in zip(a, b)
                )
            return a == b

        def _selected_record_ok(store: registries.RegistryStore) -> None:
            """Bind the selected record from the actual fresh view exactly."""
            view = store.items_of(registries.TRANSITIONS_KIND)
            if type(view) is not dict:
                _refuse("registry_view")
            if set(view) != set(transition_id(case_id, t) for t in _EDGE_ORDER):
                _refuse("registry_view")
            record = view.get(transition_id(case_id, target))
            if (
                type(record) is not dict
                or not _strict_equal(
                    record, _transition_record(case_id, target)
                )
            ):
                _refuse("registry_view")

        def _check_actual_reduction(actual: object) -> None:
            """Validate the ACTUAL returned model.Reduction, field by field."""
            if (
                type(actual) is not model.Reduction
                or type(actual.transition_id) is not str
                or actual.transition_id != transition_id(case_id, target)
            ):
                _refuse("provider_mismatch")
            successor = actual.successor
            if (
                type(successor) is not dict
                or set(successor) != _KERNEL_KEYS
            ):
                _refuse("provider_mismatch")
            prev_generation = state_plain["generation"]
            if (
                type(successor.get("generation")) is not int
                or successor["generation"] != prev_generation + 1
            ):
                _refuse("provider_mismatch")
            next_generation = successor["generation"]
            expected_id = (
                "lc-state:" + case_id + ":" + str(next_generation)
            )
            if (
                type(successor.get("id")) is not str
                or successor["id"] != expected_id
            ):
                _refuse("provider_mismatch")
            if (
                type(successor.get("phase")) is not str
                or successor["phase"]
                != _transition_record(case_id, target)["to"]
            ):
                _refuse("provider_mismatch")
            result = successor.get("result")
            if (
                type(result) is not dict
                or set(result) != {"case", "item"}
                or type(result.get("case")) is not str
                or result["case"] != case_id
                or type(result.get("item")) is not str
                or result["item"] != expected_id
            ):
                _refuse("provider_mismatch")
            directive = actual.directive
            if (
                type(directive) is not dict
                or set(directive) != {"kind", "payload"}
                or type(directive.get("kind")) is not str
                or directive["kind"] != "wait_for_observation"
            ):
                _refuse("provider_mismatch")
            payload = directive.get("payload")
            if (
                type(payload) is not dict
                or set(payload) != {"detail", "evidence"}
                or type(payload.get("detail")) is not str
                or payload["detail"] != successor["phase"]
            ):
                _refuse("provider_mismatch")
            evidence = payload.get("evidence")
            if (
                type(evidence) is not dict
                or set(evidence) != {"case", "item"}
                or type(evidence.get("case")) is not str
                or evidence["case"] != case_id
                or type(evidence.get("item")) is not str
                or evidence["item"] != actual.transition_id
            ):
                _refuse("provider_mismatch")

        readiness = state_plain["readiness"]
        if target == "shared":
            if readiness["shared"]:
                _refuse("consumed_edge")
        else:
            if not readiness["shared"]:
                _refuse("early_edge")
            if readiness["lanes"][target]:
                _refuse("consumed_edge")
        store = fresh_registry(case_id)
        _selected_record_ok(store)
        kernel_state = {
            key: value for key, value in state_plain.items() if key != "readiness"
        }
        kernel = model.reduce(
            kernel_state, _kernel_stimulus(case_id, target), store
        )
        _check_actual_reduction(kernel)
        _selected_record_ok(store)
        successor_plain = _apply_readiness(
            kernel.successor, state_plain["readiness"], target
        )
        _check_rich_state(successor_plain)
        directive = _directive_for_state(successor_plain)
        if directive["kind"] == "terminal_closure":
            _refuse("terminal_refused")
        return reference_values.freeze(
            {
                "successor": successor_plain,
                "directive": directive,
                "transition_id": kernel.transition_id,
            }
        )
    except _Refusal as err:
        _raise(_refuse_reason(err))


def initial_state(case_id: str) -> reference_values.FrozenValue:
    """One closed generation-0 rich state: kernel init plus all-false readiness."""
    try:
        case_id = _check_case(case_id)
        kernel_state = model.initial_state(case_id)
        rich_state = dict(kernel_state)
        rich_state["readiness"] = {
            "shared": False,
            "lanes": {"spec": False, "standards": False},
        }
        _check_rich_state(rich_state)
        return reference_values.freeze(rich_state)
    except _Refusal as err:
        _raise(_refuse_reason(err))


# Preserve the tested readiness seam and extend the same public interface. The
# seed's completed generation is the protocol entry, never an external boundary.


def _protocol_state(state: object) -> bool:
    if type(state) is not reference_values.FrozenValue:
        return False
    plain = state.to_plain()
    return type(plain) is dict and ("history" in plain or plain.get("generation") == 3)


def reduce(state: reference_values.FrozenValue, stimulus: object) -> reference_values.FrozenValue:
    """One closed observation, one current foundation reduction, one successor."""
    return protocol.reduce(state, stimulus) if _protocol_state(state) else _readiness_reduce(state, stimulus)


def outgoing_stimuli(state: reference_values.FrozenValue) -> reference_values.FrozenValue:
    """Every finite legal observation at the current lifecycle point."""
    return protocol.outgoing_stimuli(state) if _protocol_state(state) else _readiness_outgoing(state)


def legal_directive(state: reference_values.FrozenValue) -> reference_values.FrozenValue:
    """Exactly one action, wait, external requirement or settled closure."""
    return protocol.legal_directive(state) if _protocol_state(state) else _readiness_directive(state)


def registry_snapshot(state: reference_values.FrozenValue) -> reference_values.FrozenValue:
    """The actual readiness registry or current protocol transition registry."""
    return protocol.registry_snapshot(state) if _protocol_state(state) else _readiness_snapshot(state)
