"""Finite two-lane protocol after host readiness; no physical lifecycle effects.

Every state is a detached immutable value. Its bounded abstract history is
replayed to validate all derived facts, including identities and obligations.
Observations are evidence supplied to this model, never evidence of a real host.
"""
from __future__ import annotations

from functools import lru_cache
from copy import deepcopy

from lifecycle_conformance import model, reference_values as rv, registries, values

LANES = ("spec", "standards")
MAX_EVENTS = 28
REFUSALS = ("malformed", "stale", "mismatched", "duplicated")
UNCERTAIN = ("unknown", "interrupted_after", "partial", "missing", "cleanup_unavailable")
KNOWN_FAILURES = ("refused", "failed", "interrupted_before", "not_dispatched")
STAGES = rv.freeze({
    "activate": ["host_readiness", "wait_for_observation", "activation"],
    "grant.spec": ["activation", "wait_for_observation", "authorize_spawn"],
    "spawn.spec": ["spawn_grant", "action", "spawn_agent"],
    "grant.standards": ["spawn", "wait_for_observation", "authorize_spawn"],
    "spawn.standards": ["spawn_grant", "action", "spawn_agent"],
    "ack": ["acknowledgement", "wait_for_observation", "acknowledgement"],
    "continue.spec": ["continuation", "action", "send_input"],
    "result.spec": ["typed_result", "wait_for_observation", "typed_result"],
    "continue.standards": ["typed_result", "action", "send_input"],
    "result.standards": ["typed_result", "wait_for_observation", "typed_result"],
    "checkpoint.spec": ["worker_progress", "wait_for_observation", "worker_progress"],
    "checkpoint.standards": ["worker_progress", "wait_for_observation", "worker_progress"],
    "progress": ["worker_progress", "wait_for_observation", "admit_continuation"],
    "aggregate": ["aggregation", "wait_for_observation", "aggregate"],
    "review": ["sol_review", "wait_for_observation", "sol_review"],
    "verify": ["terminal_verification", "wait_for_observation", "terminal_verification"],
    "cleanup": ["cleanup", "wait_for_observation", "authorize_cleanup"],
    "close.spec": ["cleanup", "action", "close_agent"],
    "close.standards": ["cleanup", "action", "close_agent"],
    "process": ["cleanup", "wait_for_observation", "process_group_proof"],
    "settle": ["capacity_settlement", "wait_for_observation", "release_capacity"],
    "final_qualification": ["final_qualification", "wait_for_observation", "final_qualification"],
    "failure_closure": ["failure_closure", "wait_for_observation", "failure_closure"],
    "rotate": ["owner_rotation", "action", "rotate_owner"],
    "terminal": ["terminal", "terminal_closure", "closed"],
})
KERNEL_KEYS = frozenset({"id", "phase", "generation", "result"})
FINAL_CHECKS = rv.freeze({
    "final_qualification": ("wave_v3_terminal", "typed_terminal_contracts", "independent_attempt_observer",
                            "run_trace", "coordinator_capsule", "dogfood_spine", "shared_capacity_settlement"),
    "failure_closure": ("verified_failure", "grant_settlement", "lane_cleanup", "process_group",
                        "capacity_settlement", "owner_identity"),
})


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("reference_model:" + reason)


def strict_equal(left: object, right: object) -> bool:
    """JSON equality with exact scalar/container types (including subclasses)."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(strict_equal(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(strict_equal(a, b) for a, b in zip(left, right))
    return left == right


def _identity(case: str, kind: str, generation: int, stage: str, lane: str) -> str:
    return f"{kind}:{case}:{generation}:{stage}:{lane}"


def _initial(case: str) -> dict:
    item = f"lc-state:{case}:3"
    return {
        "id": item, "phase": "host_readiness", "generation": 3,
        "result": {"case": case, "item": item},
        "readiness": {"shared": True, "lanes": {lane: True for lane in LANES}},
        "stage": "activate", "history": [],
        "controller": {"owner": f"root:{case}", "cursor": 3, "active": False,
                       "owner_disposition": "retained", "successor_owner": None},
        "lanes": {lane: {"capacity": "none", "creation": "none", "acknowledgement": "pending",
                          "worker_id": None, "spawn_action": None, "continuation": "none",
                          "checkpoint_continuation": None, "checkpoint": None,
                          "typed_result": None, "cleanup": "not_required"}
                  for lane in LANES},
        "grants": {}, "action": None, "aggregation": "pending", "sol_review": "pending",
        "terminal_verification": "pending", "process_group": "unproven",
        "progress_admission": "unrequested",
        "attempt_closure": None,
        "capacity_settlement": "pending", "outcome": "success", "requirement": None,
    }


def _targets(state: dict) -> list[str]:
    stage = state["stage"]
    if stage == "ack":
        return [lane for lane in LANES if state["lanes"][lane]["acknowledgement"] == "pending"]
    if stage.startswith("result."):
        # Both sealed calls have been submitted before entering this wait.
        # Its representative stage does not order the missing lane results.
        return [lane for lane in LANES if state["lanes"][lane]["typed_result"] is None]
    if stage.startswith("checkpoint."):
        return [lane for lane in LANES if state["lanes"][lane]["checkpoint"] is None]
    if stage == "cleanup":
        return [lane for lane in LANES if state["lanes"][lane]["cleanup"] == "pending"]
    return [stage.split(".")[1] if "." in stage else "controller"]


def _binding(state: dict, lane: str, stage: str | None = None) -> dict:
    stage = state["stage"] if stage is None else stage
    case, generation = state["result"]["case"], state["generation"]
    if state["action"] is not None:
        action = state["action"]
        action_id, grant = action["id"], action["grant"]
    else:
        action_id = _identity(case, "observation", generation, stage, lane)
        requested = [key for key, status in state["grants"].items() if status == "requested"]
        grant = requested[0] if stage.startswith("grant.") and len(requested) == 1 else "none"
    return {"case": case, "generation": generation, "owner": state["controller"]["owner"],
            "cursor": state["controller"]["cursor"], "stage": stage, "lane": lane,
            "action_id": action_id, "grant_id": grant}


def _compensating(state: dict) -> bool:
    """A known first worker can be closed while a second spawn stays unknown."""
    return (state["stage"] == "close.spec" and state["terminal_verification"] == "pending"
            and state["outcome"] == "failure" and bool(state["history"])
            and state["history"][-1]["stage"] == "spawn.standards"
            and state["history"][-1]["outcome"] in ("failed", "unknown"))


def _sealed_release_ready(state: dict) -> bool:
    return (state["action"] is None and state["capacity_settlement"] == "pending"
            and (state["stage"].startswith("result.") or state["stage"] in ("aggregate", "review", "verify"))
            and all(row["creation"] == "created" and row["continuation"] != "none"
                    for row in state["lanes"].values())
            and all(status in ("settled", "released") for status in state["grants"].values()))


def _choices(state: dict) -> list[dict]:
    if state["stage"] == "terminal":
        return []
    if state["requirement"] is not None and not _compensating(state):
        # A missing review observation is a quality obligation, not an unknown
        # worker effect. Exact independent release evidence may settle physical
        # resources once; it grants no review retry, work or terminal authority.
        if (state["stage"] == state["requirement"]["stage"] == "review"
                and _sealed_release_ready(state)):
            return [{"stage": "settle", "lane": "controller", "outcome": "accepted", "variant": "sealed_release"}]
        return []
    choices = []
    for lane in _targets(state):
        stage = (state["stage"].split(".")[0] + "." + lane
                 if state["stage"].startswith(("result.", "checkpoint.")) else state["stage"])
        variants = ("SUCCESS", "NOT_APPLICABLE") if stage == "ack" else (
            ("direct", "deferred") if stage.startswith("continue.") else ("evidence",))
        if stage.startswith("continue."):
            if state["progress_admission"] == "pending":
                variants = ("checkpoint_direct", "checkpoint_deferred")
            elif stage == "continue.spec" and state["progress_admission"] == "unrequested":
                variants += ("checkpoint_direct", "checkpoint_deferred")
        if stage == "final_qualification":
            # Complete independent failure closure is distinct from an
            # unverified/failed final check that retains an external barrier.
            variants += ("verified_budget_failure",)
        choices.extend({"stage": stage, "lane": lane, "outcome": "accepted", "variant": v}
                       for v in variants)
        # Invalid envelopes are refusals, not outgoing transitions. Uncertain
        # observations are admitted only as a retained external requirement.
        outcomes = KNOWN_FAILURES + UNCERTAIN[:-1]
        if stage in ("cleanup", "close.spec", "close.standards", "process"):
            outcomes += ("cleanup_unavailable",)
        choices.extend({"stage": stage, "lane": lane, "outcome": outcome, "variant": "evidence"}
                       for outcome in outcomes)
        if stage == "grant.spec":
            # Capacity admission can commit both reservations before the first
            # proposal is refused. Keep that verified effect distinct from a
            # refusal that occurred before allocation.
            choices.append({"stage": stage, "lane": lane, "outcome": "refused", "variant": "capacity_reserved"})
    # Receipt consumption is independent of the whole-run quality phase.
    # There must be no outstanding native call or unresolved effect; all lanes
    # are known and the completed batch leaves only evidence to be collected.
    if _sealed_release_ready(state):
        choices.append({"stage": "settle", "lane": "controller", "outcome": "accepted", "variant": "sealed_release"})
        choices.extend({"stage": "settle", "lane": "controller", "outcome": outcome, "variant": "evidence"}
                       for outcome in KNOWN_FAILURES + UNCERTAIN)
    return choices


def _proof(state: dict, choice: dict) -> dict | None:
    if choice["outcome"] != "accepted":
        return None
    stage, lane = choice["stage"], choice["lane"]
    if stage in FINAL_CHECKS.to_plain():
        if choice["variant"] == "verified_budget_failure":
            return _final_proof({**state, "outcome": "failure"}, "failure_closure")
        return _final_proof(state, stage)
    if stage == "settle" and choice["variant"] == "sealed_release":
        return {"schema": "orch-dork/lifecycle-sealed-release-observation/v1",
                "case": state["result"]["case"], "observer": "independent",
                "lanes": [{"lane": name, "worker_id": facts["worker_id"],
                           "spawn_action": facts["spawn_action"], "route": "native",
                           "terminal_state": "completed", "cleanup": "complete", "owned_descendants": 0}
                          for name, facts in state["lanes"].items()]}
    if stage.startswith("checkpoint.") or choice["variant"] == "checkpoint_direct":
        action_id = (state["action"]["id"] if stage.startswith("continue.")
                     else state["lanes"][lane]["checkpoint_continuation"])
        return {"schema": "orch-dork/lifecycle-worker-progress/v1", "case": state["result"]["case"],
                "lane": lane, "action_id": action_id, "sequence": 1, "status": "PASS"}
    if stage.startswith("result.") or (stage.startswith("continue.") and choice["variant"] == "direct"):
        action_id = (state["action"]["id"] if stage.startswith("continue.")
                     else state["lanes"][lane]["continuation"])
        return {"schema": "orch-dork/lifecycle-typed-result/v1", "case": state["result"]["case"],
                "lane": lane, "action_id": action_id, "status": "PASS"}
    if stage.startswith("spawn."):
        return {"status": "PASS", "scope": stage, "worker_id": f"worker:{state['result']['case']}:{lane}",
                "spawn_action": state["action"]["id"]}
    if stage == "ack" or stage.startswith("close."):
        return {"status": "PASS", "scope": stage, "worker_id": state["lanes"][lane]["worker_id"],
                "spawn_action": state["lanes"][lane]["spawn_action"]}
    if stage == "process":
        return {"owned_descendants": 0, "observer": "independent", "status": "PASS"}
    if stage in ("verify", "review"):
        return {"status": "PASS", "scope": stage, "outcome": state["outcome"]}
    return {"status": "PASS", "scope": stage}


def _final_proof(state: dict, stage: str) -> dict:
    """A supplied model observation names all checks, without attesting a host."""
    return {"status": "PASS", "scope": stage, "outcome": state["outcome"],
            "case": state["result"]["case"], "owner": state["controller"]["owner"],
            "observer": "independent", "checks": FINAL_CHECKS.to_plain()[stage]}


def _envelope(state: dict, choice: dict) -> dict:
    return {**_binding(state, choice["lane"], choice["stage"]), "kind": "lifecycle_observation",
            "transition": transition_id(state["result"]["case"], choice),
            "outcome": choice["outcome"], "variant": choice["variant"],
            "acknowledgement": (choice["variant"] if choice["stage"] == "ack"
                                and choice["outcome"] == "accepted" else "NOT_APPLICABLE"),
            "proof": _proof(state, choice)}


def _retain_requirement(state: dict, stage: str, lane: str, outcome: str) -> None:
    requirement = {"stage": stage, "lane": lane, "observation": outcome,
                   "authority": "independent_host_observer",
                   "evidence": f"resolve:{stage}:{lane}:{outcome}"}
    # Compensation can fail while the preceding spawn remains unresolved.
    # Preserve the whole prior requirement, including any earlier obligations.
    if state["requirement"] is not None:
        requirement["prior_requirements"] = [state["requirement"]]
    state["requirement"] = requirement


def _settle_action(state: dict, outcome: str) -> None:
    if state["action"] is not None:
        grant = state["action"]["grant"]
        state["grants"][grant] = ("released" if outcome in ("refused", "interrupted_before", "not_dispatched")
                                  else "settled")
        state["action"] = None


def _enter(state: dict, stage: str) -> None:
    state["stage"] = stage
    state["phase"] = STAGES.to_plain()[stage][0]
    state["action"] = None
    if stage == "cleanup" and not _targets(state):
        _enter(state, "process")
        return
    if stage == "process" and state["process_group"] == "zero_owned_descendants":
        _enter(state, "settle")
        return
    if stage == "settle" and state["capacity_settlement"] == "released":
        _enter(state, "final_qualification" if state["outcome"] == "success" else "failure_closure")
        return
    if stage.startswith("grant."):
        lane = _targets(state)[0]
        state["grants"][_identity(state["result"]["case"], "grant", state["generation"], stage, lane)] = "requested"
    if STAGES.to_plain()[stage][1] == "action" and stage != "cleanup":
        lane = _targets(state)[0]
        binding = _binding(state, lane)
        grant = _identity(binding["case"], "grant", binding["generation"], stage, lane)
        if stage.startswith("spawn."):
            requested = [key for key, status in state["grants"].items() if status == "requested"]
            if len(requested) != 1:
                _refuse("grant_mismatch")
            grant = requested[0]
        state["grants"][grant] = "authorized"
        state["action"] = {"id": _identity(binding["case"], "action", binding["generation"], stage, lane),
                           "grant": grant, "lane": lane, "method": STAGES.to_plain()[stage][2],
                           "controller_returned": True, "worker_id": state["lanes"][lane]["worker_id"] if lane in LANES else None}


def _advance(state: dict, choice: dict) -> dict:
    """Pure facts only. The public reducer separately verifies one real kernel call."""
    compensating = _compensating(state)
    state = deepcopy(state)
    proof = _proof(state, choice)
    prior_action = state["action"]
    stage, lane, outcome = choice["stage"], choice["lane"], choice["outcome"]
    state["history"].append(dict(choice))
    state["generation"] += 1
    state["controller"]["cursor"] += 1
    item = f"lc-state:{state['result']['case']}:{state['generation']}"
    state["id"] = item
    state["result"]["item"] = item
    if stage == "grant.spec" and choice["variant"] == "capacity_reserved":
        for facts in state["lanes"].values():
            facts["capacity"] = "reserved"
    if outcome in UNCERTAIN:
        if prior_action:
            state["grants"][prior_action["grant"]] = "dispatched"
        _retain_requirement(state, stage, lane, outcome)
        # An observed unknown second spawn still permits compensation of the
        # first known worker. Keep the unresolved spawn grant and requirement;
        # the original action identity remains bound by the immutable history.
        if stage == "spawn.standards" and outcome == "unknown":
            state["outcome"] = "failure"
            _enter(state, "close.spec")
        return state
    _settle_action(state, outcome)
    if outcome in KNOWN_FAILURES:
        state["outcome"] = "failure"
        if stage == "progress":
            state["progress_admission"] = "stopped"
            _enter(state, "close.spec")
        elif stage in ("verify", "cleanup", "close.spec", "close.standards", "process", "settle", "final_qualification", "failure_closure", "rotate"):
            _retain_requirement(state, stage, lane, outcome)
        elif stage == "spawn.standards" and outcome == "failed":
            _enter(state, "close.spec")
        else:
            _enter(state, "verify")
        return state
    if stage == "activate":
        state["controller"]["active"] = True
        _enter(state, "grant.spec")
    elif stage.startswith("grant."):
        # Production admits capacity for the complete wave before authorizing
        # its first per-lane spawn. The second action uses that same reservation.
        if lane == "spec":
            for facts in state["lanes"].values():
                facts["capacity"] = "reserved"
        _enter(state, "spawn." + lane)
    elif stage.startswith("spawn."):
        state["lanes"][lane].update(creation="created", capacity="occupied", cleanup="pending",
                                     worker_id=proof["worker_id"], spawn_action=proof["spawn_action"])
        _enter(state, "grant.standards" if lane == "spec" else "ack")
    elif stage == "ack":
        state["lanes"][lane]["acknowledgement"] = choice["variant"]
        _enter(state, "ack" if _targets(state) else "continue.spec")
    elif stage.startswith("continue.") and choice["variant"].startswith("checkpoint_"):
        state["progress_admission"] = "pending"
        state["lanes"][lane]["checkpoint_continuation"] = prior_action["id"]
        if choice["variant"] == "checkpoint_direct":
            state["lanes"][lane]["checkpoint"] = proof
        pending = next((name for name in LANES if state["lanes"][name]["checkpoint"] is None), None)
        _enter(state, "continue.standards" if lane == "spec" else "checkpoint." + pending if pending else "progress")
    elif stage.startswith("checkpoint."):
        state["lanes"][lane]["checkpoint"] = proof
        pending = next((name for name in LANES if state["lanes"][name]["checkpoint"] is None), None)
        _enter(state, "checkpoint." + pending if pending else "progress")
    elif stage == "progress":
        state["progress_admission"] = "accepted"
        _enter(state, "continue.spec")
    elif stage.startswith("continue."):
        state["lanes"][lane]["continuation"] = prior_action["id"]
        if choice["variant"] == "direct":
            state["lanes"][lane]["typed_result"] = proof
        # A successful submission completes this native call even when its
        # typed result is deferred. The next sealed call may then be issued;
        # the later join still requires both exact continuation results.
        if lane == "spec":
            _enter(state, "continue.standards")
        else:
            pending = next((name for name in LANES if state["lanes"][name]["typed_result"] is None), None)
            _enter(state, "result." + pending if pending else "aggregate")
    elif stage.startswith("result."):
        state["lanes"][lane]["typed_result"] = proof
        pending = next((name for name in LANES if state["lanes"][name]["typed_result"] is None), None)
        _enter(state, "result." + pending if pending else "aggregate")
    elif stage == "aggregate":
        state["aggregation"] = "accepted"
        _enter(state, "review")
    elif stage == "review":
        state["sol_review"] = "accepted"
        _enter(state, "verify")
    elif stage == "verify":
        state["terminal_verification"] = "accepted"
        _enter(state, "cleanup")
    elif stage == "cleanup":
        _enter(state, "close." + lane)
    elif stage.startswith("close."):
        state["lanes"][lane]["cleanup"] = "closed"
        if state["progress_admission"] == "stopped":
            _enter(state, "close.standards" if lane == "spec" else "verify")
        else:
            _enter(state, "verify" if compensating else "cleanup")
    elif stage == "process":
        state["process_group"] = "zero_owned_descendants"
        _enter(state, "settle")
    elif stage == "settle":
        state["grants"] = {key: "released" for key in state["grants"]}
        for facts in state["lanes"].values():
            facts["capacity"] = "released"
        state["capacity_settlement"] = "released"
        if choice["variant"] == "sealed_release":
            for facts in state["lanes"].values():
                facts["cleanup"] = "closed"
            state["process_group"] = "zero_owned_descendants"
            # Keep the existing result/join/verification phase and obligations.
            # This observation is no authority for further worker dispatch.
        else:
            _enter(state, "final_qualification" if state["outcome"] == "success" else "failure_closure")
    elif stage in FINAL_CHECKS.to_plain():
        if choice["variant"] == "verified_budget_failure":
            state["outcome"] = "failure"
        state["attempt_closure"] = proof
        _enter(state, "rotate")
    elif stage == "rotate":
        # The rotation grant was settled above, and is released with owner disposition.
        state["grants"] = {key: "released" for key in state["grants"]}
        state["controller"]["owner_disposition"] = "rotated"
        state["controller"]["successor_owner"] = f"root:{state['result']['case']}:successor"
        state["controller"]["active"] = False
        _enter(state, "terminal")
    return state


def closed(state: dict) -> bool:
    return (state["terminal_verification"] == "accepted" and state["requirement"] is None
            and strict_equal(state.get("attempt_closure"), _final_proof(
                state, "final_qualification" if state["outcome"] == "success" else "failure_closure"))
            and state["action"] is None and all(v == "released" for v in state["grants"].values())
            and all(l["cleanup"] in ("closed", "not_required") and l["capacity"] == "released"
                    for l in state["lanes"].values())
            and state["process_group"] == "zero_owned_descendants"
            and state["capacity_settlement"] == "released"
            and state["controller"]["owner_disposition"] == "rotated"
            and state["controller"]["successor_owner"] == f"root:{state['result']['case']}:successor"
            and not state["controller"]["active"]
            and (state["outcome"] == "failure" or (
                state["aggregation"] == state["sol_review"] == "accepted"
                and all(l["typed_result"] is not None for l in state["lanes"].values()))))


@lru_cache(maxsize=4096)
def _validated_state(value: rv.FrozenValue) -> rv.FrozenValue:
    if type(value) is not rv.FrozenValue:
        _refuse("state_mismatch")
    data = value.to_plain()
    if type(data) is not dict or type(data.get("result")) is not dict:
        _refuse("state_mismatch")
    case = data["result"].get("case")
    if type(case) is not str or not values._CASE_ID.fullmatch(case):
        _refuse("state_mismatch")
    expected = _initial(case)
    # Accept exactly the completed readiness seed at the interface boundary.
    seed = {k: v for k, v in expected.items() if k in KERNEL_KEYS or k == "readiness"}
    if strict_equal(data, seed):
        return rv.freeze(expected)
    history = data.get("history")
    if type(history) is not list or len(history) > MAX_EVENTS:
        _refuse("state_mismatch")
    for choice in history:
        if not any(strict_equal(choice, legal) for legal in _choices(expected)):
            _refuse("state_mismatch")
        expected = _advance(expected, choice)
    if not strict_equal(data, expected) or (data["stage"] == "terminal" and not closed(data)):
        _refuse("state_mismatch")
    return value


def _state(value: rv.FrozenValue) -> dict:
    # Cache only immutable validation results, never registry views or kernel
    # reductions. Every public projection is fresh and every edge still calls
    # the current foundation exactly once.
    if type(value) is not rv.FrozenValue:
        _refuse("state_mismatch")
    return _validated_state(value).to_plain()


def transition_id(case: str, choice: dict) -> str:
    return f"lc-trans:{case}:{choice['stage']}.{choice['lane']}.{choice['outcome']}.{choice['variant']}"


def _record(state: dict, choice: dict) -> dict:
    after = _advance(state, choice)
    return {"from": state["phase"], "to": after["phase"], "trigger": choice["stage"],
            "choice": choice, "evidence": {"case": state["result"]["case"], "item": state["id"]}}


def fresh_registry(state: rv.FrozenValue) -> registries.RegistryStore:
    data = _state(state)
    store = registries.RegistryStore()
    for choice in _choices(data):
        store.add("lc-trans", transition_id(data["result"]["case"], choice), "issue-166", _record(data, choice))
    return store


def registry_snapshot(state: rv.FrozenValue) -> rv.FrozenValue:
    return rv.freeze(fresh_registry(state).items_of("lc-trans"))


def outgoing_stimuli(state: rv.FrozenValue) -> rv.FrozenValue:
    data = _state(state)
    return rv.freeze([_envelope(data, choice) for choice in _choices(data)])


def _directive(data: dict) -> dict:
    evidence = dict(data["result"])
    if data["requirement"] is not None and not _compensating(data):
        return {"kind": "external_authority_required", "payload": {
            "detail": data["requirement"], "evidence": evidence}}
    stage = data["stage"]
    kind, method = STAGES.to_plain()[stage][1:]
    if stage == "terminal":
        if not closed(data):
            _refuse("unsettled_terminal")
        return {"kind": kind, "payload": {"detail": "closed", "outcome": data["outcome"], "evidence": evidence}}
    # Cleanup has a single typed wait for either lane's controller authorization,
    # rather than issuing two competing physical actions in one directive.
    if stage == "cleanup":
        kind = "wait_for_observation"
    payload = {"detail": method, "evidence": evidence, "bindings": []}
    for choice in _choices(data):
        binding = _binding(data, choice["lane"], choice["stage"])
        if binding not in payload["bindings"]:
            payload["bindings"].append(binding)
    if data["action"] is not None:
        payload["action"] = dict(data["action"])
    return {"kind": kind, "payload": payload}


def legal_directive(state: rv.FrozenValue) -> rv.FrozenValue:
    return rv.freeze(_directive(_state(state)))


def reduce(state: rv.FrozenValue, stimulus: object) -> rv.FrozenValue:
    data = _state(state)
    if type(stimulus) is rv.FrozenValue:
        stimulus = stimulus.to_plain()
    if type(stimulus) is not dict:
        _refuse("invalid_stimulus")
    selected = [c for c in _choices(data) if strict_equal(stimulus, _envelope(data, c))]
    if len(selected) != 1:
        _refuse("invalid_observation")
    choice = selected[0]
    expected = _advance(data, choice)
    key = transition_id(data["result"]["case"], choice)
    record = _record(data, choice)
    store = fresh_registry(state)
    inventory = {transition_id(data["result"]["case"], c): _record(data, c) for c in _choices(data)}
    if not strict_equal(store.items_of("lc-trans"), inventory):
        _refuse("registry_view")
    actual = model.reduce({k: data[k] for k in KERNEL_KEYS}, {
        "kind": "transition_reference", "reference": key,
        "phrase": "controller:" + record["trigger"], "evidence": None}, store)
    expected_kernel = {k: expected[k] for k in KERNEL_KEYS}
    expected_directive = {"kind": "terminal_closure" if expected["phase"] == "terminal" else "wait_for_observation",
                          "payload": {"detail": "terminal" if expected["phase"] == "terminal" else expected["phase"],
                                      "evidence": {"case": data["result"]["case"], "item": key}}}
    if (type(actual) is not model.Reduction or not strict_equal(actual.transition_id, key)
            or not strict_equal(actual.successor, expected_kernel)
            or not strict_equal(actual.directive, expected_directive)):
        _refuse("provider_mismatch")
    if not strict_equal(store.items_of("lc-trans"), inventory):
        _refuse("registry_view")
    # Bind to actual accepted kernel bytes. Facts remain the independently
    # derived extension; no fabricated kernel successor replaces a bad result.
    expected.update(actual.successor)
    return rv.freeze({"successor": expected, "directive": _directive(expected), "transition_id": actual.transition_id})
