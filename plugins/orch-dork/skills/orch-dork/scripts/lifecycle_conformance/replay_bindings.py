"""Execute historical choices under the live graph identity without rewriting history.

This join validates every graph record it touches. The executing campaign still
owns exhaustive graph validation and production coverage; this report supplies
neither qualification authority nor evidence of an old host execution.
"""
from __future__ import annotations

from lifecycle_conformance import explorer, replays, reference_model as rm
from lifecycle_conformance import reference_values as rv, values


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("replay_bindings:" + reason)


def _state_record(state: rv.FrozenValue) -> dict:
    plain = state.to_plain()
    return {"phase": plain["phase"], "state_digest": state.digest(),
            "stage": plain.get("stage", "activate" if plain["generation"] == 3 else plain["phase"]),
            "directive_kind": rm.legal_directive(state).to_plain()["kind"]}


def bind(graph_registry: rv.FrozenValue, corpus: rv.FrozenValue, *, legacy_bytes: bytes) -> rv.FrozenValue:
    """Replay all 36 pinned histories and bind exact current state/edge records.

No caller-supplied replay receipt is trusted. The original replay runs again,
then the same choices run independently with the explorer's graph case identity.
Historical refused attempts retain their original verdicts and identifiers.
"""
    if type(graph_registry) is not rv.FrozenValue or type(corpus) is not rv.FrozenValue:
        _refuse("input_type")
    graph = graph_registry.to_plain()
    if (type(graph) is not dict or set(graph) != {"lc-state", "lc-trans"}
            or any(type(rows) is not dict for rows in graph.values())):
        _refuse("graph_shape")
    historical = replays.replay(corpus, legacy_bytes=legacy_bytes)
    results = {row["case_id"]: row for row in historical["cycles"]}
    bindings = []
    for row in corpus.to_plain()["cycles"]:
        state = rm.initial_state(explorer.GRAPH_CASE)
        visited, edges = [], []

        def visit(value):
            identity = explorer.state_identity(value)
            if rv.freeze(graph["lc-state"].get(identity)) != rv.freeze(_state_record(value)):
                _refuse("state_binding")
            visited.append(identity)
            return identity

        source = visit(state)
        for choice in row["normalized"]["choices"]:
            candidates = [event for event in rm.outgoing_stimuli(state).to_plain()
                          if rv.freeze(explorer.abstract_event(event)) == rv.freeze(choice)]
            if len(candidates) != 1:
                _refuse("choice_binding")
            event = candidates[0]
            transition = rm.registry_snapshot(state).to_plain()[event["transition"]]
            reduced = rm.reduce(state, event).to_plain()
            successor = rv.freeze(reduced["successor"])
            target = visit(successor)
            identity = "lc-trans:issue-166:" + values.canonical_digest(
                {"from": source, "choice": choice, "to": target})
            expected = {"from": state.to_plain()["phase"], "to": successor.to_plain()["phase"],
                        "trigger": transition["trigger"], "source_state": source, "target_state": target,
                        "model_transition": event["transition"], "choice": choice}
            if (rv.freeze(graph["lc-trans"].get(identity)) != rv.freeze(expected)
                    or rv.freeze(reduced["directive"]) != rm.legal_directive(successor)):
                _refuse("transition_binding")
            edges.append(identity)
            state, source = successor, target
        mode = row["normalized"]["mode"]
        if mode == "guard_refusal":
            before = state.digest()
            event = rm.outgoing_stimuli(state).to_plain()[0]
            event["unadmitted_historical_observation"] = row["failure"]["code"]
            try:
                rm.reduce(state, event)
            except values.LifecycleContractError:
                pass
            else:
                _refuse("guard_accepted")
            if state.digest() != before:
                _refuse("guard_mutated")
        elif not edges:
            _refuse("missing_transition")
        original = results[row["case_id"]]
        bindings.append({"replay": "lc-replay:issue-167:" + row["case_id"],
                         "historical_mapping": original["mapping"],
                         "historical_result_sha256": values.canonical_digest(original),
                         "kind": mode, "states": visited, "transitions": edges,
                         "target": source if mode == "guard_refusal" else edges[-1],
                         "final_state_sha256": state.digest(),
                         "final_directive_sha256": rm.legal_directive(state).digest()})
    return rv.freeze({"schema": "orch-dork/historical-graph-bindings/v1", "status": "PASS",
                      "graph_registry_sha256": graph_registry.digest(),
                      "historical_report_sha256": values.canonical_digest(historical),
                      "bindings": bindings, "historical_report": historical,
                      "boundary": {"touched_graph_records_only": True,
                                   "original_host_validator_reexecuted": False,
                                   "qualification_authorized": False}})
