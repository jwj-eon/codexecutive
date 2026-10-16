"""Bind Issue169 cuts to actual reachable Issue166 states and observations.

Context construction and execution are pure. The graph walker checks every
current model edge before accepting the supplied registry. It emits no release
or qualification authority. The campaign owns complete union and host evidence.
"""
from __future__ import annotations

from lifecycle_conformance import explorer, failure_injection, injection_oracle, injection_sites
from lifecycle_conformance import reference_model as rm, reference_values as rv, values


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("cartesian:" + reason)


def context_for(state: rv.FrozenValue, event: dict) -> rv.FrozenValue:
    """One exact accepted observation and every applicable registered cut."""
    if type(state) is not rv.FrozenValue or type(event) is not dict:
        _refuse("context_type")
    selected = [e for e in rm.outgoing_stimuli(state).to_plain() if rv.freeze(e) == rv.freeze(event)]
    if len(selected) != 1 or event.get("outcome", "accepted") != "accepted":
        _refuse("accepted_observation")
    registry = injection_sites.site_registry()
    inventory = injection_sites.inventory(registry).to_plain()
    bound = {"state": state.to_plain(), "event": event}
    identity = "context170-" + values.canonical_digest(bound)
    applicable = {item for item, row in inventory.items()
                  if row["stage"] == event.get("stage") and row["lane"] == event.get("lane")}
    jobs = [job for job in injection_sites.schedule(registry).to_plain() if job["site"] in applicable]
    if event.get("kind") == "lifecycle_observation" and not jobs:
        _refuse("uncovered_observation")
    instances = [{"case": "inject170-" + values.canonical_digest({"context": identity, "job": job["id"]}),
                  "job": job} for job in jobs]
    return rv.freeze({"schema": "orch-dork/lifecycle-injection-context/v1", "id": identity,
                      **bound, "site_registry_sha256": injection_sites.inventory(registry).digest(),
                      "instances": instances})


def execute_context(context: rv.FrozenValue) -> rv.FrozenValue:
    """Execute and independently verify every cut at this complete observation."""
    if type(context) is not rv.FrozenValue:
        _refuse("context_type")
    data = context.to_plain()
    if type(data) is not dict or "state" not in data or "event" not in data:
        _refuse("context_shape")
    state = rv.freeze(data["state"])
    if context_for(state, data["event"]) != context:
        _refuse("context_binding")
    registry = injection_sites.site_registry()
    rows = []
    for instance in data["instances"]:
        job = instance["job"]
        trace = failure_injection.run_case(registry, job, state, data["event"])
        proof = injection_oracle.verify_trace(registry, trace).to_plain()
        rows.append({"case": instance["case"], "context": data["id"], "base_case": job["id"],
                     "site": job["site"], "failure": job["failure"], "timing": job["timing"],
                     "proof": proof})
    return rv.freeze({"schema": "orch-dork/lifecycle-injection-context-result/v1", "status": "PASS",
                      "context": data["id"], "context_sha256": context.digest(), "cases": rows,
                      "physical_dispatches": 0, "qualification_authorized": False})


def walk_contexts(graph: explorer.Exploration):
    """Walk all current model edges and bind every accepted observation.

    The caller must exhaust the iterator. A prefix is never complete coverage.
    Readiness observations have no registered mutation/action cut and remain
    explicit zero-instance contexts for the production/model integration.
    """
    if type(graph) is not explorer.Exploration:
        _refuse("graph_type")
    registry = graph.registry.to_plain()
    if set(registry) != {"lc-state", "lc-trans"}:
        _refuse("graph_registry")
    state_rows, edge_rows = registry["lc-state"], registry["lc-trans"]
    outgoing = {key: {} for key in state_rows}
    for key, row in edge_rows.items():
        if row["source_state"] not in outgoing or row["target_state"] not in state_rows:
            _refuse("graph_edge")
        choice = values.canonical_json(row["choice"])
        if choice in outgoing[row["source_state"]]:
            _refuse("graph_ambiguity")
        outgoing[row["source_state"]][choice] = (key, row)
    pending, seen, walked = [rm.initial_state(explorer.GRAPH_CASE)], set(), set()
    while pending:
        state = pending.pop()
        key = explorer.state_identity(state)
        if key in seen:
            continue
        seen.add(key)
        plain = state.to_plain()
        directive = rm.legal_directive(state).to_plain()
        expected_state = {"phase": plain["phase"], "state_digest": state.digest(),
                          "stage": plain.get("stage", "activate" if plain["generation"] == 3 else plain["phase"]),
                          "directive_kind": directive["kind"]}
        if key not in state_rows or rv.freeze(state_rows[key]) != rv.freeze(expected_state):
            _refuse("graph_state")
        actual = rm.outgoing_stimuli(state).to_plain()
        if {values.canonical_json(explorer.abstract_event(e)) for e in actual} != set(outgoing[key]):
            _refuse("graph_outgoing")
        accepted = []
        model_registry = rm.registry_snapshot(state).to_plain()
        for event in actual:
            edge_key, row = outgoing[key][values.canonical_json(explorer.abstract_event(event))]
            result = rm.reduce(state, event).to_plain()
            successor = rv.freeze(result["successor"])
            target = explorer.state_identity(successor)
            transition = model_registry[event["transition"]]
            expected_edge = {"from": plain["phase"], "to": successor.to_plain()["phase"],
                             "trigger": transition["trigger"], "source_state": key, "target_state": target,
                             "model_transition": event["transition"], "choice": explorer.abstract_event(event)}
            expected_id = "lc-trans:issue-166:" + values.canonical_digest(
                {"from": key, "choice": explorer.abstract_event(event), "to": target})
            if (edge_key != expected_id or rv.freeze(row) != rv.freeze(expected_edge)
                    or rv.freeze(result["directive"]) != rm.legal_directive(successor)):
                _refuse("graph_successor")
            walked.add(edge_key)
            pending.append(successor)
            if event.get("outcome", "accepted") == "accepted":
                accepted.append(event)
        for event in accepted:
            yield context_for(state, event)
    if seen != set(state_rows) or walked != set(edge_rows):
        _refuse("graph_closure")
