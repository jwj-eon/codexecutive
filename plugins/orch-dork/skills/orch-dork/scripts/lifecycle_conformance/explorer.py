"""Exhaustive serial traces and coverage over the public two-lane model.

Model generation has no environment, provider, clock or filesystem inputs.
Optional POSIX CPU workers change scheduling only; an outer host must bound
their process group and observe cleanup, as for the interruption matrix.
The optional CLI writes only the explicitly selected coverage artifact. Shards
filter the very same content-derived case inventory; they never change choices.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import ProcessPoolExecutor
from contextlib import nullcontext
from dataclasses import dataclass
import argparse
import json
import multiprocessing
import os
from pathlib import Path
import threading

from lifecycle_conformance import fragment, injection_oracle, protocol, reference_model as rm, reference_values as rv, registries, values

GRAPH_CASE = "graph-166"
OWNER = "issue-166"
# The frozen model census has 1,063,381 states and 1,915,996 complete paths.
# These are finite safety ceilings, not expected counts or coverage evidence.
MAX_STATES = 1_100_000
MAX_CASES = 2_000_000
MAX_DEPTH = 32


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("explorer:" + reason)


def abstract_event(stimulus: dict) -> dict:
    if stimulus["kind"] == "transition_reference":
        return {"target": stimulus["target"]}
    return {key: stimulus[key] for key in ("stage", "lane", "outcome", "variant")}


def case_identity(choices: list[dict]) -> str:
    """Hash abstract choices BEFORE binding the result into case envelopes."""
    return "c166-" + values.canonical_digest({"schema": "orch-dork/lifecycle-case/v1", "choices": choices})


def state_identity(state: rv.FrozenValue) -> str:
    """Rich-state identity; kernel generation alone conflates lane histories."""
    return "lc-state:" + OWNER + ":" + state.digest()


def edge_identity(before: str, stimulus: dict, after: str) -> str:
    """Content identity shared by exhaustive and production-observed edges."""
    return "lc-trans:" + OWNER + ":" + values.canonical_digest(
        {"from": before, "choice": abstract_event(stimulus), "to": after})


def _edge_identity(before: str, stimulus: dict, after: str) -> str:
    """Compatibility alias for historical callers of the private helper."""
    return edge_identity(before, stimulus, after)


def _enabled_registry(state: rv.FrozenValue, registry: dict) -> set[str]:
    plain = state.to_plain()
    if plain["generation"] >= 3:
        return set(registry)
    if set(registry) != {rm.transition_id(plain["result"]["case"], target) for target in rm.TARGETS}:
        _refuse("undeclared_or_missing_edge")
    ready = plain["readiness"]
    targets = (["shared"] if not ready["shared"] else [lane for lane in rm.LANES if not ready["lanes"][lane]])
    return {rm.transition_id(plain["result"]["case"], target) for target in targets}


@dataclass(frozen=True)
class Exploration:
    """Detached immutable report, registries and case paths; no mutable stores."""
    report: rv.FrozenValue
    registry: rv.FrozenValue
    cases: rv.FrozenValue
    events: rv.FrozenValue
    coverage: rv.FrozenValue

    def choices(self, case_id: str) -> list[dict]:
        events = self.events.to_plain()
        return [events[index] for index in self.cases.to_plain()[case_id]]

    def store(self) -> registries.RegistryStore:
        store = registries.RegistryStore()
        for kind, entries in self.registry.to_plain().items():
            for key, record in entries.items():
                store.add(kind, key, OWNER, record)
        return store


def _expand_state(plain: dict) -> tuple:
    """Check one public model state and every outgoing edge before returning."""
    state = rv.freeze(plain)
    key = state_identity(state)
    stage = plain.get("stage", "activate" if plain["generation"] == 3 else plain["phase"])
    directive = rm.legal_directive(state).to_plain()
    state_record = {"phase": plain["phase"], "state_digest": state.digest(),
                    "stage": stage, "directive_kind": directive["kind"]}
    outgoing = rm.outgoing_stimuli(state).to_plain()
    registry = rm.registry_snapshot(state).to_plain()
    if {x["transition"] for x in outgoing} != _enabled_registry(state, registry):
        _refuse("undeclared_or_missing_edge")
    if not outgoing and directive["kind"] not in ("terminal_closure", "external_authority_required"):
        _refuse("unexpected_dead_end")
    if outgoing and directive["kind"] == "terminal_closure":
        _refuse("closed_state_has_edges")
    if directive["kind"] == "external_authority_required":
        requirement = directive["payload"]["detail"]
        if (type(requirement) is not dict or requirement.get("stage") not in protocol.STAGES.to_plain()
                or not requirement.get("evidence") or not requirement.get("authority")):
            _refuse("unexplained_external_requirement")
        if outgoing:
            # External quality evidence may coexist with finite physical
            # release. Check its exact scope independently before traversal.
            injection_oracle.state_invariants(state, directive)
    edges, seen = [], set()
    for event in outgoing:
        choice = abstract_event(event)
        choice_key = values.canonical_json(choice)
        if choice_key in seen:
            _refuse("ambiguous_edge")
        seen.add(choice_key)
        result = rm.reduce(state, event).to_plain()
        successor = rv.freeze(result["successor"])
        target = state_identity(successor)
        record = registry.get(event["transition"])
        if (type(record) is not dict or result["transition_id"] != event["transition"]
                or record["from"] != plain["phase"] or record["to"] != result["successor"]["phase"]
                or result["directive"] != rm.legal_directive(successor).to_plain()
                or result["successor"]["generation"] != plain["generation"] + 1):
            _refuse("registry_successor_mismatch")
        edge_id = _edge_identity(key, event, target)
        edge_record = {"from": record["from"], "to": record["to"], "trigger": record["trigger"],
                       "source_state": key, "target_state": target,
                       "model_transition": event["transition"], "choice": choice}
        edges.append((edge_id, edge_record, result["successor"], event.get("outcome", "accepted")))
    return key, state_record, edges


def explore(*, workers: int = 1) -> Exploration:
    """Enumerate every public outgoing edge and every complete causal path.

    Graph memoization shares computation at identical states; it does not omit
    paths. Both prefixes through a converged readiness state are still walked.
    No permutation is reduced, so the equivalence-witness inventory is empty.
    With multiple workers, only independent state expansions run concurrently.
    Canonical case construction and coverage validation remain in the caller.
    The pool is joined on success and failure; the caller owns the host deadline.
    """
    if type(workers) is not int or not 1 <= workers <= 16:
        _refuse("workers")
    if workers > 1 and (os.name != "posix" or threading.active_count() != 1):
        _refuse("fork_host")
    initial = rm.initial_state(GRAPH_CASE)
    states: set[str] = set()
    adjacency: dict[str, list[tuple[dict, str, str]]] = {}
    store = registries.RegistryStore()
    stages, observed_classes = set(), set()
    pending = [initial.to_plain()]
    execution = (nullcontext(None) if workers == 1 else
                 ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("fork")))
    with execution as pool:
        while pending:
            batch = []
            while pending and len(batch) < (1 if pool is None else workers * 32):
                plain = pending.pop()
                key = state_identity(rv.freeze(plain))
                if key in states:
                    continue
                if len(states) >= MAX_STATES:
                    _refuse("state_bound")
                states.add(key)
                batch.append(plain)
            expanded = (map(_expand_state, batch) if pool is None else
                        pool.map(_expand_state, batch, chunksize=8))
            for key, state_record, edges in expanded:
                store.add("lc-state", key, OWNER, state_record)
                stages.add(state_record["stage"])
                adjacency[key] = []
                for edge_id, record, successor, observation in edges:
                    store.add("lc-trans", edge_id, OWNER, record)
                    adjacency[key].append((record["choice"], record["target_state"], edge_id))
                    observed_classes.add(observation)
                    pending.append(successor)
    if not set(protocol.STAGES.to_plain()).issubset(stages):
        _refuse("unreachable_declared_stage")
    if observed_classes != set(values.OBSERVATION_CLASSES) - set(protocol.REFUSALS):
        _refuse("missing_observation_class")
    # Complete serial paths, including both paths through any shared node.
    # Pack each case as integer indexes into a canonical event vocabulary;
    # long repeated histories must not inflate the immutable JSON catalogue.
    event_keys = sorted({values.canonical_json(choice) for edges in adjacency.values() for choice, _, _ in edges})
    events = [json.loads(key) for key in event_keys]
    event_indexes = {key: index for index, key in enumerate(event_keys)}
    cases, witnesses = {}, {}
    def visit(key: str, choices: list[dict], items: list[str]) -> None:
        if len(choices) > MAX_DEPTH:
            _refuse("depth_bound")
        if adjacency[key]:
            for choice, target, edge in adjacency[key]:
                visit(target, choices + [choice], items + [edge, target])
            return
        if len(cases) >= MAX_CASES:
            _refuse("case_bound")
        case = case_identity(choices)
        if case in cases:
            _refuse("case_collision")
        cases[case] = [event_indexes[values.canonical_json(choice)] for choice in choices]
        for item in items:
            witnesses.setdefault(item, case)
    visit(state_identity(initial), [], [state_identity(initial)])
    declared = {key for kind in store.kinds() for key in store.items_of(kind)}
    if set(witnesses) != declared:
        _refuse("unexplained_coverage_gap")
    # One direct trace witness per item is enough for the fragment. The full
    # case inventory independently retains every permutation and outcome path.
    grouped: dict[str, list[str]] = {}
    for key, case in sorted(witnesses.items()):
        grouped.setdefault(case, []).append(key)
    entries = [{"id": ids, "status": "covered", "cases": [{"id": case, "strength": "direct"}], "rationale": ""}
               for case, ids in sorted(grouped.items())]
    coverage = fragment.build_fragment(OWNER, values.vocabulary_digest(), store.digest(), entries)
    validate_coverage(coverage, store, cases, events)
    report = {"schema": "orch-dork/lifecycle-exploration/v1", "states": len(states),
              "transitions": sum(len(e) for e in adjacency.values()), "cases": len(cases),
              "stages": sorted(stages), "observation_classes": sorted(observed_classes),
              "refused_observation_classes": list(protocol.REFUSALS),
              "permutation_reduction": "none", "equivalence_witnesses": [],
              "case_inventory_digest": values.canonical_digest(sorted(cases)),
              "registry_digest": store.digest(), "coverage_digest": values.canonical_digest(coverage)}
    return Exploration(rv.freeze(report), rv.freeze({kind: store.items_of(kind) for kind in store.kinds() if store.items_of(kind)}),
                       rv.freeze(cases), rv.freeze(events), rv.freeze(coverage))


def _causal_path_count(outgoing: dict, root: str) -> int:
    """Count paths through the complete DAG, including converged prefixes."""
    incoming = dict.fromkeys(outgoing, 0)
    for choices in outgoing.values():
        for _, target in choices.values():
            incoming[target] += 1
    pending = deque([root])
    paths, depths = {root: 1}, {root: 0}
    visited = total = 0
    while pending:
        source = pending.popleft()
        visited += 1
        if depths[source] > MAX_DEPTH:
            _refuse("depth_bound")
        if not outgoing[source]:
            total += paths[source]
            if total > MAX_CASES:
                _refuse("case_bound")
        for _, target in outgoing[source].values():
            paths[target] = paths.get(target, 0) + paths[source]
            depths[target] = max(depths.get(target, 0), depths[source] + 1)
            incoming[target] -= 1
            if incoming[target] == 0:
                pending.append(target)
    if visited != len(outgoing):
        _refuse("cyclic_or_unreachable_graph")
    return total


def validate_coverage(coverage: dict, store: registries.RegistryStore, cases: dict[str, list[int]], events: list[dict]) -> None:
    """Foundation shape validation PLUS exact registry and causal witness closure."""
    fragment.validate_fragment(coverage, owner=OWNER, store=store)
    if coverage["digests"]["vocab"] != values.vocabulary_digest():
        _refuse("vocabulary_drift")
    states, edges = store.items_of("lc-state"), store.items_of("lc-trans")
    declared = {key for kind in store.kinds() for key in store.items_of(kind)}
    outgoing: dict[str, dict[str, tuple[str, str]]] = {key: {} for key in states}
    targets = set()
    for edge_id, edge in edges.items():
        source, target = edge["source_state"], edge["target_state"]
        if (source not in states or target not in states or edge["from"] != states[source]["phase"]
                or edge["to"] != states[target]["phase"]):
            _refuse("registry_successor_mismatch")
        choice = values.canonical_json(edge["choice"])
        if choice in outgoing[source]:
            _refuse("ambiguous_edge")
        outgoing[source][choice] = (edge_id, target)
        targets.add(target)
    roots = set(states) - targets
    if len(roots) != 1:
        _refuse("ambiguous_root")
    root = next(iter(roots))
    expected_cases = _causal_path_count(outgoing, root)
    witnessed: dict[str, set[str]] = {}
    for case_id, indexes in cases.items():
        if any(type(index) is not int or not 0 <= index < len(events) for index in indexes):
            _refuse("invalid_event_index")
        choices = [events[index] for index in indexes]
        if case_id != case_identity(choices):
            _refuse("case_identity_mismatch")
        current, seen = root, {root}
        for choice in choices:
            edge = outgoing[current].get(values.canonical_json(choice))
            if edge is None:
                _refuse("illegal_case_order")
            edge_id, current = edge
            seen.update((edge_id, current))
        if outgoing[current] or states[current]["directive_kind"] not in ("terminal_closure", "external_authority_required"):
            _refuse("incomplete_case")
        witnessed[case_id] = seen
    if set().union(*witnessed.values()) != declared:
        _refuse("unexplained_coverage_gap")
    # Every supplied case is content-addressed, legal and complete. Equality
    # with the independently counted path total proves no complete path is
    # omitted, even when the remaining cases still witness every graph item.
    if len(cases) != expected_cases:
        _refuse("missing_causal_case")
    covered = set()
    for entry in coverage["entries"]:
        if entry["status"] != "covered" or not entry["cases"] or entry["rationale"]:
            _refuse("unexplained_coverage_gap")
        if any(case["id"] not in witnessed or case["strength"] != "direct" for case in entry["cases"]):
            _refuse("unknown_case_witness")
        supporting = set().union(*(witnessed[case["id"]] for case in entry["cases"]))
        if not set(entry["id"]).issubset(supporting):
            _refuse("unrelated_case_witness")
        covered.update(entry["id"])
    if covered != declared:
        _refuse("unexplained_coverage_gap")


def shard_cases(exploration: Exploration, index: int, count: int) -> rv.FrozenValue:
    if type(index) is not int or type(count) is not int or count < 1 or not 0 <= index < count:
        _refuse("invalid_shard")
    return rv.freeze({key: path for key, path in exploration.cases.to_plain().items()
                      if int(key.removeprefix("c166-"), 16) % count == index})


def replay(case_id: str, choices: list[dict]) -> rv.FrozenValue:
    """Each case starts in fresh immutable state; every observation is serial."""
    if case_id != case_identity(choices):
        _refuse("case_identity_mismatch")
    state = rm.initial_state(case_id)
    trace = []
    for choice in choices:
        matching = [x for x in rm.outgoing_stimuli(state).to_plain() if protocol.strict_equal(abstract_event(x), choice)]
        if len(matching) != 1:
            _refuse("illegal_case_order")
        result = rm.reduce(state, matching[0]).to_plain()
        state = rv.freeze(result["successor"])
        trace.append({"state": state.digest(), "directive": result["directive"], "transition": result["transition_id"]})
    if rm.outgoing_stimuli(state).to_plain():
        _refuse("incomplete_case")
    return rv.freeze({"case": case_id, "trace": trace, "terminal": state.to_plain(),
                      "directive": rm.legal_directive(state).to_plain()})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-coverage", type=Path)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    result = explore(workers=args.workers)
    if args.write_coverage:
        args.write_coverage.parent.mkdir(parents=True, exist_ok=True)
        args.write_coverage.write_text(values.canonical_json(result.coverage.to_plain()) + "\n", encoding="utf-8")
    print(json.dumps(result.report.to_plain(), sort_keys=True))


if __name__ == "__main__":
    main()
