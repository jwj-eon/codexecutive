"""Independent trace, exactly-once and resource-closure checks for Issue 169.

The oracle replays actual public model transitions and compares whole values.
It does not call the injector or trust its counts, digests, directive or verdict.
"""
from __future__ import annotations

from lifecycle_conformance import injection_sites as sites, reference_model as rm
from lifecycle_conformance import reference_values as rv, values

FIELDS = {"schema", "job", "initial", "event", "guard_refusal", "cut", "effects",
          "reconciled", "journal", "final", "directive"}


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise values.LifecycleContractError("injection_oracle:" + reason)


def _same(left: object, right: object) -> bool:
    return rv.freeze(left) == rv.freeze(right)


def _typed_requirement(requirement: object) -> None:
    """Check a bounded, lossless chain of outstanding observation obligations."""
    fields = {"stage", "lane", "observation", "authority", "evidence"}
    for _ in range(40):
        _require(type(requirement) is dict and set(requirement) in
                 (fields, fields | {"prior_requirements"}), "typed_requirement")
        _require(all(type(requirement[key]) is str and requirement[key] for key in fields), "typed_requirement")
        _require(requirement["authority"] == "independent_host_observer" and requirement["evidence"] ==
                 "resolve:" + ":".join(requirement[key] for key in ("stage", "lane", "observation")), "typed_requirement")
        if "prior_requirements" not in requirement:
            return
        prior = requirement["prior_requirements"]
        _require(type(prior) is list and len(prior) == 1, "typed_requirement")
        requirement = prior[0]
    _require(False, "typed_requirement")


def _external_release_obligations(data: dict, events: list) -> None:
    """Independently limit a review barrier to one exact resource observation."""
    requirement = data['requirement']
    eligible = (data.get('stage') == requirement['stage'] == 'review'
                and data.get('action') is None and data.get('capacity_settlement') == 'pending'
                and all(row['creation'] == 'created' and row['continuation'] != 'none'
                        for row in data['lanes'].values())
                and all(status in ('settled', 'released') for status in data['grants'].values()))
    if not eligible:
        _require(events == [], 'external_nonterminal')
        return
    case, generation = data['result']['case'], data['generation']
    proof = {'schema': 'orch-dork/lifecycle-sealed-release-observation/v1',
             'case': case, 'observer': 'independent',
             'lanes': [{'lane': lane, 'worker_id': data['lanes'][lane]['worker_id'],
                        'spawn_action': data['lanes'][lane]['spawn_action'], 'route': 'native',
                        'terminal_state': 'completed', 'cleanup': 'complete', 'owned_descendants': 0}
                       for lane in ('spec', 'standards')]}
    expected = {'case': case, 'generation': generation, 'owner': data['controller']['owner'],
                'cursor': data['controller']['cursor'], 'stage': 'settle', 'lane': 'controller',
                'action_id': f'observation:{case}:{generation}:settle:controller', 'grant_id': 'none',
                'kind': 'lifecycle_observation', 'transition': f'lc-trans:{case}:settle.controller.accepted.sealed_release',
                'outcome': 'accepted', 'variant': 'sealed_release', 'acknowledgement': 'NOT_APPLICABLE',
                'proof': proof}
    _require(_same(events, [expected]), 'review_barrier_release_scope')


def _semantic_review_invariants(data: dict, directive: dict) -> None:
    """Check the semantic join independently of the model's stage table/replay."""
    if "aggregation" not in data:
        return
    history = data["history"]
    aggregates = [i for i, event in enumerate(history)
                  if event["stage"] == "aggregate" and event["outcome"] == "accepted"]
    reviews = [i for i, event in enumerate(history) if event["stage"] == "review"]
    accepted_reviews = [i for i in reviews if history[i]["outcome"] == "accepted"]
    _require(len(aggregates) <= 1 and len(reviews) <= 1
             and (data["aggregation"] == "accepted") == bool(aggregates)
             and (data["sol_review"] == "accepted") == bool(accepted_reviews)
             and all(aggregates and aggregates[0] < i for i in reviews), "semantic_review_order")
    if data["stage"] == "review":
        _require(data["aggregation"] == "accepted" and data["sol_review"] == "pending",
                 "semantic_review_order")
    if data["stage"] == "verify" and data["outcome"] == "success":
        _require(data["aggregation"] == data["sol_review"] == "accepted", "semantic_review_order")

    # These are the protocol's physical/owner grant scopes, written independently
    # of STAGES. A semantic review can never add even a settled/released grant.
    scopes = {"grant.spec:spec", "grant.standards:standards", "continue.spec:spec",
              "continue.standards:standards", "close.spec:spec", "close.standards:standards",
              "rotate:controller"}
    grant_scopes = [":".join(key.split(":")[-2:]) for key in data["grants"]]
    _require(all(scope in scopes for scope in grant_scopes)
             and (data["action"] is None or data["action"].get("method") != "sol_review"),
             "semantic_review_authority")
    if data["stage"] in ("aggregate", "review"):
        continuations = 2 if data["progress_admission"] == "accepted" else 1
        expected_counts = {"grant.spec:spec": 1, "grant.standards:standards": 1,
                           "continue.spec:spec": continuations, "continue.standards:standards": continuations}
        _require(data["action"] is None and "action" not in directive["payload"]
                 and {scope: grant_scopes.count(scope) for scope in grant_scopes} == expected_counts
                 and all(status in ("settled", "released") for status in data["grants"].values()),
                 "semantic_review_authority")
        if data["requirement"] is None:
            _require(directive["kind"] == "wait_for_observation"
                     and directive["payload"]["detail"] == (
                         "sol_review" if data["stage"] == "review" else "aggregate")
                     and all(binding["grant_id"] == "none"
                             for binding in directive["payload"]["bindings"]), "semantic_review_authority")


def _final_gate_invariants(data: dict, directive: dict) -> None:
    """Final proofs and their durable boundaries cannot be hidden by the model."""
    if "lanes" not in data:
        return
    stages = ("final_qualification", "failure_closure")
    history = data["history"]
    events = [(index, event) for index, event in enumerate(history) if event["stage"] in stages]
    accepted = [(index, event) for index, event in events if event["outcome"] == "accepted"]
    proof = data.get("attempt_closure")
    _require(len(events) <= 1 and (proof is not None) == bool(accepted), "final_gate_history")
    if accepted:
        index, event = accepted[0]
        prior_failed = any(row["outcome"] in ("refused", "failed", "interrupted_before", "not_dispatched") for row in history[:index])
        budget_failed = event["variant"] == "verified_budget_failure"
        _require(not budget_failed or (event["stage"] == "final_qualification" and not prior_failed), "budget_failure_boundary")
        failed = prior_failed or budget_failed
        kind = "failure_closure" if failed else "final_qualification"
        checks = (["verified_failure", "grant_settlement", "lane_cleanup", "process_group", "capacity_settlement", "owner_identity"]
                  if failed else ["wave_v3_terminal", "typed_terminal_contracts", "independent_attempt_observer",
                                  "run_trace", "coordinator_capsule", "dogfood_spine", "shared_capacity_settlement"])
        _require(event["stage"] == ("final_qualification" if budget_failed else kind) and _same(proof, {
            "status": "PASS", "scope": kind, "outcome": "failure" if failed else "success",
            "case": data["result"]["case"], "owner": data["controller"]["owner"],
            "observer": "independent", "checks": checks}), "final_gate_proof")
        _require(all(any(row["stage"] == stage and row["outcome"] == "accepted" for row in history[:index])
                     for stage in ("verify", "settle")), "final_gate_order")
    if data["stage"] in (*stages, "rotate", "terminal"):
        _require(data["terminal_verification"] == "accepted"
                 and data["capacity_settlement"] == "released" and data["process_group"] == "zero_owned_descendants"
                 and all(row["capacity"] == "released" and row["cleanup"] in ("closed", "not_required")
                         for row in data["lanes"].values()), "final_gate_resources")
    if data["stage"] in ("rotate", "terminal"):
        _require(proof is not None, "final_gate_before_rotation")
    if data["stage"] in stages:
        _require(proof is None and data["action"] is None and all(status == "released" for status in data["grants"].values())
                 and data["controller"]["owner_disposition"] == "retained"
                 and data["controller"]["successor_owner"] is None, "final_gate_authority")
        if data["requirement"] is None:
            _require(data["stage"] == ("final_qualification" if data["outcome"] == "success" else "failure_closure")
                     and directive["kind"] == "wait_for_observation" and "action" not in directive["payload"]
                     and all(binding["grant_id"] == "none" for binding in directive["payload"]["bindings"]), "final_gate_authority")


def _capacity_history_invariants(data: dict) -> None:
    """Recompute retained capacity without trusting the reducer's lane facts."""
    if "grants" not in data:
        return
    expected = {"spec": "none", "standards": "none"}
    for event in data["history"]:
        stage, outcome, variant = event["stage"], event["outcome"], event["variant"]
        if variant == "capacity_reserved":
            _require(stage == "grant.spec" and outcome == "refused", "capacity_history")
        if stage == "grant.spec" and (outcome == "accepted" or variant == "capacity_reserved"):
            expected = {"spec": "reserved", "standards": "reserved"}
        elif stage in ("spawn.spec", "spawn.standards") and outcome == "accepted":
            expected[event["lane"]] = "occupied"
        elif stage == "settle" and outcome == "accepted":
            expected = {"spec": "released", "standards": "released"}
    _require(_same({lane: row["capacity"] for lane, row in data["lanes"].items()}, expected), "capacity_history")


def state_invariants(state: rv.FrozenValue, directive: dict) -> rv.FrozenValue:
    """Every state has one exact directive; terminal closure discharges all resources."""
    expected = rm.legal_directive(state).to_plain()
    _require(_same(directive, expected), "exact_directive")
    data = state.to_plain()
    kind = directive["kind"]
    for lane, row in data.get("lanes", {}).items():
        checkpoint = row["checkpoint"]
        if checkpoint is not None:
            _require(row["checkpoint_continuation"] is not None and _same(checkpoint, {
                "schema": "orch-dork/lifecycle-worker-progress/v1", "case": data["result"]["case"],
                "lane": lane, "action_id": row["checkpoint_continuation"], "sequence": 1, "status": "PASS",
            }), "checkpoint_binding")
        proof = row["typed_result"]
        if proof is not None:
            _require(row["continuation"] != "none" and _same(proof, {
                "schema": "orch-dork/lifecycle-typed-result/v1", "case": data["result"]["case"],
                "lane": lane, "action_id": row["continuation"], "status": "PASS",
            }), "typed_result_binding")
    if data.get("progress_admission") in ("accepted", "stopped") or data.get("stage") == "progress":
        _require(all(row["checkpoint"] is not None for row in data["lanes"].values()), "progress_obligations")
    if data.get("progress_admission") == "accepted":
        _require(all(row["continuation"] == "none" or row["continuation"] != row["checkpoint_continuation"]
                     for row in data["lanes"].values()), "distinct_final_continuation")
    if any(row["capacity"] == "released" for row in data.get("lanes", {}).values()):
        _require(data["capacity_settlement"] == "released"
                 and data["process_group"] == "zero_owned_descendants"
                 and all(row["capacity"] == "released" and row["cleanup"] in ("closed", "not_required")
                         for row in data["lanes"].values()), "released_resources")
    if data.get("aggregation") == "accepted":
        _require(all(row["typed_result"] is not None for row in data["lanes"].values()), "result_obligations")
    _semantic_review_invariants(data, directive)
    _final_gate_invariants(data, directive)
    _capacity_history_invariants(data)
    if kind == "terminal_closure":
        _require(data.get("stage") == "terminal" and data.get("requirement") is None, "terminal_state")
        _require(data["action"] is None and all(v == "released" for v in data["grants"].values()), "grant_closure")
        _require(all(l["capacity"] == "released" and l["cleanup"] in ("closed", "not_required")
                     for l in data["lanes"].values()), "lane_closure")
        _require(data["process_group"] == "zero_owned_descendants", "process_closure")
        _require(data["terminal_verification"] == "accepted" and data["capacity_settlement"] == "released", "verification_closure")
        owner = data["controller"]
        _require(owner["active"] is False and owner["owner_disposition"] == "rotated"
                 and owner["successor_owner"] == "root:" + data["result"]["case"] + ":successor", "owner_closure")
        _require(not rm.outgoing_stimuli(state).to_plain(), "closed_successor")
    elif kind == "external_authority_required":
        _typed_requirement(data.get("requirement"))
        _require(data.get("stage") != "terminal", "external_nonterminal")
        _external_release_obligations(data, rm.outgoing_stimuli(state).to_plain())
    else:
        _require(kind in ("action", "wait_for_observation") and bool(rm.outgoing_stimuli(state).to_plain()), "next_observation")
    return rv.freeze({"directive_sha256": values.canonical_digest(expected), "kind": kind,
                      "terminal": kind == "terminal_closure", "resource_claim": "closed" if kind == "terminal_closure" else "retained"})


def verify_trace(store: object, trace: rv.FrozenValue) -> rv.FrozenValue:
    """Reject gaps, extra effects, stale observations, forged closure and changed bytes."""
    _require(type(trace) is rv.FrozenValue, "trace_type")
    data = trace.to_plain()
    _require(type(data) is dict and set(data) == FIELDS and data["schema"] == "orch-dork/lifecycle-injection-trace/v1", "trace_shape")
    job, initial = data["job"], rv.freeze(data["initial"])
    site = sites.validate_job(store, job)
    event = data["event"]
    _require(type(event) is dict and event.get("stage") == site["stage"] and event.get("lane") == site["lane"]
             and event.get("outcome") == "accepted", "site_binding")
    _require(sum(_same(e, event) for e in rm.outgoing_stimuli(initial).to_plain()) == 1, "legal_successor")
    after, durable = job["timing"] == "after", job["site"].startswith("lc-mut:")
    journal = data["journal"]
    _require(type(journal) is list and len(journal) <= 40, "journal_bound")
    if not journal:
        # Independently recognize only an unconsumed sealed release at the
        # already retained review barrier. All other cuts require a journal.
        facts = initial.to_plain()
        _require(not after and durable and facts.get('stage') == 'review'
                 and type(facts.get('requirement')) is dict
                 and facts['requirement'].get('stage') == 'review'
                 and event['stage'] == 'settle' and event['lane'] == 'controller'
                 and event.get('variant') == 'sealed_release'
                 and _same(rm.outgoing_stimuli(initial).to_plain(), [event]), 'empty_journal_scope')
        _require(state_invariants(initial, data['directive']).to_plain()['kind']
                 == 'external_authority_required', 'empty_journal_barrier')
        _require(_same(data['reconciled'], data['initial']), 'reconciliation')
    first_phase = "effect" if after and durable else "reconcile"
    state = initial
    consumed = set()
    for index, row in enumerate(journal):
        _require(type(row) is dict and set(row) == {"phase", "before", "event", "result"}, "journal_shape")
        _require(row["phase"] == (first_phase if index == 0 else "subsequent_evidence"), "journal_phase")
        _require(_same(row["before"], state.to_plain()), "journal_chain")
        current = rm.legal_directive(state).to_plain()
        if current["kind"] == "action":
            action_id = current["payload"]["action"]["id"]
            _require(action_id not in consumed, "duplicate_dispatch")
            consumed.add(action_id)
        if index == 0:
            _require(row["event"].get("stage") == event["stage"] and row["event"].get("lane") == event["lane"], "reconciliation_target")
        if index:
            _require(row["event"].get("outcome") == "accepted", "later_evidence")
        elif after and durable:
            _require(_same(row["event"], event), "durable_commit")
        elif not after:
            _require(row["event"].get("outcome") == "interrupted_before", "before_reconciliation")
        else:
            # Independent closed expectation, intentionally not imported from
            # the injector's outcome table. Unknowns cannot become success.
            f = job["failure"]
            if f == "continuation_success": expected_outcome = "accepted"
            elif f == "continuation_not_dispatched": expected_outcome = "not_dispatched"
            elif f == "hook_refused": expected_outcome = "refused"
            elif f in ("continuation_failed", "sol_review_failed", "terminal_verification_failed"): expected_outcome = "failed"
            elif f in ("hook_missing", "acknowledgement_missing"): expected_outcome = "missing"
            elif f == "partial_spawn": expected_outcome = "partial"
            elif f == "process_interruption": expected_outcome = "interrupted_after"
            elif f == "cleanup_failed": expected_outcome = "cleanup_unavailable"
            else: expected_outcome = "unknown"
            _require(row["event"].get("outcome") == expected_outcome, "fault_observation")
            if expected_outcome == "accepted":
                _require(_same(row["event"], event), "accepted_observation")
        _require(sum(_same(e, row["event"]) for e in rm.outgoing_stimuli(state).to_plain()) == 1, "legal_successor")
        result = rm.reduce(state, row["event"])
        _require(_same(row["result"], result.to_plain()), "exact_successor")
        state = rv.freeze(result.to_plain()["successor"])
        state_invariants(state, result.to_plain()["directive"])
        if index == 0:
            _require(_same(data["reconciled"], state.to_plain()), "reconciliation")
    expected_cut = journal[0]["result"]["successor"] if after and durable else data["initial"]
    _require(_same(data["cut"], expected_cut), "cut_state")
    effects = []
    if after:
        effects = [{"site": job["site"], "observation_sha256": values.canonical_digest(event),
                    "before_sha256": initial.digest(), "kind": "commit" if durable else "possible_external",
                    "committed_state_sha256": values.canonical_digest(expected_cut) if durable else None}]
    _require(_same(data["effects"], effects), "effect_count_or_binding")
    _require(_same(data["final"], state.to_plain()), "final_state")
    final = state_invariants(state, data["directive"])
    _require(final.to_plain()["kind"] in ("terminal_closure", "external_authority_required"), "incomplete_trace")
    guard = data["guard_refusal"]
    needs_guard = job["failure"] in ("typed_result_invalid", "grant_stale", "capacity_stale", "owner_mismatch")
    if needs_guard:
        _require(type(guard) is dict and set(guard) == {"state", "event", "reason"}, "guard_shape")
        expected_state, expected_event = initial.to_plain(), rv.freeze(event).to_plain()
        failure = job["failure"]
        if failure == "typed_result_invalid":
            expected_event["proof"] = {"status": "PASS", "lane": "wrong"}
        elif failure == "grant_stale":
            expected_state["grants"][event["grant_id"]] = "stale"
        elif failure == "capacity_stale":
            expected_state["lanes"][event["lane"]]["capacity"] = "stale"
        else:
            expected_event["owner"] = "root:wrong-owner"
        _require(_same(guard["state"], expected_state) and _same(guard["event"], expected_event), "guard_binding")
        try:
            rm.reduce(rv.freeze(guard["state"]), guard["event"])
        except values.LifecycleContractError as exc:
            _require(exc.reason == guard["reason"], "guard_reason")
        else:
            _require(False, "guard_accepted")
    else:
        _require(guard is None, "unexpected_guard")
    return rv.freeze({"status": "PASS", "case": job["id"], "trace_sha256": trace.digest(),
                      "invariants": list(values.INVARIANT_CLASSES), "effects_at_cut": len(effects),
                      "final_kind": final.to_plain()["kind"], "model_transitions": len(journal),
                      "physical_dispatches": 0})
