"""Provider-free interruptions at registered semantic lifecycle boundaries.

Each invocation owns a fresh in-memory journal. It never calls a transport,
reads host state or creates authority. A durable cut is after one atomic model
observation; an external cut is after one simulated dispatch and before its
observation. Recovery reads that journal once and never repeats the site.
"""
from __future__ import annotations

from functools import lru_cache

from lifecycle_conformance import injection_sites as sites, reference_model as rm
from lifecycle_conformance import reference_values as rv, values

SCHEMA = "orch-dork/lifecycle-injection-trace/v1"
# These classes exercise actual malformed state/envelope refusals, followed by
# conservative reconciliation; they are never passed as invented model outcomes.
GUARD_CLASSES = ("typed_result_invalid", "grant_stale", "capacity_stale", "owner_mismatch")
OBSERVATIONS = rv.freeze({
    "hook_missing": "missing", "hook_refused": "refused",
    "process_interruption": "interrupted_after", "partial_spawn": "partial",
    "acknowledgement_missing": "missing", "continuation_success": "accepted",
    "continuation_failed": "failed", "continuation_unknown": "unknown",
    "continuation_not_dispatched": "not_dispatched", "typed_result_invalid": "unknown",
    "grant_stale": "unknown", "capacity_stale": "unknown", "owner_mismatch": "unknown",
    "sol_review_failed": "failed", "terminal_verification_failed": "failed",
    "cleanup_failed": "cleanup_unavailable",
})


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("failure_injection:" + reason)


def stage_of(state: rv.FrozenValue) -> str:
    rm.legal_directive(state)
    data = state.to_plain()
    return data.get("stage", "activate" if data["generation"] == 3 else "readiness")


def accepted_event(state: rv.FrozenValue, lane: str | None = None) -> dict:
    """Deterministic successful observation; deferred results keep both seams."""
    candidates = [e for e in rm.outgoing_stimuli(state).to_plain()
                  if e.get("outcome", "accepted") == "accepted"
                  and (lane is None or e.get("lane", e.get("target")) == lane)]
    deferred = [e for e in candidates if e.get("variant") in ("deferred", "checkpoint_deferred")]
    if deferred:
        return deferred[0]
    if not candidates:
        _refuse("no_observation")
    return candidates[0]


@lru_cache(maxsize=1)
def minimal_states() -> rv.FrozenValue:
    """Historical success, checkpoint success and verified failure witness cuts."""
    state = rm.initial_state("injection-minimal")
    states = {}
    failure_branch = None
    checkpoint_branch = None
    # Three finite traces; each remains within the protocol's 28-event bound.
    for _ in range(3 * (28 + 3)):
        stage = stage_of(state)
        if stage == "continue.spec" and checkpoint_branch is None:
            checkpoint = next(event for event in rm.outgoing_stimuli(state).to_plain()
                              if event["outcome"] == "accepted" and event["variant"] == "checkpoint_deferred")
            checkpoint_branch = rv.freeze(rm.reduce(state, checkpoint).to_plain()["successor"])
        if stage == "review" and failure_branch is None:
            failed = next(event for event in rm.outgoing_stimuli(state).to_plain() if event["outcome"] == "failed")
            failure_branch = rv.freeze(rm.reduce(state, failed).to_plain()["successor"])
        if stage != "readiness":
            for event in rm.outgoing_stimuli(state).to_plain():
                if event["outcome"] == "accepted":
                    states.setdefault(event["stage"] + ":" + event["lane"], state.to_plain())
        if rm.legal_directive(state).to_plain()["kind"] == "terminal_closure":
            if "failure_closure:controller" in states and "progress:controller" in states:
                return rv.freeze(states)
            if failure_branch is None or checkpoint_branch is None:
                _refuse("failure_witness_missing")
            state = failure_branch if "failure_closure:controller" not in states else checkpoint_branch
            continue
        state = rv.freeze(rm.reduce(state, accepted_event(state)).to_plain()["successor"])
    _refuse("trace_bound")


def guard_input(state: rv.FrozenValue, event: dict, failure: str) -> tuple[rv.FrozenValue, dict]:
    """Plant the named defect in a complete value; no private monkeypatch point."""
    changed_state, changed_event = state.to_plain(), rv.freeze(event).to_plain()
    lane = event["lane"]
    if failure == "typed_result_invalid":
        changed_event["proof"] = {"status": "PASS", "lane": "wrong"}
    elif failure == "grant_stale":
        changed_state["grants"][event["grant_id"]] = "stale"
    elif failure == "capacity_stale":
        changed_state["lanes"][lane]["capacity"] = "stale"
    elif failure == "owner_mismatch":
        changed_event["owner"] = "root:wrong-owner"
    else:
        _refuse("guard_class")
    return rv.freeze(changed_state), changed_event


def _reduce(state: rv.FrozenValue, event: dict, phase: str, journal: list) -> rv.FrozenValue:
    result = rm.reduce(state, event)
    journal.append({"phase": phase, "before": state.to_plain(), "event": event,
                    "result": result.to_plain()})
    return rv.freeze(result.to_plain()["successor"])


def run_case(store: object, job: dict, state: rv.FrozenValue, event: dict) -> rv.FrozenValue:
    """Interrupt one registered site at an explicit complete model observation.

    The caller may supply any reachable state for Issue 170 Cartesian coverage.
    This function owns neither model policy nor production seam translation.
    """
    site = sites.validate_job(store, job)
    # Freeze/compare exact scalar types before using caller-owned dictionaries.
    event = rv.freeze(event).to_plain()
    if (type(event) is not dict or event.get("stage") != site["stage"]
            or event.get("lane") != site["lane"] or event.get("outcome") != "accepted"
            or sum(rv.freeze(e) == rv.freeze(event) for e in rm.outgoing_stimuli(state).to_plain()) != 1):
        _refuse("site_observation")
    before, journal, effects = state, [], []
    failure, timing = job["failure"], job["timing"]
    guard = None
    if failure in GUARD_CLASSES:
        bad_state, bad_event = guard_input(before, event, failure)
        try:
            rm.reduce(bad_state, bad_event)
        except values.LifecycleContractError as exc:
            guard = {"state": bad_state.to_plain(), "event": bad_event, "reason": exc.reason}
        else:
            _refuse("guard_accepted")
    durable = job["site"].startswith("lc-mut:")
    if timing == "after":
        if durable:
            state = _reduce(before, event, "effect", journal)
        effects.append({"site": job["site"], "observation_sha256": values.canonical_digest(event),
                        "before_sha256": before.digest(), "kind": "commit" if durable else "possible_external",
                        "committed_state_sha256": state.digest() if durable else None})
    cut = state
    # At a retained review barrier the only admitted observation is independent
    # sealed resource release. A before-commit interruption supplies no such
    # observation: retain the complete barrier without inventing a transition.
    retained_release = (timing == 'before' and durable
                        and event['stage'] == 'settle' and event['lane'] == 'controller'
                        and event.get('variant') == 'sealed_release'
                        and rm.legal_directive(before).to_plain()['kind'] == 'external_authority_required'
                        and rm.outgoing_stimuli(before).to_plain() == [event])
    # An after-commit fault cannot erase a durable accepted result. Read it from
    # the journal. All other cuts reconcile exactly one admitted observation.
    if not (timing == "after" and durable) and not retained_release:
        outcome = "interrupted_before" if timing == "before" else OBSERVATIONS.to_plain()[failure]
        choices = [e for e in rm.outgoing_stimuli(state).to_plain()
                   if e["stage"] == site["stage"] and e["lane"] == site["lane"] and e["outcome"] == outcome]
        if outcome == "accepted":
            selected = event
        elif choices:
            selected = choices[0]
        else:
            _refuse("unmodeled_failure")
        state = _reduce(state, selected, "reconcile", journal)
    reconciled = state
    # Subsequent accepted observations are modeled independent evidence. They
    # close a known failure; an external requirement has no outgoing transition.
    for _ in range(40):
        directive = rm.legal_directive(state).to_plain()
        if directive["kind"] in ("terminal_closure", "external_authority_required"):
            break
        state = _reduce(state, accepted_event(state), "subsequent_evidence", journal)
    else:
        _refuse("trace_bound")
    return rv.freeze({"schema": SCHEMA, "job": job, "initial": before.to_plain(), "event": event,
                      "guard_refusal": guard, "cut": cut.to_plain(), "effects": effects,
                      "reconciled": reconciled.to_plain(), "journal": journal,
                      "final": state.to_plain(), "directive": rm.legal_directive(state).to_plain()})
