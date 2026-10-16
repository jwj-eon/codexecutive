"""Derive checkpoint and completion accounting from whole native sources.

The policy defines non-monetary integer weights, never provider prices. This
module has no IO or authority. Its caller must independently obtain the owned
sources and freeze the policy before any native admission.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from typing import Any

from lifecycle_conformance import host_adapter as host
import orch_dork_hostile_input as hostile
import orch_dork_model_profile_registry as model_profiles

POLICY_SCHEMA = "orch-dork/checkpoint-accounting-policy/v1"
OBSERVATION_SCHEMA = "orch-dork/checkpoint-budget-observation/v1"
ADMISSION_SCHEMA = "orch-dork/checkpoint-admission-observation/v1"
# The hosted root a policy accounts for is the plan's declared root, which
# must be a registered orchestrator profile (Issue 185); there is no root
# literal here.  The checkpoint worker route is the pinned historical one.
WORKER_MODEL = "qwen-local/qwen-smart"
_RAW = ("uncached_input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens")
_INVALID = (KeyError, TypeError, ValueError, OverflowError, RecursionError)


def _bytes(value: Any) -> bytes:
    host.decode_bounded_response(value)
    return hostile.canonicalize_bounded_json(host.canonical_bytes(value))


def _sha(value: Any) -> str:
    return hashlib.sha256(_bytes(value)).hexdigest()


def build_checkpoint_accounting_policy(*, max_root_responses: int, root_model: Any = None) -> dict:
    """Declare one token unit per raw component and a bounded hosted root.

    Output tokens include reasoning; the separate reasoning weight deliberately
    adds one unit for that component. Consequently the derived total is at most
    twice the raw token total. It is not a dollar estimate or a billing receipt.
    root_model is the plan's declared root and must be admitted, a
    registered orchestrator or an onboarded model (ADR 0012); a caller
    without a plan accounts for the registry's default orchestrator.  The
    attempt preflight requires the accounted root, the plan's declared root
    and the attempt identity's root to agree.
    """
    if type(max_root_responses) is not int or max_root_responses <= 0:
        raise ValueError("checkpoint_accounting:policy_invalid")
    if root_model is None:
        root_model = model_profiles.default_root_model()
    if type(root_model) is not str or not model_profiles.root_admitted(root_model):
        raise ValueError("checkpoint_accounting:root_model_not_onboarded")
    core = {"schema":POLICY_SCHEMA,"basis":"non_monetary_token_weights",
        "weight_version":"native-token-components/v1","microunits_per_token":{key:1 for key in _RAW},
        "root":{"model":root_model,"hosted":True,"max_responses":max_root_responses},
        "workers":{"model":WORKER_MODEL,"hosted":False},"cost_usd":None}
    return {**core,"policy_sha256":_sha(core)}


def validate_checkpoint_accounting_policy(policy: Any) -> bool:
    try:
        return _bytes(policy) == _bytes(build_checkpoint_accounting_policy(
            max_root_responses=policy["root"]["max_responses"], root_model=policy["root"]["model"]))
    except _INVALID:
        return False


def _clock(value: Any) -> datetime:
    if type(value) is not str:raise ValueError("invalid clock")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:raise ValueError("unbound clock")
    return result


def build_checkpoint_budget_observation(policy: Any, sources: Any) -> dict:
    """Count observed deltas once and retain the exact source cut identity.

    Wall time covers the recorded source interval, not unobserved time after
    that cut. Worker capacity is the two retained native lanes, not an OS
    process inventory or evidence that either lane has been released.
    """
    import orch_dork_qualification_progress as progress
    try:
        for value in (policy, sources):_bytes(value)
        if not validate_checkpoint_accounting_policy(policy):raise ValueError("invalid policy")
        root_report, worker_report = sources["coordinator"], sources["workers"]
        expected = root_report["expectation"]
        identity = {"root_task_id":expected["sources"]["owner"]["root_task_id"],
                    "root_model":expected["model"],"root_effort":expected["effort"]}
        ingress = progress.build_checkpoint_ingress_observation(identity,root_report,worker_report)
        if (expected["model"] != policy["root"]["model"]
                or any(worker_report["expectation"]["lanes"][lane]["model"] != policy["workers"]["model"]
                       for lane in ("spec", "standards"))):raise ValueError("different classified routes")
        root = root_report["evidence"];workers = worker_report["evidence"]["workers"]
        root_windows = [*root["windows"],root["active_prefix"]]
        actions = [action for window in root_windows for action in window["actions"]["items"]]
        physical = [a["name"] for a in actions if a["namespace"] == "multi_agent_v1"
                    and a["name"] != "wait_agent"]
        if (sorted(physical) != ["send_input", "send_input", "spawn_agent", "spawn_agent"]
                or any(a["name"] in {"spawn_agent", "send_input", "close_agent", "resume_agent"}
                       and a["namespace"] != "multi_agent_v1" for a in actions)):
            raise ValueError("different native resource lifecycle")
        usage = {"root":root["usage"],**{lane:workers[lane]["source"]["usage"] for lane in ("spec", "standards")}}
        raw = {key:0 for key in _RAW};generations = {};turns = 0
        for role, observed in usage.items():
            totals = observed["totals"]
            raw["uncached_input_tokens"] += totals["input_tokens"]-totals["cached_input_tokens"]
            raw["cached_input_tokens"] += totals["cached_input_tokens"]
            raw["output_tokens"] += totals["output_tokens"]
            raw["reasoning_tokens"] += totals["reasoning_output_tokens"]
            generations[role] = sum(len(turn["response_ids"]) for turn in observed["per_turn"])
            turns += len(observed["turn_ids"])
        start = root_windows[0]["start"]
        ends = [root["active_prefix"]["through"],*[workers[lane]["source"]["windows"][-1]["end"] for lane in ("spec", "standards")]]
        end = max(ends,key=lambda ref:_clock(ref["timestamp"]))
        if any(_clock(w["start"]["timestamp"]) < _clock(start["timestamp"])
               for lane in ("spec", "standards") for w in workers[lane]["source"]["windows"]):
            raise ValueError("worker before root source interval")
        delta = _clock(end["timestamp"])-_clock(start["timestamp"])
        wall_ms = delta.days*86_400_000+delta.seconds*1000+delta.microseconds//1000
        if wall_ms < 0:raise ValueError("negative source interval")
        amounts = {"tokens":ingress["total_tokens"],"turns":turns,
            "cost_microunits":sum(raw[key]*policy["microunits_per_token"][key] for key in _RAW),
            "hosted_calls":generations["root"],"wall_time_ms":wall_ms,
            "children":2,"depth":1,"concurrency":2}
        core = {"schema":OBSERVATION_SCHEMA,"scope":"owned_native_checkpoint_source_cut",
            "policy_sha256":policy["policy_sha256"],"sources_sha256":_sha(sources),
            "amounts":amounts,"raw_token_components":raw,"model_generations":generations,
            "wall_interval":{"start":deepcopy(start),"end":deepcopy(end)},
            "worker_capacity_scope":"admitted_native_lanes_retained",
            "provider_free":True,"continuation_permitted":False,"cost_usd":None}
        return {**core,"report_sha256":_sha(core)}
    except _INVALID as error:
        raise ValueError("checkpoint_accounting:input_invalid") from error


def validate_checkpoint_budget_observation(report: Any, policy: Any, sources: Any) -> bool:
    try:
        return _bytes(report) == _bytes(build_checkpoint_budget_observation(policy,sources))
    except _INVALID:
        return False


def build_checkpoint_admission_observation(policy: Any, sources: Any, *, now: datetime) -> dict:
    """Charge through a supplied trusted host time, including source-read delay.

    The caller owns the clock. This pure value authenticates no authority and
    is only a checkpoint decision; it grants no later dispatch deadline.
    """
    try:
        source = build_checkpoint_budget_observation(policy, sources)
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("missing host clock")
        instant = now.astimezone(timezone.utc)
        if instant < _clock(source["wall_interval"]["end"]["timestamp"]):
            raise ValueError("clock before source completion")
        delta = instant-_clock(source["wall_interval"]["start"]["timestamp"])
        wall_ms = delta.days*86_400_000+delta.seconds*1000+(delta.microseconds+999)//1000
        core = deepcopy({k:v for k,v in source.items() if k != "report_sha256"})
        core.update(schema=ADMISSION_SCHEMA,scope="owned_native_checkpoint_admission",
                    source_cut_report_sha256=source["report_sha256"],observed_at=instant.isoformat())
        core["amounts"]["wall_time_ms"] = wall_ms
        return {**core,"report_sha256":_sha(core)}
    except _INVALID as error:
        raise ValueError("checkpoint_accounting:admission_clock_invalid") from error


def validate_checkpoint_admission_observation(report: Any, policy: Any, sources: Any) -> bool:
    try:
        return _bytes(report) == _bytes(build_checkpoint_admission_observation(policy,sources,now=_clock(report["observed_at"])))
    except _INVALID:
        return False


def build_checkpoint_admission_budget(predecessor_receipt: Any, sources: Any, *, now: datetime) -> tuple[dict, dict]:
    """Reconcile the frozen allocation with independently observed consumption.

    Native callers must reread owned sources and supply their clock. The cost
    reservation uses the declared maximum of two units per remaining token;
    actual consumed units retain the observed raw components.
    """
    import orch_dork_qualification_progress as progress
    import orch_dork_efficiency_governor as governor
    try:
        policy = predecessor_receipt["bindings"]["checkpoint_accounting_policy"]
        program = progress.build_checkpoint_budget_program(predecessor_receipt,sources)
        if predecessor_receipt["bindings"].get("checkpoint_reservation_profile") != progress.RESERVATION_PROFILE:
            raise ValueError("missing lifecycle reservation")
        observed = build_checkpoint_admission_observation(policy,sources,now=now)
        limits = program["budget_policy"]["limits"]
        if (limits["hosted_calls"] != policy["root"]["max_responses"]
                or limits["cost_microunits"] != 2*limits["tokens"]):
            raise ValueError("different frozen accounting policy")
        pointer = "checkpoint-admission://sha256/" + observed["report_sha256"]
        program["runtime_window"]["source_pointer"] = pointer
        record = program["runtime_records"][0]
        record.update(source_pointer=pointer,amounts={key:{"status":"known","value":value,"reason":None}
                      for key,value in observed["amounts"].items()})
        for row in program["admission_requests"]:
            row["reservation"]["cost_microunits"] = 2*row["reservation"]["tokens"]
            row["reservation"]["hosted_calls"] = (max(0,limits["hosted_calls"]-observed["amounts"]["hosted_calls"])
                if row["node_id"] == "checkpoint-root-completion" else 0)
        _bytes(program)
        if governor.evaluate_budget_program(program)["status"] not in {"PASS", "BUDGET_EXHAUSTED"}:
            raise ValueError("invalid observed budget")
        return program, observed
    except _INVALID as error:
        raise ValueError("checkpoint_accounting:admission_budget_invalid") from error


def validate_checkpoint_admission_budget(program: Any, observation: Any, predecessor_receipt: Any, sources: Any) -> bool:
    """Validate the whole pair; its host clock custody remains external."""
    try:
        expected, observed = build_checkpoint_admission_budget(predecessor_receipt,sources,now=_clock(observation["observed_at"]))
        return _bytes(program) == _bytes(expected) and _bytes(observation) == _bytes(observed)
    except _INVALID:
        return False


COMPLETION_SCHEMA = "orch-dork/completion-budget-observation/v1"


def _completion_root_usage(before: dict, after: dict) -> tuple[list[dict], dict]:
    """Union same-file telemetry by exact source line; never sum overlap twice."""
    import orch_dork_codex_usage as usage
    windows = {}
    for window in [*before["windows"], *after["windows"]]:
        previous = windows.get(window["turn_id"])
        if previous is not None and _bytes(previous) != _bytes(window):
            raise ValueError("changed completed root turn")
        windows[window["turn_id"]] = window
    ordered = sorted(windows.values(), key=lambda row:row["start"]["line"])
    evidence = {}
    for row in [*before["usage"]["evidence"], *after["usage"]["evidence"]]:
        previous = evidence.get(row["line"])
        if previous is not None and _bytes(previous) != _bytes(row):
            raise ValueError("changed root usage overlap")
        evidence[row["line"]] = row
    # Both source reports have already passed their whole owning validators,
    # including the immutable checkpoint prefix. This reducer consumes their
    # compact telemetry directly and preserves native delta/mirror semantics.
    merged = usage._report([evidence[line] for line in sorted(evidence)], after["task_id"],
                           [window["turn_id"] for window in ordered])
    if merged["status"] != "OBSERVED" or not usage.validate_usage_observation(merged)["valid"]:
        raise ValueError("root usage union invalid")
    return ordered, merged


def build_completion_budget_observation(policy: Any, checkpoint_sources: Any, complete_observation: Any) -> dict:
    """Account for the complete checkpoint lifecycle, including earlier root turns.

    The native completion transport intentionally begins at worker spawn. Join
    the accepted earlier root windows and overlapping active-turn telemetry to
    that transport before counting. This is canonical evidence only: the host
    must authenticate source custody and apply frozen limits at its final gate.
    Wall time ends at the last recorded completion, not the later host decision.
    """
    import orch_dork_native_checkpoint_attempt as complete
    try:
        if not validate_checkpoint_accounting_policy(policy):raise ValueError("invalid policy")
        if (not complete.validate_native_checkpoint_attempt_observation(complete_observation, checkpoint_sources)["valid"]
                or complete_observation["status"] != "OBSERVED"):
            raise ValueError("completion unobserved")
        expected = complete_observation["expectation"]["attempt"]
        if (expected["root"]["model"] != policy["root"]["model"]
                or any(expected["lanes"][lane]["model"] != policy["workers"]["model"] for lane in ("spec", "standards"))):
            raise ValueError("different classified routes")
        evidence = complete_observation["evidence"]
        before = checkpoint_sources["coordinator"]["evidence"]
        roles = evidence["roles"]
        windows, root_usage = _completion_root_usage(before, roles["root"])
        usage = {"root":root_usage, **{lane:roles[lane]["usage"] for lane in ("spec", "standards")}}
        all_windows = [*windows, *roles["spec"]["windows"], *roles["standards"]["windows"]]
        actions = [action for window in windows for action in window["actions"]["items"]]
        physical = [row["name"] for row in actions if row["namespace"] == "multi_agent_v1" and row["name"] != "wait_agent"]
        if (sorted(physical) != ["close_agent"]*2 + ["send_input"]*4 + ["spawn_agent"]*2
                or any(row["name"] in {"spawn_agent", "send_input", "close_agent", "resume_agent"}
                       and row["namespace"] != "multi_agent_v1" for row in actions)):
            raise ValueError("different completion lifecycle")
        raw = {key:0 for key in _RAW}; generations = {}
        for role, observed in usage.items():
            totals = observed["totals"]
            raw["uncached_input_tokens"] += totals["input_tokens"] - totals["cached_input_tokens"]
            raw["cached_input_tokens"] += totals["cached_input_tokens"]
            raw["output_tokens"] += totals["output_tokens"]
            raw["reasoning_tokens"] += totals["reasoning_output_tokens"]
            generations[role] = sum(len(row["response_ids"]) for row in observed["per_turn"])
        start = windows[0]["start"]
        end = max((row["end"] for row in all_windows), key=lambda ref:_clock(ref["timestamp"]))
        if any(_clock(row["start"]["timestamp"]) < _clock(start["timestamp"]) for row in all_windows):
            raise ValueError("work before accounting interval")
        delta = _clock(end["timestamp"]) - _clock(start["timestamp"])
        wall_ms = delta.days*86_400_000 + delta.seconds*1000 + (delta.microseconds+999)//1000
        if wall_ms < 0:raise ValueError("negative interval")
        tokens = sum(row["totals"]["total_tokens"] for row in usage.values())
        core = {"schema":COMPLETION_SCHEMA, "scope":"owned_native_completion_source_cut",
            "policy_sha256":policy["policy_sha256"], "checkpoint_sources_sha256":complete_observation["expectation"]["checkpoint_sources_sha256"],
            "completion_source_sha256":complete_observation["report_sha256"],
            "amounts":{"tokens":tokens, "turns":len(all_windows),
                "cost_microunits":sum(raw[key]*policy["microunits_per_token"][key] for key in _RAW),
                "hosted_calls":generations["root"], "wall_time_ms":wall_ms, "children":2, "depth":1, "concurrency":2},
            "ingress":{"sol_ingress_tokens":root_usage["totals"]["input_tokens"], "total_tokens":tokens,
                "tool_calls":sum(row["actions"]["count"] for row in all_windows)},
            "raw_token_components":raw, "model_generations":generations,
            "usage_sha256_by_role":{role:row["report_sha256"] for role,row in usage.items()},
            "root_turn_ids":root_usage["turn_ids"], "wall_interval":{"start":start,"end":end},
            "worker_capacity_scope":"observed_native_lane_peak", "provider_free":True,
            "continuation_permitted":False, "terminal_claim_permitted":False, "cost_usd":None}
        report = deepcopy({**core,"report_sha256":_sha(core)})
        _bytes(report)
        return report
    except _INVALID as error:
        raise ValueError("completion_accounting:input_invalid") from error


def validate_completion_budget_observation(report: Any, policy: Any, checkpoint_sources: Any, complete_observation: Any) -> bool:
    """Validate exact accounting transport, without source or final authority."""
    try:
        return _bytes(report) == _bytes(build_completion_budget_observation(policy, checkpoint_sources, complete_observation))
    except _INVALID:
        return False


COMPLETION_ADMISSION_SCHEMA = "orch-dork/completion-admission-observation/v1"


def build_completion_admission_observation(policy: Any, checkpoint_sources: Any, complete_observation: Any, *, now: datetime) -> dict:
    """Charge through a trusted host decision time; grant no dispatch authority."""
    try:
        source = build_completion_budget_observation(policy, checkpoint_sources, complete_observation)
        if not isinstance(now, datetime) or now.tzinfo is None:raise ValueError("missing host clock")
        instant = now.astimezone(timezone.utc)
        if instant < _clock(source["wall_interval"]["end"]["timestamp"]):raise ValueError("clock before completion")
        delta = instant - _clock(source["wall_interval"]["start"]["timestamp"])
        wall_ms = delta.days*86_400_000 + delta.seconds*1000 + (delta.microseconds+999)//1000
        core = deepcopy({key:value for key,value in source.items() if key != "report_sha256"})
        core.update(schema=COMPLETION_ADMISSION_SCHEMA, scope="owned_native_completion_admission",
                    source_cut_report_sha256=source["report_sha256"], observed_at=instant.isoformat())
        core["amounts"]["wall_time_ms"] = wall_ms
        return {**core, "report_sha256":_sha(core)}
    except _INVALID as error:
        raise ValueError("completion_accounting:admission_clock_invalid") from error


def validate_completion_admission_observation(report: Any, policy: Any, checkpoint_sources: Any, complete_observation: Any) -> bool:
    """Reconstruct the whole transport; the host owns clock and source custody."""
    try:
        return _bytes(report) == _bytes(build_completion_admission_observation(policy, checkpoint_sources,
            complete_observation, now=_clock(report["observed_at"])))
    except _INVALID:
        return False


COMPLETION_DECISION_SCHEMA = "orch-dork/completion-budget-decision/v1"


def build_completion_budget_decision(identity: Any, predecessor_report: Any, pre_spawn_program: Any,
                                     checkpoint_sources: Any, complete_observation: Any, *, now: datetime) -> dict:
    """Compare observed completion with the exact declared admission limits.

    This pure decision neither authenticates its inputs nor grants a terminal
    claim. The native final gate must bind the supplied pre-spawn program hash
    to its historical admission intent and inject current source/clock custody.
    No synthetic worker or new reservation is introduced to test consumption.
    """
    import orch_dork_governed_attempt as attempt
    import orch_dork_qualification_progress as progress
    import orch_dork_qualification_verification as verification
    from orch_dork_governed_native_reports import _json
    try:
        _json(pre_spawn_program)
        if len(attempt._canonical(pre_spawn_program)) > 1_000_000:raise ValueError("program bounds")
        issues = []
        bound = attempt._validate_identity(identity, issues)
        receipt = attempt._post_batch_predecessor_report(bound, predecessor_report, issues)
        if (issues or receipt["stage"] != "capacity_settlement" or receipt["next_action"] != "final_qualification"
                or set(pre_spawn_program) != attempt._PROGRAM_FIELDS
                or pre_spawn_program["schema"] != attempt.CHECKPOINT_PROGRAM_SCHEMA
                or pre_spawn_program["operation"] != "pre_spawn" or pre_spawn_program["predecessor_receipt"] is not None
                or _bytes(pre_spawn_program["identity"]) != _bytes(bound)):
            raise ValueError("different admission identity")
        payload = pre_spawn_program["payload"]
        bindings = receipt["bindings"]
        frozen, policy = bindings["checkpoint_budget_program"], bindings["checkpoint_accounting_policy"]
        if (bindings["worker_checkpoint_profile"] != attempt.WORKER_CHECKPOINT_PROFILE
                or bindings["checkpoint_reservation_profile"] != progress.RESERVATION_PROFILE
                or payload["checkpoint_reservation_profile"] != progress.RESERVATION_PROFILE
                or _bytes(frozen) != _bytes(payload["budget_program"])
                or _bytes(policy) != _bytes(payload["checkpoint_accounting_policy"])
                or _bytes(bindings["attempt_limits"]) != _bytes(payload["attempt_limits"])
                or not progress.validate_checkpoint_reservation_program(frozen,payload["logical_plan"],accounting_policy=policy)):
            raise ValueError("different frozen budget")
        plan = progress.governor.validate_logical_plan(payload["logical_plan"])
        if plan["status"] != "PASS" or plan["plan_sha256"] != receipt["plan_sha256"]:
            raise ValueError("different frozen plan")
        if (not verification.validate_verified_native_attempt(predecessor_report,complete_observation,
                checkpoint_sources=checkpoint_sources)["valid"] or complete_observation["status"] != "OBSERVED"):
            raise ValueError("unverified completion")
        prior = bindings["checkpoint_budget_observation"]
        if not validate_checkpoint_admission_observation(prior,policy,checkpoint_sources):
            raise ValueError("invalid earlier accounting")
        observed = build_completion_admission_observation(policy,checkpoint_sources,complete_observation,now=now)
        if (_clock(observed["observed_at"]) < _clock(prior["observed_at"])
                or any(observed["amounts"][key] < prior["amounts"][key] for key in observed["amounts"])):
            raise ValueError("consumption regressed")
        limits = frozen["budget_policy"]["limits"]
        ingress_limits = bindings["attempt_limits"]
        if (set(limits) != set(observed["amounts"]) or any(type(v) is not int or v < 0 for v in limits.values())
                or set(ingress_limits) != {"max_sol_ingress_tokens", "max_total_tokens", "max_tool_calls"}
                or any(type(v) is not int or v <= 0 for v in ingress_limits.values())
                or limits["tokens"] != ingress_limits["max_total_tokens"]):
            raise ValueError("invalid frozen limits")
        previous_ingress = bindings["latest_ingress"]
        if (previous_ingress["status"] != "observed"
                or any(type(previous_ingress[key]) is not int or observed["ingress"][key] < previous_ingress[key]
                       for key in observed["ingress"])):
            raise ValueError("ingress regressed")
        exhausted = ["completion_budget:limit_exceeded:"+key for key,value in observed["amounts"].items() if value > limits[key]]
        exhausted.extend("completion_budget:limit_exceeded:"+key for key,value in observed["ingress"].items()
                         if value > ingress_limits["max_"+key])
        core = {"schema":COMPLETION_DECISION_SCHEMA, "status":"BUDGET_EXHAUSTED" if exhausted else "PASS",
            "issues":sorted(exhausted), "scope":"canonical_completion_budget_comparison",
            "identity_sha256":receipt["identity_sha256"], "predecessor_receipt_sha256":receipt["receipt_sha256"],
            "pre_spawn_program_sha256":attempt._sha(pre_spawn_program), "frozen_budget_sha256":_sha(frozen),
            "limits":limits, "ingress_limits":ingress_limits, "observation":observed,
            "continuation_permitted":False, "terminal_claim_permitted":False, "provider_free":True, "cost_usd":None}
        return deepcopy({**core,"report_sha256":_sha(core)})
    except _INVALID as error:
        raise ValueError("completion_budget:input_invalid") from error


def validate_completion_budget_decision(report: Any, identity: Any, predecessor_report: Any, pre_spawn_program: Any,
                                        checkpoint_sources: Any, complete_observation: Any) -> bool:
    """Validate the complete comparison; confer no admission or owner authority."""
    try:
        return _bytes(report) == _bytes(build_completion_budget_decision(identity,predecessor_report,pre_spawn_program,
            checkpoint_sources,complete_observation,now=_clock(report["observation"]["observed_at"])))
    except _INVALID:
        return False


__all__ = ["POLICY_SCHEMA","OBSERVATION_SCHEMA","build_checkpoint_accounting_policy",
           "validate_checkpoint_accounting_policy","build_checkpoint_budget_observation",
           "validate_checkpoint_budget_observation","ADMISSION_SCHEMA","build_checkpoint_admission_observation",
           "validate_checkpoint_admission_observation","build_checkpoint_admission_budget","validate_checkpoint_admission_budget",
           "COMPLETION_SCHEMA","build_completion_budget_observation","validate_completion_budget_observation",
           "COMPLETION_ADMISSION_SCHEMA","build_completion_admission_observation","validate_completion_admission_observation",
           "COMPLETION_DECISION_SCHEMA","build_completion_budget_decision","validate_completion_budget_decision"]
