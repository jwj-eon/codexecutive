"""Bind a real worker checkpoint to host-observed usage without admission.

The worker supplies claims and checks. The host supplies the completed native
turn and runtime observation; the worker cannot supply its own usage or source
pointer. This pure constructor does not read a runtime, grant a continuation,
or replace the eventual typed handoff. Source custody remains a host concern.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any

from lifecycle_conformance import host_adapter as host
import orch_dork_adaptive_contracts as contracts
import orch_dork_hostile_input as hostile
import orch_dork_routing_verify as routing
import orch_dork_efficiency_governor as governor
import orch_dork_qualification_results as results

SUBMISSION_SCHEMA = "orch-dork/worker-progress-submission/v1"
REPORT_SCHEMA = "orch-dork/qualification-worker-progress/v1"
RESERVATION_PROFILE = "orch-dork/checkpoint-lifecycle-reservation/v1"
_CONTENT = {"sequence", "claims", "artifact_refs", "checks"}
_BINDING = {"logical_worker_id", "worker_id", "model", "effort", "observer_id", "turn_id", "root_turn_id"}
_COUNTERS = {"model_calls", "native_calls", "hosted_calls", "network_calls", "credential_reads", "task_creations"}
_INVALID = (KeyError, TypeError, ValueError, RecursionError, OverflowError)


def _bytes(value: Any) -> bytes:
    # Bound the in-memory graph before encoding, then apply the contract profile.
    host.decode_bounded_response(value)
    return hostile.canonicalize_bounded_json(host.canonical_bytes(value))


def _sha(value: Any) -> str:
    return hashlib.sha256(_bytes(value)).hexdigest()


def build_worker_progress_report(task_spec: Any, binding: Any, submission: Any,
                                 native_source: Any, runtime_observation: Any) -> dict:
    """Validate the first completed work checkpoint and retain its whole inputs.

    Observed usage is cumulative for the worker. Completion-reserve admission
    belongs to the controller and is deliberately not granted by this report.
    """
    try:
        for value in (task_spec, binding, submission, native_source, runtime_observation):
            _bytes(value)
        task = contracts.validate_task_spec(task_spec)
        if (task.get("valid") is not True or task_spec.get("executor") != "subagent"
                or type(binding) is not dict or set(binding) != _BINDING
                or any(type(value) is not str or not 0 < len(value) <= 128 for value in binding.values())
                or task_spec["id"] != binding["logical_worker_id"] or binding["worker_id"] == binding["observer_id"]):
            raise ValueError("invalid task binding")
        if (type(submission) is not dict or set(submission) != {"schema", "task_spec_sha256", *_CONTENT}
                or submission["schema"] != SUBMISSION_SCHEMA or submission["task_spec_sha256"] != task["digest"]
                or type(submission["sequence"]) is not int or submission["sequence"] != 1):
            raise ValueError("invalid checkpoint submission")
        if host.validate_native_v1_runtime_window(native_source).get("valid") is not True:
            raise ValueError("invalid native checkpoint source")
        native_window = native_source["native_window"]
        if (native_window["turn_id"] != binding["turn_id"] or native_window["root_turn_id"] != binding["root_turn_id"]
                or native_window["model"] != binding["model"] or native_window["effort"] != binding["effort"]):
            raise ValueError("invalid native checkpoint turn")
        if routing.validate_session_runtime_observation(runtime_observation).get("valid") is not True:
            raise ValueError("invalid runtime observation")
        expected_route = {"session_id": binding["worker_id"], "model": binding["model"], "effort": binding["effort"],
                          "context_policy": "none", "inherited_history": False}
        if (runtime_observation["observer_id"] != binding["observer_id"] or runtime_observation["route"] != expected_route
                or runtime_observation["terminal_schema"] != SUBMISSION_SCHEMA
                or runtime_observation["terminal_json_sha256"] != _sha(submission)
                or runtime_observation["terminal_record"] != native_source["canonical_source_refs"][-1]
                or runtime_observation["usage_record"] not in native_source["canonical_source_refs"][1:-1]):
            raise ValueError("checkpoint output not bound to native turn")
        observed = runtime_observation["usage"]
        packet = contracts.seal_incremental_claim_packet({
            "schema": contracts.INCREMENTAL_CLAIM_PACKET_SCHEMA,
            "packet_id": binding["logical_worker_id"] + ":progress:" + _sha(submission),
            "task_spec_sha256": task["digest"], **deepcopy({key: submission[key] for key in _CONTENT}),
            "usage": {key: observed[key] for key in ("status", "input_tokens", "output_tokens", "total_tokens", "tool_calls")},
            "source_pointer": runtime_observation["source_pointer"] + "#" + str(runtime_observation["terminal_record"]["line"])
                              + ":sha256:" + runtime_observation["terminal_record"]["sha256"],
        }, task_spec=task_spec)
        core = {"schema": REPORT_SCHEMA, "status": "PASS", "scope": "canonical_progress_transport",
                "task_spec": deepcopy(task_spec), "binding": deepcopy(binding), "submission": deepcopy(submission),
                "native_source": deepcopy(native_source), "runtime_observation": deepcopy(runtime_observation),
                "progress_packet": packet, "continuation_permitted": False, "terminal_claim_permitted": False,
                "provider_free": True, **{key: 0 for key in _COUNTERS}}
        report = {**core, "report_sha256": _sha(core)}
        _bytes(report)
        return report
    except _INVALID as error:
        raise ValueError("worker_progress:input_invalid") from error


def validate_worker_progress_report(report: Any) -> dict:
    """Validate exact complete transport, without authenticating caller custody."""
    try:
        encoded = _bytes(report)
        expected = build_worker_progress_report(report["task_spec"], report["binding"], report["submission"],
                                                 report["native_source"], report["runtime_observation"])
        if encoded != _bytes(expected):
            raise ValueError("noncanonical report")
    except _INVALID:
        return {"valid": False, "issues": ["worker_progress:report_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def build_checkpoint_progress_program(predecessor_receipt: Any, reports: Any) -> dict:
    """Derive one complete progress prefix from the admitted native checkpoints.

    This is a pure transport join. The native controller must independently
    observe these sources at its current owner/cursor before admitting work.
    """
    import orch_dork_governed_attempt as attempt
    try:
        _bytes(predecessor_receipt)
        _bytes({"reports": reports})
        receipt = predecessor_receipt
        bindings = receipt["bindings"]
        if (receipt["schema"] != attempt.RECEIPT_SCHEMA or receipt["stage"] != "worker_start"
                or receipt["status"] != "AUTHORIZED" or receipt["next_action"] != "continue"
                or receipt["receipt_sha256"] != _sha({k: v for k, v in receipt.items() if k != "receipt_sha256"})
                or bindings.get("worker_checkpoint_profile") != attempt.WORKER_CHECKPOINT_PROFILE
                or type(bindings["capacity_wave_index"]) is not int or bindings["capacity_wave_index"] != 1
                or bindings["progress_prefixes"] != {} or type(reports) is not list or len(reports) != 2):
            raise ValueError("invalid checkpoint predecessor")
        expected = results.join_bindings(bindings, receipt["root_task_id"])
        specs, events = [], []
        for index, (report, target) in enumerate(zip(reports, expected)):
            if (validate_worker_progress_report(report)["valid"] is not True
                    or {key: report["binding"][key] for key in target["binding"]} != target["binding"]
                    or report["task_spec"]["task_spec_sha256"] != target["task_spec_sha256"]):
                raise ValueError("checkpoint membership mismatch")
            lane, worker = report["binding"]["logical_worker_id"], report["binding"]["worker_id"]
            packet = report["progress_packet"]
            specs.append({"logical_worker_id": lane, "worker_id": worker, "task_spec": deepcopy(report["task_spec"])})
            events.append({"seq": index + 1, "type": "packet.observed", "logical_worker_id": lane,
                           "worker_id": worker, "packet": deepcopy(packet), "evidence_pointer": packet["source_pointer"]})
        program = {"schema": governor.WAVE_PROGRESS_PROGRAM_SCHEMA,
                   "progress_id": "checkpoint:" + receipt["attempt_id"] + ":1", "task_specs": specs,
                   "completion_reserve": deepcopy(bindings["completion_reserve"]), "events": events}
        _bytes(program)
        if governor.evaluate_wave_progress(program)["status"] != "PASS":
            raise ValueError("invalid checkpoint prefix")
        return program
    except _INVALID as error:
        raise ValueError("checkpoint_batch:input_invalid") from error


def build_checkpoint_ingress_observation(identity: Any, coordinator_report: Any, worker_report: Any) -> dict:
    """Join exact root/worker usage at one owner snapshot, without admission.

    Root input includes cached input; it is a token ceiling, not a dollar
    estimate. Frozen attempt identity and source custody remain the controller's
    responsibility. Missing usage or mismatched whole inventories cannot join.
    """
    import orch_dork_coordinator_usage as coordinator
    import orch_dork_native_attempt_observer as native
    try:
        for value in (identity, coordinator_report, worker_report):_bytes(value)
        if (coordinator.validate_coordinator_usage(coordinator_report)["valid"] is not True
                or native.validate_native_worker_checkpoint_observation(worker_report)["valid"] is not True
                or coordinator_report["status"] != "OBSERVED" or worker_report["status"] != "OBSERVED"):
            raise ValueError("unobserved usage")
        root, workers = coordinator_report["evidence"], worker_report["evidence"]
        expected = coordinator_report["expectation"]
        if (root["source_inventory"] != workers["source_inventory"]
                or identity["root_task_id"] != expected["sources"]["owner"]["root_task_id"]
                or identity["root_model"] != expected["model"] or identity["root_effort"] != expected["effort"]):
            raise ValueError("source or root mismatch")
        observed = root["usage"]["totals"]
        return {"status":"observed", "sol_ingress_tokens":observed["input_tokens"],
                "total_tokens":observed["total_tokens"] + sum(row["source"]["usage"]["totals"]["total_tokens"] for row in workers["workers"].values()),
                "tool_calls":root["tool_calls"] + sum(window["actions"]["count"] for row in workers["workers"].values() for window in row["source"]["windows"]),
                "source_pointer":"checkpoint-ingress://sha256/" + _sha({"coordinator":coordinator_report["report_sha256"], "workers":worker_report["report_sha256"]})}
    except _INVALID as error:
        raise ValueError("checkpoint_ingress:input_invalid") from error


def build_checkpoint_budget_program(predecessor_receipt: Any, sources: Any) -> dict:
    """Reconcile available usage against the retained pre-spawn reservation.

    Native token records establish tokens and observed turns. They do not
    establish billing, provider classification, an admission-time clock, or
    complete resource/capacity accounting. Those dimensions stay unknown. This
    constructor therefore cannot grant continuation; completing those sources
    is required before the native checkpoint profile can be enabled.
    """
    try:
        _bytes(predecessor_receipt)
        if type(sources) is not dict or set(sources) != {"coordinator", "workers"}:
            raise ValueError("invalid checkpoint sources")
        receipt = predecessor_receipt
        identity = {"root_task_id":receipt["root_task_id"],
                    "root_model":sources["coordinator"]["expectation"]["model"],
                    "root_effort":sources["coordinator"]["expectation"]["effort"]}
        ingress = build_checkpoint_ingress_observation(identity, sources["coordinator"], sources["workers"])
        build_checkpoint_progress_program(receipt,
            [sources["workers"]["evidence"]["workers"][lane]["progress_report"] for lane in ("spec", "standards")])
        frozen = receipt["bindings"]["checkpoint_budget_program"]
        checked = governor.evaluate_budget_program(frozen)
        if (checked["status"] != "PASS" or checked["plan_sha256"] != receipt["plan_sha256"]
                or checked["receipt_sha256"] != receipt["bindings"]["budget_receipt_sha256"]):
            raise ValueError("different frozen reservation")
        turns = len(sources["coordinator"]["evidence"]["usage"]["turn_ids"])
        turns += sum(len(row["source"]["usage"]["turn_ids"])
                     for row in sources["workers"]["evidence"]["workers"].values())
        known = {"tokens":ingress["total_tokens"], "turns":turns}
        amounts = {dimension:({"status":"known", "value":known[dimension], "reason":None} if dimension in known
                   else {"status":"unknown", "value":None, "reason":"checkpoint_" + dimension + "_unobserved"})
                   for dimension in governor.LIMIT_DIMENSIONS}
        requests = deepcopy(frozen["admission_requests"])
        if "checkpoint_reservation_profile" in receipt["bindings"]:
            if receipt["bindings"]["checkpoint_reservation_profile"] != RESERVATION_PROFILE:
                raise ValueError("unknown checkpoint reservation profile")
            by_lane = {row["node_id"]:row for row in requests}
            if len(requests) != 2 or set(by_lane) != {"spec", "standards"}:
                raise ValueError("different reserved lanes")
            root_tokens = frozen["budget_policy"]["limits"]["tokens"] - sum(row["reservation"]["tokens"] for row in requests)
            if root_tokens <= 0 or frozen["budget_policy"]["limits"]["turns"] != 8:
                raise ValueError("missing root lifecycle reserve")
            root_usage = sources["coordinator"]["evidence"]["usage"]
            root_reservation = {dimension:0 for dimension in governor.LIMIT_DIMENSIONS}
            root_reservation.update(tokens=max(0,root_tokens-root_usage["totals"]["total_tokens"]),
                                    turns=max(0,2-len(root_usage["turn_ids"])))
            for lane,row in by_lane.items():
                usage = sources["workers"]["evidence"]["workers"][lane]["source"]["usage"]
                reservation = row["reservation"]
                if reservation["turns"] != 3 or reservation["children"] != 1:
                    raise ValueError("different worker lifecycle reserve")
                reservation.update(tokens=max(0,reservation["tokens"]-usage["totals"]["total_tokens"]),
                                   turns=max(0,3-len(usage["turn_ids"])),children=0)
            # Budget nodes reserve accounting capacity; this root node never
            # becomes a delegated worker or a native action. Reserve it first.
            requests.insert(0,{"node_id":"checkpoint-root-completion","dependencies":[],"reservation":root_reservation})
        program = {"schema":governor.BUDGET_PROGRAM_SCHEMA,
                   "program_id":"checkpoint-budget:" + receipt["receipt_sha256"][:32],
                   "plan_sha256":receipt["plan_sha256"], "budget_policy":deepcopy(frozen["budget_policy"]),
                   "runtime_window":{"status":"complete", "evidence_tier":"runtime-observed",
                                     "source_pointer":ingress["source_pointer"], "completed_node_ids":[]},
                   "runtime_records":[{"record_id":"checkpoint-consumption", "node_id":None, "kind":"controller_turn",
                                       "evidence_tier":"runtime-observed", "source_pointer":ingress["source_pointer"], "amounts":amounts}],
                   "admission_requests":requests}
        _bytes(program)
        if governor.evaluate_budget_program(program)["status"] != "BUDGET_UNKNOWN":
            raise ValueError("invalid checkpoint consumption")
        return program
    except _INVALID as error:
        raise ValueError("checkpoint_budget:input_invalid") from error


def build_checkpoint_reservation_program(logical_plan: Any, *, program_id: str,
                                         max_total_tokens: int, root_token_reserve: int,
                                         accounting_policy: Any = None) -> dict:
    """Reserve the two-worker lifecycle while preserving the total token cap.

    Two root turns and three turns per worker cover canary/control and
    acknowledgement/checkpoint/final work. The unallocated initial token share
    is reserved explicitly for root completion at the checkpoint. This declares
    allocations only; it supplies no runtime telemetry or monetary cost policy.
    """
    try:
        if (type(max_total_tokens) is not int or type(root_token_reserve) is not int
                or not 0 < root_token_reserve <= max_total_tokens-2):
            raise ValueError("invalid root token reserve")
        program = governor.build_budget_reservation_program(logical_plan,program_id=program_id,max_total_tokens=max_total_tokens)
        requests = program["admission_requests"]
        if len(requests) != 2 or {row["node_id"] for row in requests} != {"spec", "standards"}:
            raise ValueError("different checkpoint lanes")
        requests.sort(key=lambda row:row["node_id"])
        worker_tokens = max_total_tokens-root_token_reserve
        for index,row in enumerate(requests):
            row["reservation"].update(tokens=worker_tokens//2 + (worker_tokens%2 if index else 0),turns=3)
        program["budget_policy"]["limits"]["turns"] = 8
        if accounting_policy is not None:
            import orch_dork_qualification_budget as accounting
            if not accounting.validate_checkpoint_accounting_policy(accounting_policy):
                raise ValueError("invalid accounting policy")
            program["budget_policy"]["limits"].update(cost_microunits=2*max_total_tokens,
                hosted_calls=accounting_policy["root"]["max_responses"])
            for row in requests:row["reservation"]["cost_microunits"] = 2*row["reservation"]["tokens"]
        _bytes(program)
        if governor.evaluate_budget_program(program)["status"] != "PASS":
            raise ValueError("invalid lifecycle reservation")
        return program
    except _INVALID as error:
        raise ValueError("checkpoint_reservation:input_invalid") from error


def validate_checkpoint_reservation_program(program: Any, logical_plan: Any, *, accounting_policy: Any = None) -> bool:
    """Rebuild the exact declared reservation; no observation is inferred."""
    try:
        _bytes(program)
        total = program["budget_policy"]["limits"]["tokens"]
        root_tokens = total-sum(row["reservation"]["tokens"] for row in program["admission_requests"])
        expected = build_checkpoint_reservation_program(logical_plan,program_id=program["program_id"],
            max_total_tokens=total,root_token_reserve=root_tokens,accounting_policy=accounting_policy)
        return _bytes(program) == _bytes(expected)
    except _INVALID:
        return False


def build_checkpoint_stage_program(identity: Any, predecessor_report: Any, sources: Any) -> dict:
    """Compose the first checkpoint from whole sources and frozen reservation.

    Unobserved budget dimensions remain unknown and require the existing stop
    path. This constructor does not choose a cost policy or grant continuation.
    Components are individually bounded; the consuming controller applies its
    unchanged whole-program transport ceiling.
    """
    import orch_dork_governed_attempt as attempt
    try:
        for value in (identity, predecessor_report, sources):_bytes(value)
        issues = []
        identity = attempt._validate_identity(identity, issues)
        receipt = attempt._capacity_settlement_predecessor(identity, predecessor_report, issues)
        if (issues or receipt["stage"] != "worker_start"
                or receipt["bindings"].get("worker_checkpoint_profile") != attempt.WORKER_CHECKPOINT_PROFILE):
            raise ValueError("invalid first checkpoint predecessor")
        reports = [sources["workers"]["evidence"]["workers"][lane]["progress_report"] for lane in ("spec", "standards")]
        return {"schema":attempt.PROGRAM_SCHEMA, "operation":"progress", "identity":deepcopy(dict(identity)),
                "predecessor_receipt":deepcopy(dict(receipt)),
                "payload":{"progress_program":build_checkpoint_progress_program(receipt, reports),
                    "budget_program":build_checkpoint_budget_program(receipt, sources), "tool_events":[],
                    "ingress_observation":build_checkpoint_ingress_observation(identity, sources["coordinator"], sources["workers"]),
                    "checkpoint_sources":deepcopy(sources)}}
    except _INVALID as error:
        raise ValueError("checkpoint_stage:input_invalid") from error


__all__ = ["SUBMISSION_SCHEMA", "REPORT_SCHEMA", "build_worker_progress_report", "validate_worker_progress_report",
           "build_checkpoint_progress_program", "build_checkpoint_ingress_observation", "build_checkpoint_budget_program",
           "build_checkpoint_stage_program", "build_checkpoint_reservation_program", "validate_checkpoint_reservation_program"]
