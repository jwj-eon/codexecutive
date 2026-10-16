"""Deterministic local CPU execution of bound interruption contexts.

The host must bound this process group and observe its exit/cleanup. Reports
here attest neither exhaustive graph preparation nor production conformance.
They cannot authorize qualification. POSIX fork avoids the detached tracker
left by the spawn pool in the preserved Issue 170 development failure.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import os
import threading

from lifecycle_conformance import cartesian, reference_values as rv, values

# Capacity ceilings, not assertions about the model's expected coverage.
MAX_CONTEXTS = 131072
MAX_CASES = 4194304
MAX_WORKERS = 16
MAX_PENDING_PER_WORKER = 2
SCHEMA = "orch-dork/interruption-matrix-shard/v1"


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("matrix_runner:" + reason)


def _plan(contexts, shard_index, shard_count):
    if (type(contexts) is not list or not 1 <= len(contexts) <= MAX_CONTEXTS
            or type(shard_count) is not int or not 1 <= shard_count <= len(contexts)
            or type(shard_index) is not int or not 0 <= shard_index < shard_count):
        _refuse("plan")
    bound, cases = {}, set()
    for context in contexts:
        if type(context) is not rv.FrozenValue:
            _refuse("context_type")
        data = context.to_plain()
        if type(data) is not dict or "state" not in data or "event" not in data:
            _refuse("context_shape")
        if cartesian.context_for(rv.freeze(data["state"]), data["event"]) != context:
            _refuse("context_binding")
        # Bound the retained ID inventory across the whole plan, including
        # unselected shards, before allocating or extending another ID list.
        if len(data["instances"]) > MAX_CASES - len(cases):
            _refuse("case_limit")
        ids = [row["case"] for row in data["instances"]]
        if data["id"] in bound or len(ids) != len(set(ids)) or cases.intersection(ids):
            _refuse("duplicate")
        cases.update(ids)
        bound[data["id"]] = context
    ordered = [bound[key] for key in sorted(bound)]
    selected = ordered[shard_index::shard_count]
    plan_sha = values.canonical_digest([value.digest() for value in ordered])
    return selected, plan_sha


def _execute(data):
    # FrozenValue intentionally cannot be reconstructed by pickle.
    return cartesian.execute_context(rv.freeze(data)).to_plain()


def _check_result(context, result):
    data = context.to_plain()
    if (type(result) is not dict
            or set(result) != {"schema", "status", "context", "context_sha256", "cases",
                               "physical_dispatches", "qualification_authorized"}
            or result["schema"] != "orch-dork/lifecycle-injection-context-result/v1"
            or result["status"] != "PASS" or result["context"] != data["id"]
            or result["context_sha256"] != context.digest()
            or type(result["physical_dispatches"]) is not int or result["physical_dispatches"] != 0
            or result["qualification_authorized"] is not False or type(result["cases"]) is not list
            or len(result["cases"]) != len(data["instances"])):
        _refuse("result_binding")
    for expected, actual in zip(data["instances"], result["cases"]):
        job = expected["job"]
        if (type(actual) is not dict
                or set(actual) != {"case", "context", "base_case", "site", "failure", "timing", "proof"}
                or actual["case"] != expected["case"] or actual["context"] != data["id"]
                or actual["base_case"] != job["id"]
                or any(actual[key] != job[key] for key in ("site", "failure", "timing"))):
            _refuse("case_binding")
        proof = actual["proof"]
        retained_release = (job['timing'] == 'before' and job['site'].startswith('lc-mut:')
                            and data['event'].get('stage') == 'settle'
                            and data['event'].get('lane') == 'controller'
                            and data['event'].get('variant') == 'sealed_release'
                            and data['state'].get('stage') == 'review'
                            and type(data['state'].get('requirement')) is dict
                            and data['state']['requirement'].get('stage') == 'review')
        if (type(proof) is not dict
                or set(proof) != {"status", "case", "trace_sha256", "invariants", "effects_at_cut",
                                  "final_kind", "model_transitions", "physical_dispatches"}
                or proof["status"] != "PASS" or proof["case"] != job["id"]
                or type(proof["trace_sha256"]) is not str or len(proof["trace_sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in proof["trace_sha256"])
                or proof["invariants"] != list(values.INVARIANT_CLASSES)
                or type(proof["effects_at_cut"]) is not int
                or proof["effects_at_cut"] != int(job["timing"] == "after")
                or proof["final_kind"] not in ("terminal_closure", "external_authority_required")
                or type(proof["model_transitions"]) is not int
                or not (0 if retained_release else 1) <= proof["model_transitions"] <= 40
                or (proof['model_transitions'] == 0 and proof['final_kind'] != 'external_authority_required')
                or type(proof["physical_dispatches"]) is not int or proof["physical_dispatches"] != 0):
            _refuse("proof_binding")


def run(contexts: list[rv.FrozenValue], *, workers: int = 1, shard_index: int = 0,
        shard_count: int = 1, emit=None) -> rv.FrozenValue:
    """Execute one exact partition; emit each checked whole result in ID order.

All inputs are validated before a pool starts. Emit failure propagates, and the
owned pool is joined before returning or raising. An outer host deadline remains
required for a stuck worker. No network, model, or qualification operation occurs.
Only the dispatch window is streamed: input contexts, duplicate-check inventories
and final summaries remain in memory, bounded by MAX_CONTEXTS and MAX_CASES.
An emitted prefix is not a completed shard; acceptance requires the return value.
"""
    if (type(workers) is not int or not 1 <= workers <= MAX_WORKERS
            or (emit is not None and not callable(emit))):
        _refuse("execution_options")
    if workers > 1 and (os.name != "posix" or threading.active_count() != 1):
        _refuse("fork_host")
    selected, plan_sha = _plan(contexts, shard_index, shard_count)
    summaries, case_ids = [], []
    terminal = external = 0

    def collect(context, result):
        nonlocal terminal, external
        _check_result(context, result)
        frozen = rv.freeze(result)
        ids = [row["case"] for row in result["cases"]]
        case_ids.extend(ids)
        terminal += sum(row["proof"]["final_kind"] == "terminal_closure" for row in result["cases"])
        external += sum(row["proof"]["final_kind"] == "external_authority_required" for row in result["cases"])
        summaries.append({"context": result["context"], "context_sha256": context.digest(),
                          "result_sha256": frozen.digest(), "cases": len(ids),
                          "case_inventory_sha256": values.canonical_digest(sorted(ids))})
        if emit is not None:
            emit(frozen)

    if workers == 1:
        for context in selected:
            collect(context, _execute(context.to_plain()))
    else:
        with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("fork")) as pool:
            remaining, pending = iter(selected), deque()

            def submit_next():
                context = next(remaining, None)
                if context is not None:
                    pending.append((context, pool.submit(_execute, context.to_plain())))

            try:
                for _ in range(min(len(selected), workers * MAX_PENDING_PER_WORKER)):
                    submit_next()
                while pending:
                    context, future = pending.popleft()
                    # Drain in ID order even when later work finishes first.
                    # Refill only after validation AND the sink have succeeded.
                    collect(context, future.result())
                    del future
                    submit_next()
            finally:
                # Cancel work that has not started on validation, worker, or
                # sink failure. The context manager still joins every worker.
                for _, future in pending:
                    future.cancel()
    if len(summaries) != len(selected):
        _refuse("incomplete_partition")
    return rv.freeze({"schema": SCHEMA, "status": "PASS", "plan_sha256": plan_sha,
                      "shard": {"index": shard_index, "count": shard_count}, "contexts": summaries,
                      "case_count": len(case_ids), "case_inventory_sha256": values.canonical_digest(sorted(case_ids)),
                      "terminal_cases": terminal, "external_requirement_cases": external,
                      "physical_dispatches": 0, "qualification_authorized": False})
