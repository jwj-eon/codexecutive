"""Semantic lifecycle cut points, shared by the injector and later integration.

Sites name public observation boundaries, never private Python lines. A durable
site commits one whole model observation atomically. An external site records
one possibly dispatched effect before its observation is reconciled. Issue 170
binds these abstract sites to production seams and all reachable model states.
"""
from __future__ import annotations

from lifecycle_conformance import protocol, registries, values
from lifecycle_conformance import reference_values as rv

OWNER = "issue-169"
TIMINGS = ("before", "after")


def refuse(reason: str) -> None:
    raise values.LifecycleContractError("injection_sites:" + reason)


def failure_classes(kind: str, site_class: str, stage: str) -> list[str]:
    selected = {"process_interruption", "owner_mismatch"}
    if site_class in ("hook_durability_record", "host_task_start") or kind == "lc-act":
        selected.update(("hook_missing", "hook_refused"))
    if stage.startswith(("grant.", "spawn.", "continue.", "close.")):
        selected.update(("grant_stale", "capacity_stale"))
    if stage.startswith("spawn."):
        selected.add("partial_spawn")
    if stage == "ack":
        selected.add("acknowledgement_missing")
    if stage.startswith("continue."):
        selected.update(("continuation_success", "continuation_failed", "continuation_unknown",
                         "continuation_not_dispatched", "typed_result_invalid"))
    if stage.startswith(("result.", "checkpoint.")) or stage == "progress":
        selected.add("typed_result_invalid")
    if stage == "review":
        selected.add("sol_review_failed")
    if stage in ("verify", "final_qualification", "failure_closure"):
        selected.add("terminal_verification_failed")
    if stage in ("cleanup", "close.spec", "close.standards", "process", "settle", "rotate"):
        selected.add("cleanup_failed")
    return [name for name in values.FAILURE_CLASSES if name in selected]


def _add(store: registries.RegistryStore, kind: str, site_class: str, stage: str, lane: str) -> None:
    item = f"{kind}:{OWNER}:{site_class}.{stage}.{lane}"
    store.add(kind, item, OWNER, {"class": site_class, "stage": stage, "lane": lane,
                                 "failures": failure_classes(kind, site_class, stage)})


def site_registry() -> registries.RegistryStore:
    """Fresh complete registry for the minimal semantic boundary campaign."""
    store = registries.RegistryStore()
    for stage in protocol.STAGES.to_plain():
        if stage == "terminal":
            continue
        lanes = values.LANES if stage in ("ack", "cleanup") else (
            (stage.split(".")[1],) if "." in stage else ("controller",))
        for lane in lanes:
            mutations = ["controller_event_commit"]
            if stage.startswith(("grant.", "spawn.", "continue.", "close.")) or stage in ("review", "progress", "settle", "rotate"):
                mutations.append("grant_transition")
            if stage.startswith(("grant.", "spawn.")) or stage == "settle":
                mutations.append("capacity_reserve_release")
            if stage == "activate" or protocol.STAGES.to_plain()[stage][1] == "action":
                mutations.append("hook_durability_record")
            if stage.startswith(("result.", "checkpoint.", "continue.")) or stage in ("activate", "ack", "progress", "aggregate", "review", "verify", "final_qualification", "failure_closure"):
                mutations.append("artifact_receipt_creation")
            if stage in ("final_qualification", "failure_closure"):
                mutations.append("terminal_commit")
            if stage.startswith("close.") or stage in ("process", "settle"):
                mutations.append("cleanup_evidence")
            if stage == "rotate":
                mutations += ["terminal_commit", "owner_rotation"]
            for site_class in mutations:
                _add(store, "lc-mut", site_class, stage, lane)
            external = None
            if stage == "activate": external = "host_task_start"
            elif stage.startswith("spawn."): external = "spawn"
            elif stage == "ack": external = "acknowledgement_observation"
            elif stage.startswith("continue."): external = "continuation"
            elif stage.startswith(("result.", "checkpoint.")): external = "typed_result_observation"
            elif stage == "review": external = "sol_review"
            elif stage in ("verify", "final_qualification", "failure_closure"): external = "terminal_observation"
            elif stage.startswith("close."): external = "worker_closure"
            elif stage == "process": external = "process_interruption"
            elif stage == "cleanup": external = "cleanup"
            if external:
                _add(store, "lc-act", external, stage, lane)
    return store


def inventory(store: registries.RegistryStore) -> rv.FrozenValue:
    """Validate every supplied site, including newly registered semantic sites."""
    if type(store) is not registries.RegistryStore:
        refuse("registry")
    sites = {**store.items_of("lc-mut"), **store.items_of("lc-act")}
    if not sites:
        refuse("empty")
    for item, row in sites.items():
        kind = item.split(":")[0]
        if (set(row) != {"class", "stage", "lane", "failures"}
                or row["stage"] not in protocol.STAGES.to_plain() or row["stage"] == "terminal"
                or row["lane"] not in (*values.LANES, "controller")
                or row["failures"] != failure_classes(kind, row["class"], row["stage"])):
            refuse("record")
    return rv.freeze(sites)


def schedule(store: registries.RegistryStore) -> rv.FrozenValue:
    """Every registered site x each applicable class x both cuts, without gaps."""
    sites = inventory(store)
    binding = sites.digest()
    jobs = []
    for item, row in sites.to_plain().items():
        for failure in row["failures"]:
            for timing in TIMINGS:
                fields = {"site": item, "failure": failure, "timing": timing, "sites_sha256": binding}
                jobs.append({"id": "inject-" + values.canonical_digest(fields)[:32], **fields})
    return rv.freeze(jobs)


def validate_job(store: registries.RegistryStore, job: object) -> dict:
    if type(job) is not dict or set(job) != {"id", "site", "failure", "timing", "sites_sha256"}:
        refuse("job")
    sites = inventory(store)
    row = sites.to_plain().get(job["site"]) if type(job["site"]) is str else None
    if (row is None or job["sites_sha256"] != sites.digest() or job["failure"] not in row["failures"]
            or job["timing"] not in TIMINGS
            or job["id"] != "inject-" + values.canonical_digest({k: v for k, v in job.items() if k != "id"})[:32]):
        refuse("job")
    return row


def validate_case_union(store: registries.RegistryStore, case_ids: list[str]) -> None:
    """A new site, omitted timing/class, duplicated shard or stale job refuses."""
    expected = {job["id"] for job in schedule(store).to_plain()}
    if type(case_ids) is not list or any(type(case) is not str for case in case_ids):
        refuse("case_union")
    if len(case_ids) != len(set(case_ids)) or set(case_ids) != expected:
        refuse("case_union")
