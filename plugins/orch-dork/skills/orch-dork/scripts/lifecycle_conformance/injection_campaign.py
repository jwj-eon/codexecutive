"""Execute the registry-derived minimal injection matrix and coverage fragment.

All registered semantic sites and applicable failure classes run at both cuts.
Every trace is independently replayed by the oracle. This is the Issue 169
slice; Issue 170 owns the Cartesian product with all model/production states.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from lifecycle_conformance import failure_injection as inject, injection_oracle as oracle
from lifecycle_conformance import injection_sites as sites, fragment, registries, values
from lifecycle_conformance import reference_values as rv


def run(*, shard_index: int = 0, shard_count: int = 1, store: registries.RegistryStore | None = None) -> dict:
    if store is None:
        store = sites.site_registry()
    inventory = sites.inventory(store).to_plain()
    jobs = sites.schedule(store).to_plain()
    if (type(shard_index) is not int or type(shard_count) is not int
            or not 1 <= shard_count <= len(jobs) or not 0 <= shard_index < shard_count):
        sites.refuse("shard")
    states = inject.minimal_states().to_plain()
    results = []
    coverage_store = registries.RegistryStore()
    case_map = {}

    def record(kind: str, item: str, row: dict, case: str) -> None:
        if item not in case_map:
            coverage_store.add(kind, item, sites.OWNER, row)
            case_map[item] = []
        case_map[item].append(case)

    for index, job in enumerate(jobs):
        if index % shard_count != shard_index:
            continue
        row = inventory[job["site"]]
        key = row["stage"] + ":" + row["lane"]
        if key not in states:
            sites.refuse("uncovered_site")
        state = rv.freeze(states[key])
        event = inject.accepted_event(state, row["lane"])
        trace = inject.run_case(store, job, state, event)
        verified = oracle.verify_trace(store, trace).to_plain()
        result = {**verified, "site": job["site"], "failure": job["failure"], "timing": job["timing"]}
        results.append(result)
        record(job["site"].split(":")[0], job["site"], row, job["id"])
        for invariant in verified["invariants"]:
            record("lc-inv", f"lc-inv:{sites.OWNER}:{invariant}",
                   {"kind": "closure" if invariant == "no_stranded_resource" else "trace", "class": invariant}, job["id"])
        record("lc-inv", f"lc-inv:{sites.OWNER}:failure.{job['failure']}",
               {"kind": "trace", "class": "protocol_custody", "failure_class": job["failure"]}, job["id"])
    if shard_count == 1:
        sites.validate_case_union(store, [r["case"] for r in results])
    entries = [{"id": [item], "status": "covered", "cases": [{"id": case, "strength": "direct"} for case in cases],
                "rationale": ""} for item, cases in sorted(case_map.items())]
    coverage = fragment.build_fragment(sites.OWNER, values.vocabulary_digest(), coverage_store.digest(), entries)
    validation = fragment.validate_fragment(coverage, owner=sites.OWNER, store=coverage_store)
    return {"schema": "orch-dork/lifecycle-injection-campaign/v1", "status": "PASS",
            "sites_sha256": sites.inventory(store).digest(), "schedule_sha256": sites.schedule(store).digest(),
            "site_count": len(inventory), "matrix_count": len(jobs), "cases": results,
            "registry": {kind: coverage_store.items_of(kind) for kind in coverage_store.kinds()},
            "coverage": coverage, "coverage_validation": validation,
            "boundary": {"minimal_contract_traces": True, "all_reachable_states": False,
                         "production_seams_bound": False, "physical_dispatches": 0}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--write-coverage", type=Path)
    args = parser.parse_args()
    report = run(shard_index=args.shard_index, shard_count=args.shard_count)
    if args.write_coverage:
        args.write_coverage.write_text(json.dumps(report["coverage"], sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
