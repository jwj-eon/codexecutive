"""Replay pinned host and public-constructor fixtures into shared coverage.

The optional CLI writes only an explicitly named coverage file. POSIX capture
is separate: replay neither opens host artifacts nor creates a process/task.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from lifecycle_conformance import fragment, host_adapter as host, production_adapter as production
from lifecycle_conformance import reference_values as rv, registries, values

OWNER = "issue-168"
ROOT = Path(__file__).resolve().parents[4]
FIXTURES = ROOT / "skills/orch-dork/runtime/lifecycle-conformance"
HOST_DIGEST = "0b5082b172de651d6c11ac62025b4cdb1253d99e54218f3d0d8e69052b98686c"
ADAPTER_DIGEST = "633d7ecf8fc6120401018d7b0f78afd5b3fee0e5dbaea525d1f74151a6257256"
MAX_CORPUS_BYTES = 4_000_000
LEGACY_OBSERVATIONS = (
    "tool_name", "response", "newline_frame", "javascript_globals", "environment",
    "owned_file", "hook_inventory", "session_start", "permission", "pty",
)


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("host_fixtures:" + reason)


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("duplicate_key")
        result[key] = value
    return result


def _read(path: Path) -> rv.FrozenValue:
    with path.open("rb") as handle:
        raw = handle.read(MAX_CORPUS_BYTES + 1)
    if len(raw) > MAX_CORPUS_BYTES:
        _refuse("size")
    try:
        data = json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: _refuse("nonfinite"))
        return rv.freeze(data)
    except (ValueError, RecursionError, UnicodeError):
        _refuse("json")


def validate_corpora(host_corpus: rv.FrozenValue, adapter_corpus: rv.FrozenValue) -> None:
    if (type(host_corpus) is not rv.FrozenValue or type(adapter_corpus) is not rv.FrozenValue
            or host_corpus.digest() != HOST_DIGEST or adapter_corpus.digest() != ADAPTER_DIGEST):
        _refuse("identity")
    hosts = host_corpus.to_plain()
    adapters = adapter_corpus.to_plain()
    if (hosts["schema"] != "orch-dork/codex-host-fixture-corpus/v1"
            or adapters["schema"] != "orch-dork/production-adapter-fixture-corpus/v1"
            or {row["kind"] for row in hosts["cases"]} != set(LEGACY_OBSERVATIONS)):
        _refuse("inventory")
    ids = [row["id"] for row in hosts["cases"] + adapters["cases"]]
    if len(ids) != len(set(ids)) or len(ids) != 59:
        _refuse("inventory")
    for row in hosts["cases"] + adapters["cases"]:
        if (values.canonical_digest(row["raw_input"]) != row["raw_input_sha256"]
                or values.canonical_digest(row["raw_output"]) != row["raw_output_sha256"]):
            _refuse("raw_binding")


def load_corpora(root: Path = FIXTURES) -> tuple[rv.FrozenValue, rv.FrozenValue]:
    hosts = _read(root / "codex-linux-0.153.4.json")
    adapters = _read(root / "activation-preparation.json")
    validate_corpora(hosts, adapters)
    return hosts, adapters


def replay(host_corpus: rv.FrozenValue | None = None, adapter_corpus: rv.FrozenValue | None = None,
           *, shard_index: int = 0, shard_count: int = 1) -> dict:
    if (type(shard_index) is not int or type(shard_count) is not int
            or not 1 <= shard_count <= 59 or not 0 <= shard_index < shard_count):
        _refuse("shard")
    if host_corpus is None and adapter_corpus is None:
        host_corpus, adapter_corpus = load_corpora()
    validate_corpora(host_corpus, adapter_corpus)
    hosts, adapters = host_corpus.to_plain(), adapter_corpus.to_plain()
    store = registries.RegistryStore()
    entries, results = [], []
    jobs = [("lc-fix", row) for row in hosts["cases"]] + [("lc-pair", row) for row in adapters["cases"]]
    for index, (kind, row) in enumerate(jobs):
        if index % shard_count != shard_index:
            continue
        if kind == "lc-fix":
            adapter = host.CodexHostAdapter(row["host_profile"])
            try:
                observed = {"decision": "ACCEPTED", "value": adapter.normalize(row["kind"], row["raw_input"])}
            except values.LifecycleContractError as exc:
                observed = {"decision": "REFUSED", "reason": exc.reason}
            if (observed["decision"] != row["expected_disposition"]
                    or (observed["decision"] == "ACCEPTED"
                        and values.canonical_digest(observed["value"]) != values.canonical_digest(row["expected_canonical"]))):
                _refuse("canonical_observation")
            registration = {"host_profile_sha256": values.canonical_digest(row["host_profile"]),
                            "observation_kind": row["kind"], "origin": row["origin"],
                            "raw_input_sha256": row["raw_input_sha256"], "raw_output_sha256": row["raw_output_sha256"]}
        else:
            observed = production.ProductionLifecycleAdapter.prepare_activation(**row["raw_input"])
            validation = production.native.validate_activation_preparation_report(observed)
            if validation.get("valid") is not True or observed.get("status") != row["expected_status"]:
                _refuse("constructor_validator")
            registration = {"constructor": row["constructor"], "validator": row["validator"],
                            "status_branch": row["expected_status"], "report_sha256": row["raw_output_sha256"]}
        if values.canonical_digest(observed) != row["raw_output_sha256"]:
            _refuse("raw_output")
        item = kind + ":issue-168:" + row["id"]
        store.add(kind, item, OWNER, registration)
        case = "host-" + row["id"]
        entries.append({"id": [item], "status": "covered", "cases": [{"id": case, "strength": "direct"}], "rationale": ""})
        results.append({"case": case, "item": item, "observation_sha256": values.canonical_digest(observed), "status": "PASS"})
    coverage = fragment.build_fragment(OWNER, values.vocabulary_digest(), store.digest(), entries)
    verified = fragment.validate_fragment(coverage, owner=OWNER, store=store)
    return {"schema": "orch-dork/host-adapter-conformance/v1", "status": "PASS",
            "digests": {"host_corpus": HOST_DIGEST, "adapter_corpus": ADAPTER_DIGEST},
            "cases": results, "registry": {kind: store.items_of(kind) for kind in store.kinds()},
            "coverage": coverage, "coverage_validation": verified,
            "boundary": {"fixture_replay_only": True, "physical_calls": 0, "authority_created": False,
                         "host_observation_kinds": list(LEGACY_OBSERVATIONS),
                         "current_host_vocabulary_complete": set(LEGACY_OBSERVATIONS) == set(host.OBSERVATIONS),
                         "all_public_constructor_pairs_closed": False}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-coverage", type=Path)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    args = parser.parse_args()
    result = replay(shard_index=args.shard_index, shard_count=args.shard_count)
    if args.write_coverage:
        args.write_coverage.write_text(json.dumps(result["coverage"], indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
