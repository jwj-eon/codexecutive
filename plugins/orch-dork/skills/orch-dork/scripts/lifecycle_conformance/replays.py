"""Immutable historical metadata and causal, provider-free model replays.

The corpus binds historical claims; it does not reconstruct missing artifacts
or re-run an old live attempt. Raw host references are never opened. Normalized
choices exercise the public reference model, not the original host validators.
The unchanged cumulative legacy fixture remains a separately tested contract.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

from lifecycle_conformance import fragment, reference_model as rm
from lifecycle_conformance import reference_values as rv, registries, values

SCHEMA = "orch-dork/lifecycle-historical-corpus/v1"
REPORT_SCHEMA = "orch-dork/lifecycle-historical-replay/v1"
OWNER = "issue-167"
CORPUS_DIGEST = "f14341bf7c6cfbc0d79e79aad4abeff4dc88d094510c6d97949e8b70e5ec99e0"
LEGACY_DIGEST = "f993c1cc533527e20d3d25279d65c3059906a8b0de47c24f5c78481e46ce123b"
ROOT = Path(__file__).resolve().parents[4]
CORPUS_PATH = ROOT / "skills/orch-dork/runtime/lifecycle-conformance/cycles-01-36.json"
LEGACY_PATH = ROOT / "skills/orch-dork/runtime/qualification-rehearsal-replays-v1.json"
MAX_BYTES = 1048576


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("historical_replay:" + reason)


def _json_types(value: object, depth: int = 0) -> None:
    if depth > 24:
        _refuse("malformed")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _refuse("malformed")
            _json_types(item, depth + 1)
    elif type(value) is list:
        for item in value:
            _json_types(item, depth + 1)
    elif type(value) is float:
        if not math.isfinite(value):
            _refuse("malformed")
    elif type(value) not in (str, int, bool, type(None)):
        _refuse("malformed")


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("duplicate_key")
        result[key] = value
    return result


def _decode(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        _refuse("size_or_type")
    try:
        result = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: _refuse("malformed"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, values.LifecycleContractError):
            raise
        _refuse("malformed")
    _json_types(result)
    if type(result) is not dict:
        _refuse("malformed")
    return result


def _read(path: Path) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        _refuse("size_or_type")
    return raw


def validate_corpus(corpus: object, legacy_bytes: bytes) -> rv.FrozenValue:
    """Validate detached JSON against a source-pinned historical identity.

    There is no caller-supplied digest to reseal. A new historical corpus is a
    reviewed source change. The exact legacy file and each referenced canonical
    case must agree, including its original schema, failure stage and code.
    """
    _json_types(corpus)
    if type(corpus) is not dict or set(corpus) != {"schema", "source_inventory_sha256", "cycles"}:
        _refuse("malformed")
    if corpus["schema"] != SCHEMA or type(corpus["cycles"]) is not list:
        _refuse("malformed")
    rows = corpus["cycles"]
    if len(rows) != 36 or any(type(row) is not dict or type(row.get("cycle")) is not int
                              or row["cycle"] != index for index, row in enumerate(rows, 1)):
        _refuse("cycle_inventory")
    if values.canonical_digest(corpus) != CORPUS_DIGEST:
        _refuse("historical_identity")
    if type(legacy_bytes) is not bytes or hashlib.sha256(legacy_bytes).hexdigest() != LEGACY_DIGEST:
        _refuse("legacy_identity")
    legacy = _decode(legacy_bytes)
    cases = {item["case_id"]: item for item in legacy["cases"]}
    for row in rows:
        ref = row["evidence"]["legacy_ref"]
        if ref is None:
            continue
        old = cases.get(ref["case_id"])
        if (old is None or values.canonical_digest(old) != ref["canonical_case_sha256"]
                or old["schema"] != ref["schema"] or ref["corpus_sha256"] != LEGACY_DIGEST
                or old["failure_stage"] != row["failure"]["stage"]
                or old["failure_code"] != row["failure"]["code"]):
            _refuse("legacy_reference")
    return rv.freeze(corpus)


def load_corpus(path: Path = CORPUS_PATH, *, legacy_path: Path = LEGACY_PATH) -> rv.FrozenValue:
    """Read only the explicit corpus and tracked legacy fixture, never host refs."""
    return validate_corpus(_decode(_read(path)), _read(legacy_path))


def _choice(event: dict) -> dict:
    if "target" in event:
        return {"target": event["target"]}
    return {key: event[key] for key in ("stage", "lane", "outcome", "variant")}


def _replay(row: dict) -> tuple[dict, dict]:
    case = row["case_id"]
    state = rm.initial_state(case)
    normalized = row["normalized"]
    last_record, last_id, before = None, None, state
    for choice in normalized["choices"]:
        candidates = [event for event in rm.outgoing_stimuli(state).to_plain()
                      if _choice(event) == choice]
        if len(candidates) != 1:
            _refuse("observation_unreachable")
        event = candidates[0]
        records = rm.registry_snapshot(state).to_plain()
        if event["transition"] not in records:
            _refuse("mapping_unregistered")
        before = state
        reduced = rm.reduce(state, event).to_plain()
        if reduced["transition_id"] != event["transition"]:
            _refuse("mapping_mismatch")
        last_id = reduced["transition_id"]
        last_record = records[last_id]
        state = rv.freeze(reduced["successor"])
    if normalized["mode"] == "guard_refusal":
        before = state
        event = rm.outgoing_stimuli(state).to_plain()[0]
        # This is an abstract custody guard, not reconstructed historical input.
        event["unadmitted_historical_observation"] = row["failure"]["code"]
        try:
            rm.reduce(state, event)
        except values.LifecycleContractError:
            pass
        else:
            _refuse("guard_did_not_refuse")
        if state.digest() != before.digest():
            _refuse("guard_mutated_state")
        last_id = "lc-inv:issue-167:" + case
        last_record = {"kind": "state", "class": "protocol_custody",
                       "assertion": "unadmitted observation refuses without state change"}
    if last_id != normalized["mapping"] or last_record is None:
        _refuse("mapping_mismatch")
    expected_stage = before.to_plain().get("stage", "activate")
    if expected_stage != normalized["stage"]:
        _refuse("stage_mismatch")
    if row["cycle"] == 36:
        prior, after = before.to_plain(), state.to_plain()
        action = rm.legal_directive(before).to_plain()["payload"]["action"]
        if (prior["lanes"]["spec"]["typed_result"] is None
                or action["lane"] != "standards" or action["method"] != "send_input"
                or prior["grants"][action["grant"]] != "authorized"
                or after["lanes"]["standards"]["typed_result"] is not None
                or after["outcome"] != "failure"):
            _refuse("continuation_facts")
    report = {"cycle": row["cycle"], "case_id": case,
              "generation": row["generation"], "failure": row["failure"],
              "availability": row["evidence"]["availability"],
              "observations": row["observations"], "mapping": last_id,
              "before_sha256": before.digest(), "after_sha256": state.digest(),
              "directive": rm.legal_directive(state).to_plain(),
              "historical_record_sha256": values.canonical_digest(row),
              "historical_claims_verified": "pinned metadata and tracked legacy bytes only",
              "model_observation": normalized["rationale"],
              "original_host_validator_reexecuted": False}
    return report, last_record


def replay(corpus: rv.FrozenValue | None = None, *, legacy_bytes: bytes | None = None,
           shard_index: int = 0, shard_count: int = 1) -> dict:
    """Replay pinned records; shards filter the same ordered cycle inventory.

    Registry coverage cites actual reduced transitions or exercised refusal
    invariants. It never claims the original host regression was re-executed.
    Explicit in-memory input also requires the legacy bytes; a FrozenValue is
    data, not evidence that its caller ran load_corpus. Issue 168 owns host
    fixtures; Issue 170 merges these slice-owned fragments.
    """
    if (type(shard_index) is not int or type(shard_count) is not int
            or not 1 <= shard_count <= 36 or not 0 <= shard_index < shard_count):
        _refuse("shard")
    if corpus is None:
        if legacy_bytes is not None:
            _refuse("legacy_without_corpus")
        bound = load_corpus()
    else:
        if type(corpus) is not rv.FrozenValue:
            _refuse("historical_identity")
        bound = validate_corpus(corpus.to_plain(), legacy_bytes)
    rows = bound.to_plain()["cycles"]
    store = registries.RegistryStore()
    reports, entries = [], []
    for row in rows:
        if (row["cycle"] - 1) % shard_count != shard_index:
            continue
        report, record = _replay(row)
        reports.append(report)
        mapping = report["mapping"]
        store.add(mapping.split(":")[0], mapping, OWNER, record)
        replay_id = "lc-replay:issue-167:" + row["case_id"]
        store.add("lc-replay", replay_id, OWNER,
                  {"cycle": row["cycle"], "record_sha256": report["historical_record_sha256"],
                   "mapping": mapping, "availability": report["availability"]})
        for item_id, strength in ((mapping, "direct"), (replay_id, "evidence")):
            entries.append({"id": [item_id], "status": "covered",
                            "cases": [{"id": row["case_id"], "strength": strength}], "rationale": ""})
    coverage = fragment.build_fragment(OWNER, values.vocabulary_digest(), store.digest(), entries)
    validation = fragment.validate_fragment(coverage, owner=OWNER, store=store)
    return {"schema": REPORT_SCHEMA, "status": "PASS", "corpus_sha256": CORPUS_DIGEST,
            "legacy_sha256": LEGACY_DIGEST, "shard": {"index": shard_index, "count": shard_count},
            "cycles": reports, "registry": {kind: store.items_of(kind) for kind in store.kinds()},
            "coverage": coverage, "coverage_validation": validation,
            "boundary": {"provider_free": True, "host_artifacts_opened": False,
                         "live_authority": False, "qualification_receipt": False}}


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
