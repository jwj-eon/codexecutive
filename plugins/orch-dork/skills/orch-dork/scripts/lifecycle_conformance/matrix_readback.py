"""Bounded matrix output integrity against an independently frozen inventory.

This checks recorded data, not independent invariant proofs, authenticated host
execution, production coverage or final executed shard union. Original traces
are absent from runner output; well-shaped proof claims are not replayed here.
The coordinator owns the provenance of the frozen expectations, artifact/source
digests, host custody and campaign integration. No output supplies its own plan.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator
import hashlib
import json
from typing import BinaryIO

from lifecycle_conformance import cartesian, reference_values as rv, values

# Explicit capacity ceilings, not expected model totals or host RSS guarantees.
MAX_CONTEXTS = 131072
MAX_CASES = 4194304
MAX_CASES_PER_CONTEXT = 4096
MAX_RECORD_BYTES = 1024 * 1024
MAX_CONTEXT_BYTES = 4 * 1024**3
MAX_OUTPUT_BYTES = 16 * 1024**3
MAX_INDEX_BYTES = 32 * 1024**2
MAX_REPORT_BYTES = 64 * 1024**2

_CONTEXT_SCHEMA = "orch-dork/lifecycle-injection-context/v1"
_RESULT_SCHEMA = "orch-dork/lifecycle-injection-context-result/v1"
_REPORT_SCHEMA = "orch-dork/interruption-matrix-shard/v1"


def _refuse(reason):
    raise values.LifecycleContractError("matrix_readback:" + reason)


def _integer(value, ceiling):
    return type(value) is int and 0 <= value <= ceiling


def _sha(value):
    return (type(value) is str and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _context_id(value):
    return type(value) is str and value.startswith("context170-") and _sha(value[11:])


def _plain(value, ceiling):
    if type(value) is not rv.FrozenValue:
        _refuse("frozen_value")
    data = value.to_plain()
    encoded = values.canonical_json(data)
    # The canonical encoder emits ASCII, so character count is byte count.
    if len(encoded) > ceiling:
        _refuse("value_bytes")
    return data, len(encoded), hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _array_digest(items):
    """Exact canonical array digest without assembling a whole ID JSON string."""
    digest = hashlib.sha256(b"[")
    separator = b""
    for item in items:
        digest.update(separator)
        digest.update(values.canonical_json(item).encode("ascii"))
        separator = b","
    digest.update(b"]")
    return digest.hexdigest()


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("json_duplicate_key")
        result[key] = value
    return result


def _json_constant(value):
    _refuse("json_number")


def read_jsonl(stream: BinaryIO) -> Iterator[rv.FrozenValue]:
    """Yield only context/result FrozenValues from a caller-owned binary stream.

    Reads at most MAX_RECORD_BYTES+1 bytes per call. Blank, unterminated,
    oversized, duplicate-key and non-finite records refuse. Exhaustion is required;
    this iterator alone certifies no inventory. It never closes caller resources.
    """
    total = count = 0
    while True:
        line = stream.readline(MAX_RECORD_BYTES + 1)
        if type(line) is not bytes:
            _refuse("jsonl_binary_stream")
        if not line:
            return
        total += len(line)
        count += 1
        if (len(line) > MAX_RECORD_BYTES or total > MAX_OUTPUT_BYTES
                or count > MAX_CONTEXTS or not line.endswith(b"\n")):
            _refuse("jsonl_bound")
        try:
            data = json.loads(line.decode("utf-8"), object_pairs_hook=_json_object,
                              parse_constant=_json_constant)
        except (ValueError, UnicodeError, RecursionError):
            _refuse("jsonl_record")
        if type(data) is not dict or data.get("schema") not in (_CONTEXT_SCHEMA, _RESULT_SCHEMA):
            _refuse("jsonl_schema")
        yield rv.freeze(data)
        del data, line


def _prepare(contexts, frozen_index, index_sha, case_sha, shard_index, shard_count):
    if not _sha(index_sha) or not _sha(case_sha):
        _refuse("expectation_digest")
    index, _, digest = _plain(frozen_index, MAX_INDEX_BYTES)
    if (digest != index_sha or type(index) is not list
            or not 1 <= len(index) <= MAX_CONTEXTS):
        _refuse("expected_index")
    if (not _integer(shard_count, len(index)) or shard_count == 0
            or not _integer(shard_index, shard_count - 1)):
        _refuse("shard_options")
    expected, selected_ids = {}, set()
    previous, total_cases = "", 0
    for position, row in enumerate(index):
        if (type(row) is not dict or set(row) != {"context", "sha256", "cases"}
                or not _context_id(row["context"]) or row["context"] <= previous
                or not _sha(row["sha256"]) or not _integer(row["cases"], MAX_CASES_PER_CONTEXT)):
            _refuse("expected_index_row")
        previous = row["context"]
        total_cases += row["cases"]
        if total_cases > MAX_CASES:
            _refuse("case_limit")
        expected[previous] = row
        if position % shard_count == shard_index:
            selected_ids.add(previous)

    bound, all_cases, selected_cases = {}, set(), []
    total_bytes = 0
    for context in contexts:
        if len(bound) >= len(index):
            _refuse("context_inventory")
        data, size, digest = _plain(context, MAX_RECORD_BYTES)
        total_bytes += size
        if total_bytes > MAX_CONTEXT_BYTES:
            _refuse("context_bytes")
        if (type(data) is not dict
                or set(data) != {"schema", "id", "state", "event", "site_registry_sha256", "instances"}
                or data["schema"] != _CONTEXT_SCHEMA or not _context_id(data["id"])
                or data["id"] not in expected or data["id"] in bound):
            _refuse("context_inventory")
        row = expected[data["id"]]
        if (digest != row["sha256"] or type(data["instances"]) is not list
                or len(data["instances"]) != row["cases"]
                or cartesian.context_for(rv.freeze(data["state"]), data["event"]) != context):
            _refuse("context_binding")
        ids = [instance["case"] for instance in data["instances"]]
        if len(set(ids)) != len(ids) or not all_cases.isdisjoint(ids):
            _refuse("duplicate_case")
        all_cases.update(ids)
        if data["id"] in selected_ids:
            selected_cases.extend(ids)
        bound[data["id"]] = context
    if len(bound) != len(index) or len(all_cases) != total_cases:
        _refuse("context_inventory")
    if _array_digest(sorted(all_cases)) != case_sha:
        _refuse("case_inventory")
    plan_sha = _array_digest(row["sha256"] for row in index)
    selected_sha = case_sha if shard_count == 1 else _array_digest(sorted(selected_cases))
    return ([(bound[row["context"]], row) for row in index if row["context"] in selected_ids],
            plan_sha, selected_sha, len(selected_cases))


def _check_output(data, expected, context_sha):
    """Independent reader-side binding and shape checks; never execute a trace."""
    if (type(data) is not dict
            or set(data) != {"schema", "status", "context", "context_sha256", "cases",
                             "physical_dispatches", "qualification_authorized"}
            or data["schema"] != _RESULT_SCHEMA or data["status"] != "PASS"
            or data["context"] != expected["id"] or data["context_sha256"] != context_sha
            or not _integer(data["physical_dispatches"], 0) or data["qualification_authorized"] is not False
            or type(data["cases"]) is not list or len(data["cases"]) != len(expected["instances"])):
        _refuse("result_binding")
    terminal = external = 0
    for instance, actual in zip(expected["instances"], data["cases"]):
        job = instance["job"]
        if (type(actual) is not dict
                or set(actual) != {"case", "context", "base_case", "site", "failure", "timing", "proof"}
                or actual["case"] != instance["case"] or actual["context"] != expected["id"]
                or actual["base_case"] != job["id"]
                or any(actual[key] != job[key] for key in ("site", "failure", "timing"))):
            _refuse("case_binding")
        proof = actual["proof"]
        # A before-durable cut can retain this existing review barrier without
        # any model transition. Bind the exception to the independent context.
        retained_release = (
            job["timing"] == "before" and job["site"].startswith("lc-mut:")
            and expected["event"].get("stage") == "settle"
            and expected["event"].get("lane") == "controller"
            and expected["event"].get("variant") == "sealed_release"
            and expected["state"].get("stage") == "review"
            and type(expected["state"].get("requirement")) is dict
            and expected["state"]["requirement"].get("stage") == "review"
        )
        if (type(proof) is not dict
                or set(proof) != {"status", "case", "trace_sha256", "invariants", "effects_at_cut",
                                  "final_kind", "model_transitions", "physical_dispatches"}
                or proof["status"] != "PASS" or proof["case"] != job["id"]
                or not _sha(proof["trace_sha256"]) or proof["invariants"] != list(values.INVARIANT_CLASSES)
                or not _integer(proof["effects_at_cut"], 1)
                or proof["effects_at_cut"] != int(job["timing"] == "after")
                or proof["final_kind"] not in ("terminal_closure", "external_authority_required")
                or not _integer(proof["model_transitions"], 40)
                or (proof["model_transitions"] == 0
                    and (not retained_release or proof["final_kind"] != "external_authority_required"))
                or not _integer(proof["physical_dispatches"], 0)):
            _refuse("proof_binding")
        terminal += proof["final_kind"] == "terminal_closure"
        external += proof["final_kind"] == "external_authority_required"
    return terminal, external


def validate_output_integrity(expected_contexts: Iterable[rv.FrozenValue],
                              outputs: Iterable[rv.FrozenValue], matrix_report: rv.FrozenValue, *,
                              expected_index: rv.FrozenValue, expected_index_sha256: str,
                              expected_case_inventory_sha256: str,
                              shard_index: int = 0, shard_count: int = 1) -> rv.FrozenValue:
    """Return the unchanged runner report after exhausting exact bound inventories.

    expected_index is the frozen preparation index [{context, sha256, cases}]
    in strictly increasing context-ID order. Its digest and the global case-ID
    digest must come from an independent frozen preparation, never this output.
    expected_contexts and outputs are iterables of FrozenValues (read_jsonl can
    supply them). Expected contexts may arrive in any order; results must follow
    the runner's ID order for the independently specified shard, default (0, 1).

    Contexts/index/report and exact case IDs are count/byte bounded in memory;
    case-ID sorting uses O(MAX_CASES) references. Result bodies are consumed one
    at a time and not retained. Preconstructed FrozenValues have already been
    allocated by the caller; use read_jsonl to bound raw record decoding and an
    outer host memory/deadline bound for Python overhead or a stalled iterator.
    Caller-owned iterators/streams are not closed. No partial return or receipt
    is published on a late failure. Root artifact/host trust checks remain due.
    Self-consistent edits to otherwise well-shaped proof claims are undetectable
    without those external pins or the original traces; this is integrity only.
    """
    selected, plan_sha, case_sha, case_count = _prepare(
        expected_contexts, expected_index, expected_index_sha256,
        expected_case_inventory_sha256, shard_index, shard_count)
    report, _, _ = _plain(matrix_report, MAX_REPORT_BYTES)
    if (type(report) is not dict
            or set(report) != {"schema", "status", "plan_sha256", "shard", "contexts", "case_count",
                               "case_inventory_sha256", "terminal_cases", "external_requirement_cases",
                               "physical_dispatches", "qualification_authorized"}
            or report["schema"] != _REPORT_SCHEMA or report["status"] != "PASS"
            or report["plan_sha256"] != plan_sha
            or type(report["shard"]) is not dict or set(report["shard"]) != {"index", "count"}
            or type(report["shard"]["index"]) is not int or type(report["shard"]["count"]) is not int
            or report["shard"] != {"index": shard_index, "count": shard_count}
            or type(report["contexts"]) is not list or len(report["contexts"]) != len(selected)
            or not _integer(report["case_count"], MAX_CASES) or report["case_count"] != case_count
            or report["case_inventory_sha256"] != case_sha
            or not _integer(report["terminal_cases"], case_count)
            or not _integer(report["external_requirement_cases"], case_count)
            or report["terminal_cases"] + report["external_requirement_cases"] != case_count
            or not _integer(report["physical_dispatches"], 0) or report["qualification_authorized"] is not False):
        _refuse("report_binding")
    results = iter(outputs)
    absent = object()
    terminal = external = output_bytes = 0
    for (context, row), summary in zip(selected, report["contexts"]):
        expected = context.to_plain()
        ids = [instance["case"] for instance in expected["instances"]]
        if (type(summary) is not dict
                or set(summary) != {"context", "context_sha256", "result_sha256", "cases", "case_inventory_sha256"}
                or summary["context"] != row["context"] or summary["context_sha256"] != row["sha256"]
                or not _integer(summary["cases"], MAX_CASES_PER_CONTEXT) or summary["cases"] != row["cases"]
                or not _sha(summary["result_sha256"])
                or summary["case_inventory_sha256"] != _array_digest(sorted(ids))):
            _refuse("summary_binding")
        result = next(results, absent)
        if result is absent:
            _refuse("missing_result")
        data, size, digest = _plain(result, MAX_RECORD_BYTES)
        output_bytes += size
        if output_bytes > MAX_OUTPUT_BYTES:
            _refuse("output_bytes")
        if digest != summary["result_sha256"]:
            _refuse("result_digest")
        closed, required = _check_output(data, expected, row["sha256"])
        terminal += closed
        external += required
        del result, data
    if next(results, absent) is not absent:
        _refuse("extra_result")
    if terminal != report["terminal_cases"] or external != report["external_requirement_cases"]:
        _refuse("closure_counts")
    return matrix_report
