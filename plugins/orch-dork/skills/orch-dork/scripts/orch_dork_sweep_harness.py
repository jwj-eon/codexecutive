#!/usr/bin/env python3
"""Optional provider-free sweep harness over sealed experiment campaigns.

The harness is deliberately downstream of the standard-library campaign and
trace contracts.  It enumerates one sealed campaign, invokes an injected
replicate adapter exactly once per configuration/seed cell, and records every
accepted or failed-closed attempt in the ordinary append-only trace chain.
Reports are always reconstructed from that chain; adapter return values and
in-memory counters are never a reporting source.

This module is an optional adapter, not a kernel dependency.  A production
adapter must route the request through ``evaluate_governed_orchestration_run``
using ``orch-dork/governed-attempt-program/v1``.  Provider-free fixtures inject
the same narrow callable seam and return a sealed receipt with zero model and
hosted calls.  The harness owns no spawn, retry, fallback, default-change, or
completion authority.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from fractions import Fraction
import hashlib
import importlib.util
import json
from math import comb
from pathlib import Path
import re
import sys
from typing import Any


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:  # pragma: no cover - isolated direct-file loading.
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault(name, module)
        spec.loader.exec_module(module)
        return module


campaign_contract = _load_sibling("orch_dork_experiment_campaign")
hostile = _load_sibling("orch_dork_hostile_input")
trace = _load_sibling("orch_dork_trace")
PROFILE = hostile.PROFILE

OPTIONAL_ADAPTER = True
CORE_DEPENDENCY_ADDED = False

HARNESS_VERSION = "sweep-harness/v1"
REPORT_SCHEMA = "orch-dork/sweep-campaign-report/v1"
CAMPAIGN_RECORD_SCHEMA = "orch-dork/sweep-campaign-record/v1"
REPLICATE_REQUEST_SCHEMA = "orch-dork/sweep-replicate-request/v1"
REPLICATE_RECEIPT_DRAFT_SCHEMA = "orch-dork/sweep-replicate-receipt-draft/v1"
REPLICATE_RECEIPT_SCHEMA = "orch-dork/sweep-replicate-receipt/v1"
REPLICATE_RECEIPT_REPORT_SCHEMA = (
    "orch-dork/sweep-replicate-receipt-report/v1"
)
REPLICATE_RECORD_SCHEMA = "orch-dork/sweep-replicate-record/v1"

GOVERNED_ENTRYPOINT = "evaluate_governed_orchestration_run"
GOVERNED_PROGRAM_SCHEMA = "orch-dork/governed-attempt-program/v1"

_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_CHAIN_FIELDS = frozenset({"seq", "prev_sha256", "record", "record_sha256"})
_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "campaign_sha256",
        "configuration",
        "configuration_sha256",
        "replicate_index",
        "seed",
        "metric",
        "governed_entrypoint",
        "governed_program_schema",
        "request_sha256",
    }
)
_RECEIPT_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "request_sha256",
        "campaign_sha256",
        "configuration_id",
        "configuration_sha256",
        "replicate_index",
        "seed",
        "governed_entrypoint",
        "governed_program_schema",
        "governed_report_sha256",
        "outcome",
        "metric",
        "provider_free",
        "model_calls",
        "hosted_calls",
    }
)
_RECEIPT_FIELDS = _RECEIPT_DRAFT_FIELDS | frozenset({"receipt_sha256"})
_METRIC_FIELDS = frozenset({"name", "numerator", "denominator"})
_CAMPAIGN_RECORD_FIELDS = frozenset(
    {"schema", "campaign", "campaign_sha256", "adapter_contract", "record_sha256"}
)
_ADAPTER_CONTRACT_FIELDS = frozenset(
    {
        "kind",
        "mode",
        "governed_entrypoint",
        "governed_program_schema",
        "attempts_per_replicate",
        "automatic_retries",
        "automatic_fallbacks",
    }
)
_REPLICATE_RECORD_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "configuration_id",
        "configuration_sha256",
        "replicate_index",
        "seed",
        "request_sha256",
        "validation_status",
        "failure_reason",
        "outcome",
        "metric",
        "governed_entrypoint",
        "governed_program_schema",
        "governed_report_sha256",
        "adapter_receipt_sha256",
        "provider_free_evidence",
        "model_calls",
        "hosted_calls",
        "record_sha256",
    }
)
_FAILURE_REASONS = frozenset(
    {
        "adapter:exception",
        "receipt:hostile_or_noncanonical",
        "receipt:invalid",
        "receipt:seal_mismatch",
        "receipt:request_sha256_mismatch",
        "receipt:campaign_sha256_mismatch",
        "receipt:configuration_id_mismatch",
        "receipt:configuration_sha256_mismatch",
        "receipt:replicate_index_mismatch",
        "receipt:seed_mismatch",
        "receipt:governed_entrypoint_mismatch",
        "receipt:governed_program_schema_mismatch",
        "receipt:metric_mismatch",
    }
)


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hostile.canonicalize_bounded_json(raw, profile=PROFILE, batch=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _closed(
    value: Any,
    fields: frozenset[str],
    label: str,
    issues: list[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, f"{label}:type_invalid")
        return {}
    result = dict(value)
    for field in sorted(fields - set(result)):
        _issue(issues, f"{label}:missing_field:{field}")
    for field in sorted(set(result) - fields):
        _issue(issues, f"{label}:unknown_field:{field}")
    return result


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _sha_valid(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _bounded_int(
    value: Any,
    *,
    minimum: int = 0,
    maximum: int = 10**12,
) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _sealed(core: Mapping[str, Any], seal_field: str) -> dict[str, Any]:
    value = dict(core)
    return {**value, seal_field: _sha256(value)}


def _seal_valid(value: Any, seal_field: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    core = dict(value)
    recorded = core.pop(seal_field, None)
    try:
        return _sha_valid(recorded) and recorded == _sha256(core)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return False


def _metric_material(value: Any, label: str, issues: list[str]) -> dict[str, Any]:
    metric = _closed(value, _METRIC_FIELDS, label, issues)
    if not _identifier(metric.get("name")):
        _issue(issues, f"{label}:name_invalid")
    if not _bounded_int(metric.get("numerator"), minimum=-(10**12)):
        _issue(issues, f"{label}:numerator_invalid")
    if not _bounded_int(metric.get("denominator"), minimum=1):
        _issue(issues, f"{label}:denominator_invalid")
    return {
        "name": metric.get("name"),
        "numerator": metric.get("numerator"),
        "denominator": metric.get("denominator"),
    }


def _receipt_material(
    value: Any,
    *,
    expected_schema: str,
    sealed: bool,
    issues: list[str],
) -> dict[str, Any]:
    receipt = _closed(
        value,
        _RECEIPT_FIELDS if sealed else _RECEIPT_DRAFT_FIELDS,
        "receipt",
        issues,
    )
    if receipt.get("schema") != expected_schema:
        _issue(issues, "receipt:schema_invalid")
    for field in (
        "request_sha256",
        "campaign_sha256",
        "configuration_sha256",
        "governed_report_sha256",
    ):
        if not _sha_valid(receipt.get(field)):
            _issue(issues, f"receipt:{field}_invalid")
    if not _identifier(receipt.get("configuration_id")):
        _issue(issues, "receipt:configuration_id_invalid")
    if not _bounded_int(
        receipt.get("replicate_index"),
        minimum=1,
        maximum=PROFILE.max_array_items,
    ):
        _issue(issues, "receipt:replicate_index_invalid")
    if not _bounded_int(
        receipt.get("seed"), minimum=0, maximum=(2**63) - 1
    ):
        _issue(issues, "receipt:seed_invalid")
    if receipt.get("governed_entrypoint") != GOVERNED_ENTRYPOINT:
        _issue(issues, "receipt:governed_entrypoint_invalid")
    if receipt.get("governed_program_schema") != GOVERNED_PROGRAM_SCHEMA:
        _issue(issues, "receipt:governed_program_schema_invalid")
    if receipt.get("outcome") not in {"passed", "failed"}:
        _issue(issues, "receipt:outcome_invalid")
    metric = _metric_material(receipt.get("metric"), "receipt.metric", issues)
    if receipt.get("provider_free") is not True:
        _issue(issues, "receipt:provider_free_evidence_invalid")
    for field in ("model_calls", "hosted_calls"):
        if type(receipt.get(field)) is not int or receipt.get(field) != 0:
            _issue(issues, f"receipt:{field}_invalid")
    material = {
        "schema": expected_schema,
        "request_sha256": receipt.get("request_sha256"),
        "campaign_sha256": receipt.get("campaign_sha256"),
        "configuration_id": receipt.get("configuration_id"),
        "configuration_sha256": receipt.get("configuration_sha256"),
        "replicate_index": receipt.get("replicate_index"),
        "seed": receipt.get("seed"),
        "governed_entrypoint": receipt.get("governed_entrypoint"),
        "governed_program_schema": receipt.get("governed_program_schema"),
        "governed_report_sha256": receipt.get("governed_report_sha256"),
        "outcome": receipt.get("outcome"),
        "metric": metric,
        "provider_free": receipt.get("provider_free"),
        "model_calls": receipt.get("model_calls"),
        "hosted_calls": receipt.get("hosted_calls"),
    }
    if sealed:
        material["receipt_sha256"] = receipt.get("receipt_sha256")
    return material


def _receipt_report(
    operation: str,
    issues: list[str],
    receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": REPLICATE_RECEIPT_REPORT_SCHEMA,
        "operation": operation,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "replicate_receipt": dict(receipt) if isinstance(receipt, Mapping) else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "default_changed": False,
    }


def seal_replicate_receipt(draft: Any) -> dict[str, Any]:
    """Validate and seal one provider-free governed-entry adapter receipt."""

    issues: list[str] = []
    try:
        _canonical(draft)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _receipt_report("seal", ["receipt:hostile_or_noncanonical"])
    material = _receipt_material(
        draft,
        expected_schema=REPLICATE_RECEIPT_DRAFT_SCHEMA,
        sealed=False,
        issues=issues,
    )
    if issues:
        return _receipt_report("seal", issues)
    core = {**material, "schema": REPLICATE_RECEIPT_SCHEMA}
    return _receipt_report(
        "seal", [], _sealed(core, "receipt_sha256")
    )


def validate_replicate_receipt(value: Any) -> dict[str, Any]:
    """Verify one closed adapter receipt without repairing or executing it."""

    issues: list[str] = []
    try:
        _canonical(value)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _receipt_report("verify", ["receipt:hostile_or_noncanonical"])
    material = _receipt_material(
        value,
        expected_schema=REPLICATE_RECEIPT_SCHEMA,
        sealed=True,
        issues=issues,
    )
    if not _seal_valid(material, "receipt_sha256"):
        _issue(issues, "receipt:seal_mismatch")
    return _receipt_report(
        "verify", issues, material if not issues else None
    )


def _request(
    campaign: Mapping[str, Any],
    configuration: Mapping[str, Any],
    replicate_index: int,
    seed: int,
) -> dict[str, Any]:
    configuration_value = dict(configuration)
    core = {
        "schema": REPLICATE_REQUEST_SCHEMA,
        "campaign_id": campaign.get("campaign_id"),
        "campaign_sha256": campaign.get("campaign_sha256"),
        "configuration": configuration_value,
        "configuration_sha256": _sha256(configuration_value),
        "replicate_index": replicate_index,
        "seed": seed,
        "metric": campaign.get("question", {}).get("primary_metric"),
        "governed_entrypoint": GOVERNED_ENTRYPOINT,
        "governed_program_schema": GOVERNED_PROGRAM_SCHEMA,
    }
    return {**core, "request_sha256": _sha256(core)}


def _adapter_contract() -> dict[str, Any]:
    return {
        "kind": "optional_replicate_adapter",
        "mode": "provider_free_fixture",
        "governed_entrypoint": GOVERNED_ENTRYPOINT,
        "governed_program_schema": GOVERNED_PROGRAM_SCHEMA,
        "attempts_per_replicate": 1,
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
    }


def _campaign_record(campaign: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        "schema": CAMPAIGN_RECORD_SCHEMA,
        "campaign": dict(campaign),
        "campaign_sha256": campaign.get("campaign_sha256"),
        "adapter_contract": _adapter_contract(),
    }
    return _sealed(core, "record_sha256")


def _failed_record(
    request: Mapping[str, Any],
    reason: str,
    *,
    submitted_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    observed = isinstance(submitted_receipt, Mapping)
    core = {
        "schema": REPLICATE_RECORD_SCHEMA,
        "campaign_sha256": request.get("campaign_sha256"),
        "configuration_id": request.get("configuration", {}).get("configuration_id"),
        "configuration_sha256": request.get("configuration_sha256"),
        "replicate_index": request.get("replicate_index"),
        "seed": request.get("seed"),
        "request_sha256": request.get("request_sha256"),
        "validation_status": "failed_closed",
        "failure_reason": reason,
        "outcome": "unknown",
        "metric": None,
        "governed_entrypoint": GOVERNED_ENTRYPOINT,
        "governed_program_schema": GOVERNED_PROGRAM_SCHEMA,
        "governed_report_sha256": (
            submitted_receipt.get("governed_report_sha256") if observed else None
        ),
        "adapter_receipt_sha256": (
            submitted_receipt.get("receipt_sha256") if observed else None
        ),
        "provider_free_evidence": "observed" if observed else "unknown",
        "model_calls": submitted_receipt.get("model_calls") if observed else None,
        "hosted_calls": submitted_receipt.get("hosted_calls") if observed else None,
    }
    return _sealed(core, "record_sha256")


def _accepted_record(
    request: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    core = {
        "schema": REPLICATE_RECORD_SCHEMA,
        "campaign_sha256": request.get("campaign_sha256"),
        "configuration_id": request.get("configuration", {}).get("configuration_id"),
        "configuration_sha256": request.get("configuration_sha256"),
        "replicate_index": request.get("replicate_index"),
        "seed": request.get("seed"),
        "request_sha256": request.get("request_sha256"),
        "validation_status": "accepted",
        "failure_reason": None,
        "outcome": receipt.get("outcome"),
        "metric": dict(receipt.get("metric", {})),
        "governed_entrypoint": receipt.get("governed_entrypoint"),
        "governed_program_schema": receipt.get("governed_program_schema"),
        "governed_report_sha256": receipt.get("governed_report_sha256"),
        "adapter_receipt_sha256": receipt.get("receipt_sha256"),
        "provider_free_evidence": "observed",
        "model_calls": receipt.get("model_calls"),
        "hosted_calls": receipt.get("hosted_calls"),
    }
    return _sealed(core, "record_sha256")


def _binding_issue(
    request: Mapping[str, Any], receipt: Mapping[str, Any]
) -> str | None:
    checks = (
        ("request_sha256", "receipt:request_sha256_mismatch"),
        ("campaign_sha256", "receipt:campaign_sha256_mismatch"),
        ("configuration_id", "receipt:configuration_id_mismatch"),
        ("configuration_sha256", "receipt:configuration_sha256_mismatch"),
        ("replicate_index", "receipt:replicate_index_mismatch"),
        ("seed", "receipt:seed_mismatch"),
        ("governed_entrypoint", "receipt:governed_entrypoint_mismatch"),
        ("governed_program_schema", "receipt:governed_program_schema_mismatch"),
    )
    expected = {
        **dict(request),
        "configuration_id": request.get("configuration", {}).get("configuration_id"),
    }
    for field, reason in checks:
        if receipt.get(field) != expected.get(field):
            return reason
    metric = receipt.get("metric")
    if not isinstance(metric, Mapping) or metric.get("name") != request.get("metric"):
        return "receipt:metric_mismatch"
    return None


def _receipt_failure_reason(issues: Any) -> str:
    values = [str(item) for item in issues] if isinstance(issues, list) else []
    if "receipt:hostile_or_noncanonical" in values:
        return "receipt:hostile_or_noncanonical"
    if values == ["receipt:seal_mismatch"]:
        return "receipt:seal_mismatch"
    return "receipt:invalid"


def _append_record(path: str | Path, record: Mapping[str, Any]) -> bool:
    try:
        receipt = trace.append_trace_record(path, record)
    except (OSError, ValueError, TypeError):
        return False
    return receipt.get("status") == "PASS"


def _read_chain(path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    target = Path(path)
    if not target.exists():
        return [], []
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return [], ["ledger:unreadable"]
    entries: list[dict[str, Any]] = []
    previous: str | None = None
    populated = [index for index, line in enumerate(lines) if line.strip()]
    last_populated = populated[-1] if populated else -1

    def _break(seq: int, index: int) -> tuple[list[dict[str, Any]], list[str]]:
        kind = "torn_tail" if index == last_populated else "chain_broken"
        return [], [f"ledger:{kind}:{seq}"]

    for index, line in enumerate(lines):
        seq = index + 1
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, UnicodeError):
            return _break(seq, index)
        if not isinstance(entry, Mapping) or set(entry) != _CHAIN_FIELDS:
            return _break(seq, index)
        if type(entry.get("seq")) is not int or entry.get("seq") != seq:
            return _break(seq, index)
        if entry.get("prev_sha256") != previous:
            return _break(seq, index)
        record = entry.get("record")
        recorded = entry.get("record_sha256")
        try:
            expected = _sha256(
                {"seq": seq, "prev_sha256": previous, "record": record}
            )
        except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
            return _break(seq, index)
        if not isinstance(record, Mapping) or recorded != expected:
            return _break(seq, index)
        previous = str(recorded)
        entries.append(dict(entry))
    return entries, []


def read_experiment_ledger(
    path: str | Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return verified experiment-ledger entries for downstream adapters.

    This low-level seam deliberately returns ledger records rather than a
    public campaign report.  Record/replay needs the lossless model-call bodies
    for local scoring, while all user-facing reports remain sanitized.
    """

    entries, issues = _read_chain(path)
    return ([dict(entry) for entry in entries], list(issues))


def _failure_report(
    campaign_sha256: Any,
    issues: list[str],
    *,
    ledger_length: int = 0,
    ledger_last_sha256: str | None = None,
) -> dict[str, Any]:
    core = {
        "schema": REPORT_SCHEMA,
        "harness_version": HARNESS_VERSION,
        "status": "FAIL",
        "campaign_status": "unknown",
        "issues": sorted(set(issues)),
        "campaign_sha256": campaign_sha256 if _sha_valid(campaign_sha256) else None,
        "campaign_id": None,
        "ledger": {
            "chain_length": ledger_length,
            "last_sha256": ledger_last_sha256,
            "campaign_record_seq": None,
            "campaign_record_sha256": None,
        },
        "counts": None,
        "configurations": None,
        "provider_free": False,
        "model_calls": None,
        "hosted_calls": None,
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "default_changed": False,
    }
    return {**core, "report_sha256": _sha256(core)}


def _validate_campaign_record(
    value: Any, expected_digest: str, issues: list[str]
) -> Mapping[str, Any]:
    record = _closed(value, _CAMPAIGN_RECORD_FIELDS, "campaign_record", issues)
    if record.get("schema") != CAMPAIGN_RECORD_SCHEMA:
        _issue(issues, "campaign_record:schema_invalid")
    if record.get("campaign_sha256") != expected_digest:
        _issue(issues, "campaign_record:digest_mismatch")
    if not _seal_valid(record, "record_sha256"):
        _issue(issues, "campaign_record:seal_mismatch")
    campaign = record.get("campaign")
    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS":
        _issue(issues, "campaign_record:campaign_invalid")
    elif campaign.get("campaign_sha256") != expected_digest:
        _issue(issues, "campaign_record:campaign_digest_mismatch")
    adapter = _closed(
        record.get("adapter_contract"),
        _ADAPTER_CONTRACT_FIELDS,
        "campaign_record.adapter_contract",
        issues,
    )
    if adapter != _adapter_contract():
        _issue(issues, "campaign_record:adapter_contract_invalid")
    return record


def _expected_cells(campaign: Mapping[str, Any]) -> dict[tuple[str, int, int], dict[str, Any]]:
    result: dict[tuple[str, int, int], dict[str, Any]] = {}
    for configuration in campaign.get("configuration_grid", []):
        configuration_id = str(configuration.get("configuration_id"))
        configuration_sha256 = _sha256(configuration)
        for index, seed in enumerate(campaign.get("seeds", []), start=1):
            request = _request(campaign, configuration, index, seed)
            result[(configuration_id, index, seed)] = {
                "configuration": configuration,
                "configuration_sha256": configuration_sha256,
                "request": request,
            }
    return result


def _validate_replicate_record(
    value: Any,
    campaign: Mapping[str, Any],
    expected: Mapping[tuple[str, int, int], Mapping[str, Any]],
    issues: list[str],
) -> tuple[tuple[str, int, int] | None, Mapping[str, Any]]:
    record = _closed(value, _REPLICATE_RECORD_FIELDS, "replicate_record", issues)
    if record.get("schema") != REPLICATE_RECORD_SCHEMA:
        _issue(issues, "replicate_record:schema_invalid")
    if not _seal_valid(record, "record_sha256"):
        _issue(issues, "replicate_record:seal_mismatch")
    if record.get("campaign_sha256") != campaign.get("campaign_sha256"):
        _issue(issues, "replicate_record:campaign_mismatch")
    key = (
        str(record.get("configuration_id")),
        record.get("replicate_index"),
        record.get("seed"),
    )
    cell = expected.get(key)
    if cell is None:
        _issue(issues, "replicate_record:unexpected_cell")
        return None, record
    request = cell["request"]
    for field in (
        "configuration_sha256",
        "request_sha256",
        "governed_entrypoint",
        "governed_program_schema",
    ):
        if record.get(field) != request.get(field):
            _issue(issues, f"replicate_record:{field}_mismatch")
    status = record.get("validation_status")
    if status == "accepted":
        if record.get("failure_reason") is not None:
            _issue(issues, "replicate_record:accepted_failure_reason_present")
        if record.get("outcome") not in {"passed", "failed"}:
            _issue(issues, "replicate_record:accepted_outcome_invalid")
        metric_issues: list[str] = []
        metric = _metric_material(
            record.get("metric"), "replicate_record.metric", metric_issues
        )
        for item in metric_issues:
            _issue(issues, item)
        if metric.get("name") != request.get("metric"):
            _issue(issues, "replicate_record:metric_mismatch")
        for field in ("governed_report_sha256", "adapter_receipt_sha256"):
            if not _sha_valid(record.get(field)):
                _issue(issues, f"replicate_record:{field}_invalid")
        if (
            record.get("provider_free_evidence") != "observed"
            or record.get("model_calls") != 0
            or type(record.get("model_calls")) is not int
            or record.get("hosted_calls") != 0
            or type(record.get("hosted_calls")) is not int
        ):
            _issue(issues, "replicate_record:provider_free_evidence_invalid")
    elif status == "failed_closed":
        if record.get("failure_reason") not in _FAILURE_REASONS:
            _issue(issues, "replicate_record:failure_reason_invalid")
        if record.get("outcome") != "unknown" or record.get("metric") is not None:
            _issue(issues, "replicate_record:failed_closed_result_present")
        evidence = record.get("provider_free_evidence")
        if evidence == "observed":
            if (
                record.get("model_calls") != 0
                or type(record.get("model_calls")) is not int
                or record.get("hosted_calls") != 0
                or type(record.get("hosted_calls")) is not int
                or not _sha_valid(record.get("governed_report_sha256"))
                or not _sha_valid(record.get("adapter_receipt_sha256"))
            ):
                _issue(issues, "replicate_record:observed_failure_evidence_invalid")
        elif evidence == "unknown":
            if any(
                record.get(field) is not None
                for field in (
                    "model_calls",
                    "hosted_calls",
                    "governed_report_sha256",
                    "adapter_receipt_sha256",
                )
            ):
                _issue(issues, "replicate_record:unknown_failure_evidence_invalid")
        else:
            _issue(issues, "replicate_record:provider_free_evidence_invalid")
    else:
        _issue(issues, "replicate_record:validation_status_invalid")
    return key, record


def _rational(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def _rule_outcome(mean: Fraction, rule: Mapping[str, Any]) -> str:
    threshold_value = rule.get("threshold", {})
    threshold = Fraction(
        threshold_value.get("numerator"), threshold_value.get("denominator")
    )
    operator = rule.get("operator")
    passed = {
        "greater_than": mean > threshold,
        "greater_than_or_equal": mean >= threshold,
        "less_than": mean < threshold,
        "less_than_or_equal": mean <= threshold,
        "equal": mean == threshold,
    }.get(operator, False)
    return "pass" if passed else "fail"


def _configuration_summary(
    campaign: Mapping[str, Any],
    configuration: Mapping[str, Any],
    rows: list[Mapping[str, Any]],
) -> dict[str, Any]:
    expected_count = int(campaign.get("replicate_count", 0))
    accepted = [row for row in rows if row.get("validation_status") == "accepted"]
    failed_closed = [
        row for row in rows if row.get("validation_status") == "failed_closed"
    ]
    missing = expected_count - len(rows)
    passed_count = sum(row.get("outcome") == "passed" for row in accepted)
    failed_count = sum(row.get("outcome") == "failed" for row in accepted)
    counts = {
        "expected_replicates": expected_count,
        "observed_replicates": len(rows),
        "complete_replicates": len(accepted),
        "failed_closed_replicates": len(failed_closed),
        "missing_replicates": missing,
        "passed_replicates": passed_count,
        "failed_replicates": failed_count,
    }
    if failed_closed or missing or len(accepted) != expected_count:
        reliability = {
            "status": "incomplete",
            "k": expected_count,
            "pass_at_k": None,
            "pass_power_k": None,
            "reason": "replicate_evidence_incomplete",
        }
        mean = None
        decision = "incomplete"
        status = "incomplete"
    else:
        metric_values = [
            Fraction(row["metric"]["numerator"], row["metric"]["denominator"])
            for row in accepted
        ]
        mean_value = sum(metric_values, Fraction(0, 1)) / expected_count
        pass_at_denominator = comb(expected_count, expected_count)
        pass_at_numerator = pass_at_denominator - comb(
            expected_count - passed_count, expected_count
        )
        pass_at = Fraction(pass_at_numerator, pass_at_denominator)
        pass_power = Fraction(passed_count, expected_count) ** expected_count
        reliability = {
            "status": "observed",
            "k": expected_count,
            "pass_at_k": {
                "label": "pass@k",
                **_rational(pass_at),
                "definition": "at_least_one_success_without_replacement",
            },
            "pass_power_k": {
                "label": "pass^k",
                **_rational(pass_power),
                "definition": "all_k_successes_at_empirical_rate",
            },
        }
        mean = _rational(mean_value)
        decision = _rule_outcome(mean_value, campaign.get("decision_rule", {}))
        status = "complete"
    return {
        "configuration_id": configuration.get("configuration_id"),
        "configuration_sha256": _sha256(configuration),
        "status": status,
        "counts": counts,
        "primary_metric_mean": mean,
        "decision_rule_outcome": decision,
        "reliability": reliability,
    }


def summarize_sweep_campaign(
    ledger_path: str | Path, campaign_sha256: str
) -> dict[str, Any]:
    """Re-derive one campaign report solely from its append-only ledger."""

    if not _sha_valid(campaign_sha256):
        return _failure_report(None, ["campaign_sha256:invalid"])
    entries, chain_issues = _read_chain(ledger_path)
    last_sha256 = entries[-1]["record_sha256"] if entries else None
    if chain_issues:
        return _failure_report(campaign_sha256, chain_issues)
    matching_campaign_entries = [
        entry
        for entry in entries
        if entry["record"].get("schema") == CAMPAIGN_RECORD_SCHEMA
        and entry["record"].get("campaign_sha256") == campaign_sha256
    ]
    if len(matching_campaign_entries) != 1:
        reason = (
            "campaign_record:missing"
            if not matching_campaign_entries
            else "campaign_record:duplicate"
        )
        return _failure_report(
            campaign_sha256,
            [reason],
            ledger_length=len(entries),
            ledger_last_sha256=last_sha256,
        )
    campaign_entry = matching_campaign_entries[0]
    issues: list[str] = []
    campaign_record = _validate_campaign_record(
        campaign_entry["record"], campaign_sha256, issues
    )
    campaign = campaign_record.get("campaign")
    if issues or not isinstance(campaign, Mapping):
        return _failure_report(
            campaign_sha256,
            issues or ["campaign_record:campaign_invalid"],
            ledger_length=len(entries),
            ledger_last_sha256=last_sha256,
        )
    expected = _expected_cells(campaign)
    records_by_key: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    registration_seq = campaign_entry["seq"]
    for entry in entries:
        record = entry["record"]
        if record.get("campaign_sha256") != campaign_sha256:
            continue
        if record.get("schema") == CAMPAIGN_RECORD_SCHEMA:
            continue
        if record.get("schema") != REPLICATE_RECORD_SCHEMA:
            # The ordinary experiment ledger is intentionally heterogeneous:
            # later adapters append campaign-bound replay and holdout records.
            # Only this harness's own closed schemas affect its projection.
            continue
        if entry["seq"] <= registration_seq:
            _issue(issues, "replicate_record:before_campaign_registration")
        key, normalized = _validate_replicate_record(
            record, campaign, expected, issues
        )
        if key is None:
            continue
        if key in records_by_key:
            _issue(issues, "replicate_record:duplicate_cell")
        else:
            records_by_key[key] = normalized
    if issues:
        return _failure_report(
            campaign_sha256,
            issues,
            ledger_length=len(entries),
            ledger_last_sha256=last_sha256,
        )
    configurations: list[dict[str, Any]] = []
    for configuration in campaign.get("configuration_grid", []):
        configuration_id = str(configuration.get("configuration_id"))
        rows = [
            records_by_key[key]
            for key in expected
            if key[0] == configuration_id and key in records_by_key
        ]
        configurations.append(
            _configuration_summary(campaign, configuration, rows)
        )
    all_rows = list(records_by_key.values())
    accepted_count = sum(
        row.get("validation_status") == "accepted" for row in all_rows
    )
    failed_closed_count = sum(
        row.get("validation_status") == "failed_closed" for row in all_rows
    )
    expected_count = len(expected)
    missing_count = expected_count - len(all_rows)
    complete = accepted_count == expected_count
    evidence_known = (
        len(all_rows) == expected_count
        and all(row.get("provider_free_evidence") == "observed" for row in all_rows)
    )
    provider_free = evidence_known and all(
        row.get("model_calls") == 0 and row.get("hosted_calls") == 0
        for row in all_rows
    )
    model_calls = (
        sum(int(row["model_calls"]) for row in all_rows)
        if evidence_known
        else None
    )
    hosted_calls = (
        sum(int(row["hosted_calls"]) for row in all_rows)
        if evidence_known
        else None
    )
    core = {
        "schema": REPORT_SCHEMA,
        "harness_version": HARNESS_VERSION,
        "status": "PASS" if complete else "INCOMPLETE",
        "campaign_status": "complete" if complete else "incomplete",
        "issues": [] if complete else ["campaign:replicate_evidence_incomplete"],
        "campaign_sha256": campaign_sha256,
        "campaign_id": campaign.get("campaign_id"),
        "ledger": {
            "chain_length": len(entries),
            "last_sha256": last_sha256,
            "campaign_record_seq": registration_seq,
            "campaign_record_sha256": campaign_entry["record_sha256"],
        },
        "counts": {
            "expected_replicates": expected_count,
            "observed_replicates": len(all_rows),
            "complete_replicates": accepted_count,
            "failed_closed_replicates": failed_closed_count,
            "missing_replicates": missing_count,
            "adapter_calls": len(all_rows),
        },
        "configurations": configurations,
        "provider_free": provider_free,
        "model_calls": model_calls,
        "hosted_calls": hosted_calls,
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "default_changed": False,
    }
    return {**core, "report_sha256": _sha256(core)}


def run_sweep_campaign(
    campaign: Any,
    ledger_path: str | Path,
    *,
    replicate_adapter: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    """Drain one sealed campaign and return only its ledger-derived report."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS":
        return _failure_report(
            campaign.get("campaign_sha256") if isinstance(campaign, Mapping) else None,
            [
                str(item)
                if str(item).startswith("campaign:")
                else "campaign:" + str(item)
                for item in verified.get("issues", [])
            ],
        )
    if not callable(replicate_adapter):
        return _failure_report(
            campaign.get("campaign_sha256"), ["adapter:not_callable"]
        )
    if not isinstance(campaign, Mapping):  # Defensive after the verifier.
        return _failure_report(None, ["campaign:type_invalid"])
    campaign_sha256 = str(campaign.get("campaign_sha256"))
    existing, chain_issues = _read_chain(ledger_path)
    if chain_issues:
        return _failure_report(campaign_sha256, chain_issues)
    if any(
        entry["record"].get("campaign_sha256") == campaign_sha256
        and entry["record"].get("schema")
        in {CAMPAIGN_RECORD_SCHEMA, REPLICATE_RECORD_SCHEMA}
        for entry in existing
    ):
        return _failure_report(
            campaign_sha256,
            ["campaign:already_recorded"],
            ledger_length=len(existing),
            ledger_last_sha256=(existing[-1]["record_sha256"] if existing else None),
        )
    if not _append_record(ledger_path, _campaign_record(campaign)):
        return _failure_report(campaign_sha256, ["ledger:append_failed"])
    for configuration in campaign.get("configuration_grid", []):
        for replicate_index, seed in enumerate(campaign.get("seeds", []), start=1):
            request = _request(campaign, configuration, replicate_index, seed)
            try:
                submitted = replicate_adapter(dict(request))
            except Exception:
                record = _failed_record(request, "adapter:exception")
            else:
                receipt_report = validate_replicate_receipt(submitted)
                normalized = receipt_report.get("replicate_receipt")
                if receipt_report.get("status") != "PASS" or not isinstance(
                    normalized, Mapping
                ):
                    record = _failed_record(
                        request,
                        _receipt_failure_reason(receipt_report.get("issues")),
                    )
                else:
                    binding_issue = _binding_issue(request, normalized)
                    record = (
                        _failed_record(
                            request,
                            binding_issue,
                            submitted_receipt=normalized,
                        )
                        if binding_issue is not None
                        else _accepted_record(request, normalized)
                    )
            if not _append_record(ledger_path, record):
                return _failure_report(
                    campaign_sha256, ["ledger:append_failed_after_adapter_call"]
                )
    return summarize_sweep_campaign(ledger_path, campaign_sha256)


__all__ = [
    "CAMPAIGN_RECORD_SCHEMA",
    "CORE_DEPENDENCY_ADDED",
    "GOVERNED_ENTRYPOINT",
    "GOVERNED_PROGRAM_SCHEMA",
    "HARNESS_VERSION",
    "OPTIONAL_ADAPTER",
    "REPLICATE_RECEIPT_DRAFT_SCHEMA",
    "REPLICATE_RECEIPT_REPORT_SCHEMA",
    "REPLICATE_RECEIPT_SCHEMA",
    "REPLICATE_RECORD_SCHEMA",
    "REPLICATE_REQUEST_SCHEMA",
    "REPORT_SCHEMA",
    "read_experiment_ledger",
    "run_sweep_campaign",
    "seal_replicate_receipt",
    "summarize_sweep_campaign",
    "validate_replicate_receipt",
]
