#!/usr/bin/env python3
"""Bounded provider-free evidence-integrity policy contracts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


PROGRAM_SCHEMA = "orch-dork/evidence-policy-program/v1"
REPORT_SCHEMA = "orch-dork/evidence-policy-report/v1"
PRODUCED_EVIDENCE_SCHEMA = "orch-dork/produced-evidence/v1"
EXECUTION_RECEIPT_SCHEMA = "orch-dork/execution-receipt/v1"
FAILURE_ORIGIN_SCHEMA = "orch-dork/failure-origin/v1"
ADVISORY_USE_SCHEMA = "orch-dork/advisory-use/v1"
EVIDENCE_REVEAL_SCHEMA = "orch-dork/evidence-reveal/v1"
EVIDENCE_MANIFEST_SCHEMA = "orch-dork/evidence-manifest/v1"

EVIDENCE_POLICY_OPERATIONS = (
    "produced_evidence",
    "failure_origin",
    "advisory_use",
    "evidence_reveal",
)
FAILURE_ORIGINS = frozenset(
    {"candidate", "evaluator", "infrastructure", "policy", "unknown"}
)
EVIDENCE_KINDS = frozenset(
    {"artifact", "observation", "receipt", "test_result", "analysis"}
)
MAX_ITEMS = 64
MAX_CANONICAL_BYTES = 262_144
MAX_BRIEF_BYTES = 2_048
MAX_DEPTH = 32
MAX_NODES = 4_096
MAX_OBJECT_KEYS = 256
MAX_ARRAY_ITEMS = 256
MAX_STRING_BYTES = 65_536
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_bytes(value: Any) -> bytes:
    """Return bounded canonical JSON bytes."""

    _validate_json(value, depth=0, nodes=[0])
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical_json:too_large")
    return raw


def _validate_json(value: Any, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > MAX_NODES or depth > MAX_DEPTH:
        raise ValueError("canonical_json:structure_bound")
    if value is None or type(value) in (bool, int, float):
        return
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise ValueError("canonical_json:string_bound")
        return
    if type(value) is list:
        if len(value) > MAX_ARRAY_ITEMS:
            raise ValueError("canonical_json:array_bound")
        for child in value:
            _validate_json(child, depth=depth + 1, nodes=nodes)
        return
    if type(value) is dict:
        if len(value) > MAX_OBJECT_KEYS or any(type(key) is not str for key in value):
            raise ValueError("canonical_json:object_bound")
        for key, child in value.items():
            _validate_json(key, depth=depth + 1, nodes=nodes)
            _validate_json(child, depth=depth + 1, nodes=nodes)
        return
    raise ValueError("canonical_json:type_invalid")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    issues.append(value)


def _closed(
    value: Any,
    *,
    path: str,
    required: frozenset[str],
    issues: list[str],
) -> dict[str, Any] | None:
    if type(value) is not dict:
        _issue(issues, f"{path}:not_object")
        return None
    for key in sorted(set(value) - required):
        _issue(issues, f"{path}:unknown_field:{key}")
    for key in sorted(required - set(value)):
        _issue(issues, f"{path}:missing:{key}")
    return value


def _identifier(value: Any, path: str, issues: list[str]) -> str | None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _issue(issues, f"{path}:invalid")
        return None
    return value


def _sha(value: Any, path: str, issues: list[str]) -> str | None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _issue(issues, f"{path}:invalid_sha256")
        return None
    return value


def _boolean(value: Any, path: str, issues: list[str]) -> bool | None:
    if type(value) is not bool:
        _issue(issues, f"{path}:not_boolean")
        return None
    return value


def _integer(value: Any, path: str, issues: list[str], *, minimum: int = 0) -> int | None:
    if type(value) is not int or value < minimum:
        _issue(issues, f"{path}:invalid_integer")
        return None
    return value


def _id_list(value: Any, path: str, issues: list[str]) -> list[str]:
    if type(value) is not list:
        _issue(issues, f"{path}:not_array")
        return []
    if len(value) > MAX_ITEMS:
        _issue(issues, f"{path}:too_many_items")
    result: list[str] = []
    for index, item in enumerate(value[:MAX_ITEMS]):
        parsed = _identifier(item, f"{path}[{index}]", issues)
        if parsed is not None:
            result.append(parsed)
    if len(result) != len(set(result)):
        _issue(issues, f"{path}:duplicate")
    return result


def _report(
    operation: str | None,
    issues: list[str],
    result: dict[str, Any] | None,
    *,
    failure_decision: str = "REJECTED",
) -> dict[str, Any]:
    unique = sorted(set(issues))
    return {
        "schema": REPORT_SCHEMA,
        "status": "FAIL" if unique else "PASS",
        "decision": failure_decision if unique else "ACCEPTED",
        "operation": operation,
        "issues": unique,
        "result": result,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _produced_evidence(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    required = frozenset(
        {
            "schema",
            "evidence_id",
            "kind",
            "producer_node_id",
            "producer_operation",
            "subject_sha256",
            "execution_receipt",
            "execution_receipt_sha256",
            "marker_only",
            "settles_claim",
        }
    )
    item = _closed(payload, path="evidence", required=required, issues=issues)
    result = None
    if item is not None:
        if item.get("schema") != PRODUCED_EVIDENCE_SCHEMA:
            _issue(issues, "evidence:schema_invalid")
        evidence_id = _identifier(item.get("evidence_id"), "evidence.evidence_id", issues)
        kind = item.get("kind")
        if kind not in EVIDENCE_KINDS:
            _issue(issues, "evidence.kind:invalid")
        producer = _identifier(item.get("producer_node_id"), "evidence.producer_node_id", issues)
        operation = _identifier(item.get("producer_operation"), "evidence.producer_operation", issues)
        subject = _sha(item.get("subject_sha256"), "evidence.subject_sha256", issues)
        marker_only = _boolean(item.get("marker_only"), "evidence.marker_only", issues)
        settles = _boolean(item.get("settles_claim"), "evidence.settles_claim", issues)
        supplied_receipt_sha = _sha(
            item.get("execution_receipt_sha256"),
            "evidence.execution_receipt_sha256",
            issues,
        )
        receipt_required = frozenset(
            {
                "schema",
                "receipt_id",
                "worker_id",
                "session_id",
                "operation",
                "subject_sha256",
                "status",
            }
        )
        receipt = _closed(
            item.get("execution_receipt"),
            path="receipt",
            required=receipt_required,
            issues=issues,
        )
        computed_receipt_sha = None
        if receipt is not None:
            if receipt.get("schema") != EXECUTION_RECEIPT_SCHEMA:
                _issue(issues, "receipt:schema_invalid")
            _identifier(receipt.get("receipt_id"), "receipt.receipt_id", issues)
            worker = _identifier(receipt.get("worker_id"), "receipt.worker_id", issues)
            _identifier(receipt.get("session_id"), "receipt.session_id", issues)
            receipt_operation = _identifier(receipt.get("operation"), "receipt.operation", issues)
            receipt_subject = _sha(receipt.get("subject_sha256"), "receipt.subject_sha256", issues)
            if receipt.get("status") != "succeeded":
                _issue(issues, "receipt:status_not_succeeded")
            if producer is not None and worker != producer:
                _issue(issues, "evidence:producer_receipt_mismatch")
            if operation is not None and receipt_operation != operation:
                _issue(issues, "evidence:operation_receipt_mismatch")
            if subject is not None and receipt_subject != subject:
                _issue(issues, "evidence:subject_receipt_mismatch")
            try:
                computed_receipt_sha = canonical_sha256(receipt)
            except (TypeError, ValueError):
                _issue(issues, "receipt:canonicalization_failed")
            if computed_receipt_sha is not None and supplied_receipt_sha != computed_receipt_sha:
                _issue(issues, "evidence:execution_receipt_digest_mismatch")
        if marker_only is True and settles is True:
            _issue(issues, "evidence:marker_cannot_settle_claim")
        result = {
            "evidence_id": evidence_id,
            "execution_receipt_sha256": computed_receipt_sha,
            "claim_settled": settles is True and marker_only is False and not issues,
        }
    return _report("produced_evidence", issues, result)


def _failure_origin(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    required = frozenset(
        {
            "schema",
            "failure_id",
            "origin",
            "carries_candidate_quality_evidence",
            "candidate_evidence_ids",
        }
    )
    item = _closed(payload, path="failure", required=required, issues=issues)
    result = None
    if item is not None:
        if item.get("schema") != FAILURE_ORIGIN_SCHEMA:
            _issue(issues, "failure:schema_invalid")
        failure_id = _identifier(item.get("failure_id"), "failure.failure_id", issues)
        origin = item.get("origin")
        if origin not in FAILURE_ORIGINS:
            _issue(issues, "failure.origin:invalid")
        carries = _boolean(
            item.get("carries_candidate_quality_evidence"),
            "failure.carries_candidate_quality_evidence",
            issues,
        )
        evidence_ids = _id_list(
            item.get("candidate_evidence_ids"),
            "failure.candidate_evidence_ids",
            issues,
        )
        if carries is True and not evidence_ids:
            _issue(issues, "failure:candidate_quality_evidence_missing")
        if carries is False and evidence_ids:
            _issue(issues, "failure:candidate_quality_evidence_unclaimed")
        result = {
            "failure_id": failure_id,
            "origin": origin if origin in FAILURE_ORIGINS else None,
            "carries_candidate_quality_evidence": carries,
            "candidate_evidence_ids": evidence_ids,
        }
    return _report("failure_origin", issues, result)


def _advisory_use(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    required = frozenset(
        {
            "schema",
            "advisory_id",
            "baseline_claim_ids",
            "baseline_sha256",
            "generated_claim_ids",
            "novel_claim_ids",
            "used_claim_ids",
            "novelty_brief",
            "stopped_for_no_novel_delta",
        }
    )
    item = _closed(payload, path="advisory", required=required, issues=issues)
    result = None
    if item is not None:
        if item.get("schema") != ADVISORY_USE_SCHEMA:
            _issue(issues, "advisory:schema_invalid")
        advisory_id = _identifier(item.get("advisory_id"), "advisory.advisory_id", issues)
        baseline = _id_list(item.get("baseline_claim_ids"), "advisory.baseline_claim_ids", issues)
        baseline_sha = _sha(item.get("baseline_sha256"), "advisory.baseline_sha256", issues)
        if baseline_sha is not None and baseline_sha != canonical_sha256(baseline):
            _issue(issues, "advisory:baseline_digest_mismatch")
        generated = _id_list(item.get("generated_claim_ids"), "advisory.generated_claim_ids", issues)
        novel = _id_list(item.get("novel_claim_ids"), "advisory.novel_claim_ids", issues)
        used = _id_list(item.get("used_claim_ids"), "advisory.used_claim_ids", issues)
        expected_novel = [claim for claim in generated if claim not in set(baseline)]
        if novel != expected_novel:
            _issue(issues, "advisory:novel_claim_ids_mismatch")
        if not set(used).issubset(set(generated)):
            _issue(issues, "advisory:used_claim_not_generated")
        brief = item.get("novelty_brief")
        if type(brief) is not str or len(brief.encode("utf-8")) > MAX_BRIEF_BYTES:
            _issue(issues, "advisory.novelty_brief:invalid")
        stopped = _boolean(
            item.get("stopped_for_no_novel_delta"),
            "advisory.stopped_for_no_novel_delta",
            issues,
        )
        if stopped is not None and stopped != (len(novel) == 0):
            _issue(issues, "advisory:no_novel_delta_decision_mismatch")
        result = {
            "advisory_id": advisory_id,
            "novel_claim_ids": novel,
            "used_claim_ids": used,
            "actual_use": bool(used),
            "zero_use_valid": True,
        }
    return _report("advisory_use", issues, result)


def _evidence_reveal(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    required = frozenset(
        {
            "schema",
            "request_id",
            "manifest",
            "manifest_sha256",
            "selected_claim_ids",
            "selected_artifact_ids",
            "current_seq",
            "max_age_seq",
            "byte_cap",
        }
    )
    item = _closed(payload, path="reveal", required=required, issues=issues)
    result = None
    if item is not None:
        if item.get("schema") != EVIDENCE_REVEAL_SCHEMA:
            _issue(issues, "reveal:schema_invalid")
        request_id = _identifier(item.get("request_id"), "reveal.request_id", issues)
        supplied_manifest_sha = _sha(item.get("manifest_sha256"), "reveal.manifest_sha256", issues)
        selected_claims = _id_list(item.get("selected_claim_ids"), "reveal.selected_claim_ids", issues)
        selected_artifacts = _id_list(item.get("selected_artifact_ids"), "reveal.selected_artifact_ids", issues)
        current_seq = _integer(item.get("current_seq"), "reveal.current_seq", issues)
        max_age = _integer(item.get("max_age_seq"), "reveal.max_age_seq", issues)
        byte_cap = _integer(item.get("byte_cap"), "reveal.byte_cap", issues, minimum=1)
        manifest_required = frozenset({"schema", "manifest_id", "sealed_at_seq", "claims", "artifacts"})
        manifest = _closed(
            item.get("manifest"),
            path="manifest",
            required=manifest_required,
            issues=issues,
        )
        claim_sizes: dict[str, int] = {}
        artifact_sizes: dict[str, int] = {}
        claim_artifact_refs: set[str] = set()
        computed_manifest_sha = None
        if manifest is not None:
            if manifest.get("schema") != EVIDENCE_MANIFEST_SCHEMA:
                _issue(issues, "manifest:schema_invalid")
            _identifier(manifest.get("manifest_id"), "manifest.manifest_id", issues)
            sealed_at = _integer(manifest.get("sealed_at_seq"), "manifest.sealed_at_seq", issues)
            claims = manifest.get("claims")
            artifacts = manifest.get("artifacts")
            if type(claims) is not list or len(claims) > MAX_ITEMS:
                _issue(issues, "manifest.claims:invalid_array")
                claims = []
            if type(artifacts) is not list or len(artifacts) > MAX_ITEMS:
                _issue(issues, "manifest.artifacts:invalid_array")
                artifacts = []
            for index, claim in enumerate(claims):
                parsed = _closed(
                    claim,
                    path=f"manifest.claims[{index}]",
                    required=frozenset({"claim_id", "sha256", "size_bytes", "artifact_ids"}),
                    issues=issues,
                )
                if parsed is None:
                    continue
                claim_id = _identifier(parsed.get("claim_id"), f"manifest.claims[{index}].claim_id", issues)
                _sha(parsed.get("sha256"), f"manifest.claims[{index}].sha256", issues)
                size = _integer(parsed.get("size_bytes"), f"manifest.claims[{index}].size_bytes", issues)
                claim_artifact_refs.update(
                    _id_list(
                        parsed.get("artifact_ids"),
                        f"manifest.claims[{index}].artifact_ids",
                        issues,
                    )
                )
                if claim_id is not None and size is not None:
                    if claim_id in claim_sizes:
                        _issue(issues, "manifest.claims:duplicate_id")
                    claim_sizes[claim_id] = size
            for index, artifact in enumerate(artifacts):
                parsed = _closed(
                    artifact,
                    path=f"manifest.artifacts[{index}]",
                    required=frozenset({"artifact_id", "sha256", "size_bytes"}),
                    issues=issues,
                )
                if parsed is None:
                    continue
                artifact_id = _identifier(
                    parsed.get("artifact_id"),
                    f"manifest.artifacts[{index}].artifact_id",
                    issues,
                )
                _sha(parsed.get("sha256"), f"manifest.artifacts[{index}].sha256", issues)
                size = _integer(parsed.get("size_bytes"), f"manifest.artifacts[{index}].size_bytes", issues)
                if artifact_id is not None and size is not None:
                    if artifact_id in artifact_sizes:
                        _issue(issues, "manifest.artifacts:duplicate_id")
                    artifact_sizes[artifact_id] = size
            if not claim_artifact_refs.issubset(set(artifact_sizes)):
                _issue(issues, "manifest:claim_artifact_missing")
            try:
                computed_manifest_sha = canonical_sha256(manifest)
            except (TypeError, ValueError):
                _issue(issues, "manifest:canonicalization_failed")
            if computed_manifest_sha is not None and supplied_manifest_sha != computed_manifest_sha:
                _issue(issues, "reveal:manifest_digest_mismatch")
            if current_seq is not None and sealed_at is not None and max_age is not None:
                if current_seq < sealed_at or current_seq - sealed_at > max_age:
                    _issue(issues, "reveal:manifest_stale")
        missing_claims = sorted(set(selected_claims) - set(claim_sizes))
        missing_artifacts = sorted(set(selected_artifacts) - set(artifact_sizes))
        if missing_claims:
            _issue(issues, "reveal:selected_claim_missing")
        if missing_artifacts:
            _issue(issues, "reveal:selected_artifact_missing")
        total_bytes = sum(claim_sizes.get(key, 0) for key in selected_claims) + sum(
            artifact_sizes.get(key, 0) for key in selected_artifacts
        )
        if byte_cap is not None and total_bytes > byte_cap:
            _issue(issues, "reveal:byte_cap_exceeded")
        result = {
            "request_id": request_id,
            "manifest_sha256": computed_manifest_sha,
            "authorized_claim_ids": selected_claims if not issues else [],
            "authorized_artifact_ids": selected_artifacts if not issues else [],
            "released_bytes": total_bytes if not issues else 0,
            "transcript_expanded": False,
        }
    return _report("evidence_reveal", issues, result)


def evaluate_evidence_policy(program: Any) -> dict[str, Any]:
    """Evaluate one closed evidence-policy operation without side effects."""

    try:
        canonical_bytes(program)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return _report(None, ["program:invalid_or_unbounded_json"], None)
    issues: list[str] = []
    item = _closed(
        program,
        path="program",
        required=frozenset({"schema", "operation", "payload"}),
        issues=issues,
    )
    if item is None:
        return _report(None, issues, None)
    if item.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    operation = item.get("operation")
    if operation not in EVIDENCE_POLICY_OPERATIONS:
        _issue(issues, "program:operation_invalid")
    if type(item.get("payload")) is not dict:
        _issue(issues, "program.payload:not_object")
    if issues:
        return _report(operation if operation in EVIDENCE_POLICY_OPERATIONS else None, issues, None)
    evaluators = {
        "produced_evidence": _produced_evidence,
        "failure_origin": _failure_origin,
        "advisory_use": _advisory_use,
        "evidence_reveal": _evidence_reveal,
    }
    try:
        return evaluators[operation](item["payload"])
    except (TypeError, ValueError, OverflowError):
        return _report(operation, [f"{operation}:evaluation_failed"], None)


__all__ = [
    "ADVISORY_USE_SCHEMA",
    "EVIDENCE_MANIFEST_SCHEMA",
    "EVIDENCE_POLICY_OPERATIONS",
    "EVIDENCE_REVEAL_SCHEMA",
    "EXECUTION_RECEIPT_SCHEMA",
    "FAILURE_ORIGIN_SCHEMA",
    "PROGRAM_SCHEMA",
    "PRODUCED_EVIDENCE_SCHEMA",
    "REPORT_SCHEMA",
    "canonical_bytes",
    "canonical_sha256",
    "evaluate_evidence_policy",
]
