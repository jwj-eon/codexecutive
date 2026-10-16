#!/usr/bin/env python3
"""Deterministic validators for relay manifests and relay deliveries.

North star Part II section 19 treats context transfer between producer and
consumer nodes as a typed dependency: the producer publishes a relay manifest
that pins every required input by content hash, names the facts the consumer
must acknowledge, and fences off context that must never cross the relay.
This module decides, from declared evidence only, whether such a manifest is
well-formed and whether a delivery actually honored it. Nothing here reads the
filesystem, touches the network, or calls a model; both functions are pure
deterministic functions of the submitted objects.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


RELAY_MANIFEST_SCHEMA = "orch-dork/relay-manifest/v1"
RELAY_MANIFEST_REPORT_SCHEMA = "orch-dork/relay-manifest-report/v1"
RELAY_DELIVERY_PROGRAM_SCHEMA = "orch-dork/relay-delivery-program/v1"
RELAY_DELIVERY_REPORT_SCHEMA = "orch-dork/relay-delivery-report/v1"

_FRESHNESS_KIND = "plan_revision"
_MISSING_INPUTS_ACTIONS = ("CONTEXT_REQUESTED", "FAIL_CLOSED")
_ACK_STATUSES = ("acknowledged", "context_requested")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, fields: set[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, f"{path}:not_object")
        return False
    for key in sorted(fields - set(value)):
        _issue(issues, f"{path}:missing:{key}")
    for key in sorted(set(value) - fields):
        _issue(issues, f"{path}:unknown:{key}")
    return set(value) == fields


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096


def _clean_ref(entry: Any, path: str, issues: list[str]) -> str | None:
    """Validate one relay artifact reference entry."""

    if not isinstance(entry, str) or not entry.strip() or len(entry) > 4096:
        _issue(issues, f"{path}:invalid")
        return None
    return entry.strip()


def _ref_list(value: Any, path: str, issues: list[str]) -> list[str]:
    """Validate a list of non-empty relay references (optional/forbidden)."""

    if not isinstance(value, list):
        _issue(issues, f"{path}:not_array")
        return []
    result: list[str] = []
    for index, entry in enumerate(value):
        clean = _clean_ref(entry, f"{path}[{index}]", issues)
        if clean is not None:
            result.append(clean)
    return result


def _report_footer(core: dict[str, Any]) -> dict[str, Any]:
    """Attach the provider-free attestation fields and the sealed report sha."""

    attested = {
        **core,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "evidence_tier": "submitted",
    }
    return {**attested, "report_sha256": _sha256(attested)}


def validate_relay_manifest(manifest: Any) -> dict[str, Any]:
    """Validate one relay manifest that pins consumer dependencies by hash.

    The manifest is the typed dependency record for a producer-to-consumer
    relay: required inputs bound to exact sha256 content, required facts bound
    to a plan revision, optional context that may cross, forbidden context
    that must not, and the consumer's fail-closed acknowledgment contract.
    PASS appends manifest_sha256 over the canonical submitted manifest.
    """

    issues: list[str] = []
    value = manifest if isinstance(manifest, Mapping) else {}
    _exact(
        value,
        {
            "schema",
            "producer_node",
            "consumer_node",
            "required_inputs",
            "required_facts",
            "optional_context",
            "forbidden_context",
            "consumer_ack",
        },
        "manifest",
        issues,
    )
    if value.get("schema") != RELAY_MANIFEST_SCHEMA:
        _issue(issues, "manifest:schema_invalid")

    producer = value.get("producer_node")
    if not _identifier(producer):
        _issue(issues, "manifest:producer_node_invalid")
    consumer = value.get("consumer_node")
    if not _identifier(consumer):
        _issue(issues, "manifest:consumer_node_invalid")
    if (
        _identifier(producer)
        and _identifier(consumer)
        and str(producer) == str(consumer)
    ):
        _issue(issues, "relay:producer_equals_consumer")

    required_refs: list[str] = []
    seen_refs: set[str] = set()
    required_value = value.get("required_inputs")
    if not isinstance(required_value, list):
        _issue(issues, "required_inputs:not_array")
        required_value = []
    for index, entry in enumerate(required_value):
        path = f"required_inputs[{index}]"
        _exact(
            entry,
            {"artifact_ref", "content_schema", "sha256", "reason"},
            path,
            issues,
        )
        if not isinstance(entry, Mapping):
            continue
        ref = _clean_ref(entry.get("artifact_ref"), f"{path}.artifact_ref", issues)
        if ref is not None:
            required_refs.append(ref)
            if ref in seen_refs:
                _issue(issues, f"required_inputs:duplicate_ref:{ref}")
            seen_refs.add(ref)
        if not _text(entry.get("content_schema")):
            _issue(issues, f"{path}.content_schema:invalid")
        if not isinstance(entry.get("sha256"), str) or not _SHA256.fullmatch(
            entry.get("sha256")
        ):
            _issue(issues, f"{path}.sha256_invalid")
        if not _text(entry.get("reason")):
            _issue(issues, f"{path}.reason:invalid")

    required_fact_ids: list[str] = []
    seen_fact_ids: set[str] = set()
    facts_value = value.get("required_facts")
    if not isinstance(facts_value, list):
        _issue(issues, "required_facts:not_array")
        facts_value = []
    for index, entry in enumerate(facts_value):
        path = f"required_facts[{index}]"
        _exact(
            entry, {"fact_id", "value_ref", "freshness"}, path, issues
        )
        if not isinstance(entry, Mapping):
            continue
        fact_id = entry.get("fact_id")
        if not _identifier(fact_id):
            _issue(issues, f"{path}.fact_id_invalid")
        else:
            fact_id = str(fact_id)
            required_fact_ids.append(fact_id)
            if fact_id in seen_fact_ids:
                _issue(issues, f"required_facts:duplicate_id:{fact_id}")
            seen_fact_ids.add(fact_id)
        if not _text(entry.get("value_ref")):
            _issue(issues, f"{path}.value_ref_invalid")
        freshness = entry.get("freshness")
        fresh_ok = _exact(
            freshness, {"kind", "revision"}, f"{path}.freshness", issues
        )
        if fresh_ok:
            if freshness.get("kind") != _FRESHNESS_KIND:
                _issue(issues, f"{path}.freshness:kind_invalid")
            revision = freshness.get("revision")
            if type(revision) is not int or revision < 1:
                _issue(issues, f"{path}.freshness:revision_invalid")

    optional_refs = _ref_list(
        value.get("optional_context"), "optional_context", issues
    )
    forbidden_refs = _ref_list(
        value.get("forbidden_context"), "forbidden_context", issues
    )
    for ref in sorted(set(forbidden_refs)):
        if ref in optional_refs or ref in required_refs:
            _issue(issues, f"relay:forbidden_overlaps:{ref}")

    _exact(
        value.get("consumer_ack"),
        {"required", "missing_inputs_action"},
        "consumer_ack",
        issues,
    )
    if isinstance(value.get("consumer_ack"), Mapping):
        if value.get("consumer_ack", {}).get("required") is not True:
            _issue(issues, "relay:ack_not_required")
        if value.get("consumer_ack", {}).get("missing_inputs_action") not in (
            _MISSING_INPUTS_ACTIONS
        ):
            _issue(issues, "consumer_ack:missing_inputs_action_invalid")

    status = "FAIL" if issues else "PASS"
    core: dict[str, Any] = {
        "schema": RELAY_MANIFEST_REPORT_SCHEMA,
        "status": status,
        "issues": sorted(issues),
        "producer_node": str(producer) if _identifier(producer) else None,
        "consumer_node": str(consumer) if _identifier(consumer) else None,
        "required_input_count": len(set(required_refs)),
        "required_fact_count": len(set(required_fact_ids)),
        "optional_context_count": len(optional_refs),
        "forbidden_context_count": len(forbidden_refs),
    }
    if status == "PASS":
        core["manifest_sha256"] = _sha256(dict(value))
    return _report_footer(core)


def evaluate_relay_delivery(program: Any) -> dict[str, Any]:
    """Check that a consumer actually received what its relay manifest promised.

    The delivery program submits the manifest itself plus the consumer's
    evidence: which artifacts arrived with which content hash, which facts
    the consumer acknowledged, and the consumer's acknowledgment state.
    Everything required arriving intact and acknowledged is PASS; missing
    inputs correctly routed through a CONTEXT_REQUESTED manifest pin are
    PASS_WITH_REQUESTS; anything else is FAIL. PASS and PASS_WITH_REQUESTS
    append delivery_sha256 over the canonical submitted program.
    """

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        value,
        {
            "schema",
            "manifest",
            "delivered_artifacts",
            "acknowledged_facts",
            "consumer_ack_status",
        },
        "program",
        issues,
    )
    if value.get("schema") != RELAY_DELIVERY_PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")

    manifest_value = value.get("manifest")
    manifest_report = validate_relay_manifest(manifest_value)
    nested_issues: list[str] = []
    if manifest_report["status"] != "PASS":
        _issue(issues, "delivery:manifest_invalid")
        for nested in manifest_report["issues"]:
            _issue(nested_issues, f"manifest:{nested}")
    issues.extend(nested_issues)

    manifest = manifest_value if isinstance(manifest_value, Mapping) else {}
    manifest_action = (
        manifest.get("consumer_ack", {}).get("missing_inputs_action")
        if isinstance(manifest.get("consumer_ack"), Mapping)
        else None
    )

    required_inputs: dict[str, str] = {}
    for entry in (
        manifest.get("required_inputs")
        if isinstance(manifest.get("required_inputs"), list)
        else []
    ):
        if (
            isinstance(entry, Mapping)
            and _text(entry.get("artifact_ref"))
            and isinstance(entry.get("sha256"), str)
        ):
            required_inputs[str(entry.get("artifact_ref")).strip()] = (
                str(entry.get("sha256"))
            )
    required_fact_ids = {
        str(entry.get("fact_id"))
        for entry in (
            manifest.get("required_facts")
            if isinstance(manifest.get("required_facts"), list)
            else []
        )
        if isinstance(entry, Mapping) and _identifier(entry.get("fact_id"))
    }
    forbidden_refs = _ref_list(
        manifest.get("forbidden_context"), "_forbidden", []
    )

    delivered_refs: set[str] = set()
    delivered_value = value.get("delivered_artifacts")
    if not isinstance(delivered_value, list):
        _issue(issues, "delivered_artifacts:not_array")
        delivered_value = []
    declared_refs: set[str] = set(required_inputs) | set(forbidden_refs)
    undeclared: list[str] = []
    for index, entry in enumerate(delivered_value):
        path = f"delivered_artifacts[{index}]"
        _exact(entry, {"artifact_ref", "sha256"}, path, issues)
        if not isinstance(entry, Mapping):
            continue
        ref = entry.get("artifact_ref")
        if not _text(ref):
            _issue(issues, f"{path}.artifact_ref_invalid")
            continue
        ref = str(ref).strip()
        if ref in required_inputs:
            if (
                not isinstance(entry.get("sha256"), str)
                or entry.get("sha256") != required_inputs[ref]
            ):
                _issue(issues, f"delivery:sha_mismatch:{ref}")
            elif ref not in delivered_refs:
                delivered_refs.add(ref)
        elif ref in declared_refs:
            pass
        else:
            if ref not in undeclared:
                undeclared.append(ref)
        if ref in forbidden_refs:
            _issue(issues, f"delivery:forbidden_delivered:{ref}")

    acked_value = value.get("acknowledged_facts")
    if not isinstance(acked_value, list):
        _issue(issues, "acknowledged_facts:not_array")
        acked_value = []
    acknowledged: set[str] = set()
    for index, entry in enumerate(acked_value):
        if not _text(entry):
            _issue(issues, f"acknowledged_facts[{index}]:invalid")
            continue
        acknowledged.add(str(entry).strip())
    for fact_id in sorted(required_fact_ids - acknowledged):
        _issue(issues, f"delivery:fact_unacknowledged:{fact_id}")

    ack_status = value.get("consumer_ack_status")
    if ack_status not in _ACK_STATUSES:
        _issue(issues, "program:consumer_ack_status_invalid")

    missing_inputs = sorted(set(required_inputs) - delivered_refs)
    for ref in missing_inputs:
        _issue(issues, f"delivery:missing_input:{ref}")
    if (
        missing_inputs
        and manifest_action == "CONTEXT_REQUESTED"
        and ack_status != "context_requested"
    ):
        _issue(issues, "delivery:ack_state_wrong")

    fatal_issues = [
        item
        for item in issues
        if not item.startswith("delivery:missing_input:")
    ]
    correctly_routed = (
        bool(missing_inputs)
        and manifest_action == "CONTEXT_REQUESTED"
        and ack_status == "context_requested"
    )
    if fatal_issues or (missing_inputs and not correctly_routed):
        status = "FAIL"
    elif missing_inputs:
        status = "PASS_WITH_REQUESTS"
    else:
        status = "PASS"
    core: dict[str, Any] = {
        "schema": RELAY_DELIVERY_REPORT_SCHEMA,
        "status": status,
        "manifest_sha256": (
            manifest_report.get("manifest_sha256")
            if manifest_report["status"] == "PASS"
            else None
        ),
        "issues": sorted(issues),
        "missing_inputs": missing_inputs,
        "undeclared_delivered": sorted(undeclared),
        "delivered_count": len(delivered_refs),
        "acknowledged_fact_count": len(acknowledged),
    }
    if status in ("PASS", "PASS_WITH_REQUESTS"):
        core["delivery_sha256"] = _sha256(dict(value))
    return _report_footer(core)
