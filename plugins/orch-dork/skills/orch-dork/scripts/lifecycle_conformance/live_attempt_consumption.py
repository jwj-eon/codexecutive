"""Read one real terminal live qualification result; never mint its authority.

Issue 170 authorizes exactly one live attempt.  This reader establishes that
attempt's two completion facts from durable originals only: the append-only
consumption chain that already recorded the single live_attempt phase, and the
promotion qualification receipt that attempt emitted.  It performs no effect,
takes no callback, consumes nothing itself, and never returns promotion
authority.  A terminal FAILURE is preserved exactly as faithfully as a PASS;
only the durable outcome recorded by consumption lets the fixed gate authorize
promotion, and this module always reports False.

The durable chain is the anti-forgery anchor.  consumption.read_store replays
the on-disk MAC chain under its lock, so a caller cannot present a receipt the
store does not already hold.  The retained terminal bytes are bound by
recomputing the exact chain event consumption.record_outcome appended and
requiring its canonical digest to equal the replayed tip; forging that would
need a SHA-256 preimage.  The campaign runtime digest comes from the durable
binding's post-cachebuster package identity, which consumption set only after
candidate_identity re-read two real trees, so a receipt naming any other
generation is refused.

Scope this reader does not cover: git ancestry, branch state and ticket
evidence belong to orch_dork_promotion_preflight; host custody belongs to
host_attestation.  This module reads bindings, not history.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import weakref

from lifecycle_conformance import consumption, reference_values as rv
from lifecycle_conformance.values import (
    LifecycleContractError,
    canonical_digest,
    canonical_json,
)


SCHEMA = "orch-dork/issue170-live-attempt-consumption/v1"
RECEIPT_SCHEMA = "orch-dork/promotion-qualification-receipt/v1"
PHASE = "live_attempt"
FACTS = ("fresh_live_attempt_consumed_once", "terminal_live_result_preserved")
# The closed outcome vocabulary consumption already records for a phase.
TERMINAL_OUTCOMES = ("SUCCEEDED", "FAILED", "REFUSED", "CRASHED")
SUCCESS_OUTCOME = "SUCCEEDED"
PASS_STATUS = "PASS"
MAX_RECEIPT_BYTES = 64 * 1024
# The closed promotion receipt contract owned by the promotion preflight.
RECEIPT_FIELDS = frozenset({
    "generation", "qualification_evidence_sha256", "repair_branch",
    "runtime_package_digest", "schema", "source_commit", "status", "ticket_id",
})
_PACKAGE_FIELDS = ("version", "inventory_hash", "descriptor_hash", "package_digest")
_SHA = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_TICKET = re.compile(r"[1-9][0-9]*")
_BRANCH = re.compile(r"codex/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?-repair")
_STATUS = re.compile(r"[A-Z][A-Z_]{0,31}")
_AUTHORITY = object()
_ISSUED = {}


@dataclass(frozen=True)
class ValidatedLiveAttempt:
    """One reader-issued result; construction alone grants nothing."""

    report: rv.FrozenValue
    _authority: object


def _require(condition, reason):
    if condition is not True:
        raise LifecycleContractError("live_attempt_consumption:" + reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _fingerprint(value):
    if type(value) is ValidatedLiveAttempt:
        return (value.report.digest(), id(value._authority))
    return None


def _issue(value):
    identity = id(value)
    _ISSUED[identity] = (weakref.ref(value, lambda _: _ISSUED.pop(identity, None)),
                         os.getpid(), _fingerprint(value))
    return value


def _issued(value):
    record = _ISSUED.get(id(value))
    _require(record is not None and record[0]() is value
             and record[1] == os.getpid() and record[2] == _fingerprint(value),
             "issued_object_binding")


if hasattr(os, "register_at_fork"):
    # A forked child inherits object identities but not this reader's issuance.
    os.register_at_fork(after_in_child=_ISSUED.clear)


def _decode(raw, label):
    """Strict JSON object decode: duplicate keys and non-canonical values fail."""

    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, label + ":duplicate_key")
            result[key] = value
        return result

    _require(type(raw) is bytes and 0 < len(raw) <= consumption.MAX_BYTES, label + ":extent")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        canonical_json(value)
    except LifecycleContractError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise LifecycleContractError(
            "live_attempt_consumption:" + label + ":invalid_json") from error
    _require(type(value) is dict, label + ":not_object")
    return value


def _shape(value, fields, label):
    _require(type(value) is dict and set(value) == set(fields), label)


def _text(value, pattern, label):
    _require(type(value) is str and pattern.fullmatch(value) is not None, label)


def _package(value, label):
    _shape(value, _PACKAGE_FIELDS, label)
    for field in _PACKAGE_FIELDS:
        _require(type(value[field]) is str and bool(value[field]), label)
    for field in ("inventory_hash", "descriptor_hash", "package_digest"):
        _text(value[field], _SHA, label)


def _receipt_bytes(path):
    """Read the receipt through one descriptor; refuse links and shared names."""
    _require(isinstance(path, (str, Path)) and bool(str(path)), "receipt_path")
    name = str(path)
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        raise LifecycleContractError(
            "live_attempt_consumption:receipt_unavailable") from error
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), "receipt_not_regular_file")
        _require(before.st_uid in (0, os.getuid()), "receipt_not_owned")
        _require(not stat.S_IMODE(before.st_mode) & 0o022, "receipt_writable")
        _require(before.st_nlink == 1, "receipt_shared_name")
        _require(before.st_size > 0, "receipt_empty")
        _require(before.st_size <= MAX_RECEIPT_BYTES, "receipt_too_large")
        raw = os.pread(descriptor, before.st_size + 1, 0)
        after = os.fstat(descriptor)
        named = os.lstat(name)
        _require(len(raw) == before.st_size
                 and (before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                 and (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino),
                 "receipt_changed")
        return raw
    finally:
        os.close(descriptor)


def _receipt_fields(value, label):
    """Apply the closed promotion receipt contract to one decoded object."""
    _require(type(value) is dict and set(value) == RECEIPT_FIELDS, label + ":fields")
    _require(value["schema"] == RECEIPT_SCHEMA, label + ":schema")
    _text(value["status"], _STATUS, label + ":status")
    _text(value["ticket_id"], _TICKET, label + ":ticket_id")
    _text(value["repair_branch"], _BRANCH, label + ":repair_branch")
    _text(value["source_commit"], _COMMIT, label + ":source_commit")
    for field in ("runtime_package_digest", "qualification_evidence_sha256"):
        _text(value[field], _SHA, label + ":" + field)
    generation = value["generation"]
    _require(type(generation) is str and 0 < len(generation) <= 128
             and not any(character in generation for character in "/\\\x00")
             and all(ord(character) >= 0x20 and ord(character) != 0x7F
                     for character in generation),
             label + ":generation")
    return value


def read_promotion_receipt(path):
    """Return one on-disk promotion receipt and its exact file digest."""
    raw = _receipt_bytes(path)
    return _receipt_fields(_decode(raw, "receipt"), "receipt"), _sha(raw)


def _retained_original(transport):
    """Classify the durably retained original as a promotion receipt or not.

    A real terminal failure need not emit a promotion receipt at all, so the
    non-receipt branch stays open for failure evidence only.  Anything that
    claims the promotion schema is held to the whole closed contract here.
    """
    _shape(transport, ("schema", "status", "original_receipt_json"), "transport_shape")
    _require(transport["schema"] == consumption.TRANSPORT_SCHEMA
             and transport["status"] in ("VALIDATED", "REFUSED")
             and type(transport["original_receipt_json"]) is str, "transport_shape")
    original = _decode(transport["original_receipt_json"].encode("utf-8"), "retained_original")
    schema = original.get("schema")
    _require(type(schema) is str and 0 < len(schema) <= 256, "retained_original_schema")
    if schema == RECEIPT_SCHEMA:
        return "promotion_receipt", _receipt_fields(original, "retained_receipt")
    return "non_receipt_original", original


def _outcome_text(outcome_receipt):
    try:
        return outcome_receipt.decode("utf-8")
    except UnicodeError as error:
        raise LifecycleContractError(
            "live_attempt_consumption:outcome:invalid_json") from error


def _terminal_event(claim_receipt, latest, outcome_receipt):
    """Rebuild the exact chain event consumption appended, and bind its digest."""
    plain = latest.to_plain()
    event = {"previous_sha256": claim_receipt.digest(), "operation": "outcome",
             "phase": plain["phase"], "claim": plain["claim"],
             "outcome_json": _outcome_text(outcome_receipt), "transition": None}
    _require(canonical_digest(event) == plain["tip_sha256"], "durable_outcome_binding")
    return event


def _claim_snapshot(claim_receipt, latest):
    """The retained claim receipt must be this chain's immediate predecessor."""
    _require(type(claim_receipt) is rv.FrozenValue, "claim_receipt_required")
    claim, plain = claim_receipt.to_plain(), latest.to_plain()
    _require(type(claim) is dict and set(claim) == set(plain), "claim_receipt_shape")
    _require(claim["schema"] == consumption.RECEIPT_SCHEMA
             and claim["store"] == plain["store"] and claim["binding"] == plain["binding"]
             and claim["phase"] == plain["phase"] and claim["claim"] == plain["claim"]
             and claim["status"] == "CLAIMED" and claim["sequence"] == plain["sequence"] - 1,
             "claim_receipt_binding")
    return claim


def verify_campaign_consumption(store_root, *, claim_receipt, latest_receipt,
                                expected_binding, outcome_receipt, receipt_path=None):
    """Derive the two live-attempt facts from durable originals; grant nothing else."""
    _require(type(latest_receipt) is rv.FrozenValue, "latest_receipt_required")
    _require(type(outcome_receipt) is bytes and 0 < len(outcome_receipt) <= consumption.MAX_BYTES,
             "outcome_receipt_extent")
    # Replay the on-disk chain. A caller-built receipt cannot survive this.
    latest = consumption.read_store(store_root, latest_receipt, expected_binding=expected_binding)
    # Redundant today and deliberately kept: consumption._locked already refuses
    # a receipt that differs from the replayed chain, so mutation testing cannot
    # reach this line. It asserts that cross-module invariant locally, and would
    # start failing if read_store ever returned a value it did not re-derive.
    _require(latest == latest_receipt, "latest_receipt_binding")
    plain = latest.to_plain()
    _require(plain["phase"] == PHASE, "phase_binding")
    _require(plain["status"] in TERMINAL_OUTCOMES, "terminal_status_required")
    _claim_snapshot(claim_receipt, latest)
    _terminal_event(claim_receipt, latest, outcome_receipt)

    envelope = _decode(outcome_receipt, "outcome")
    _shape(envelope, ("schema", "phase", "claim_sha256", "outcome", "transport"), "outcome_shape")
    _require(envelope["schema"] == consumption.OUTCOME_SCHEMA
             and envelope["phase"] == PHASE
             and envelope["claim_sha256"] == claim_receipt.digest()
             and envelope["outcome"] == plain["status"], "outcome_binding")
    transport = envelope["transport"]
    kind, retained = _retained_original(transport)

    binding = plain["binding"]
    _require(type(binding) is dict and set(binding) == {
        "campaign_receipt_sha256", "pre_runtime", "post_runtime", "transition_sha256"},
        "binding_shape")
    pre, post = binding["pre_runtime"], binding["post_runtime"]
    _package(pre, "pre_runtime_shape")
    _require(type(post) is dict, "candidate_generation_required")
    _package(post, "post_runtime_shape")
    _text(binding["transition_sha256"], _SHA, "transition_binding")
    _require(pre["package_digest"] != post["package_digest"], "generation_not_distinct")

    success = plain["status"] == SUCCESS_OUTCOME
    _require(not success or transport["status"] == "VALIDATED", "transport_refused")
    if kind == "promotion_receipt":
        _require(receipt_path is not None, "receipt_path_required")
        receipt, receipt_sha256 = read_promotion_receipt(receipt_path)
        # The preserved artifact must still be the one the attempt retained.
        _require(retained == receipt, "retained_receipt_binding")
        # A receipt from any other generation is refused here.
        _require(receipt["runtime_package_digest"] == post["package_digest"],
                 "receipt_generation_digest")
        _require(receipt["generation"] == post["version"], "receipt_generation_version")
        _require(success == (receipt["status"] == PASS_STATUS), "terminal_status_binding")
        evidence = {"kind": kind, "schema": receipt["schema"],
                    "canonical_sha256": canonical_digest(receipt),
                    "path": str(receipt_path), "bytes_sha256": receipt_sha256,
                    "receipt": {
                        "status": receipt["status"], "generation": receipt["generation"],
                        "ticket_id": receipt["ticket_id"],
                        "repair_branch": receipt["repair_branch"],
                        "source_commit": receipt["source_commit"],
                        "runtime_package_digest": receipt["runtime_package_digest"],
                        "qualification_evidence_sha256":
                            receipt["qualification_evidence_sha256"]}}
    else:
        # Only a preserved failure may lack a promotion receipt. The campaign
        # generation still binds through the durable post-cachebuster identity.
        _require(not success, "success_requires_promotion_receipt")
        _require(receipt_path is None, "unexpected_receipt_path")
        evidence = {"kind": kind, "schema": retained["schema"],
                    "canonical_sha256": canonical_digest(retained),
                    "path": None, "bytes_sha256": None, "receipt": None}

    report = rv.freeze({
        "schema": SCHEMA,
        "status": "LIVE_ATTEMPT_CONSUMPTION_VERIFIED",
        "phase": PHASE,
        "durable": {
            "store": plain["store"], "sequence": plain["sequence"],
            "tip_sha256": plain["tip_sha256"],
            "claim_receipt_sha256": claim_receipt.digest(),
            "latest_receipt_sha256": latest.digest(),
            "campaign_receipt_sha256": binding["campaign_receipt_sha256"],
            "transition_sha256": binding["transition_sha256"],
            "outcome_receipt_sha256": _sha(outcome_receipt),
            "terminal_outcome": plain["status"],
            "transport_status": transport["status"]},
        "terminal_evidence": evidence,
        "runtime_identity": {
            "pre_package_digest": pre["package_digest"], "pre_version": pre["version"],
            "post_package_digest": post["package_digest"], "post_version": post["version"]},
        "completion_facts": list(FACTS),
        "terminal_outcome_is_success": success,
        "terminal_result_preserved": True,
        "single_consumption_required": True,
        "retry_permitted": False,
        "campaign_authority": False,
        "release_authority": False,
        "live_authority": False,
        "qualification_authority": False,
        "promotion_authority": False})
    return _issue(ValidatedLiveAttempt(report, _AUTHORITY))


def validate_campaign_consumption(store_root, report, *, claim_receipt, latest_receipt,
                                  expected_binding, outcome_receipt, receipt_path=None):
    """Re-derive from the same originals; a supplied report cannot reseal itself."""
    _require(type(report) is rv.FrozenValue, "report_not_immutable")
    rebuilt = verify_campaign_consumption(
        store_root, claim_receipt=claim_receipt, latest_receipt=latest_receipt,
        expected_binding=expected_binding, outcome_receipt=outcome_receipt,
        receipt_path=receipt_path)
    _require(report == rebuilt.report, "report_binding")
    return rebuilt


def completion_facts(validated):
    """Return the two facts only for a result this reader itself issued."""
    _require(type(validated) is ValidatedLiveAttempt, "validated_type")
    _issued(validated)
    report = validated.report.to_plain()
    _require(validated._authority is _AUTHORITY
             and report["schema"] == SCHEMA
             and report["status"] == "LIVE_ATTEMPT_CONSUMPTION_VERIFIED"
             and report["phase"] == PHASE, "issued_report_binding")
    return tuple(report["completion_facts"])


__all__ = ["SCHEMA", "RECEIPT_SCHEMA", "PHASE", "FACTS", "RECEIPT_FIELDS",
           "TERMINAL_OUTCOMES", "ValidatedLiveAttempt", "read_promotion_receipt",
           "verify_campaign_consumption", "validate_campaign_consumption",
           "completion_facts"]
