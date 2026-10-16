"""Host-authenticated promotion evidence; immutable v1 receipts stay unchanged.

Only a process-issued completed live execution can publish. Readers resolve
records and trust from the fixed per-owner observer authority, never receipt
fields or request-selected state. Exact rechecks are read-only and idempotent.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat

import orch_dork_artifact_attestation as attestation
import orch_dork_observer_authority as authority
import orch_dork_observer_receipt as observer_receipt
from lifecycle_conformance import live_attempt_consumption as live, reference_values as rv
from lifecycle_conformance.values import LifecycleContractError, canonical_json

SCHEMA = "orch-dork/promotion-authentication/v1"
TERMINAL_SCHEMA = "orch-dork/issue170-qualification-owner-complete/v1"
TERMINAL_NAME = ".issue170-qualification-terminal.stage.json"
MAX_TERMINAL_BYTES = 16 * 1024 * 1024
_FIELDS = {"schema", "algorithm", "key_id", "host_id", "payload", "signature"}
_PAYLOAD_FIELDS = {"receipt_path", "receipt_sha256", "terminal_path", "terminal_sha256",
                   "store_root", "claim_receipt", "latest_receipt", "outcome_json"}


def _require(value, label):
    if value is not True:
        raise LifecycleContractError("promotion_authentication:" + label)


def _bytes(value):
    return canonical_json(value).encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(path, maximum):
    """One bounded no-follow file descriptor, with custody and stable name."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        raise LifecycleContractError("promotion_authentication:artifact_unavailable") from error
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                 and before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o022,
                 "artifact_custody")
        _require(0 < before.st_size <= maximum, "artifact_extent")
        raw = os.pread(fd, before.st_size + 1, 0)
        after, named = os.fstat(fd), os.lstat(path)
        _require(len(raw) == before.st_size
                 and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                 and (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino), "artifact_changed")
        return raw
    finally:
        os.close(fd)


def _decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        _bytes(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise LifecycleContractError("promotion_authentication:artifact_json") from error
    _require(type(value) is dict, "artifact_object")
    return value


def _directory(*, create=False):
    root = authority.default_state_dir()
    # Never provision/rotate trust as a consequence of a submitted receipt.
    authority._validate_directory(root, exact_mode=0o700, label="state_dir")
    directory = root / "promotions"
    if create:
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
    authority._validate_directory(directory, exact_mode=0o700, label="promotions")
    return directory


def _terminal(receipt_path, receipt):
    path = receipt_path.parent / TERMINAL_NAME
    raw = _read(path, MAX_TERMINAL_BYTES)
    terminal = _decode(raw)
    _require(_sha(raw) == receipt["qualification_evidence_sha256"], "terminal_digest")
    _require(terminal.get("schema") == TERMINAL_SCHEMA and terminal.get("status") == "PASS"
             and terminal.get("disposition") == "QUALIFICATION_OWNER_COMPLETED", "terminal_success")
    _require(all(terminal.get(k) == receipt[k] for k in
                 ("generation", "runtime_package_digest", "source_commit", "repair_branch"))
             and type(terminal.get("ticket_id")) is int
             and str(terminal["ticket_id"]) == receipt["ticket_id"], "terminal_identity")
    return path, _sha(raw)


def _verify_originals(payload, receipt_path):
    _require(type(payload) is dict and set(payload) == _PAYLOAD_FIELDS, "payload_shape")
    receipt, digest = live.read_promotion_receipt(receipt_path)
    _require(payload["receipt_path"] == str(receipt_path) and payload["receipt_sha256"] == digest,
             "receipt_binding")
    terminal_path, terminal_sha = _terminal(receipt_path, receipt)
    _require(payload["terminal_path"] == str(terminal_path)
             and payload["terminal_sha256"] == terminal_sha, "terminal_binding")
    _require(type(payload["outcome_json"]) is str, "outcome_type")
    claim, latest = rv.freeze(payload["claim_receipt"]), rv.freeze(payload["latest_receipt"])
    result = live.verify_campaign_consumption(
        payload["store_root"], claim_receipt=claim, latest_receipt=latest,
        expected_binding=latest.to_plain()["binding"],
        outcome_receipt=payload["outcome_json"].encode("utf-8"), receipt_path=receipt_path)
    _require(result.report.to_plain()["terminal_outcome_is_success"] is True
             and receipt["status"] == "PASS", "attempt_not_successful")
    return result.report.to_plain()


def publish_successful_execution(execution):
    """Publish once from a live execution this interpreter independently issued."""
    from lifecycle_conformance import live_qualification_execution as executor
    # Its validator rejects caller dictionaries, copies and foreign-process objects.
    report = executor.live_report(execution).to_plain()
    _require(report["terminal_outcome_is_success"] is True, "attempt_not_successful")
    originals = executor.completion_originals(execution)
    receipt_path = Path(originals["promotion_receipt_path"]).absolute()
    receipt, receipt_sha = live.read_promotion_receipt(receipt_path)
    terminal_path, terminal_sha = _terminal(receipt_path, receipt)
    payload = {"receipt_path": str(receipt_path), "receipt_sha256": receipt_sha,
               "terminal_path": str(terminal_path), "terminal_sha256": terminal_sha,
               "store_root": str(execution.root),
               "claim_receipt": originals["claim_receipt"].to_plain(),
               "latest_receipt": originals["latest_receipt"].to_plain(),
               "outcome_json": originals["outcome_receipt"].decode("utf-8")}
    _verify_originals(payload, receipt_path)
    root = authority.default_state_dir()
    identity = authority.inspect_authority()
    seed = authority._read_exact(root / authority.SEED_FILENAME, 32)
    body = {"schema": SCHEMA, "algorithm": "ed25519", "key_id": identity["key_id"],
            "host_id": identity["host_id"], "payload": payload}
    record = {**body, "signature": base64.b64encode(attestation.ed25519_sign(seed, _bytes(body))).decode("ascii")}
    directory = _directory(create=True)
    path = directory / (receipt_sha + ".json")
    raw = _bytes(record) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            _require(count > 0, "record_short_write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return verify_promotion_receipt(receipt_path)


def verify_promotion_receipt(receipt_path):
    """Authenticate fixed host evidence, then rehash terminal and replay the MAC chain."""
    receipt_path = Path(receipt_path).absolute()
    _receipt, digest = live.read_promotion_receipt(receipt_path)
    path = _directory() / (digest + ".json")
    record_raw = _read(path, 2 * 1024 * 1024)
    record = _decode(record_raw)
    _require(set(record) == _FIELDS and record["schema"] == SCHEMA
             and record["algorithm"] == "ed25519", "record_shape")
    root = authority.default_state_dir()
    store = observer_receipt.ObserverTrustStore.from_host_file(root / authority.TRUST_STORE_FILENAME)
    key = store.keys.get(record["key_id"])
    _require(key is not None and record["host_id"] == store.host_id, "host_identity")
    try:
        signature = base64.b64decode(record["signature"], validate=True)
    except (ValueError, TypeError) as error:
        raise LifecycleContractError("promotion_authentication:signature_invalid") from error
    body = {k: v for k, v in record.items() if k != "signature"}
    _require(attestation.ed25519_verify(key["public"], signature, _bytes(body)), "signature_invalid")
    report = _verify_originals(record["payload"], receipt_path)
    return {"schema": SCHEMA, "status": "PASS", "record_sha256": _sha(record_raw),
            "qualification_receipt_sha256": digest,
            "qualification_evidence_sha256": record["payload"]["terminal_sha256"],
            "durable_attempt": report["durable"]}
