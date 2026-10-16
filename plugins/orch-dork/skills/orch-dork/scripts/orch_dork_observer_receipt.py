#!/usr/bin/env python3
"""Host-signed observer receipts with pinned trust and replay control.

Submitted SHA-256 self-seals prove only internal consistency.  This module is
the authority boundary for capacity, custody, and calibration observations:
the host signs a closed envelope with Ed25519; verification resolves the key
from host-owned state, binds expected payload fields and time, and records the
nonce in host-owned replay state.  Neither a trust root nor a signing key is
accepted from the submitted envelope.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any, Mapping, MutableMapping


def _load_sibling(name: str):
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name + " unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    import orch_dork_artifact_attestation as attestation
    import orch_dork_evidence_core as evidence
except ModuleNotFoundError:  # standalone spec loading in focused tests
    attestation = _load_sibling("orch_dork_artifact_attestation")
    evidence = _load_sibling("orch_dork_evidence_core")


ENVELOPE_SCHEMA = "orch-dork/signed-observer-receipt/v1"
TRUST_STORE_SCHEMA = "orch-dork/observer-trust-store/v1"
REPORT_SCHEMA = "orch-dork/signed-observer-verification/v1"
TRUST_STORE_ENV = "ORCH_DORK_OBSERVER_TRUST_STORE"
REPLAY_DB_ENV = "ORCH_DORK_OBSERVER_REPLAY_DB"
MAX_VALIDITY_SECONDS = 300

_ENVELOPE_FIELDS = {
    "schema",
    "receipt_kind",
    "key_id",
    "algorithm",
    "host_id",
    "issued_at",
    "valid_until",
    "nonce",
    "payload",
    "payload_sha256",
    "signature",
}
_TRUST_FIELDS = {"schema", "generation", "host_id", "keys"}
_KEY_FIELDS = {
    "key_id",
    "algorithm",
    "public_key",
    "fingerprint",
    "status",
}


class ObserverReceiptError(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _text(value: Any, *, limit: int = 512) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit and "\x00" not in value


def _safe_digest(value: Any) -> str | None:
    try:
        return evidence.digest(value)
    except (TypeError, ValueError, UnicodeError):
        return None


def _utc(value: datetime | str | None) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return None
        return value.astimezone(timezone.utc)
    return evidence.instant(value)


def _secure_host_file(path: str | os.PathLike[str]) -> Path:
    target = Path(path)
    if not target.is_absolute() or target.is_symlink():
        raise ObserverReceiptError("host_file:unsafe_path")
    try:
        info = target.stat()
    except OSError as exc:
        raise ObserverReceiptError("host_file:unavailable") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ObserverReceiptError("host_file:not_regular")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ObserverReceiptError("host_file:wrong_owner")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise ObserverReceiptError("host_file:writable_by_others")
    return target


def _read_secure_host_file(
    path: str | os.PathLike[str], *, max_bytes: int
) -> bytes:
    """Read one host file through a no-follow descriptor and recheck it."""

    target = _secure_host_file(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise ObserverReceiptError("host_file:changed_during_read")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ObserverReceiptError("host_file:too_large")
        return data
    except OSError as exc:
        raise ObserverReceiptError("host_file:unavailable") from exc
    finally:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass


def _decode_public_key(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ObserverReceiptError("trust_store:public_key_invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ObserverReceiptError("trust_store:public_key_invalid") from exc
    if len(decoded) != 32:
        raise ObserverReceiptError("trust_store:public_key_invalid")
    return decoded


class ObserverTrustStore:
    """Validated pinned public keys loaded from host-owned state."""

    def __init__(self, value: Mapping[str, Any], *, source: str) -> None:
        issues: list[str] = []
        if evidence.closed(value, _TRUST_FIELDS, "trust_store", issues) is None:
            raise ObserverReceiptError(issues[0])
        if value.get("schema") != TRUST_STORE_SCHEMA:
            raise ObserverReceiptError("trust_store:schema_invalid")
        if not _text(value.get("generation"), limit=128):
            raise ObserverReceiptError("trust_store:generation_invalid")
        if not _text(value.get("host_id"), limit=128):
            raise ObserverReceiptError("trust_store:host_id_invalid")
        rows = value.get("keys")
        if not isinstance(rows, list) or not rows:
            raise ObserverReceiptError("trust_store:no_keys")
        keys: dict[str, dict[str, Any]] = {}
        for index, row in enumerate(rows):
            row_issues: list[str] = []
            if evidence.closed(row, _KEY_FIELDS, f"trust_store.keys[{index}]", row_issues) is None:
                raise ObserverReceiptError(row_issues[0])
            assert isinstance(row, Mapping)
            key_id = row.get("key_id")
            if not _text(key_id, limit=128) or key_id in keys:
                raise ObserverReceiptError("trust_store:key_id_invalid")
            if row.get("algorithm") != "ed25519" or row.get("status") != "active":
                raise ObserverReceiptError("trust_store:key_policy_invalid")
            public = _decode_public_key(row.get("public_key"))
            fingerprint = row.get("fingerprint")
            if (
                not isinstance(fingerprint, str)
                or evidence.SHA256_PATTERN.fullmatch(fingerprint) is None
                or fingerprint != attestation.sha256_hex(public)
            ):
                raise ObserverReceiptError("trust_store:fingerprint_mismatch")
            keys[str(key_id)] = {"public": public, "fingerprint": fingerprint}
        self.generation = str(value["generation"])
        self.host_id = str(value["host_id"])
        self.keys = keys
        self.source = source

    @classmethod
    def from_host_file(cls, path: str | os.PathLike[str]) -> "ObserverTrustStore":
        try:
            value = attestation.parse_canonical_json(
                _read_secure_host_file(path, max_bytes=1 << 20)
            )
        except (attestation.AttestationError, OSError) as exc:
            raise ObserverReceiptError("trust_store:malformed") from exc
        if not isinstance(value, Mapping):
            raise ObserverReceiptError("trust_store:not_object")
        return cls(value, source=str(Path(path)))

    @classmethod
    def from_mapping_for_tests(cls, value: Mapping[str, Any]) -> "ObserverTrustStore":
        return cls(value, source="test-fixture")


class InMemoryHostSigner:
    """Deterministic fixture signer; production uses ``FileHostSigner``."""

    def __init__(self, seed: bytes, *, key_id: str, host_id: str, fixture: bool) -> None:
        if not fixture:
            raise ObserverReceiptError("signer:fixture_constructor_forbidden")
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise ObserverReceiptError("signer:seed_invalid")
        if not _text(key_id, limit=128) or not _text(host_id, limit=128):
            raise ObserverReceiptError("signer:identity_invalid")
        self._seed = seed
        self.key_id = key_id
        self.host_id = host_id

    @classmethod
    def for_tests(cls, seed: bytes, *, key_id: str, host_id: str) -> "InMemoryHostSigner":
        return cls(seed, key_id=key_id, host_id=host_id, fixture=True)

    def issue(
        self,
        receipt_kind: str,
        payload: Mapping[str, Any],
        *,
        issued_at: str,
        valid_until: str,
        nonce: str,
    ) -> dict[str, Any]:
        if not _text(receipt_kind, limit=128) or not isinstance(payload, Mapping):
            raise ObserverReceiptError("receipt:payload_invalid")
        if not _text(nonce, limit=256):
            raise ObserverReceiptError("receipt:nonce_invalid")
        issued = evidence.instant(issued_at)
        until = evidence.instant(valid_until)
        if issued is None or until is None or issued > until:
            raise ObserverReceiptError("receipt:time_invalid")
        if (until - issued).total_seconds() > MAX_VALIDITY_SECONDS:
            raise ObserverReceiptError("receipt:validity_too_long")
        body = {
            "schema": ENVELOPE_SCHEMA,
            "receipt_kind": receipt_kind,
            "key_id": self.key_id,
            "algorithm": "ed25519",
            "host_id": self.host_id,
            "issued_at": issued_at,
            "valid_until": valid_until,
            "nonce": nonce,
            "payload": dict(payload),
            "payload_sha256": evidence.digest(payload),
        }
        signature = attestation.ed25519_sign(self._seed, evidence.canonical_bytes(body))
        return {
            **body,
            "signature": base64.b64encode(signature).decode("ascii"),
        }


class FileHostSigner(InMemoryHostSigner):
    """Production signer whose private seed is read only from a host file."""

    @classmethod
    def from_host_file(
        cls,
        path: str | os.PathLike[str],
        *,
        key_id: str,
        host_id: str,
    ) -> "FileHostSigner":
        seed = _read_secure_host_file(path, max_bytes=32)
        if len(seed) != 32:
            raise ObserverReceiptError("signer:seed_invalid")
        return cls(seed, key_id=key_id, host_id=host_id, fixture=True)


class MemoryReplayGuard:
    def __init__(self) -> None:
        self._seen: MutableMapping[tuple[str, str], str] = {}

    def observe(self, namespace: str, nonce: str, receipt_sha256: str) -> str:
        key = (namespace, nonce)
        previous = self._seen.get(key)
        if previous is None:
            self._seen[key] = receipt_sha256
            return "accepted"
        return "idempotent" if previous == receipt_sha256 else "collision"


class SQLiteReplayGuard:
    """Host-owned durable nonce registry; exact re-verification is idempotent."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        target = Path(path)
        if not target.is_absolute() or target.is_symlink() or not target.parent.is_dir():
            raise ObserverReceiptError("replay:unsafe_path")
        parent_info = target.parent.stat()
        if (
            target.parent.is_symlink()
            or (hasattr(os, "getuid") and parent_info.st_uid != os.getuid())
            or stat.S_IMODE(parent_info.st_mode) & 0o022
        ):
            raise ObserverReceiptError("replay:unsafe_parent")
        if target.exists():
            _secure_host_file(target)
        self.path = target

    def observe(self, namespace: str, nonce: str, receipt_sha256: str) -> str:
        try:
            connection = sqlite3.connect(self.path, timeout=2.0)
            if self.path.exists():
                self.path.chmod(0o600)
            with connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS observer_nonce (namespace TEXT NOT NULL, nonce TEXT NOT NULL, receipt_sha256 TEXT NOT NULL, PRIMARY KEY(namespace, nonce))"
                )
                row = connection.execute(
                    "SELECT receipt_sha256 FROM observer_nonce WHERE namespace=? AND nonce=?",
                    (namespace, nonce),
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO observer_nonce(namespace, nonce, receipt_sha256) VALUES (?, ?, ?)",
                        (namespace, nonce, receipt_sha256),
                    )
                    return "accepted"
                return "idempotent" if row[0] == receipt_sha256 else "collision"
        except sqlite3.Error:
            return "unavailable"
        finally:
            try:
                connection.close()
            except (NameError, sqlite3.Error):
                pass


def _report(
    status: str,
    reason: str,
    *,
    envelope: Mapping[str, Any] | None = None,
    trust_store: ObserverTrustStore | None = None,
    payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    receipt_sha = _safe_digest(envelope) if isinstance(envelope, Mapping) else None
    core = {
        "schema": REPORT_SCHEMA,
        "status": status,
        "reason": reason,
        "verified": status == "PASS",
        "receipt_kind": envelope.get("receipt_kind") if isinstance(envelope, Mapping) else None,
        "host_id": envelope.get("host_id") if isinstance(envelope, Mapping) else None,
        "key_id": envelope.get("key_id") if isinstance(envelope, Mapping) else None,
        "trust_generation": trust_store.generation if trust_store is not None else None,
        "payload_sha256": envelope.get("payload_sha256") if isinstance(envelope, Mapping) else None,
        "signed_receipt_sha256": receipt_sha,
        "payload": dict(payload) if status == "PASS" and isinstance(payload, Mapping) else None,
        "provider_free": True,
        "network_attempts": 0,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return evidence.seal(core, "report_sha256")


def _host_dependencies(
    trust_store: ObserverTrustStore | None,
    replay_guard: Any,
    environ: Mapping[str, str],
) -> tuple[ObserverTrustStore | None, Any, str | None]:
    try:
        if trust_store is None:
            path = environ.get(TRUST_STORE_ENV)
            if not path:
                return None, replay_guard, "trust_store:unavailable"
            trust_store = ObserverTrustStore.from_host_file(path)
        if replay_guard is None:
            replay_path = environ.get(REPLAY_DB_ENV)
            if not replay_path:
                return trust_store, None, "replay:unavailable"
            replay_guard = SQLiteReplayGuard(replay_path)
    except ObserverReceiptError as exc:
        return trust_store, replay_guard, exc.reason
    return trust_store, replay_guard, None


def host_authority_configured(
    *,
    trust_store: ObserverTrustStore | None = None,
    replay_guard: Any = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Whether :func:`verify_signed_receipt` has both host dependencies named.

    This is the naming half of ``_host_dependencies``: a trust store and a
    replay guard, each either injected or named by its environment
    variable.  It answers whether verification can start at all, not whether
    the named material is usable; opening and validating it stays with the
    verifier, whose ``trust_store:unavailable`` and ``replay:unavailable``
    outcomes are exactly the cases this predicate reports as False.
    """

    environment = os.environ if environ is None else environ
    return (
        trust_store is not None or bool(environment.get(TRUST_STORE_ENV))
    ) and (replay_guard is not None or bool(environment.get(REPLAY_DB_ENV)))


def verify_signed_receipt(
    envelope: Any,
    *,
    expected_kind: str,
    expected_payload: Mapping[str, Any],
    evaluation_time: datetime | str,
    trust_store: ObserverTrustStore | None = None,
    replay_guard: Any = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify one receipt without accepting trust material from its payload."""

    environment = os.environ if environ is None else environ
    trust_store, replay_guard, dependency_issue = _host_dependencies(
        trust_store, replay_guard, environment
    )
    if dependency_issue is not None:
        return _report("UNAVAILABLE", dependency_issue, trust_store=trust_store)
    assert trust_store is not None
    if isinstance(envelope, Mapping):
        value = dict(envelope)
    elif isinstance(envelope, (bytes, bytearray, memoryview, str)):
        try:
            parsed = attestation.parse_canonical_json(envelope)
        except (attestation.AttestationError, TypeError, ValueError):
            return _report("DENY", "receipt:malformed", trust_store=trust_store)
        value = dict(parsed) if isinstance(parsed, Mapping) else {}
    else:
        value = {}
    issues: list[str] = []
    if evidence.closed(value, _ENVELOPE_FIELDS, "receipt", issues) is None:
        return _report("DENY", issues[0], envelope=value, trust_store=trust_store)
    if value.get("schema") != ENVELOPE_SCHEMA:
        return _report("DENY", "receipt:schema_invalid", envelope=value, trust_store=trust_store)
    if value.get("receipt_kind") != expected_kind:
        return _report("DENY", "receipt:kind_mismatch", envelope=value, trust_store=trust_store)
    if value.get("algorithm") != "ed25519":
        return _report("DENY", "signature:algorithm_unsupported", envelope=value, trust_store=trust_store)
    if value.get("host_id") != trust_store.host_id:
        return _report("DENY", "trust_store:host_mismatch", envelope=value, trust_store=trust_store)
    key_id = value.get("key_id")
    key = trust_store.keys.get(str(key_id))
    if key is None:
        return _report("UNAVAILABLE", "signature:unknown_key", envelope=value, trust_store=trust_store)
    payload = value.get("payload")
    payload_digest = _safe_digest(payload)
    if (
        not isinstance(payload, Mapping)
        or payload_digest is None
        or value.get("payload_sha256") != payload_digest
    ):
        return _report("DENY", "receipt:payload_digest_mismatch", envelope=value, trust_store=trust_store)
    body = dict(value)
    encoded_signature = body.pop("signature", None)
    if not isinstance(encoded_signature, str) or len(encoded_signature) > 256:
        return _report("DENY", "signature:malformed", envelope=value, trust_store=trust_store)
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except (TypeError, ValueError):
        return _report("DENY", "signature:malformed", envelope=value, trust_store=trust_store)
    try:
        signed_body = evidence.canonical_bytes(body)
    except (TypeError, ValueError, UnicodeError):
        return _report("DENY", "receipt:malformed", envelope=value, trust_store=trust_store)
    if len(signature) != 64 or not attestation.ed25519_verify(
        key["public"], signature, signed_body
    ):
        return _report("DENY", "signature:invalid", envelope=value, trust_store=trust_store)
    now = _utc(evaluation_time)
    issued = evidence.instant(value.get("issued_at"))
    until = evidence.instant(value.get("valid_until"))
    freshness = evidence.freshness_issues(
        issued,
        issued,
        until,
        now=now,
        max_seconds=MAX_VALIDITY_SECONDS,
    )
    if freshness:
        return _report("DENY", freshness[0], envelope=value, trust_store=trust_store)
    if not _text(value.get("nonce"), limit=256):
        return _report("DENY", "receipt:nonce_invalid", envelope=value, trust_store=trust_store)
    for field, expected in expected_payload.items():
        if field not in payload or payload.get(field) != expected:
            return _report("DENY", "receipt:subject_mismatch:" + str(field), envelope=value, trust_store=trust_store)
    receipt_sha = _safe_digest(value)
    if receipt_sha is None:
        return _report("DENY", "receipt:malformed", envelope=value, trust_store=trust_store)
    try:
        replay = replay_guard.observe(
            str(value.get("receipt_kind")) + ":" + str(value.get("host_id")),
            str(value.get("nonce")),
            receipt_sha,
        )
    except Exception:
        replay = "unavailable"
    if replay == "collision":
        return _report("DENY", "replay:nonce_collision", envelope=value, trust_store=trust_store)
    if replay not in {"accepted", "idempotent"}:
        return _report("UNAVAILABLE", "replay:unavailable", envelope=value, trust_store=trust_store)
    return _report(
        "PASS",
        "verified",
        envelope=value,
        trust_store=trust_store,
        payload=payload,
    )


def require_signed_payload(
    submitted: Any,
    *,
    expected_kind: str,
    expected_payload: Mapping[str, Any],
    evaluation_time: datetime | str,
    trust_store: ObserverTrustStore | None = None,
    replay_guard: Any = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return one verified payload gateway for all observer consumers.

    A well-formed unsigned mapping remains available only as a compatibility
    candidate so domain validators can explain why its self-seal is advisory.
    Once a value claims to be a signed envelope, any verification failure
    suppresses its payload entirely; consumers must never project attacker-
    controlled envelope contents into an authority report.
    """

    value = dict(submitted) if isinstance(submitted, Mapping) else {}
    signed = value.get("schema") == ENVELOPE_SCHEMA
    if signed:
        report = verify_signed_receipt(
            value,
            expected_kind=expected_kind,
            expected_payload=expected_payload,
            evaluation_time=evaluation_time,
            trust_store=trust_store,
            replay_guard=replay_guard,
            environ=environ,
        )
        candidate = report.get("payload") if report.get("status") == "PASS" else None
    else:
        report = {
            "status": "DENY",
            "reason": "receipt:host_signature_required",
            "key_id": None,
            "trust_generation": None,
            "signed_receipt_sha256": None,
        }
        candidate = value if _safe_digest(value) is not None else None
    return {
        "status": report.get("status"),
        "reason": report.get("reason"),
        "payload": dict(candidate) if isinstance(candidate, Mapping) else None,
        "key_id": report.get("key_id"),
        "trust_generation": report.get("trust_generation"),
        "signed_receipt_sha256": report.get("signed_receipt_sha256"),
        "signed_envelope": signed,
    }


def signature_issue_codes(
    gateway: Mapping[str, Any],
    *,
    required_code: str,
    status_prefix: str,
    reason_prefix: str,
) -> list[str]:
    """Project one gateway failure into a domain's stable issue namespace."""

    if gateway.get("status") == "PASS":
        return []
    reason = gateway.get("reason")
    if reason == "receipt:host_signature_required":
        return [required_code]
    issues = [status_prefix + str(gateway.get("status", "invalid")).lower()]
    if _text(reason):
        issues.append(reason_prefix + str(reason))
    return issues


def signing_provenance(report: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize the three fields that identify host signing authority."""

    value = report if isinstance(report, Mapping) else {}
    verified = value.get("status") == "PASS"
    digest = value.get("signed_receipt_sha256") if verified else None
    key_id = value.get("key_id") if verified else None
    generation = value.get("trust_generation") if verified else None
    return {
        "signed_receipt_sha256": (
            digest
            if isinstance(digest, str) and evidence.SHA256_PATTERN.fullmatch(digest)
            else None
        ),
        "signing_key_id": key_id if _text(key_id, limit=128) else None,
        "trust_generation": generation if _text(generation, limit=128) else None,
    }


__all__ = [
    "ENVELOPE_SCHEMA",
    "MAX_VALIDITY_SECONDS",
    "REPLAY_DB_ENV",
    "REPORT_SCHEMA",
    "TRUST_STORE_ENV",
    "TRUST_STORE_SCHEMA",
    "FileHostSigner",
    "InMemoryHostSigner",
    "MemoryReplayGuard",
    "ObserverReceiptError",
    "ObserverTrustStore",
    "SQLiteReplayGuard",
    "host_authority_configured",
    "require_signed_payload",
    "signature_issue_codes",
    "signing_provenance",
    "verify_signed_receipt",
]
