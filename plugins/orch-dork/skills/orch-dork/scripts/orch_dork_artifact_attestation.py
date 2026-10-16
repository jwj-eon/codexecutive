"""Provider-free detached attestation verification and atomic update helpers.

This module intentionally has no third-party dependencies and no online code
path.  It implements the small DSSE/in-toto surface needed by the portable
package gate:

* bounded, duplicate-key-free canonical JSON and UTF-8 handling;
* detached DSSE signatures over the exact decoded payload bytes;
* a strict Ed25519 verifier (plus a deterministic fixture signer used by
  tests) with pinned conventional-key and offline keyless policies; and
* verify-before-stage updates which leave the previous generation untouched
  until all validation has completed.

The public verification functions return machine evidence together with a
compact ``receipt``.  The receipt deliberately omits paths, signatures, key
material, and full cryptographic identifiers; callers that need those values
must use the machine-evidence fields and keep them out of human approval
messages.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _datetime
import hashlib
import json
import math
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "orch-dork/artifact-attestation/v1"
RECEIPT_SCHEMA = "orch-dork/artifact-verification-receipt/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
STATUS_PASS = "PASS"
STATUS_DENY = "DENY"
STATUS_UNAVAILABLE = "UNAVAILABLE"

# Bounds are deliberately finite.  They are large enough for the package
# metadata but protect a verifier that receives hostile detached evidence.
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_SIGNATURES = 16
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_TEXT = 1 * 1024 * 1024

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HASH_RE = re.compile(r"(?:sha256:)?([0-9a-fA-F]{64})\Z")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class AttestationError(ValueError):
    """Malformed or policy-invalid detached attestation input."""

    def __init__(self, message: str, *, issues: Sequence[str] = ()) -> None:
        self.issues = tuple(str(i) for i in issues if i) or (message,)
        super().__init__(message)


VerificationError = AttestationError


class _Issue(Exception):
    def __init__(self, status: str, reason: str, **evidence: Any) -> None:
        self.status = status
        self.reason = reason
        self.evidence = evidence
        super().__init__(reason)


class _DuplicateKey(ValueError):
    pass


def _pairs_no_duplicates(pairs: list[tuple[Any, Any]]) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(str(key))
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number: {value}")


def _walk_json(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_NODES:
        raise AttestationError("json:too_many_nodes", issues=("json:too_many_nodes",))
    if depth > MAX_DEPTH:
        raise AttestationError("json:too_deep", issues=("json:too_deep",))
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AttestationError("json:object_key_not_string", issues=("json:object_key_not_string",))
            if _CONTROL_RE.search(key):
                raise AttestationError("json:control_character", issues=("json:control_character",))
            _walk_json(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk_json(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, str):
        if len(value) > MAX_TEXT or _CONTROL_RE.search(value):
            raise AttestationError("json:unsafe_text", issues=("json:unsafe_text",))
        # A lone surrogate cannot be represented as UTF-8.  Checking here
        # gives a named policy failure instead of an implementation traceback.
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise AttestationError("json:invalid_utf8", issues=("json:invalid_utf8",)) from exc
    elif isinstance(value, float) and not math.isfinite(value):
        raise AttestationError("json:non_finite_number", issues=("json:non_finite_number",))
    elif value is None or isinstance(value, (bool, int, float)):
        return
    else:
        raise AttestationError("json:unsupported_value", issues=("json:unsupported_value",))


def canonical_json_bytes(value: Any, *, max_bytes: int = MAX_JSON_BYTES) -> bytes:
    """Return deterministic compact UTF-8 JSON, rejecting ambiguity.

    Mapping keys are sorted by their Unicode code points, matching Python's
    deterministic JSON encoder.  Duplicate keys can only occur while parsing
    bytes; :func:`parse_canonical_json` installs the duplicate-key hook first.
    """

    _walk_json(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AttestationError("json:canonical_encoding_failed", issues=("json:canonical_encoding_failed",)) from exc
    if len(encoded) > max_bytes:
        raise AttestationError("json:too_large", issues=("json:too_large",))
    return encoded


def parse_canonical_json(value: bytes | bytearray | memoryview | str | Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Parse bytes and require that their representation is canonical JSON."""

    if isinstance(value, Path):
        try:
            raw = value.read_bytes()
        except OSError as exc:
            raise AttestationError("json:read_failed", issues=("json:read_failed",)) from exc
    elif isinstance(value, str):
        raw = value.encode("utf-8", "strict")
    else:
        raw = bytes(value)
    if len(raw) > max_bytes:
        raise AttestationError("json:too_large", issues=("json:too_large",))
    try:
        text = raw.decode("utf-8", "strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (_DuplicateKey, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        issue = "json:duplicate_key" if isinstance(exc, _DuplicateKey) else "json:malformed"
        raise AttestationError(issue, issues=(issue,)) from exc
    canonical = canonical_json_bytes(parsed, max_bytes=max_bytes)
    if canonical != raw:
        raise AttestationError("json:not_canonical", issues=("json:not_canonical",))
    return parsed


def canonicalize_json(value: Any, *, max_bytes: int = MAX_JSON_BYTES) -> bytes:
    """Compatibility alias for callers that use the noun/verb spelling."""

    return canonical_json_bytes(value, max_bytes=max_bytes)


def sha256_hex(value: bytes | bytearray | memoryview) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def _normalise_digest(value: Any, *, field: str = "digest") -> str:
    if isinstance(value, Mapping):
        value = value.get("sha256")
    if not isinstance(value, str):
        raise _Issue(STATUS_DENY, f"{field}:missing")
    match = _HASH_RE.fullmatch(value.strip())
    if match is None:
        raise _Issue(STATUS_DENY, f"{field}:invalid_sha256")
    return match.group(1).lower()


def _digest_label(value: str | None) -> str | None:
    if not value:
        return None
    return f"sha256:{value[:12]}"


def _decode_base64(value: Any, *, field: str, max_bytes: int = MAX_PAYLOAD_BYTES) -> bytes:
    if not isinstance(value, str) or not value or len(value) > max_bytes * 2:
        raise _Issue(STATUS_DENY, f"{field}:invalid_base64")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise _Issue(STATUS_DENY, f"{field}:invalid_base64") from exc
    if len(decoded) > max_bytes:
        raise _Issue(STATUS_DENY, f"{field}:too_large")
    # DSSE uses the standard padded base64 alphabet.  Reject alternate
    # spellings so the envelope has one signed representation.
    if base64.b64encode(decoded).decode("ascii") != value:
        raise _Issue(STATUS_DENY, f"{field}:noncanonical_base64")
    return decoded


def _decode_public_key(value: Any) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        text = value.strip()
        if text.startswith("0x"):
            text = text[2:]
        if len(text) == 64 and all(char in "0123456789abcdefABCDEF" for char in text):
            try:
                raw = bytes.fromhex(text)
            except ValueError as exc:
                raise _Issue(STATUS_DENY, "trust_store:invalid_public_key") from exc
        else:
            try:
                raw = base64.b64decode(text.encode("ascii"), validate=True)
            except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
                raise _Issue(STATUS_DENY, "trust_store:invalid_public_key") from exc
    else:
        raise _Issue(STATUS_DENY, "trust_store:invalid_public_key")
    if len(raw) != 32:
        raise _Issue(STATUS_DENY, "trust_store:invalid_public_key_length")
    return raw


def _fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


# RFC 8032 Ed25519 constants.  The implementation is intentionally compact,
# self-contained, and does not delegate verification to a provider/library.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_B_Y = 4 * pow(5, _P - 2, _P) % _P


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if (x * x - xx) % _P:
        raise ValueError("invalid Ed25519 point")
    return x


def _decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("invalid Ed25519 point length")
    raw = int.from_bytes(encoded, "little")
    sign = raw >> 255
    y = raw & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("invalid Ed25519 point encoding")
    x = _x_recover(y)
    if (x & 1) != sign:
        x = _P - x
    # Extended point uses (X:Y:Z:T) with x=X/Z, y=Y/Z.
    return x, y


def _point_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    xx = x1 * x2 % _P
    yy = y1 * y2 % _P
    dxy = _D * xx * yy % _P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + dxy, _P - 2, _P) % _P
    y3 = (yy + xx) * pow(1 - dxy, _P - 2, _P) % _P
    return x3, y3


def _point_mul(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


_B = (_x_recover(_B_Y), _B_Y)


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature using RFC 8032 arithmetic."""

    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        r_bytes, s_bytes = signature[:32], signature[32:]
        s = int.from_bytes(s_bytes, "little")
        if s >= _L:
            return False
        a = _decode_point(public_key)
        r = _decode_point(r_bytes)
        h = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _L
        # Cofactor clearing rejects small-order point/malleability edge cases.
        lhs = _point_mul(_B, 8 * s)
        rhs = _point_mul(_point_add(r, _point_mul(a, h)), 8)
        return lhs == rhs
    except (ValueError, ArithmeticError, OverflowError):
        return False


def ed25519_public_key(seed: bytes) -> bytes:
    """Derive a public key from a 32-byte deterministic fixture seed."""

    if len(seed) != 32:
        raise ValueError("Ed25519 seed must contain 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return _encode_point(_point_mul(_B, scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Create deterministic Ed25519 signatures for disposable test fixtures."""

    if len(seed) != 32:
        raise ValueError("Ed25519 seed must contain 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    public_key = _encode_point(_point_mul(_B, scalar))
    nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % _L
    r_bytes = _encode_point(_point_mul(_B, nonce))
    challenge = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _L
    s = (nonce + challenge * scalar) % _L
    return r_bytes + s.to_bytes(32, "little")


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Return the DSSE pre-authentication encoding for exact signed bytes."""

    if not isinstance(payload_type, str) or not payload_type or "\x00" in payload_type:
        raise AttestationError("dsse:invalid_payload_type", issues=("dsse:invalid_payload_type",))
    try:
        type_bytes = payload_type.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise AttestationError("dsse:invalid_payload_type", issues=("dsse:invalid_payload_type",)) from exc
    body = bytes(payload)
    return b"DSSEv1" + b" " + str(len(type_bytes)).encode("ascii") + b" " + type_bytes + b" " + str(len(body)).encode("ascii") + b" " + body


def _load_mapping(value: Any, *, field: str, max_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    if isinstance(value, Mapping):
        # Canonicalize to exercise bounds and reject unsupported values even
        # when callers passed an in-memory object rather than bytes.
        canonical_json_bytes(value, max_bytes=max_bytes)
        return dict(value)
    try:
        parsed = parse_canonical_json(value, max_bytes=max_bytes)
    except AttestationError as exc:
        raise _Issue(STATUS_DENY, f"{field}:malformed") from exc
    if not isinstance(parsed, dict):
        raise _Issue(STATUS_DENY, f"{field}:must_be_object")
    return parsed


def _normalise_envelope(envelope: Any) -> tuple[dict[str, Any], bytes, list[dict[str, Any]]]:
    env = _load_mapping(envelope, field="dsse")
    allowed = {"payloadType", "payload", "signatures"}
    unknown = sorted(set(env) - allowed)
    if unknown:
        raise _Issue(STATUS_DENY, "dsse:unexpected_fields")
    if env.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise _Issue(STATUS_DENY, "dsse:payload_type_mismatch")
    payload = _decode_base64(env.get("payload"), field="dsse.payload")
    signatures = env.get("signatures")
    if not isinstance(signatures, list) or not signatures or len(signatures) > MAX_SIGNATURES:
        raise _Issue(STATUS_DENY, "dsse:invalid_signatures")
    result: list[dict[str, Any]] = []
    allowed_sig = {"keyid", "sig", "algorithm", "kind", "identity", "issuer", "certificate_chain", "inclusion_proof"}
    for item in signatures:
        if not isinstance(item, Mapping):
            raise _Issue(STATUS_DENY, "dsse:signature_not_object")
        if set(item) - allowed_sig:
            raise _Issue(STATUS_DENY, "dsse:signature_unexpected_fields")
        if not isinstance(item.get("keyid"), str) or not item.get("keyid"):
            raise _Issue(STATUS_DENY, "dsse:signature_keyid_missing")
        sig_bytes = _decode_base64(item.get("sig"), field="dsse.signature", max_bytes=128)
        if len(sig_bytes) != 64:
            raise _Issue(STATUS_DENY, "dsse:signature_length")
        copied = dict(item)
        copied["_sig_bytes"] = sig_bytes
        result.append(copied)
    return env, payload, result


def _validate_statement(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise _Issue(STATUS_DENY, "payload:too_large")
    try:
        statement = parse_canonical_json(payload, max_bytes=MAX_PAYLOAD_BYTES)
    except AttestationError as exc:
        raise _Issue(STATUS_DENY, f"payload:{exc.issues[0].split(':', 1)[-1]}") from exc
    if not isinstance(statement, dict):
        raise _Issue(STATUS_DENY, "payload:must_be_object")
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        raise _Issue(STATUS_DENY, "payload:type_mismatch")
    subject = statement.get("subject")
    if not isinstance(subject, list) or not subject:
        raise _Issue(STATUS_DENY, "payload:subject_missing")
    if len(subject) > 128:
        raise _Issue(STATUS_DENY, "payload:subject_too_large")
    for item in subject:
        if not isinstance(item, Mapping) or not isinstance(item.get("name"), str) or not item.get("name"):
            raise _Issue(STATUS_DENY, "payload:subject_invalid")
        digest = item.get("digest")
        if not isinstance(digest, Mapping) or "sha256" not in digest:
            raise _Issue(STATUS_DENY, "payload:subject_digest_missing")
        _normalise_digest(digest.get("sha256"), field="payload.subject.sha256")
    return statement


def _find_digest_values(value: Any, names: set[str], *, path: str = "$") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if key_text in names:
                try:
                    found.append((f"{path}.{key_text}", _normalise_digest(child, field=path)))
                except _Issue:
                    raise
            found.extend(_find_digest_values(child, names, path=f"{path}.{key_text}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_find_digest_values(child, names, path=f"{path}[{index}]"))
    return found


def _validate_expected_digests(
    statement: Mapping[str, Any],
    *,
    expected_subject: Any = None,
    expected_package_digest: Any = None,
    expected_sbom_digest: Any = None,
    expected_provenance_digest: Any = None,
    expected_digests: Mapping[str, Any] | None = None,
) -> dict[str, str | None]:
    aliases = dict(expected_digests or {})
    if expected_package_digest is None:
        expected_package_digest = aliases.get("package_digest", aliases.get("package"))
    if expected_sbom_digest is None:
        expected_sbom_digest = aliases.get("sbom_digest", aliases.get("sbom"))
    if expected_provenance_digest is None:
        expected_provenance_digest = aliases.get("provenance_digest", aliases.get("provenance"))
    package = _normalise_digest(expected_package_digest, field="expected.package") if expected_package_digest is not None else None
    sbom = _normalise_digest(expected_sbom_digest, field="expected.sbom") if expected_sbom_digest is not None else None
    provenance = _normalise_digest(expected_provenance_digest, field="expected.provenance") if expected_provenance_digest is not None else None

    subjects = statement["subject"]
    if expected_subject is not None:
        if isinstance(expected_subject, Mapping):
            exp_name = expected_subject.get("name")
            exp_digest = expected_subject.get("digest", expected_subject.get("sha256"))
            if exp_name is not None and (len(subjects) != 1 or subjects[0].get("name") != exp_name):
                raise _Issue(STATUS_DENY, "subject:name_mismatch")
            if exp_digest is not None:
                package = _normalise_digest(exp_digest, field="expected.subject")
        elif isinstance(expected_subject, str):
            if len(subjects) != 1 or subjects[0].get("name") != expected_subject:
                raise _Issue(STATUS_DENY, "subject:name_mismatch")
        else:
            raise _Issue(STATUS_DENY, "expected.subject_invalid")

    subject_digests = [_normalise_digest(item["digest"]["sha256"], field="payload.subject.sha256") for item in subjects]
    if package is not None:
        if package not in subject_digests:
            raise _Issue(STATUS_DENY, "subject:package_digest_mismatch")
    elif len(subject_digests) == 1:
        package = subject_digests[0]

    if package is not None:
        for _, value in _find_digest_values(statement, {"packageDigest", "package_digest", "artifactDigest", "artifact_digest"}):
            if value != package:
                raise _Issue(STATUS_DENY, "predicate:package_digest_mismatch")
    if sbom is not None:
        values = _find_digest_values(statement, {"sbomDigest", "sbom_digest", "spdxDigest", "spdx_digest"})
        if not values:
            raise _Issue(STATUS_DENY, "predicate:sbom_digest_missing")
        if any(value != sbom for _, value in values):
            raise _Issue(STATUS_DENY, "predicate:sbom_digest_mismatch")
    elif (values := _find_digest_values(statement, {"sbomDigest", "sbom_digest", "spdxDigest", "spdx_digest"})):
        sbom = values[0][1]
        if any(value != sbom for _, value in values):
            raise _Issue(STATUS_DENY, "predicate:sbom_digest_ambiguous")
    if provenance is not None:
        values = _find_digest_values(statement, {"provenanceDigest", "provenance_digest"})
        if not values:
            raise _Issue(STATUS_DENY, "predicate:provenance_digest_missing")
        if any(value != provenance for _, value in values):
            raise _Issue(STATUS_DENY, "predicate:provenance_digest_mismatch")
    elif (values := _find_digest_values(statement, {"provenanceDigest", "provenance_digest"})):
        provenance = values[0][1]
        if any(value != provenance for _, value in values):
            raise _Issue(STATUS_DENY, "predicate:provenance_digest_ambiguous")
    return {"package": package, "sbom": sbom, "provenance": provenance}


def _trust_store(value: Any) -> dict[str, Any]:
    if value is None:
        raise _Issue(STATUS_UNAVAILABLE, "trust_store:missing")
    try:
        store = _load_mapping(value, field="trust_store")
    except _Issue:
        raise
    mode = store.get("mode", "offline")
    if mode != "offline" or store.get("allow_network") is True or store.get("offline_only") is False:
        raise _Issue(STATUS_DENY, "trust_store:online_mode_forbidden")
    if store.get("schema") not in (None, "orch-dork/trust-store/v1"):
        raise _Issue(STATUS_DENY, "trust_store:schema_mismatch")
    generation = store.get("generation")
    if not isinstance(generation, str) or not generation or len(generation) > 128:
        raise _Issue(STATUS_UNAVAILABLE, "trust_store:generation_missing")
    conventional = store.get("conventional_keys", store.get("keys", []))
    keyless = store.get("keyless_keys", store.get("keyless", []))
    if not isinstance(conventional, list) or not isinstance(keyless, list):
        raise _Issue(STATUS_UNAVAILABLE, "trust_store:malformed_keys")
    if not conventional and not keyless:
        raise _Issue(STATUS_UNAVAILABLE, "trust_store:no_trust_roots")
    return store


def _parse_time(value: Any) -> _datetime.datetime:
    if not isinstance(value, str):
        raise ValueError("not a timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = _datetime.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_datetime.timezone.utc)
    return parsed.astimezone(_datetime.timezone.utc)


def _key_matches_id(record: Mapping[str, Any], keyid: str) -> bool:
    return record.get("keyid") == keyid or record.get("id") == keyid or record.get("fingerprint") == keyid


def _verify_conventional(signature: Mapping[str, Any], record: Mapping[str, Any], signed: bytes) -> tuple[str, str]:
    algorithm = str(signature.get("algorithm", record.get("algorithm", "ed25519"))).lower()
    if algorithm != "ed25519":
        raise _Issue(STATUS_DENY, "signature:algorithm_unsupported")
    public = _decode_public_key(record.get("public_key", record.get("publicKey")))
    expected_fp = record.get("fingerprint")
    try:
        pinned_fp = _normalise_digest(expected_fp, field="trust_store.fingerprint")
    except _Issue:
        raise _Issue(STATUS_UNAVAILABLE, "trust_store:fingerprint_missing")
    actual_fp = _fingerprint(public)
    if actual_fp != pinned_fp:
        raise _Issue(STATUS_DENY, "signature:key_fingerprint_mismatch", actual_fingerprint=actual_fp)
    if not ed25519_verify(public, bytes(signature["_sig_bytes"]), signed):
        raise _Issue(STATUS_DENY, "signature:invalid")
    return "conventional", actual_fp


def _verify_keyless(signature: Mapping[str, Any], record: Mapping[str, Any], store: Mapping[str, Any], signed: bytes, verification_time: Any) -> tuple[str, str]:
    public = _decode_public_key(record.get("public_key", record.get("publicKey")))
    actual_fp = _fingerprint(public)
    try:
        pinned_fp = _normalise_digest(record.get("fingerprint"), field="trust_store.keyless.fingerprint")
    except _Issue:
        raise _Issue(STATUS_UNAVAILABLE, "trust_store:keyless_fingerprint_missing")
    if actual_fp != pinned_fp:
        raise _Issue(STATUS_DENY, "keyless:fingerprint_mismatch")
    identity = record.get("identity")
    issuer = record.get("issuer")
    if not isinstance(identity, str) or not identity or not isinstance(issuer, str) or not issuer:
        raise _Issue(STATUS_UNAVAILABLE, "keyless:identity_policy_missing")
    if signature.get("identity", identity) != identity or signature.get("issuer", issuer) != issuer:
        raise _Issue(STATUS_DENY, "keyless:identity_mismatch")
    if verification_time is None:
        raise _Issue(STATUS_UNAVAILABLE, "keyless:verification_time_required")
    try:
        at = _parse_time(verification_time)
    except ValueError as exc:
        raise _Issue(STATUS_DENY, "keyless:invalid_verification_time") from exc

    chain = record.get("certificate_chain", record.get("chain"))
    if not isinstance(chain, list) or not chain:
        raise _Issue(STATUS_UNAVAILABLE, "keyless:certificate_chain_missing")
    roots = store.get("pinned_roots", store.get("trusted_roots", []))
    root_fp = record.get("root_fingerprint")
    if not isinstance(roots, list) or not isinstance(root_fp, str):
        raise _Issue(STATUS_UNAVAILABLE, "keyless:pinned_root_missing")
    try:
        root_norm = _normalise_digest(root_fp, field="keyless.root_fingerprint")
    except _Issue:
        raise _Issue(STATUS_DENY, "keyless:root_fingerprint_invalid")
    normalized_roots = set()
    for item in roots:
        try:
            normalized_roots.add(_normalise_digest(item, field="trust_store.pinned_root"))
        except _Issue:
            raise _Issue(STATUS_DENY, "trust_store:pinned_root_invalid")
    if root_norm not in normalized_roots:
        raise _Issue(STATUS_DENY, "keyless:root_not_pinned")
    for index, cert in enumerate(chain):
        if not isinstance(cert, Mapping):
            raise _Issue(STATUS_DENY, "keyless:certificate_invalid")
        cert_fp = cert.get("fingerprint")
        if not isinstance(cert_fp, str):
            raise _Issue(STATUS_DENY, "keyless:certificate_fingerprint_missing")
        if index == len(chain) - 1:
            try:
                if _normalise_digest(cert_fp, field="keyless.certificate.fingerprint") != root_norm:
                    raise _Issue(STATUS_DENY, "keyless:root_certificate_mismatch")
            except _Issue:
                raise
        status = str(cert.get("status", "VALID")).upper()
        if status in {"REVOKED", "UNKNOWN", "EXPIRED"}:
            raise _Issue(STATUS_DENY if status != "UNKNOWN" else STATUS_UNAVAILABLE, f"keyless:certificate_{status.lower()}")
        try:
            not_before = _parse_time(cert.get("not_before", cert.get("notBefore")))
            not_after = _parse_time(cert.get("not_after", cert.get("notAfter")))
        except ValueError as exc:
            raise _Issue(STATUS_UNAVAILABLE, "keyless:certificate_validity_missing") from exc
        if not (not_before <= at <= not_after):
            raise _Issue(STATUS_DENY, "keyless:certificate_expired_or_not_yet_valid")
        if index + 1 < len(chain):
            parent = chain[index + 1]
            if cert.get("issuer") is not None and parent.get("subject") is not None and cert.get("issuer") != parent.get("subject"):
                raise _Issue(STATUS_DENY, "keyless:chain_link_mismatch")

    proof = record.get("inclusion_proof")
    if not isinstance(proof, Mapping) or not proof:
        raise _Issue(STATUS_UNAVAILABLE, "keyless:inclusion_proof_missing")
    if proof.get("verified") is not True:
        required = ("log_id", "root_hash", "leaf_hash", "proof")
        if not all(key in proof and proof[key] not in (None, "", []) for key in required):
            raise _Issue(STATUS_UNAVAILABLE, "keyless:inclusion_proof_unverified")
    pinned_proofs = store.get("pinned_inclusion_proofs", store.get("inclusion_proofs", {}))
    if isinstance(pinned_proofs, Mapping) and record.get("keyid") in pinned_proofs:
        try:
            if canonical_json_bytes(proof) != canonical_json_bytes(pinned_proofs[record["keyid"]]):
                raise _Issue(STATUS_DENY, "keyless:inclusion_proof_mismatch")
        except AttestationError as exc:
            raise _Issue(STATUS_DENY, "keyless:inclusion_proof_invalid") from exc
    if not ed25519_verify(public, bytes(signature["_sig_bytes"]), signed):
        raise _Issue(STATUS_DENY, "signature:invalid")
    return "keyless", actual_fp


def _safe_receipt(status: str, reason: str, *, mode: str = "offline", digests: Mapping[str, Any] | None = None, preserved: bool | None = None, committed: bool | None = None, signature_kind: str | None = None) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "status": status,
        "reason": reason,
        "mode": mode,
        "network_attempts": 0,
    }
    if signature_kind:
        receipt["signature_kind"] = signature_kind
    if digests:
        receipt["digests"] = {key: _digest_label(value) if isinstance(value, str) else None for key, value in digests.items()}
    if preserved is not None:
        receipt["prior_generation_preserved"] = bool(preserved)
    if committed is not None:
        receipt["committed"] = bool(committed)
    return receipt


def _report(status: str, reason: str, *, evidence: Mapping[str, Any] | None = None, digests: Mapping[str, Any] | None = None, preserved: bool | None = None, committed: bool | None = None, signature_kind: str | None = None) -> dict[str, Any]:
    machine: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "reason": reason,
        "mode": "offline",
        "network_attempts": 0,
    }
    if evidence:
        machine.update(dict(evidence))
    if preserved is not None:
        machine["prior_generation_preserved"] = bool(preserved)
    if committed is not None:
        machine["committed"] = bool(committed)
    machine["receipt"] = _safe_receipt(status, reason, digests=digests, preserved=preserved, committed=committed, signature_kind=signature_kind)
    return machine


def verify_attestation(
    envelope: Any,
    trust_store: Any,
    *,
    expected_subject: Any = None,
    expected_package_digest: Any = None,
    expected_sbom_digest: Any = None,
    expected_provenance_digest: Any = None,
    expected_digests: Mapping[str, Any] | None = None,
    verification_time: Any = None,
) -> dict[str, Any]:
    """Verify one detached DSSE/in-toto statement in offline mode.

    Unknown roots and unavailable local keyless evidence intentionally return
    ``UNAVAILABLE`` instead of opening a network path.  Malformed or
    cryptographically mismatched evidence returns ``DENY``.  No exception is
    raised for untrusted detached input; malformed Python API arguments are
    converted to the same named result.
    """

    try:
        env, payload, signatures = _normalise_envelope(envelope)
        statement = _validate_statement(payload)
        digests = _validate_expected_digests(
            statement,
            expected_subject=expected_subject,
            expected_package_digest=expected_package_digest,
            expected_sbom_digest=expected_sbom_digest,
            expected_provenance_digest=expected_provenance_digest,
            expected_digests=expected_digests,
        )
        store = _trust_store(trust_store)
        signed = dsse_pae(env["payloadType"], payload)
        conventional = store.get("conventional_keys", store.get("keys", []))
        keyless = store.get("keyless_keys", store.get("keyless", []))
        matched = False
        last_issue: _Issue | None = None
        signature_kind: str | None = None
        fingerprint: str | None = None
        for signature in signatures:
            keyid = signature["keyid"]
            candidates = [record for record in conventional if isinstance(record, Mapping) and _key_matches_id(record, keyid)]
            candidates.extend(record for record in keyless if isinstance(record, Mapping) and _key_matches_id(record, keyid))
            if not candidates:
                last_issue = _Issue(STATUS_UNAVAILABLE, "signature:unknown_key")
                continue
            for record in candidates:
                try:
                    kind = str(record.get("kind", "conventional")).lower()
                    if kind in {"keyless", "certificate", "fulcio"} or record in keyless:
                        signature_kind, fingerprint = _verify_keyless(signature, record, store, signed, verification_time)
                    else:
                        signature_kind, fingerprint = _verify_conventional(signature, record, signed)
                    matched = True
                    break
                except _Issue as issue:
                    last_issue = issue
            if matched:
                break
        if not matched:
            issue = last_issue or _Issue(STATUS_UNAVAILABLE, "signature:no_usable_signature")
            return _report(issue.status, issue.reason, evidence=issue.evidence, digests=digests, signature_kind=signature_kind)
        evidence = {
            "payload_sha256": sha256_hex(payload),
            "signed_bytes_sha256": sha256_hex(signed),
            "envelope_sha256": sha256_hex(canonical_json_bytes(env)),
            "trust_store_generation": store["generation"],
            "key_fingerprint": fingerprint,
            "payload_type": env["payloadType"],
        }
        return _report(STATUS_PASS, "verified", evidence=evidence, digests=digests, signature_kind=signature_kind)
    except _Issue as issue:
        return _report(issue.status, issue.reason, evidence=issue.evidence)
    except (AttestationError, TypeError, ValueError, OSError) as exc:
        reason = exc.issues[0] if isinstance(exc, AttestationError) and exc.issues else "attestation:malformed"
        return _report(STATUS_DENY, reason)


def verify_offline_attestation(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return verify_attestation(*args, **kwargs)


def verify_detached_attestation(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return verify_attestation(*args, **kwargs)


def verify_dsse_envelope(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return verify_attestation(*args, **kwargs)


def _artifact_bytes(artifact: Any) -> bytes:
    if isinstance(artifact, (bytes, bytearray, memoryview)):
        data = bytes(artifact)
    elif isinstance(artifact, (str, Path)):
        try:
            data = Path(artifact).read_bytes()
        except OSError as exc:
            raise _Issue(STATUS_UNAVAILABLE, "artifact:read_failed") from exc
    else:
        raise _Issue(STATUS_DENY, "artifact:unsupported")
    if len(data) > MAX_PAYLOAD_BYTES * 128:
        raise _Issue(STATUS_DENY, "artifact:too_large")
    return data


def verify_artifact_attestation(artifact: Any, envelope: Any, trust_store: Any, **kwargs: Any) -> dict[str, Any]:
    """Verify an attestation and bind its subject to actual artifact bytes."""

    try:
        data = _artifact_bytes(artifact)
        digest = sha256_hex(data)
        expected = kwargs.pop("expected_package_digest", None)
        if expected is not None and _normalise_digest(expected, field="expected.package") != digest:
            return _report(STATUS_DENY, "artifact:package_digest_mismatch", digests={"package": digest}, preserved=True)
        kwargs["expected_package_digest"] = digest
        result = verify_attestation(envelope, trust_store, **kwargs)
        result.setdefault("artifact_digest", digest)
        result.setdefault("receipt", _safe_receipt(result["status"], result["reason"], digests={"package": digest}, preserved=result["status"] != STATUS_PASS))
        return result
    except _Issue as issue:
        return _report(issue.status, issue.reason, preserved=True)


def _write_fully(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stage_verified_update(
    artifact: Any,
    envelope: Any,
    trust_store: Any,
    destination: str | Path,
    *,
    expected_subject: Any = None,
    expected_package_digest: Any = None,
    expected_sbom_digest: Any = None,
    expected_provenance_digest: Any = None,
    expected_digests: Mapping[str, Any] | None = None,
    verification_time: Any = None,
    interrupt_before_commit: bool = False,
    simulate_interruption: bool = False,
) -> dict[str, Any]:
    """Verify, stage, and atomically replace a single disposable artifact.

    The destination is not touched until DSSE, trust-store, and artifact
    digest checks pass and a fully fsynced temporary file exists.  Any
    malformed/tampered/interrupted update removes only that temporary file and
    reports ``prior_generation_preserved: true``.
    """

    destination_path = Path(destination)
    try:
        data = _artifact_bytes(artifact)
        new_digest = sha256_hex(data)
        if expected_package_digest is not None and _normalise_digest(expected_package_digest, field="expected.package") != new_digest:
            return _report(STATUS_DENY, "artifact:package_digest_mismatch", digests={"package": new_digest}, preserved=True, committed=False)
        result = verify_attestation(
            envelope,
            trust_store,
            expected_subject=expected_subject,
            expected_package_digest=new_digest,
            expected_sbom_digest=expected_sbom_digest,
            expected_provenance_digest=expected_provenance_digest,
            expected_digests=expected_digests,
            verification_time=verification_time,
        )
        if result.get("status") != STATUS_PASS:
            result["receipt"]["prior_generation_preserved"] = True
            result["receipt"]["committed"] = False
            result["prior_generation_preserved"] = True
            result["committed"] = False
            return result

        previous_digest: str | None = None
        if destination_path.exists() and destination_path.is_file():
            try:
                previous_digest = sha256_hex(destination_path.read_bytes())
            except OSError:
                previous_digest = None
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_name = None
        descriptor, temporary_name = tempfile.mkstemp(prefix=".attestation-stage-", dir=str(destination_path.parent))
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        try:
            # Use O_EXCL so an unexpected pre-existing path cannot be replaced.
            temporary_path.unlink()
            _write_fully(temporary_path, data)
            if interrupt_before_commit or simulate_interruption:
                raise InterruptedError("simulated interruption before commit")
            os.replace(temporary_path, destination_path)
        except InterruptedError:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            return _report(STATUS_DENY, "update:interrupted", evidence={"artifact_digest": new_digest}, digests={"package": new_digest}, preserved=True, committed=False)
        except (OSError, ValueError) as exc:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            return _report(STATUS_UNAVAILABLE, "update:stage_failed", evidence={"error_type": type(exc).__name__}, digests={"package": new_digest}, preserved=True, committed=False)
        evidence = dict(result)
        evidence.update({"artifact_digest": new_digest, "previous_generation_digest": previous_digest, "destination": str(destination_path)})
        return _report(STATUS_PASS, "verified_and_committed", evidence=evidence, digests={"package": new_digest, "previous": previous_digest}, preserved=True, committed=True, signature_kind=result.get("receipt", {}).get("signature_kind"))
    except _Issue as issue:
        return _report(issue.status, issue.reason, preserved=True, committed=False)
    except (OSError, TypeError, ValueError) as exc:
        return _report(STATUS_DENY, "update:malformed", evidence={"error_type": type(exc).__name__}, preserved=True, committed=False)


def verify_before_stage_update(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return stage_verified_update(*args, **kwargs)


def verify_before_stage(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return stage_verified_update(*args, **kwargs)


def install_verified_artifact(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return stage_verified_update(*args, **kwargs)


__all__ = [
    "AttestationError",
    "VerificationError",
    "SCHEMA",
    "RECEIPT_SCHEMA",
    "DSSE_PAYLOAD_TYPE",
    "IN_TOTO_STATEMENT_TYPE",
    "STATUS_PASS",
    "STATUS_DENY",
    "STATUS_UNAVAILABLE",
    "canonical_json_bytes",
    "canonicalize_json",
    "parse_canonical_json",
    "sha256_hex",
    "dsse_pae",
    "ed25519_verify",
    "ed25519_public_key",
    "ed25519_sign",
    "verify_attestation",
    "verify_offline_attestation",
    "verify_detached_attestation",
    "verify_dsse_envelope",
    "verify_artifact_attestation",
    "stage_verified_update",
    "verify_before_stage_update",
    "verify_before_stage",
    "install_verified_artifact",
]
