#!/usr/bin/env python3
"""Provider-free run binding summaries and a rebuildable SQLite projection.

This module is deliberately independent of the runtime/session stores used by
the orchestration observers.  A source catalog contains *claims about runs*;
the registry stores only the validated, compact summary of those claims.  It
never follows artifact locators and never opens a session store while querying.

The wire schema is ``orch-dork/run-binding/v1``.  ``run_binding/v1`` is accepted
as an input compatibility spelling, but is never emitted.  The SQLite database
is a disposable index: summary JSON files remain the authority and a registry
can always be rebuilt from them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sqlite3
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


try:
    from orch_dork_hostile_input import PROFILE as HOSTILE_INPUT_PROFILE  # type: ignore
except ImportError:  # pragma: no cover - standalone source execution
    HOSTILE_INPUT_PROFILE = None


# Issue 49 canonical provider-free projection bounds.  These are duplicated
# here instead of importing the fuzz harness so registry validation remains a
# usable, dependency-free source surface during release-time integration.
PROFILE = HOSTILE_INPUT_PROFILE
DEFENSIVE_PROFILE_SCHEMA = PROFILE.schema if PROFILE is not None else "orch-dork/hostile-input-profile/v1"
MAX_JSON_BYTES = PROFILE.canonical_json_bytes if PROFILE is not None else 262_144
MAX_STRING_BYTES = PROFILE.max_string_bytes if PROFILE is not None else 65_536
MAX_KEY_BYTES = PROFILE.max_key_bytes if PROFILE is not None else 256
MAX_PATH_BYTES = PROFILE.max_path_bytes if PROFILE is not None else 4_096
MAX_NESTING_DEPTH = PROFILE.max_depth if PROFILE is not None else 32
MAX_NODES = PROFILE.max_nodes if PROFILE is not None else 4_096
MAX_CLAIMS_EDGES = PROFILE.registry_claims if PROFILE is not None else 4_096
MAX_ARTIFACT_RECORDS = PROFILE.registry_artifacts if PROFILE is not None else 256
MAX_SOURCE_LOCATORS = PROFILE.registry_locators if PROFILE is not None else 64
REGISTRY_VALIDATION_TIMEOUT_SECONDS = PROFILE.registry_validate_seconds if PROFILE is not None else 5
REGISTRY_COMMIT_TIMEOUT_SECONDS = PROFILE.registry_commit_seconds if PROFILE is not None else 10

SCHEMA = "orch-dork/run-binding/v1"
RUN_BINDING_SCHEMA = SCHEMA
REGISTRY_VERSION = "run-registry/1.0"
GOVERNANCE_PROJECTION_SCHEMA = "orch-dork/governance-projection/v1"
GOVERNANCE_REPORT_SCHEMAS = frozenset(
    {
        "orch-dork/profile-lifecycle-report/v1",
        "orch-dork/efficiency-evaluation-report/v1",
    }
)
SCHEMA_ALIAS = "run_binding/v1"
SOURCE_CATALOG_SCHEMA = "orch-dork/run-source-catalog/v1"
SOURCE_CATALOG_SCHEMA_ALIAS = "run_source_catalog/v1"
SUBJECT_KINDS = frozenset({"hosted_execution", "fixture", "replay", "synthetic"})
BINDING_STATUSES = frozenset({"BOUND", "UNBOUND", "CONTRADICTORY"})
EVIDENCE_TIERS = frozenset({"submitted", "runtime-observed", "sealed-runtime"})
CLAIM_STATUSES = frozenset({"SUPPORTED", "UNKNOWN", "UNBOUND", "CONTRADICTORY"})
UNKNOWN_REASON_CODES = frozenset(
    {
        "missing_source",
        "missing_identity",
        "missing_record",
        "ambiguous_selector",
        "ambiguous_binding",
        "host_unavailable",
        "permission_denied",
        "redacted",
        "unsupported_schema",
        "observation_incomplete",
        "clock_unknown",
        "clock_mismatch",
        "unit_unknown",
        "origin_unknown",
        "conversion_unavailable",
        "render_mismatch",
    }
)
CLOCK_KINDS = frozenset({"wall", "monotonic", "logical", "unknown"})
CLOCK_UNITS = frozenset({"nanoseconds", "microseconds", "milliseconds", "seconds", "ticks", "unknown"})
CLOCK_ORIGINS = frozenset(
    {"unix_epoch", "host_boot", "producer_start", "subject_start", "fixture_start", "logical_zero", "unknown"}
)

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_KEY_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_.:-]{0,255}\Z")
_RUN_KEY_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_LOCATOR_RE = re.compile(r"\A[^\x00-\x1f\x7f]{1,2048}\Z")
_SECRET_WORD_RE = re.compile(
    r"(?:prompt|message|body|reasoning|credential|password|secret|"
    r"encrypted|cipher(?:text)?|private[_-]?key|access[_-]?token|api[_-]?key|"
    r"raw[_-]?(?:file|session|trace|record|data|content))",
    re.IGNORECASE,
)
_UNSOURCED_ANNOTATION_RE = re.compile(r"(?:evaluator|quality|judg(?:e|m)|(?:^|[_-])label(?:$|[_-]))", re.IGNORECASE)
_ALLOWED_TIMING_FIELDS = {
    "producer",
    "subject",
    "kind",
    "status",
    "unknown_reason",
    "reason",
    "started_at",
    "ended_at",
    "timestamp",
    "duration_ms",
    "clock_id",
    "clock_kind",
    "unit",
    "origin",
    "spans",
    "markers",
    "clock",
    "all_required_known",
    "known_roles",
    "unknown_roles",
    "metrics",
}
_ALLOWED_ARTIFACT_FIELDS = {
    "role",
    "locator",
    "path",
    "sha256",
    "content_hash",
    "size",
    "size_bytes",
    "selector",
    "record_pointer",
    "pointer",
    "source_id",
    "kind",
    "store",
    "store_id",
    "host_identity",
    "host_id",
    "path_kind",
    "hash_scope",
    "source_file",
    "observed_file_sha256",
    "start_line",
    "end_line",
}


class RegistryError(ValueError):
    """Structured validation/indexing error.

    ``code`` is stable for callers and ``details`` is JSON-safe diagnostic
    context.  The CLI serializes this object rather than exposing a traceback.
    """

    def __init__(self, code: str, message: str | None = None, **details: Any):
        self.code = code
        self.details = details
        super().__init__(message or code)

    def as_dict(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": str(self)}
        if self.details:
            error["details"] = _safe_copy(self.details)
        return error


def _reject_unsourced_annotations(value: Any, path: str = "$", seen: set[int] | None = None) -> None:
    """Reject evaluator/quality annotations before closed-field projection.

    Evaluator labels and quality judgments are a later, separately sourced
    layer.  Silently dropping one would make an input appear runtime-derived,
    so the provider-free registry rejects those fields at every nesting level.
    Values are never included in the diagnostic.
    """

    if seen is None:
        seen = set()
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)
        for key, item in value.items():
            if isinstance(key, str) and _UNSOURCED_ANNOTATION_RE.search(key):
                raise RegistryError("unsourced_evaluator", "evaluator or quality annotation requires separate authority", field=f"{path}.{key}")
            _reject_unsourced_annotations(item, f"{path}.{key}", seen)
    elif isinstance(value, (list, tuple)):
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)
        for index, item in enumerate(value):
            _reject_unsourced_annotations(item, f"{path}[{index}]", seen)


def _safe_copy(value: Any) -> Any:
    """Return a JSON-safe deep copy without invoking user-defined objects."""

    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RegistryError("unsafe_value", "non-finite number")
        return value
    if isinstance(value, list):
        return [_safe_copy(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_copy(item) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 256:
                raise RegistryError("unsafe_shape", "mapping keys must be short strings")
            if _SECRET_WORD_RE.search(key):
                raise RegistryError("unsafe_shape", "secret-bearing field rejected", field=key)
            result[key] = _safe_copy(item)
        return result
    raise RegistryError("unsafe_shape", "unsupported value type", type=type(value).__name__)


def _text(value: Any, *, field: str, pattern: re.Pattern[str] | None = None, max_len: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise RegistryError("invalid_field", f"{field} must be a non-empty string", field=field)
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise RegistryError("unsafe_shape", f"{field} contains a control character", field=field)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise RegistryError("invalid_field", f"{field} has an unsafe shape", field=field)
    return value


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RegistryError("unsafe_shape", "value is not canonical JSON") from exc


def _validate_input_shape(value: Any, *, max_array: int = MAX_CLAIMS_EDGES) -> None:
    """Bound an in-memory summary before recursive copying/projection.

    Registry records have a larger claims/edges allowance than the generic
    parser's array bound.  Collection-specific validators below apply the
    tighter artifact/source limits without truncating a caller's input.
    """

    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    active: set[int] = set()
    nodes = 0
    while stack:
        current, depth, leaving = stack.pop()
        if leaving:
            active.discard(id(current))
            continue
        if depth > MAX_NESTING_DEPTH:
            raise RegistryError("input_depth_limit", "nested input exceeds defensive depth", bound=MAX_NESTING_DEPTH)
        if isinstance(current, (dict, list, tuple)):
            marker = id(current)
            if marker in active:
                raise RegistryError("input_cycle", "cyclic input is not JSON")
            active.add(marker)
            stack.append((current, depth, True))
            nodes += 1
            if nodes > MAX_NODES:
                raise RegistryError("input_nodes_limit", "input exceeds defensive node bound", bound=MAX_NODES)
            if isinstance(current, Mapping):
                if len(current) > MAX_CLAIMS_EDGES:
                    raise RegistryError("input_nodes_limit", "object exceeds defensive node bound", bound=MAX_CLAIMS_EDGES)
                for key, child in reversed(list(current.items())):
                    if not isinstance(key, str) or len(key.encode("utf-8")) > MAX_KEY_BYTES:
                        raise RegistryError("input_key_limit", "object key exceeds defensive bound", bound=MAX_KEY_BYTES)
                    stack.append((child, depth + 1, False))
            else:
                if len(current) > max_array:
                    raise RegistryError("input_nodes_limit", "array exceeds defensive bound", bound=max_array)
                for child in reversed(list(current)):
                    stack.append((child, depth + 1, False))
            continue
        if isinstance(current, str):
            size = len(current.encode("utf-8"))
            if size > MAX_STRING_BYTES:
                raise RegistryError("input_string_limit", "string exceeds defensive bound", bound=MAX_STRING_BYTES)
        elif isinstance(current, float) and not math.isfinite(current):
            raise RegistryError("non_finite_number", "non-finite number is not allowed")


class _DuplicateJSONKey(ValueError):
    pass


def _json_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _reject_nonfinite_json_number(token: str) -> None:
    raise RegistryError("non_finite_number", "non-finite JSON number")


def _parse_json_bytes(raw: bytes, *, path: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise RegistryError("input_bytes_limit", "JSON input exceeds defensive bound", path=path, bound=MAX_JSON_BYTES)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise RegistryError("input_bom_forbidden", "UTF-8 BOM is not accepted", path=path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError("input_utf8_invalid", "JSON input is not UTF-8", path=path) from exc
    try:
        decoder = json.JSONDecoder(
            object_pairs_hook=_json_pairs_no_duplicates,
            parse_constant=_reject_nonfinite_json_number,
        )
        value, end = decoder.raw_decode(text)
    except _DuplicateJSONKey as exc:
        raise RegistryError("input_duplicate_key", "duplicate JSON key", path=path) from exc
    except RegistryError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise RegistryError("input_invalid_json", "malformed JSON", path=path) from exc
    if text[end:].strip():
        raise RegistryError("input_trailing_data", "trailing JSON data", path=path)
    _validate_input_shape(value)
    return value


def summary_sha256(summary: Mapping[str, Any]) -> str:
    """Hash the canonical JSON representation of a validated summary."""

    return hashlib.sha256(_canonical_json(summary).encode("utf-8")).hexdigest()


def _check_locator(value: Any, *, field: str = "locator") -> str:
    locator = _text(value, field=field, pattern=_LOCATOR_RE, max_len=2048)
    if _SECRET_WORD_RE.search(locator):
        raise RegistryError("unsafe_locator", "secret-bearing locator rejected", field=field)
    return locator


def _validate_run(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RegistryError("invalid_run", f"{field} must be an object", field=field)
    copied = _safe_copy(value)
    if not isinstance(copied, dict):  # pragma: no cover - guarded by Mapping
        raise RegistryError("invalid_run", f"{field} must be an object", field=field)
    run_key = copied.get("run_key")
    if run_key is None:
        raise RegistryError("missing_run_key", f"{field}.run_key is required", field=field)
    _text(run_key, field=f"{field}.run_key", pattern=_RUN_KEY_RE, max_len=256)
    if "run_id" in copied:
        _text(copied["run_id"], field=f"{field}.run_id", pattern=_RUN_KEY_RE, max_len=256)
    # A run is an identity object, not an opaque session dump.  Keep optional
    # scalar metadata but reject nested bodies/records through _safe_copy.
    return copied


def _validate_artifact(value: Any, *, index: int, source: bool = False) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RegistryError("invalid_artifact", "artifact/source must be an object", index=index)
    copied = _safe_copy(value)
    if not isinstance(copied, dict):  # pragma: no cover
        raise RegistryError("invalid_artifact", "artifact/source must be an object", index=index)
    unknown = set(copied) - _ALLOWED_ARTIFACT_FIELDS
    # Unknown non-secret metadata is intentionally not carried into the
    # projection.  This keeps the registry compact and the schema stable.
    if unknown:
        raise RegistryError("unsafe_shape", "artifact/source has unsupported fields", fields=sorted(unknown))
    role = _text(copied.get("role"), field=f"artifact[{index}].role", max_len=128)
    locator_value = copied.get("locator", copied.get("path"))
    if locator_value is None:
        raise RegistryError("missing_locator", "artifact/source locator is required", index=index)
    locator = _check_locator(locator_value, field=f"artifact[{index}].locator")
    path_kind = copied.get("path_kind")
    if path_kind is None:
        path_kind = "absolute" if locator.startswith("/") else "relative"
    if path_kind not in {"relative", "absolute"}:
        raise RegistryError("invalid_path_kind", "artifact/source path_kind must be relative or absolute", index=index)
    if path_kind == "relative" and any(part == ".." for part in locator.split("/")):
        raise RegistryError("invalid_locator", "relative locator may not escape its store root", index=index)
    digest = copied.get("content_hash", copied.get("sha256"))
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise RegistryError("missing_or_invalid_hash", "artifact/source sha256 must be lowercase hex", index=index)
    store = copied.get("store", copied.get("store_id"))
    if store is not None:
        store = _text(store, field=f"artifact[{index}].store", max_len=512)
    host_identity = copied.get("host_identity", copied.get("host_id"))
    if path_kind == "absolute" and host_identity is None:
        # Absolute paths are only meaningful within an identified host.  A
        # catalog may use the explicit local namespace when no machine name is
        # safe to retain; it is still a stable host/store identity.
        host_identity = "local"
    if host_identity is not None:
        host_identity = _text(host_identity, field=f"artifact[{index}].host_identity", max_len=512)
    hash_scope = copied.get("hash_scope", "full_file")
    if hash_scope not in {"full_file", "bounded_segment"}:
        raise RegistryError("invalid_hash_scope", "artifact/source hash_scope is invalid", index=index)
    if hash_scope == "bounded_segment":
        source_file = copied.get("source_file", locator)
        _check_locator(source_file, field=f"artifact[{index}].source_file")
        observed = copied.get("observed_file_sha256")
        if observed is not None and (not isinstance(observed, str) or _SHA256_RE.fullmatch(observed) is None):
            raise RegistryError("invalid_hash", "bounded source observed_file_sha256 must be lowercase hex", index=index)
        start_line, end_line = copied.get("start_line"), copied.get("end_line")
        if type(start_line) is not int or type(end_line) is not int or start_line < 1 or end_line < start_line:
            raise RegistryError("invalid_selector", "bounded source start_line/end_line must be positive", index=index)
    elif any(key in copied for key in ("source_file", "observed_file_sha256", "start_line", "end_line")):
        raise RegistryError("invalid_hash_scope", "full_file source cannot carry bounded-segment fields", index=index)
    out: dict[str, Any] = {
        "role": role,
        "locator": locator,
        "path": locator,
        "path_kind": path_kind,
        "sha256": digest,
        "content_hash": digest,
    }
    if store is not None:
        out["store"] = store
    if host_identity is not None:
        out["host_identity"] = host_identity
    if hash_scope == "bounded_segment":
        out["hash_scope"] = hash_scope
        out["source_file"] = _check_locator(copied.get("source_file", locator), field=f"artifact[{index}].source_file")
        if copied.get("observed_file_sha256") is not None:
            out["observed_file_sha256"] = copied["observed_file_sha256"]
        out["start_line"] = copied["start_line"]
        out["end_line"] = copied["end_line"]
    if "size" in copied or "size_bytes" in copied:
        size = copied.get("size", copied.get("size_bytes"))
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise RegistryError("invalid_artifact", "artifact size must be a non-negative integer", index=index)
        out["size"] = size
    for key in ("selector", "record_pointer", "pointer", "source_id", "kind"):
        if key in copied:
            out[key] = _text(copied[key], field=f"artifact[{index}].{key}", max_len=2048)
    return out


def _validate_artifacts(values: Any, *, field: str) -> list[dict[str, Any]]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise RegistryError("invalid_artifacts", f"{field} must be an array", field=field)
    limit = MAX_SOURCE_LOCATORS if field == "sources" else MAX_ARTIFACT_RECORDS
    if len(values) > limit:
        raise RegistryError(
            "source_locators_limit" if field == "sources" else "artifact_records_limit",
            f"{field} exceeds one bounded projection chunk",
            field=field,
            observed=len(values),
            bound=limit,
            continuation_required=True,
        )
    result = [_validate_artifact(item, index=index, source=(field == "sources")) for index, item in enumerate(values)]
    # A duplicate locator with differing digests is an explicit contradiction;
    # duplicate exact entries are redundant and therefore rejected as well.
    seen: dict[tuple[str, str | None], str] = {}
    for item in result:
        locator = item["locator"]
        digest = item["sha256"]
        # One append-only rollout can validly provide disjoint bounded roles,
        # such as an initial lane and a later integrator turn.  Selector is
        # therefore part of source-record identity, while artifact identity
        # remains locator-only.
        identity = (locator, item.get("selector") if field == "sources" else None)
        if identity in seen:
            code = "contradictory_artifact" if seen[identity] != digest else "duplicate_artifact"
            raise RegistryError(code, "artifact/source locator is duplicated", locator=locator)
        seen[identity] = digest
    return result


def _validate_claim(value: Any, *, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RegistryError("invalid_claim", "claim must be an object", index=index)
    copied = _safe_copy(value)
    if not isinstance(copied, dict):  # pragma: no cover
        raise RegistryError("invalid_claim", "claim must be an object", index=index)
    name = copied.get("name")
    if name is None:
        # ``claim_id`` is a harmless compatibility spelling used by older
        # generated summaries; the emitted field is always ``name``.
        name = copied.get("claim_id")
    _text(name, field=f"claim[{index}].name", pattern=_KEY_RE, max_len=256)
    if "value" not in copied:
        raise RegistryError("missing_claim_value", "claim.value is required", index=index)
    tier = copied.get("evidence_tier")
    if tier is None:
        raise RegistryError("missing_evidence_tier", "claim.evidence_tier is required", index=index)
    tier = _text(tier, field=f"claim[{index}].evidence_tier", max_len=128)
    if tier == "unknown":
        # Older fixtures used ``unknown`` as a placeholder tier.  Preserve
        # their uncertainty in the claim value/reason while assigning the
        # weakest runtime source tier permitted by the closed contract.
        tier = "runtime-observed"
    if tier not in EVIDENCE_TIERS:
        raise RegistryError("invalid_evidence_tier", "claim.evidence_tier is not recognized", index=index)
    refs = copied.get("source_refs", copied.get("sources", []))
    if not isinstance(refs, list):
        raise RegistryError("invalid_claim", "claim source_refs must be an array", index=index)
    source_refs: list[str] = []
    for ref_index, ref in enumerate(refs):
        source_refs.append(_text(ref, field=f"claim[{index}].source_refs[{ref_index}]", max_len=1024))
    result: dict[str, Any] = {
        "name": name,
        "value": copied["value"],
        "evidence_tier": tier,
        "source_refs": source_refs,
    }
    if "status" in copied:
        status = _text(copied["status"], field=f"claim[{index}].status", max_len=64)
        if status not in CLAIM_STATUSES:
            raise RegistryError("invalid_claim_status", "claim.status is not recognized", index=index)
        result["status"] = status
    if "provenance" in copied:
        provenance = copied["provenance"]
        if not isinstance(provenance, list):
            raise RegistryError("invalid_claim", "claim.provenance must be an array", index=index)
        result["provenance"] = _safe_copy(provenance)
    if "unknown_reason" in copied:
        result["unknown_reason"] = _text(copied["unknown_reason"], field=f"claim[{index}].unknown_reason", max_len=1024)
    return result


def _validate_claims(values: Any) -> list[dict[str, Any]]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise RegistryError("invalid_claims", "claims must be an array")
    if len(values) > MAX_CLAIMS_EDGES:
        raise RegistryError(
            "claims_edges_limit",
            "claims/edges exceed one bounded projection chunk",
            observed=len(values),
            bound=MAX_CLAIMS_EDGES,
            continuation_required=True,
        )
    result = [_validate_claim(item, index=index) for index, item in enumerate(values)]
    by_name: dict[str, Any] = {}
    for item in result:
        name = item["name"]
        if name in by_name and _canonical_json(by_name[name]) != _canonical_json(item["value"]):
            # The caller decides whether an explicit CONTRADICTORY status is
            # supplied; retaining this marker allows that decision below.
            item.setdefault("_conflicting_name", name)
        by_name[name] = item["value"]
    for item in result:
        item.pop("_conflicting_name", None)
    return result


def _unknown_reason_code(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in UNKNOWN_REASON_CODES:
        return text
    if "clock" in text or "elapsed" in text or "timestamp" in text:
        return "clock_unknown"
    if "host" in text and ("unavailable" in text or "missing" in text):
        return "host_unavailable"
    if "identity" in text:
        return "missing_identity"
    if "bind" in text or "match" in text or "relation" in text:
        return "ambiguous_binding"
    if "permission" in text:
        return "permission_denied"
    if "redact" in text:
        return "redacted"
    return "observation_incomplete"


def _validate_timing_record(value: Any, *, field: str = "timing") -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RegistryError("invalid_timing", f"{field} must be an object")
    copied = _safe_copy(value)
    if not isinstance(copied, dict) or not copied:
        raise RegistryError("invalid_timing", f"{field} must be a non-empty object")
    unknown = set(copied) - (_ALLOWED_TIMING_FIELDS - {"producer", "subject"})
    if unknown:
        raise RegistryError("invalid_timing", f"{field} has unsupported fields", fields=sorted(unknown))
    status = copied.get("status")
    if status == "unknown" or "unknown_reason" in copied:
        reason = _unknown_reason_code(copied.get("unknown_reason", copied.get("reason")))
        result = dict(copied)
        result["status"] = "unknown"
        result["unknown_reason"] = reason
        result.setdefault("clock_id", "unknown")
        result.setdefault("clock_kind", "unknown")
        result.setdefault("unit", "unknown")
        result.setdefault("origin", "unknown")
        return result
    typed_fields = {
        key
        for key in copied
        if key in {"kind", "started_at", "ended_at", "timestamp", "duration_ms", "clock_id", "clock_kind", "unit", "origin"}
    }
    if not typed_fields:
        raise RegistryError("invalid_timing", f"{field} must be typed or explicitly unknown")
    if "kind" in copied:
        _text(copied["kind"], field=f"{field}.kind", max_len=128)
    if "clock_id" in copied:
        _text(copied["clock_id"], field=f"{field}.clock_id", max_len=256)
    for key, allowed in (("clock_kind", CLOCK_KINDS), ("unit", CLOCK_UNITS), ("origin", CLOCK_ORIGINS)):
        if key in copied and copied[key] not in allowed:
            raise RegistryError("invalid_timing", f"{field}.{key} is not recognized")
    if "duration_ms" in copied:
        duration = copied["duration_ms"]
        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration < 0:
            raise RegistryError("invalid_timing", f"{field}.duration_ms must be finite and non-negative")
    if "all_required_known" in copied and type(copied["all_required_known"]) is not bool:
        raise RegistryError("invalid_timing", f"{field}.all_required_known must be boolean")
    for key in ("known_roles", "unknown_roles"):
        if key in copied and (not isinstance(copied[key], list) or any(not isinstance(item, str) for item in copied[key])):
            raise RegistryError("invalid_timing", f"{field}.{key} must be an array of strings")
    for key in ("started_at", "ended_at", "timestamp"):
        if key in copied and not isinstance(copied[key], (str, int, float)):
            raise RegistryError("invalid_timing", f"{field}.{key} has invalid type")
        if isinstance(copied.get(key), float) and not math.isfinite(copied[key]):
            raise RegistryError("invalid_timing", f"{field}.{key} must be finite")
    return copied


def _validate_timing(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RegistryError("invalid_timing", "timing must be an object")
    copied = _safe_copy(value)
    if not isinstance(copied, dict) or not copied:
        raise RegistryError("invalid_timing", "timing must be a non-empty object")
    if "producer" in copied or "subject" in copied:
        unknown = set(copied) - {"producer", "subject"}
        if unknown:
            raise RegistryError("invalid_timing", "timing has unsupported fields", fields=sorted(unknown))
        result: dict[str, Any] = {}
        for role in ("producer", "subject"):
            if role in copied:
                result[role] = _validate_timing_record(copied[role], field=f"timing.{role}")
        return result
    return _validate_timing_record(copied)


def _validate_optional(value: Any, *, field: str) -> Any:
    if value is None:
        return None
    copied = _safe_copy(value)
    # Preserve compact telemetry only; prohibit unbounded nested arrays.
    encoded = _canonical_json(copied)
    if len(encoded.encode("utf-8")) > 65536:
        raise RegistryError("unsafe_shape", f"{field} is too large", field=field)
    return copied


def _run_key(run: Mapping[str, Any], field: str) -> str:
    return _text(run.get("run_key"), field=f"{field}.run_key", pattern=_RUN_KEY_RE, max_len=256)


def _run_id(run: Mapping[str, Any], field: str, explicit: Any = None) -> str:
    """Resolve a stable identity without confusing it with a display label."""

    value = explicit
    if value is None:
        value = run.get("run_id")
    if value is None:
        # Compatibility summaries predate explicit IDs.  Their run_key is the
        # only stable identity available and remains a safe deterministic
        # fallback; new exports should provide the explicit top-level aliases.
        value = run.get("run_key")
    return _text(value, field=field, pattern=_RUN_KEY_RE, max_len=256)


def validate_summary(value: Any, *, source_catalog: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Validate and normalize one run-binding summary.

    The function returns a fresh canonical summary and raises
    :class:`RegistryError` on every unsafe, incomplete, or contradictory shape.
    No source locator is opened.
    """

    if not isinstance(value, Mapping):
        raise RegistryError("invalid_summary", "summary must be an object")
    _validate_input_shape(value)
    _reject_unsourced_annotations(value)
    copied = _safe_copy(value)
    if not isinstance(copied, dict):  # pragma: no cover
        raise RegistryError("invalid_summary", "summary must be an object")
    schema = copied.get("schema")
    if schema not in {SCHEMA, SCHEMA_ALIAS, SOURCE_CATALOG_SCHEMA, SOURCE_CATALOG_SCHEMA_ALIAS, None}:
        raise RegistryError("invalid_schema", "unsupported run-binding schema", schema=schema)
    binding_id = copied.get("binding_id")
    if binding_id is None:
        binding_id = copied.get("ticket_key")
    if binding_id is None:
        raise RegistryError("missing_binding_id", "binding_id is required")
    _text(binding_id, field="binding_id", pattern=_KEY_RE, max_len=256)
    ticket_key = copied.get("ticket_key")
    if ticket_key is None:
        ticket_key = binding_id.split(":", 1)[0]
    _text(ticket_key, field="ticket_key", pattern=_KEY_RE, max_len=256)

    producer = _validate_run(copied.get("producer_run"), field="producer_run")
    subject = _validate_run(copied.get("subject_run"), field="subject_run")
    producer_key = _run_key(producer, "producer_run")
    subject_key = _run_key(subject, "subject_run")
    if producer_key == subject_key:
        raise RegistryError("producer_subject_conflated", "producer_run and subject_run must remain distinct")
    producer_id = _run_id(producer, "producer_run_id", copied.get("producer_run_id"))
    subject_id = _run_id(subject, "subject_run_id", copied.get("subject_run_id"))
    if producer_id == subject_id:
        raise RegistryError("producer_subject_conflated", "producer_run_id and subject_run_id must remain distinct")
    for alias, run, identity in (("producer_run_id", producer, producer_id), ("subject_run_id", subject, subject_id)):
        embedded = run.get("run_id")
        if embedded is not None and embedded != identity:
            raise RegistryError("identity_conflict", f"{alias} conflicts with embedded run_id", field=alias)

    if "observation" not in copied or not isinstance(copied.get("observation"), Mapping):
        raise RegistryError("missing_observation", "observation must be an object")
    observation = _validate_optional(copied["observation"], field="observation")
    if not isinstance(observation, dict):  # pragma: no cover
        raise RegistryError("missing_observation", "observation must be an object")

    subject_kind = copied.get("subject_kind")
    if subject_kind not in SUBJECT_KINDS:
        raise RegistryError("invalid_subject_kind", "subject_kind is not recognized", subject_kind=subject_kind)
    binding_status = copied.get("binding_status")
    if binding_status not in BINDING_STATUSES:
        raise RegistryError("invalid_binding_status", "binding_status is not recognized", binding_status=binding_status)

    artifacts = _validate_artifacts(copied.get("artifacts"), field="artifacts")
    sources = _validate_artifacts(copied.get("sources"), field="sources")
    # Artifacts and sources share one evidence namespace.  A locator appearing
    # in both lists must have one immutable digest; otherwise provenance is
    # contradictory even when each list is internally consistent.
    evidence_by_locator: dict[tuple[str, str | None], tuple[str, str]] = {}
    for bucket, values in (("artifact", artifacts), ("source", sources)):
        for evidence in values:
            locator = evidence["locator"]
            digest = evidence["sha256"]
            identity = (locator, evidence.get("selector") if bucket == "source" else None)
            previous = evidence_by_locator.get(identity)
            if previous is not None:
                previous_digest, previous_bucket = previous
                # The same immutable artifact is intentionally addressable as
                # both an artifact role and a source locator.  Duplicates in
                # one bucket remain errors; a cross-bucket digest conflict is
                # contradictory provenance.
                if previous_bucket != bucket and previous_digest == digest:
                    continue
                code = "contradictory_artifact" if previous_digest != digest else "duplicate_artifact"
                raise RegistryError(code, "artifact/source locator is duplicated", locator=locator)
            evidence_by_locator[identity] = (digest, bucket)
    claims = _validate_claims(copied.get("claims"))
    timing = _validate_timing(copied.get("timing"))
    usage = _validate_optional(copied.get("usage"), field="usage")
    tests = _validate_optional(copied.get("tests"), field="tests")

    unknown_reasons_value = copied.get("unknown_reasons", [])
    if not isinstance(unknown_reasons_value, list):
        raise RegistryError("invalid_unknown_reasons", "unknown_reasons must be an array")
    unknown_reasons: list[str] = []
    for index, reason in enumerate(unknown_reasons_value):
        unknown_reasons.append(_text(reason, field=f"unknown_reasons[{index}]", max_len=1024))
    if binding_status in {"UNBOUND", "CONTRADICTORY"} and not unknown_reasons:
        raise RegistryError("missing_unknown_reason", "non-bound summaries require explicit unknown_reasons")

    # Duplicate claim names with unequal values are contradictory evidence.  A
    # caller must mark the summary CONTRADICTORY; status is never inferred.
    names: dict[str, Any] = {}
    conflicting = False
    for claim in claims:
        name = claim["name"]
        if name in names and _canonical_json(names[name]) != _canonical_json(claim["value"]):
            conflicting = True
        names[name] = claim["value"]
    if conflicting and binding_status != "CONTRADICTORY":
        raise RegistryError("contradiction_requires_status", "conflicting claims require CONTRADICTORY status")

    # Keep source-catalog provenance, where supplied, without treating catalog
    # membership as proof of a binding.
    if source_catalog is not None and not isinstance(source_catalog, Mapping):
        raise RegistryError("invalid_source_catalog", "source_catalog must be an object")

    result = {
        "schema": SCHEMA,
        "binding_id": binding_id,
        "ticket_key": ticket_key,
        "producer_run": producer,
        "subject_run": subject,
        "producer_run_id": producer_id,
        "subject_run_id": subject_id,
        "observation": observation,
        "subject_kind": subject_kind,
        "binding_status": binding_status,
        "artifacts": artifacts,
        "sources": sources,
        "claims": claims,
        "timing": timing,
        "usage": usage,
        "tests": tests,
        "unknown_reasons": unknown_reasons,
    }
    if "artifact_dir" in copied:
        result["artifact_dir"] = _check_locator(copied["artifact_dir"], field="artifact_dir")
    if "graph" in copied:
        result["graph"] = _validate_optional(copied["graph"], field="graph")
    if "relationship" in copied:
        result["relationship"] = _validate_optional(copied["relationship"], field="relationship")
    return result


def validate_summary_report(value: Any) -> dict[str, Any]:
    """Return a structured validation result instead of raising."""

    try:
        summary = validate_summary(value)
    except RegistryError as exc:
        return {"ok": False, "error": exc.as_dict()}
    return {"ok": True, "schema": SCHEMA, "binding_id": summary["binding_id"], "summary": summary}


def _catalog_store(kind: Any) -> str:
    if kind == "persisted_rollout":
        return "codex_session_store"
    if kind == "artifact":
        return "artifact_store"
    return "source_store"


def _catalog_artifact(value: Mapping[str, Any], *, index: int, source: bool) -> dict[str, Any]:
    """Map the source-catalog locator shape into the closed artifact shape."""

    path = value.get("path", value.get("locator"))
    if path is None:
        raise RegistryError("missing_locator", "source catalog entry has no path", index=index)
    kind = value.get("kind", "artifact")
    mapped: dict[str, Any] = {
        "role": value.get("role", "source_artifact"),
        "path": path,
        "path_kind": "absolute" if isinstance(path, str) and path.startswith("/") else "relative",
        "store": _catalog_store(kind),
        "host_identity": "local",
        "selector": value.get("source_id", f"source-{index}"),
        "record_pointer": value.get("source_id", f"source-{index}"),
        "sha256": value.get("sha256", value.get("content_hash")),
        "size": value.get("size_bytes", value.get("size")),
    }
    if source and value.get("source_id") is not None:
        mapped["source_id"] = value["source_id"]
    if value.get("kind") is not None:
        mapped["kind"] = value["kind"]
    for key in ("hash_scope", "source_file", "observed_file_sha256", "start_line", "end_line"):
        if key in value:
            mapped[key] = value[key]
    return mapped


def _catalog_evidence_tier(claim_id: str, entry: Mapping[str, Any]) -> str:
    if claim_id.startswith("producer_") or claim_id == "qualification":
        return "submitted"
    subject = entry.get("subject_run")
    if isinstance(subject, Mapping) and subject.get("evidence_tier") in EVIDENCE_TIERS:
        return str(subject["evidence_tier"])
    return "runtime-observed"


def _catalog_unknown_code(claim_id: str, value: Any) -> str | None:
    if claim_id.endswith("timing"):
        return "clock_unknown"
    if claim_id in {"subject_source_surface", "producer_subject_binding"}:
        return "missing_identity" if claim_id == "producer_subject_binding" else "missing_source"
    if value is None:
        return "missing_source"
    return None


def _catalog_claim(value: Mapping[str, Any], *, index: int, entry: Mapping[str, Any]) -> dict[str, Any]:
    claim_id = value.get("claim_id", value.get("name"))
    if not isinstance(claim_id, str):
        raise RegistryError("invalid_claim", "source catalog claim_id is required", index=index)
    evidence = value.get("evidence", value.get("provenance", []))
    if not isinstance(evidence, list):
        raise RegistryError("invalid_claim", "source catalog evidence must be an array", index=index)
    refs: list[str] = []
    provenance: list[dict[str, Any]] = []
    for ref_index, ref in enumerate(evidence):
        if not isinstance(ref, Mapping):
            raise RegistryError("invalid_claim", "source catalog evidence item must be an object", index=index)
        source_id = ref.get("source_id", ref.get("source_ref"))
        pointer = ref.get("pointer", ref.get("record_pointer"))
        if not isinstance(source_id, str) or not source_id:
            raise RegistryError("invalid_claim", "source catalog evidence source_id is required", index=index)
        pointer_text = str(pointer or "$")
        refs.append(f"{source_id}#{pointer_text}")
        provenance.append({"source_id": source_id, "pointer": pointer_text})
    status = value.get("status", "SUPPORTED")
    if status not in CLAIM_STATUSES:
        raise RegistryError("invalid_claim_status", "source catalog claim status is not recognized", index=index)
    result: dict[str, Any] = {
        "name": claim_id,
        "value": value.get("value"),
        "status": status,
        "evidence_tier": _catalog_evidence_tier(claim_id, entry),
        "source_refs": refs,
        "provenance": provenance,
    }
    if status in {"UNKNOWN", "UNBOUND"}:
        result["unknown_reason"] = _catalog_unknown_code(claim_id, value.get("value")) or "observation_incomplete"
    return result


def _catalog_timing(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RegistryError("invalid_timing", "source catalog timing must be an object")
    out: dict[str, Any] = {}
    producer = value.get("producer")
    if isinstance(producer, Mapping):
        out["producer"] = {
            "status": "observed" if producer.get("status") == "OBSERVED" else str(producer.get("status", "unknown")).lower(),
            "clock_id": "producer-rollout-utc",
            "clock_kind": "wall",
            "unit": "milliseconds",
            "origin": "unix_epoch",
            "spans": producer.get("spans", {}),
        }
    subject = value.get("subject")
    if isinstance(subject, Mapping):
        if str(subject.get("status", "")).upper() == "UNKNOWN":
            out["subject"] = {
                "status": "unknown",
                "clock_id": "unknown",
                "clock_kind": "unknown",
                "unit": "unknown",
                "origin": "unknown",
                "unknown_reason": _unknown_reason_code(subject.get("unknown_reason", "clock unknown")),
                "markers": subject.get("markers", {}),
            }
        else:
            out["subject"] = dict(subject)
    if out:
        return out
    # Legacy fixture summaries carry a flat timing record.
    return dict(value)


def _catalog_entry(value: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    """Normalize the rich run-source-catalog entry into a registry summary."""

    ticket_key = value.get("ticket_key")
    binding_id = value.get("binding_id")
    if not isinstance(ticket_key, str) or not ticket_key:
        raise RegistryError("missing_ticket_key", "source catalog ticket_key is required", entry_index=index)
    if not isinstance(binding_id, str) or not binding_id:
        raise RegistryError("missing_binding_id", "source catalog binding_id is required", entry_index=index)
    producer_input = value.get("producer_run")
    subject_input = value.get("subject_run")
    if not isinstance(producer_input, Mapping) or not isinstance(subject_input, Mapping):
        raise RegistryError("missing_run", "source catalog producer_run and subject_run are required", entry_index=index)
    producer = dict(producer_input)
    subject = dict(subject_input)
    producer.setdefault("run_key", f"{ticket_key}:producer")
    subject.setdefault("run_key", f"{ticket_key}:subject")
    producer.setdefault("kind", "producer")
    subject.setdefault("kind", "subject")
    unknown_reasons: list[str] = []
    if value.get("binding_status") in {"UNBOUND", "CONTRADICTORY"}:
        reason_text = ((value.get("observation") or {}).get("relationship") or {}).get("reason")
        unknown_reasons.append(_unknown_reason_code(reason_text or "binding relation unavailable"))
    for claim in value.get("claims", []):
        if isinstance(claim, Mapping) and claim.get("status") in {"UNKNOWN", "UNBOUND"}:
            code = _catalog_unknown_code(str(claim.get("claim_id", "")), claim.get("value"))
            if code is not None:
                unknown_reasons.append(code)
    canonical: dict[str, Any] = {
        "schema": SCHEMA,
        "binding_id": binding_id,
        "ticket_key": ticket_key,
        "artifact_dir": value.get("artifact_dir"),
        "producer_run": producer,
        "subject_run": subject,
        "observation": value.get("observation", {}),
        "subject_kind": value.get("subject_kind"),
        "binding_status": value.get("binding_status"),
        "artifacts": [_catalog_artifact(item, index=artifact_index, source=False) for artifact_index, item in enumerate(value.get("artifacts", []))],
        "sources": [_catalog_artifact(item, index=source_index, source=True) for source_index, item in enumerate(value.get("sources", []))],
        "claims": [_catalog_claim(item, index=claim_index, entry=value) for claim_index, item in enumerate(value.get("claims", []))],
        "timing": _catalog_timing(value.get("timing", {})),
        "usage": value.get("usage", {}),
        "tests": value.get("tests", {}),
        "unknown_reasons": sorted(set(unknown_reasons)),
        "relationship": value.get("observation", {}).get("relationship", {}),
    }
    # Retain graph-facing run metadata in a compact, fixed field so consumers
    # can query it without opening any source locator.
    canonical["graph"] = {
        "producer": {
            "subject_kind": producer.get("subject_kind"),
            "root": producer.get("root", {}),
            "children": producer.get("children", []),
            "edges": producer.get("edges", []),
            "qualification": producer.get("qualification", {}),
        },
        "subject": {
            "subject_kind": subject.get("subject_kind"),
            "root": subject.get("root", {}),
            "children": subject.get("children", []),
            "edges": subject.get("edges", []),
            "qualification": subject.get("qualification", {}),
            "terminal_state": subject.get("terminal_state"),
        },
    }
    return canonical


def validate_source_catalog(value: Any) -> list[dict[str, Any]]:
    """Validate a source catalog and return canonical summaries in order."""

    if not isinstance(value, Mapping):
        raise RegistryError("invalid_source_catalog", "source catalog must be an object")
    _validate_input_shape(value)
    copied = _safe_copy(value)
    schema = copied.get("schema")
    if schema not in {SOURCE_CATALOG_SCHEMA, SOURCE_CATALOG_SCHEMA_ALIAS}:
        raise RegistryError("invalid_schema", "unsupported source-catalog schema", schema=schema)
    if "entries" in copied and "runs" in copied:
        raise RegistryError("ambiguous_source_catalog", "entries and runs cannot both be supplied")
    entries = copied.get("entries", copied.get("runs"))
    if not isinstance(entries, list):
        raise RegistryError("invalid_source_catalog", "source catalog entries must be an array")
    if len(entries) > MAX_ARTIFACT_RECORDS:
        raise RegistryError(
            "artifact_records_limit",
            "source catalog exceeds one bounded projection chunk",
            observed=len(entries),
            bound=MAX_ARTIFACT_RECORDS,
            continuation_required=True,
        )
    summaries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        try:
            # Rich source catalogs carry producer/subject graph metadata and
            # source locators, whereas legacy fixtures are already summaries.
            rich = isinstance(entry, Mapping) and ("ticket_key" in entry or "artifact_dir" in entry)
            summary = validate_summary(_catalog_entry(entry, index=index), source_catalog=copied) if rich else validate_summary(entry, source_catalog=copied)
        except RegistryError as exc:
            raise RegistryError(exc.code, str(exc), entry_index=index, **exc.details) from exc
        binding_id = summary["binding_id"]
        if binding_id in seen:
            raise RegistryError("duplicate_binding_id", "source catalog binding_id is duplicated", binding_id=binding_id)
        seen.add(binding_id)
        summaries.append(summary)
    return summaries


def generate_summaries(source_catalog: Any) -> list[dict[str, Any]]:
    """Provider-free summary generation from an already loaded catalog."""

    return validate_source_catalog(source_catalog)


build_summaries = generate_summaries


def _load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RegistryError("read_failed", f"cannot read {path}", path=str(path)) from exc
    try:
        return _parse_json_bytes(raw, path=str(path))
    except RegistryError as exc:
        # Keep the original parser reason stable while retaining the source
        # locator only in structured details.  No input body is copied.
        details = dict(exc.details)
        details["path"] = str(path)
        raise RegistryError(exc.code, str(exc), **details) from exc


def _write_json(path: Path, value: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_canonical_json(value) + "\n", encoding="utf-8")
    except OSError as exc:
        raise RegistryError("write_failed", f"cannot write {path}", path=str(path)) from exc


def _safe_output_name(binding_id: str, used: set[str]) -> str:
    # Binding IDs are already constrained to path-safe punctuation except ':'.
    # Do not permit traversal and make collisions explicit rather than
    # silently overwriting another ticket summary.
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", binding_id)
    if not name or name in {".", ".."}:
        raise RegistryError("unsafe_binding_id", "binding_id cannot name an output file")
    filename = name + ".json"
    if filename in used:
        raise RegistryError("output_name_collision", "binding IDs map to one output filename", filename=filename)
    used.add(filename)
    return filename


def build_from_catalog(catalog_path: str | os.PathLike[str], output_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Validate a source catalog and emit deterministic summary JSON files."""

    catalog_file = Path(catalog_path)
    catalog = _load_json(catalog_file)
    summaries = validate_source_catalog(catalog)
    output = Path(output_dir)
    used: set[str] = set()
    records: list[dict[str, Any]] = []
    for summary in summaries:
        filename = _safe_output_name(summary["binding_id"], used)
        target = output / filename
        _write_json(target, summary)
        records.append({"binding_id": summary["binding_id"], "path": str(target), "sha256": summary_sha256(summary)})
    records.sort(key=lambda item: item["binding_id"])
    return {"ok": True, "schema": SCHEMA, "output_dir": str(output), "summaries": records}


def _expand_summary_paths(paths: Iterable[str | os.PathLike[str]]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            candidates = sorted(path.rglob("*.json"), key=lambda item: item.as_posix())
        else:
            candidates = [path]
        for candidate in candidates:
            key = os.path.abspath(os.fspath(candidate))
            if key not in seen:
                seen.add(key)
                result.append(candidate)
    return sorted(result, key=lambda item: item.as_posix())


def _load_summary_files(paths: Iterable[str | os.PathLike[str]]) -> list[tuple[Path, dict[str, Any], str]]:
    loaded: list[tuple[Path, dict[str, Any], str]] = []
    seen_ids: dict[str, Path] = {}
    for path in _expand_summary_paths(paths):
        if path.is_symlink() or not path.is_file():
            raise RegistryError("summary_artifact_missing", "summary path is not a regular file", path=str(path))
        value = _load_json(path)
        summary = validate_summary(value)
        binding_id = summary["binding_id"]
        if binding_id in seen_ids:
            raise RegistryError("duplicate_binding_id", "summary files contain duplicate binding_id", binding_id=binding_id)
        seen_ids[binding_id] = path
        loaded.append((path, summary, summary_sha256(summary)))
    return loaded


def _open_db(path: str | os.PathLike[str]) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(os.fspath(path))
    except sqlite3.Error as exc:
        raise RegistryError("database_open_failed", f"cannot open registry database {path}") from exc
    connection.row_factory = sqlite3.Row
    return connection


_COMPACT_BINDING_COLUMNS = frozenset(
    {
        "binding_id",
        "ticket_key",
        "summary_sha256",
        "summary_path",
        "binding_status",
        "subject_kind",
        "producer_run_key",
        "subject_run_key",
        "evidence_tiers_json",
        "evidence_status_flags_json",
        "claim_status_counts_json",
        "claim_count",
        "artifact_count",
        "source_count",
        "graph_present",
        "timing_known",
        "timing_unknown",
        "timing_unknown_reason_codes_json",
        "usage_known",
        "usage_unknown",
        "usage_unknown_reason_codes_json",
        "test_count",
        "test_aggregate_json",
        "unknown_reason_codes_json",
    }
)


def _create_compact_schema(connection: sqlite3.Connection) -> None:
    """Create the bounded projection schema.

    ``bindings`` deliberately contains no summary body.  JSON columns are all
    fixed aggregates or closed code lists; the summary artifact remains the
    sole authority for claims, graph details, locators, timing records, usage,
    and test bodies.
    """

    connection.executescript(
        """
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS registry_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bindings (
            binding_id TEXT PRIMARY KEY,
            ticket_key TEXT NOT NULL,
            summary_sha256 TEXT NOT NULL,
            summary_path TEXT,
            binding_status TEXT NOT NULL,
            subject_kind TEXT NOT NULL,
            producer_run_key TEXT NOT NULL,
            subject_run_key TEXT NOT NULL,
            evidence_tiers_json TEXT NOT NULL,
            evidence_status_flags_json TEXT NOT NULL,
            claim_status_counts_json TEXT NOT NULL,
            claim_count INTEGER NOT NULL,
            artifact_count INTEGER NOT NULL,
            source_count INTEGER NOT NULL,
            graph_present INTEGER NOT NULL CHECK (graph_present IN (0, 1)),
            timing_known INTEGER NOT NULL CHECK (timing_known IN (0, 1)),
            timing_unknown INTEGER NOT NULL CHECK (timing_unknown IN (0, 1)),
            timing_unknown_reason_codes_json TEXT NOT NULL,
            usage_known INTEGER NOT NULL CHECK (usage_known IN (0, 1)),
            usage_unknown INTEGER NOT NULL CHECK (usage_unknown IN (0, 1)),
            usage_unknown_reason_codes_json TEXT NOT NULL,
            test_count INTEGER NOT NULL,
            test_aggregate_json TEXT NOT NULL,
            unknown_reason_codes_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS run_index (
            run_key TEXT NOT NULL,
            binding_id TEXT NOT NULL REFERENCES bindings(binding_id) ON DELETE CASCADE,
            run_role TEXT NOT NULL CHECK (run_role IN ('producer','subject')),
            PRIMARY KEY (run_key, binding_id, run_role)
        );
        CREATE INDEX IF NOT EXISTS run_index_key ON run_index(run_key);
        CREATE INDEX IF NOT EXISTS bindings_ticket_key ON bindings(ticket_key);
        CREATE INDEX IF NOT EXISTS bindings_status ON bindings(binding_status);
        CREATE TABLE IF NOT EXISTS governance_outcomes (
            outcome_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL CHECK (kind IN ('profile_lifecycle','efficiency_evaluation')),
            state TEXT NOT NULL,
            terminal_outcome TEXT,
            profile_id TEXT,
            profile_sha256 TEXT,
            report_schema TEXT NOT NULL,
            report_sha256 TEXT NOT NULL,
            report_path TEXT NOT NULL,
            projection_sha256 TEXT NOT NULL,
            source_authority TEXT NOT NULL,
            transition_count INTEGER NOT NULL,
            trial_count INTEGER NOT NULL,
            unknown_count INTEGER NOT NULL,
            contradiction_count INTEGER NOT NULL,
            suspension_required INTEGER NOT NULL CHECK (suspension_required IN (0, 1))
        );
        CREATE INDEX IF NOT EXISTS governance_kind_state ON governance_outcomes(kind, state);
        CREATE INDEX IF NOT EXISTS governance_profile ON governance_outcomes(profile_id, profile_sha256);
        """
    )


def _projection_test_aggregate(value: Any) -> dict[str, int]:
    """Reduce arbitrary validated test telemetry to counters only."""

    aggregate = {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "unknown": 0}

    def status_for(item: Any) -> str:
        if isinstance(item, Mapping):
            raw = item.get("status", item.get("result", item.get("outcome", item.get("state"))))
            if raw is None and isinstance(item.get("ok"), bool):
                raw = "passed" if item["ok"] else "failed"
        elif isinstance(item, str):
            raw = item
        else:
            raw = None
        text = str(raw or "").strip().lower()
        if text in {"pass", "passed", "ok", "success", "successful", "true"}:
            return "passed"
        if text in {"fail", "failed", "error", "errored", "false"}:
            return "failed"
        if text in {"skip", "skipped", "xfail", "expected-failure"}:
            return "skipped"
        return "unknown"

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            # Common aggregate shapes are accepted, but only their counters
            # are retained.  Do not copy names, messages, or test bodies.
            nested = item.get("tests", item.get("results", item.get("items")))
            if isinstance(nested, list):
                for child in nested:
                    visit(child)
                return
            if any(key in item for key in ("total", "passed", "failed", "skipped", "unknown")):
                total = item.get("total", item.get("count", 0))
                if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                    total = 0
                local = {"passed": 0, "failed": 0, "skipped": 0, "unknown": 0}
                for key in ("passed", "failed", "skipped", "unknown"):
                    number = item.get(key, 0)
                    if isinstance(number, bool) or not isinstance(number, int) or number < 0:
                        number = 0
                    local[key] = number
                    aggregate[key] += number
                aggregate["total"] += max(total, sum(local.values()))
                return
        aggregate["total"] += 1
        aggregate[status_for(item)] += 1

    if value is None:
        return aggregate
    if isinstance(value, list):
        for item in value:
            visit(item)
    else:
        visit(value)
    return aggregate


def _projection_timing(value: Mapping[str, Any]) -> tuple[bool, bool, list[str]]:
    records: list[Mapping[str, Any]] = []
    if "producer" in value or "subject" in value:
        for role in ("producer", "subject"):
            record = value.get(role)
            if isinstance(record, Mapping):
                records.append(record)
    else:
        records.append(value)
    known = False
    unknown = False
    reasons: set[str] = set()
    for record in records:
        if "all_required_known" in record:
            if record.get("all_required_known") is True:
                known = True
            else:
                unknown = True
                reasons.add(_unknown_reason_code(record.get("unknown_reason", "observation incomplete")))
            continue
        if str(record.get("status", "")).lower() == "unknown" or "unknown_reason" in record:
            unknown = True
            reasons.add(_unknown_reason_code(record.get("unknown_reason", record.get("reason"))))
        else:
            known = True
    if not records:
        unknown = True
        reasons.add("observation_incomplete")
    return known, unknown, sorted(reasons)


def _projection_usage(value: Any) -> tuple[bool, bool, list[str]]:
    if value is None or value == {}:
        return False, True, ["observation_incomplete"]
    if isinstance(value, Mapping):
        if "all_required_known" in value:
            if value.get("all_required_known") is True:
                return True, False, []
            reason = _unknown_reason_code(value.get("unknown_reason", value.get("reason", "usage incomplete")))
            return bool(value.get("known_roles")), True, [reason]
        if str(value.get("status", "")).lower() in {"unknown", "unavailable", "missing", "partial", "contradictory"}:
            reason = _unknown_reason_code(value.get("unknown_reason", value.get("reason", "usage unavailable")))
            return False, True, [reason]
        # Legacy fixture/producer telemetry is deliberately not an
        # all-required hosted-attempt usage signal.  It remains attached to
        # its summary but the compact index marks it partial/unknown.
        return True, True, ["observation_incomplete"]
    return True, False, []


def _compact_projection(summary: Mapping[str, Any], digest: str, summary_path: str | None) -> dict[str, Any]:
    """Build the only representation allowed in SQLite and default queries."""

    claims = summary.get("claims", [])
    artifacts = summary.get("artifacts", [])
    sources = summary.get("sources", [])
    claim_status_counts = {status: 0 for status in sorted(CLAIM_STATUSES)}
    evidence_tiers: set[str] = set()
    evidence_status_flags: set[str] = set()
    unknown_codes: set[str] = set()
    for claim in claims if isinstance(claims, list) else []:
        if not isinstance(claim, Mapping):
            continue
        tier = claim.get("evidence_tier")
        if tier in EVIDENCE_TIERS:
            evidence_tiers.add(str(tier))
        status = str(claim.get("status", "SUPPORTED"))
        if status in claim_status_counts:
            claim_status_counts[status] += 1
            evidence_status_flags.add(status)
        if status in {"UNKNOWN", "UNBOUND"} or claim.get("unknown_reason") is not None:
            unknown_codes.add(_unknown_reason_code(claim.get("unknown_reason")))
    for reason in summary.get("unknown_reasons", []) if isinstance(summary.get("unknown_reasons"), list) else []:
        unknown_codes.add(_unknown_reason_code(reason))
    timing_known, timing_unknown, timing_reasons = _projection_timing(summary.get("timing", {}))
    usage_known, usage_unknown, usage_reasons = _projection_usage(summary.get("usage"))
    unknown_codes.update(timing_reasons)
    unknown_codes.update(usage_reasons)
    test_aggregate = _projection_test_aggregate(summary.get("tests"))
    producer = summary.get("producer_run", {})
    subject = summary.get("subject_run", {})
    for run in (producer, subject):
        if isinstance(run, Mapping) and run.get("evidence_tier") in EVIDENCE_TIERS:
            evidence_tiers.add(str(run["evidence_tier"]))
        if isinstance(run, Mapping) and run.get("status") in CLAIM_STATUSES:
            evidence_status_flags.add(str(run["status"]))
    producer_id = _run_id(producer, "producer_run_id", summary.get("producer_run_id"))
    subject_id = _run_id(subject, "subject_run_id", summary.get("subject_run_id"))
    return {
        "schema": SCHEMA,
        "binding_id": str(summary["binding_id"]),
        "ticket_key": str(summary.get("ticket_key", str(summary["binding_id"]).split(":", 1)[0])),
        "producer_run_key": _run_key(producer, "producer_run"),
        "subject_run_key": _run_key(subject, "subject_run"),
        "producer_run_id": producer_id,
        "subject_run_id": subject_id,
        "binding_status": str(summary["binding_status"]),
        "subject_kind": str(summary["subject_kind"]),
        "evidence_tiers": sorted(evidence_tiers),
        "evidence_status_flags": sorted(evidence_status_flags),
        "claim_status_counts": claim_status_counts,
        "claim_count": len(claims) if isinstance(claims, list) else 0,
        "artifact_count": len(artifacts) if isinstance(artifacts, list) else 0,
        "source_count": len(sources) if isinstance(sources, list) else 0,
        "graph_present": isinstance(summary.get("graph"), Mapping),
        "timing_known": timing_known,
        "timing_unknown": timing_unknown,
        "timing_unknown_reason_codes": timing_reasons,
        "usage_known": usage_known,
        "usage_unknown": usage_unknown,
        "usage_unknown_reason_codes": usage_reasons,
        "test_count": test_aggregate["total"],
        "test_aggregate": test_aggregate,
        "unknown_reason_codes": sorted(unknown_codes),
        "summary_path": summary_path,
        "summary_sha256": digest,
    }


def _insert_projection(connection: sqlite3.Connection, projection: Mapping[str, Any]) -> None:
    connection.execute(
        """
        INSERT INTO bindings(
            binding_id, ticket_key, summary_sha256, summary_path, binding_status,
            subject_kind, producer_run_key, subject_run_key, evidence_tiers_json,
            evidence_status_flags_json, claim_status_counts_json, claim_count,
            artifact_count, source_count, graph_present, timing_known,
            timing_unknown, timing_unknown_reason_codes_json, usage_known,
            usage_unknown, usage_unknown_reason_codes_json, test_count,
            test_aggregate_json, unknown_reason_codes_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(binding_id) DO UPDATE SET
            ticket_key=excluded.ticket_key,
            summary_sha256=excluded.summary_sha256,
            summary_path=excluded.summary_path,
            binding_status=excluded.binding_status,
            subject_kind=excluded.subject_kind,
            producer_run_key=excluded.producer_run_key,
            subject_run_key=excluded.subject_run_key,
            evidence_tiers_json=excluded.evidence_tiers_json,
            evidence_status_flags_json=excluded.evidence_status_flags_json,
            claim_status_counts_json=excluded.claim_status_counts_json,
            claim_count=excluded.claim_count,
            artifact_count=excluded.artifact_count,
            source_count=excluded.source_count,
            graph_present=excluded.graph_present,
            timing_known=excluded.timing_known,
            timing_unknown=excluded.timing_unknown,
            timing_unknown_reason_codes_json=excluded.timing_unknown_reason_codes_json,
            usage_known=excluded.usage_known,
            usage_unknown=excluded.usage_unknown,
            usage_unknown_reason_codes_json=excluded.usage_unknown_reason_codes_json,
            test_count=excluded.test_count,
            test_aggregate_json=excluded.test_aggregate_json,
            unknown_reason_codes_json=excluded.unknown_reason_codes_json
        """,
        (
            projection["binding_id"],
            projection["ticket_key"],
            projection["summary_sha256"],
            projection["summary_path"],
            projection["binding_status"],
            projection["subject_kind"],
            projection["producer_run_key"],
            projection["subject_run_key"],
            _canonical_json(projection["evidence_tiers"]),
            _canonical_json(projection["evidence_status_flags"]),
            _canonical_json(projection["claim_status_counts"]),
            projection["claim_count"],
            projection["artifact_count"],
            projection["source_count"],
            int(bool(projection["graph_present"])),
            int(bool(projection["timing_known"])),
            int(bool(projection["timing_unknown"])),
            _canonical_json(projection["timing_unknown_reason_codes"]),
            int(bool(projection["usage_known"])),
            int(bool(projection["usage_unknown"])),
            _canonical_json(projection["usage_unknown_reason_codes"]),
            projection["test_count"],
            _canonical_json(projection["test_aggregate"]),
            _canonical_json(projection["unknown_reason_codes"]),
        ),
    )


def _migrate_legacy_schema(connection: sqlite3.Connection, columns: set[str]) -> None:
    """Rebuild a pre-compact table and physically discard full summary bodies."""

    legacy_name = "bindings_legacy_full"
    connection.execute("DROP TABLE IF EXISTS bindings_legacy_full")
    connection.execute("DROP TABLE IF EXISTS run_index")
    connection.execute("ALTER TABLE bindings RENAME TO bindings_legacy_full")
    _create_compact_schema(connection)
    rows = connection.execute("SELECT * FROM bindings_legacy_full ORDER BY binding_id").fetchall()
    for row in rows:
        try:
            raw = row["summary_json"]
            summary = validate_summary(json.loads(raw))
            digest = row["summary_sha256"] if isinstance(row["summary_sha256"], str) and _SHA256_RE.fullmatch(row["summary_sha256"]) else summary_sha256(summary)
            path = row["summary_path"] if "summary_path" in columns else None
            projection = _compact_projection(summary, digest, path)
            _insert_projection(connection, projection)
            connection.execute("INSERT INTO run_index(run_key, binding_id, run_role) VALUES (?, ?, 'producer')", (projection["producer_run_key"], projection["binding_id"]))
            connection.execute("INSERT INTO run_index(run_key, binding_id, run_role) VALUES (?, ?, 'subject')", (projection["subject_run_key"], projection["binding_id"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, RegistryError):
            # Invalid legacy rows cannot be made authoritative without their
            # original artifact path; dropping them is safer than retaining a
            # body or fabricating a detail path.
            continue
    connection.execute("DROP TABLE bindings_legacy_full")
    connection.execute("INSERT OR REPLACE INTO registry_meta(key, value) VALUES ('migration', 'compact-v2')")
    connection.commit()
    # DROP leaves free pages containing old text until VACUUM.  Compact
    # custody requires that legacy full bodies are gone from the file itself.
    connection.execute("VACUUM")


def _ensure_schema(connection: sqlite3.Connection) -> None:
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(bindings)").fetchall()}
    if columns and ("summary_json" in columns or not _COMPACT_BINDING_COLUMNS.issubset(columns)):
        _migrate_legacy_schema(connection, columns)
    else:
        _create_compact_schema(connection)
    connection.execute("INSERT OR REPLACE INTO registry_meta(key, value) VALUES ('schema', ?)", (SCHEMA,))
    connection.execute("PRAGMA user_version = 2")
    connection.commit()


def _upsert_summary(connection: sqlite3.Connection, summary: Mapping[str, Any], digest: str, summary_path: str) -> str:
    binding_id = str(summary["binding_id"])
    existing = connection.execute("SELECT summary_sha256, summary_path FROM bindings WHERE binding_id = ?", (binding_id,)).fetchone()
    if existing is not None and existing["summary_sha256"] == digest:
        if existing["summary_path"] != summary_path:
            projection = _compact_projection(summary, digest, summary_path)
            _insert_projection(connection, projection)
        return "unchanged"
    producer_key = _run_key(summary["producer_run"], "producer_run")
    subject_key = _run_key(summary["subject_run"], "subject_run")
    ticket_key = _text(summary.get("ticket_key", binding_id.split(":", 1)[0]), field="ticket_key", pattern=_KEY_RE, max_len=256)
    projection = _compact_projection(summary, digest, summary_path)
    # The caller owns the surrounding transaction.  Keeping this helper free
    # of implicit commits is what lets a malformed later row roll back the
    # complete chunk rather than leaving a partial projection behind.
    connection.execute("DELETE FROM run_index WHERE binding_id = ?", (binding_id,))
    _insert_projection(connection, projection)
    connection.execute("INSERT INTO run_index(run_key, binding_id, run_role) VALUES (?, ?, 'producer')", (producer_key, binding_id))
    connection.execute("INSERT INTO run_index(run_key, binding_id, run_role) VALUES (?, ?, 'subject')", (subject_key, binding_id))
    return "indexed"


def index_summaries(db_path: str | os.PathLike[str], summary_paths: Iterable[str | os.PathLike[str]]) -> dict[str, Any]:
    """Incrementally index summary files, keyed by canonical summary hash."""

    loaded = _load_summary_files(summary_paths)
    connection = _open_db(db_path)
    try:
        _ensure_schema(connection)
        counts = {"indexed": 0, "unchanged": 0}
        records: list[dict[str, Any]] = []
        with connection:
            for path, summary, digest in loaded:
                action = _upsert_summary(connection, summary, digest, os.path.abspath(os.fspath(path)))
                counts[action] += 1
                records.append({"binding_id": summary["binding_id"], "path": str(path), "sha256": digest, "action": action})
    finally:
        connection.close()
    return {"ok": True, "schema": SCHEMA, "db": os.fspath(db_path), **counts, "summaries": records}


def index_summary(db_path: str | os.PathLike[str], summary_path: str | os.PathLike[str]) -> dict[str, Any]:
    return index_summaries(db_path, [summary_path])


def validate_projection_chunk(
    records: Sequence[Any],
    *,
    claims_edges: int = 0,
    locators: Sequence[Any] = (),
    continuation: str | None = None,
    expected_continuation: str | None = None,
) -> dict[str, Any]:
    """Validate an explicit bounded projection chunk before mutation.

    A caller may submit any number of chunks, but each invocation must remain
    within the canonical per-mutation limits and carry the opaque continuation
    returned by the previous chunk.  This helper only validates; it never
    changes SQLite state.
    """

    if len(records) > MAX_ARTIFACT_RECORDS:
        raise RegistryError(
            "artifact_records_limit",
            "projection chunk exceeds artifact record bound",
            observed=len(records),
            bound=MAX_ARTIFACT_RECORDS,
            continuation_required=True,
        )
    if isinstance(claims_edges, bool) or not isinstance(claims_edges, int) or claims_edges < 0 or claims_edges > MAX_CLAIMS_EDGES:
        raise RegistryError(
            "claims_edges_limit",
            "projection chunk exceeds claims/edges bound",
            observed=claims_edges,
            bound=MAX_CLAIMS_EDGES,
            continuation_required=True,
        )
    if len(locators) > MAX_SOURCE_LOCATORS:
        raise RegistryError(
            "source_locators_limit",
            "projection chunk exceeds source locator bound",
            observed=len(locators),
            bound=MAX_SOURCE_LOCATORS,
            continuation_required=True,
        )
    if expected_continuation is not None and continuation != expected_continuation:
        raise RegistryError("stale_continuation", "projection continuation does not match current state")
    return {
        "schema": DEFENSIVE_PROFILE_SCHEMA,
        "records": len(records),
        "claims_edges": claims_edges,
        "locators": len(locators),
        "continuation": continuation,
        "bounded": True,
    }


def rebuild_registry(db_path: str | os.PathLike[str], summary_paths: Iterable[str | os.PathLike[str]]) -> dict[str, Any]:
    """Delete and rebuild the disposable projection deterministically."""

    loaded = _load_summary_files(summary_paths)
    connection = _open_db(db_path)
    try:
        _ensure_schema(connection)
        records: list[dict[str, Any]] = []
        with connection:
            connection.execute("DELETE FROM run_index")
            connection.execute("DELETE FROM bindings")
            for path, summary, digest in loaded:
                _upsert_summary(connection, summary, digest, os.path.abspath(os.fspath(path)))
                records.append({"binding_id": summary["binding_id"], "path": str(path), "sha256": digest})
    finally:
        connection.close()
    return {"ok": True, "schema": SCHEMA, "db": os.fspath(db_path), "rebuilt": len(records), "summaries": records}


rebuild = rebuild_registry


def _governance_projection(report: Mapping[str, Any], report_path: Path) -> dict[str, Any]:
    """Validate one authoritative governance report into a compact projection."""

    schema = report.get("schema")
    if schema not in GOVERNANCE_REPORT_SCHEMAS:
        raise RegistryError("invalid_governance_schema", "unsupported governance report schema", schema=schema)
    expected_report_sha = report.get("report_sha256")
    if not isinstance(expected_report_sha, str) or _SHA256_RE.fullmatch(expected_report_sha) is None:
        raise RegistryError("invalid_governance_hash", "governance report_sha256 is invalid")
    core = {key: value for key, value in report.items() if key != "report_sha256"}
    actual_report_sha = hashlib.sha256(_canonical_json(core).encode("utf-8")).hexdigest()
    if expected_report_sha != actual_report_sha:
        raise RegistryError("governance_report_hash_mismatch", "governance report hash does not verify")
    projection = report.get("registry_projection")
    if not isinstance(projection, Mapping):
        raise RegistryError("invalid_governance_projection", "registry_projection must be an object")
    if projection.get("source_authority") not in {"profile_lifecycle_report", "efficiency_evaluation_report"}:
        raise RegistryError("invalid_governance_authority", "projection source authority is invalid")
    if schema == "orch-dork/profile-lifecycle-report/v1":
        kind = "profile_lifecycle"
        outcome_id = _text(report.get("lifecycle_id"), field="lifecycle_id", pattern=_KEY_RE, max_len=256)
        state = _text(report.get("state"), field="state", pattern=_KEY_RE, max_len=256)
        profile_id = _text(report.get("profile_id"), field="profile_id", pattern=_KEY_RE, max_len=256)
        profile_sha = report.get("profile_sha256")
        terminal_outcome = None
        transition_count = report.get("historical_transition_count", 0) + (1 if report.get("transition") else 0)
        trial_count = 0
        unknown_count = 0
        contradiction_count = 0
        suspension_required = state == "SUSPENDED"
    else:
        kind = "efficiency_evaluation"
        outcome_id = _text(report.get("evaluation_id"), field="evaluation_id", pattern=_KEY_RE, max_len=256)
        state = _text(report.get("state"), field="state", pattern=_KEY_RE, max_len=256)
        terminal_outcome = report.get("terminal_outcome")
        if terminal_outcome is not None:
            _text(terminal_outcome, field="terminal_outcome", pattern=_KEY_RE, max_len=256)
        signal = report.get("profile_suspension_signal")
        if not isinstance(signal, Mapping):
            raise RegistryError("invalid_governance_projection", "profile suspension signal must be an object")
        profile_id = _text(signal.get("profile_id"), field="profile_id", pattern=_KEY_RE, max_len=256)
        profile_sha = signal.get("profile_sha256")
        transition_count = report.get("historical_transition_count", 0) + (1 if report.get("transition") else 0)
        trial_count = len(report.get("trial_summaries", []))
        unknown_count = len(report.get("unknowns", []))
        contradiction_count = len(report.get("contradictions", []))
        suspension_required = signal.get("required") is True
    if not isinstance(profile_sha, str) or _SHA256_RE.fullmatch(profile_sha) is None:
        raise RegistryError("invalid_governance_profile_hash", "profile hash is invalid")
    for field, count in (
        ("transition_count", transition_count),
        ("trial_count", trial_count),
        ("unknown_count", unknown_count),
        ("contradiction_count", contradiction_count),
    ):
        if type(count) is not int or count < 0:
            raise RegistryError("invalid_governance_count", f"{field} is invalid", field=field)
    projection_sha = hashlib.sha256(_canonical_json(projection).encode("utf-8")).hexdigest()
    return {
        "schema": GOVERNANCE_PROJECTION_SCHEMA,
        "outcome_id": outcome_id,
        "kind": kind,
        "state": state,
        "terminal_outcome": terminal_outcome,
        "profile_id": profile_id,
        "profile_sha256": profile_sha,
        "report_schema": schema,
        "report_sha256": expected_report_sha,
        "report_path": os.path.abspath(os.fspath(report_path)),
        "projection_sha256": projection_sha,
        "source_authority": str(projection.get("source_authority")),
        "transition_count": transition_count,
        "trial_count": trial_count,
        "unknown_count": unknown_count,
        "contradiction_count": contradiction_count,
        "suspension_required": bool(suspension_required),
    }


def rebuild_governance_projection(
    db_path: str | os.PathLike[str], report_paths: Iterable[str | os.PathLike[str]]
) -> dict[str, Any]:
    """Deterministically rebuild governance rows from authoritative reports."""

    paths = _expand_summary_paths(report_paths)
    projections: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise RegistryError("governance_artifact_missing", "governance report is not a regular file", path=str(path))
        projection = _governance_projection(_load_json(path), path)
        outcome_id = projection["outcome_id"]
        if outcome_id in seen:
            raise RegistryError("duplicate_governance_outcome", "governance outcome id is duplicated", outcome_id=outcome_id)
        seen.add(outcome_id)
        projections.append(projection)
    projections.sort(key=lambda row: (row["kind"], row["outcome_id"]))
    connection = _open_db(db_path)
    try:
        _ensure_schema(connection)
        with connection:
            connection.execute("DELETE FROM governance_outcomes")
            for row in projections:
                connection.execute(
                    """
                    INSERT INTO governance_outcomes(
                        outcome_id, kind, state, terminal_outcome, profile_id,
                        profile_sha256, report_schema, report_sha256, report_path,
                        projection_sha256, source_authority, transition_count,
                        trial_count, unknown_count, contradiction_count,
                        suspension_required
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["outcome_id"], row["kind"], row["state"], row["terminal_outcome"],
                        row["profile_id"], row["profile_sha256"], row["report_schema"],
                        row["report_sha256"], row["report_path"], row["projection_sha256"],
                        row["source_authority"], row["transition_count"], row["trial_count"],
                        row["unknown_count"], row["contradiction_count"], int(row["suspension_required"]),
                    ),
                )
    finally:
        connection.close()
    return {
        "ok": True,
        "schema": GOVERNANCE_PROJECTION_SCHEMA,
        "db": os.fspath(db_path),
        "rebuilt": len(projections),
        "outcomes": projections,
    }


def query_governance_projection(
    db_path: str | os.PathLike[str], *, kind: str | None = None, outcome_id: str | None = None
) -> list[dict[str, Any]]:
    """Read compact governance rows without opening authoritative reports."""

    if kind is not None and kind not in {"profile_lifecycle", "efficiency_evaluation"}:
        raise RegistryError("invalid_governance_kind", "unsupported governance projection kind", kind=kind)
    if outcome_id is not None:
        _text(outcome_id, field="outcome_id", pattern=_KEY_RE, max_len=256)
    connection = _open_db(db_path)
    try:
        _ensure_schema(connection)
        if kind is not None and outcome_id is not None:
            rows = connection.execute(
                "SELECT * FROM governance_outcomes WHERE kind = ? AND outcome_id = ? ORDER BY outcome_id",
                (kind, outcome_id),
            ).fetchall()
        elif kind is not None:
            rows = connection.execute(
                "SELECT * FROM governance_outcomes WHERE kind = ? ORDER BY outcome_id", (kind,)
            ).fetchall()
        elif outcome_id is not None:
            rows = connection.execute(
                "SELECT * FROM governance_outcomes WHERE outcome_id = ? ORDER BY kind", (outcome_id,)
            ).fetchall()
        else:
            rows = connection.execute("SELECT * FROM governance_outcomes ORDER BY kind, outcome_id").fetchall()
        return [
            {
                "schema": GOVERNANCE_PROJECTION_SCHEMA,
                **{key: row[key] for key in row.keys() if key != "suspension_required"},
                "suspension_required": bool(row["suspension_required"]),
            }
            for row in rows
        ]
    finally:
        connection.close()


def query_registry(
    db_path: str | os.PathLike[str],
    *,
    binding_id: str | None = None,
    run_key: str | None = None,
    ticket_key: str | None = None,
    ticket_keys: Iterable[str] | None = None,
    include: Iterable[str] | None = None,
    detail: bool = False,
) -> list[dict[str, Any]]:
    """Query the compact SQLite projection.

    The default is deliberately closed and SQLite-only.  ``detail=True`` is
    an explicit opt-in which verifies and loads the referenced summary
    artifact; it never follows any locator contained by that summary.
    """

    if binding_id is not None:
        _text(binding_id, field="binding_id", pattern=_KEY_RE, max_len=256)
    if run_key is not None:
        _text(run_key, field="run_key", pattern=_RUN_KEY_RE, max_len=256)
    if ticket_key is not None:
        _text(ticket_key, field="ticket_key", pattern=_KEY_RE, max_len=256)
    normalized_ticket_keys: list[str] = []
    if ticket_keys is not None:
        for index, key in enumerate(ticket_keys):
            normalized_ticket_keys.append(_text(key, field=f"ticket_keys[{index}]", pattern=_KEY_RE, max_len=256))
        if not normalized_ticket_keys:
            raise RegistryError("invalid_query", "ticket_keys must not be empty")
    dimensions = sum(value is not None for value in (binding_id, run_key, ticket_key)) + bool(normalized_ticket_keys)
    if dimensions > 1:
        raise RegistryError("ambiguous_query", "choose one binding_id, run_key, ticket_key, or ticket_keys filter")
    if include is not None:
        for index, field in enumerate(include):
            _text(field, field=f"include[{index}]", max_len=128)
    detail_requested = detail
    if include is not None:
        detail_requested = detail_requested or any(field in {"detail", "summary", "full"} for field in include)
    connection = _open_db(db_path)
    try:
        _ensure_schema(connection)
        if binding_id is not None:
            rows = connection.execute("SELECT * FROM bindings WHERE binding_id = ?", (binding_id,)).fetchall()
        elif run_key is not None:
            rows = connection.execute(
                "SELECT b.* FROM run_index i JOIN bindings b ON b.binding_id = i.binding_id "
                "WHERE i.run_key = ? ORDER BY b.binding_id, i.run_role",
                (run_key,),
            ).fetchall()
        elif ticket_key is not None:
            rows = connection.execute(
                "SELECT * FROM bindings WHERE ticket_key = ? ORDER BY binding_id", (ticket_key,)
            ).fetchall()
        elif normalized_ticket_keys:
            placeholders = ",".join("?" for _ in normalized_ticket_keys)
            rows = connection.execute(
                f"SELECT * FROM bindings WHERE ticket_key IN ({placeholders}) ORDER BY ticket_key, binding_id",
                tuple(normalized_ticket_keys),
            ).fetchall()
        else:
            rows = connection.execute("SELECT * FROM bindings ORDER BY binding_id").fetchall()
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            compact = _row_to_compact(row)
            key = compact["binding_id"]
            if key not in seen:
                seen.add(key)
                result.append(compact)
        if detail_requested:
            return [_load_verified_detail(item) for item in result]
        return result
    finally:
        connection.close()


query = query_registry


def _row_to_compact(row: Mapping[str, Any]) -> dict[str, Any]:
    """Decode one row into the closed, body-free query shape."""

    return {
        "schema": SCHEMA,
        "binding_id": row["binding_id"],
        "ticket_key": row["ticket_key"],
        "producer_run_key": row["producer_run_key"],
        "subject_run_key": row["subject_run_key"],
        # Compact queries expose the same explicit identity aliases retained
        # by summary artifacts; the run-key columns remain for compatibility.
        "producer_run_id": row["producer_run_key"],
        "subject_run_id": row["subject_run_key"],
        "binding_status": row["binding_status"],
        "subject_kind": row["subject_kind"],
        "evidence_tiers": json.loads(row["evidence_tiers_json"]),
        "evidence_status_flags": json.loads(row["evidence_status_flags_json"]),
        "claim_status_counts": json.loads(row["claim_status_counts_json"]),
        "claim_count": int(row["claim_count"]),
        "artifact_count": int(row["artifact_count"]),
        "source_count": int(row["source_count"]),
        "test_count": int(row["test_count"]),
        "graph_present": bool(row["graph_present"]),
        "timing_known": bool(row["timing_known"]),
        "timing_unknown": bool(row["timing_unknown"]),
        "timing_unknown_reason_codes": json.loads(row["timing_unknown_reason_codes_json"]),
        "usage_known": bool(row["usage_known"]),
        "usage_unknown": bool(row["usage_unknown"]),
        "usage_unknown_reason_codes": json.loads(row["usage_unknown_reason_codes_json"]),
        "test_aggregate": json.loads(row["test_aggregate_json"]),
        "unknown_reason_codes": json.loads(row["unknown_reason_codes_json"]),
        "summary_path": row["summary_path"],
        "summary_sha256": row["summary_sha256"],
    }


def _load_verified_detail(compact: Mapping[str, Any]) -> dict[str, Any]:
    """Read exactly one summary artifact after path, hash, and schema checks."""

    raw_path = compact.get("summary_path")
    if not isinstance(raw_path, str) or not raw_path:
        raise RegistryError("summary_artifact_missing", "compact row has no summary artifact path", binding_id=compact.get("binding_id"))
    path = Path(raw_path)
    try:
        if path.is_symlink() or not path.is_file():
            raise RegistryError("summary_artifact_missing", "summary artifact is not a regular file", path=raw_path)
        raw = path.read_bytes()
    except OSError as exc:
        raise RegistryError("summary_artifact_read_failed", f"cannot read summary artifact {raw_path}", path=raw_path) from exc
    digest = hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest()
    # Summary files are canonical JSON emitted by this module.  Hash the
    # validated canonical object as the authoritative digest, while accepting
    # insignificant trailing whitespace in the artifact file.
    try:
        value = _parse_json_bytes(raw.rstrip(b"\r\n"), path=raw_path)
    except RegistryError as exc:
        raise RegistryError("summary_artifact_invalid", "summary artifact is not valid JSON", path=raw_path, reason_code=exc.code) from exc
    summary = validate_summary(value)
    canonical_digest = summary_sha256(summary)
    if compact.get("summary_sha256") != canonical_digest:
        raise RegistryError(
            "summary_artifact_hash_mismatch",
            "summary artifact hash does not match compact projection",
            binding_id=compact.get("binding_id"),
            path=raw_path,
        )
    if summary.get("binding_id") != compact.get("binding_id"):
        raise RegistryError("summary_artifact_identity_mismatch", "summary artifact binding_id differs from index", path=raw_path)
    # Return a copy with explicit custody metadata; the underlying summary
    # remains the detail body and is never stored in SQLite.
    result = _safe_copy(summary)
    if not isinstance(result, dict):  # pragma: no cover
        raise RegistryError("summary_artifact_invalid", "summary artifact must be an object", path=raw_path)
    result["summary_path"] = raw_path
    result["summary_sha256"] = canonical_digest
    return result


def query_registry_detail(
    db_path: str | os.PathLike[str],
    *,
    binding_id: str,
) -> dict[str, Any]:
    """Explicit verified detail retrieval for one indexed binding."""

    matches = query_registry(db_path, binding_id=binding_id, detail=True)
    if not matches:
        raise RegistryError("binding_not_found", "binding_id is not indexed", binding_id=binding_id)
    return matches[0]


get_registry_detail = query_registry_detail


def benchmark_registry(
    record_count: int = 10_000,
    root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Run a provider-free compact projection benchmark.

    The helper creates sanitized synthetic summary artifacts in a temporary
    directory when ``root`` is omitted, indexes them, repeats the unchanged
    pass, and measures exact/all compact queries.  It never opens source
    locators and returns measurements only; callers own a supplied ``root``.
    """

    if isinstance(record_count, bool) or not isinstance(record_count, int) or not 1 <= record_count <= 100_000:
        raise RegistryError("invalid_benchmark_count", "record_count must be an integer from 1 through 100000")
    owned_temp: tempfile.TemporaryDirectory[str] | None = None
    if root is None:
        owned_temp = tempfile.TemporaryDirectory(prefix="orch-dork-run-registry-benchmark-")
        benchmark_root = Path(owned_temp.name)
    else:
        benchmark_root = Path(root)
        benchmark_root.mkdir(parents=True, exist_ok=True)
    try:
        summaries_dir = benchmark_root / "summaries"
        summaries_dir.mkdir(parents=True, exist_ok=True)
        base = {
            "schema": SCHEMA,
            "binding_id": "benchmark-00000000",
            "ticket_key": "benchmark",
            "producer_run": {"run_key": "benchmark-producer-00000000", "kind": "synthetic"},
            "subject_run": {"run_key": "benchmark-subject-00000000", "kind": "synthetic"},
            "observation": {"observation_key": "benchmark-observation", "result": "bound"},
            "subject_kind": "synthetic",
            "binding_status": "BOUND",
            "artifacts": [],
            "sources": [],
            "claims": [],
            "timing": {"status": "unknown", "unknown_reason": "benchmark has no runtime clock"},
            "usage": {},
            "tests": [],
            "unknown_reasons": [],
        }
        for index in range(record_count):
            summary = dict(base)
            suffix = f"{index:08d}"
            summary["binding_id"] = f"benchmark-{suffix}"
            summary["producer_run"] = {"run_key": f"benchmark-producer-{suffix}", "kind": "synthetic"}
            summary["subject_run"] = {"run_key": f"benchmark-subject-{suffix}", "kind": "synthetic"}
            (summaries_dir / f"{summary['binding_id']}.json").write_text(_canonical_json(summary) + "\n", encoding="utf-8")
        db_path = benchmark_root / "registry.sqlite"
        start = time.perf_counter()
        initial = index_summaries(db_path, [summaries_dir])
        initial_seconds = time.perf_counter() - start
        start = time.perf_counter()
        incremental = index_summaries(db_path, [summaries_dir])
        incremental_seconds = time.perf_counter() - start
        exact_seconds: list[float] = []
        all_seconds: list[float] = []
        exact_count = 0
        all_count = 0
        for _ in range(3):
            start = time.perf_counter()
            exact_count = len(query_registry(db_path, binding_id=f"benchmark-{record_count - 1:08d}"))
            exact_seconds.append(time.perf_counter() - start)
            start = time.perf_counter()
            all_count = len(query_registry(db_path))
            all_seconds.append(time.perf_counter() - start)
        database_bytes = db_path.stat().st_size
        result = {
            "ok": True,
            "record_count": record_count,
            "database_bytes": database_bytes,
            "database_mib": database_bytes / (1024 * 1024),
            "initial_index_seconds": initial_seconds,
            "incremental_noop_seconds": incremental_seconds,
            "exact_query_seconds": min(exact_seconds),
            "exact_query_median_seconds": statistics.median(exact_seconds),
            "all_query_seconds": min(all_seconds),
            "all_query_median_seconds": statistics.median(all_seconds),
            "initial_indexed": initial["indexed"],
            "incremental_unchanged": incremental["unchanged"],
            "exact_count": exact_count,
            "all_count": all_count,
            "database_ceiling_bytes": 50 * 1024 * 1024,
        }
        if database_bytes > result["database_ceiling_bytes"]:
            raise RegistryError("benchmark_storage_exceeded", "compact registry exceeded 50 MiB ceiling", **result)
        return result
    finally:
        if owned_temp is not None:
            owned_temp.cleanup()


def _cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="orch_dork_run_registry")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate summary or source catalog JSON")
    validate.add_argument("--summary", action="append", default=[])
    validate.add_argument("--catalog")
    build = sub.add_parser("build", help="build summaries from a source catalog")
    build.add_argument("--catalog", required=True)
    build.add_argument("--output-dir", required=True)
    index = sub.add_parser("index", help="incrementally index summaries")
    index.add_argument("--db", required=True)
    index.add_argument("summaries", nargs="+")
    query_parser = sub.add_parser("query", help="query compact records")
    query_parser.add_argument("--db", required=True)
    query_parser.add_argument("--binding-id")
    query_parser.add_argument("--run-key")
    query_parser.add_argument("--ticket-key")
    query_parser.add_argument("--ticket-keys", nargs="+")
    query_parser.add_argument("--detail", action="store_true", help="verify and load referenced summary artifact(s)")
    rebuild_parser = sub.add_parser("rebuild", help="rebuild the projection from summaries")
    rebuild_parser.add_argument("--db", required=True)
    rebuild_parser.add_argument("summaries", nargs="+")
    governance_rebuild = sub.add_parser("rebuild-governance", help="rebuild governance projections from reports")
    governance_rebuild.add_argument("--db", required=True)
    governance_rebuild.add_argument("reports", nargs="+")
    governance_query = sub.add_parser("query-governance", help="query compact governance projections")
    governance_query.add_argument("--db", required=True)
    governance_query.add_argument("--kind")
    governance_query.add_argument("--outcome-id")
    benchmark_parser = sub.add_parser("benchmark", help="run the provider-free compact projection benchmark")
    benchmark_parser.add_argument("--records", type=int, default=10_000)
    benchmark_parser.add_argument("--root")
    return parser


def _cli_validate(args: argparse.Namespace) -> dict[str, Any]:
    if bool(args.catalog) == bool(args.summary):
        raise RegistryError("invalid_arguments", "provide exactly one of --catalog or --summary")
    if args.catalog:
        catalog = _load_json(Path(args.catalog))
        summaries = validate_source_catalog(catalog)
        return {
            "ok": True,
            "schema": SOURCE_CATALOG_SCHEMA,
            "count": len(summaries),
            "summaries": [{"binding_id": item["binding_id"], "sha256": summary_sha256(item)} for item in summaries],
        }
    loaded = _load_summary_files(args.summary)
    return {
        "ok": True,
        "schema": SCHEMA,
        "count": len(loaded),
        "summaries": [{"binding_id": summary["binding_id"], "sha256": digest, "path": str(path)} for path, summary, digest in loaded],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = _cli_parser()
    try:
        args = parser.parse_args(argv)
        if args.command == "validate":
            result = _cli_validate(args)
        elif args.command == "build":
            result = build_from_catalog(args.catalog, args.output_dir)
        elif args.command == "index":
            result = index_summaries(args.db, args.summaries)
        elif args.command == "query":
            result = {
                "ok": True,
                "schema": SCHEMA,
                "records": query_registry(
                    args.db,
                    binding_id=args.binding_id,
                    run_key=args.run_key,
                    ticket_key=args.ticket_key,
                    ticket_keys=args.ticket_keys,
                    detail=args.detail,
                ),
            }
        elif args.command == "rebuild":
            result = rebuild_registry(args.db, args.summaries)
        elif args.command == "rebuild-governance":
            result = rebuild_governance_projection(args.db, args.reports)
        elif args.command == "query-governance":
            result = {
                "ok": True,
                "schema": GOVERNANCE_PROJECTION_SCHEMA,
                "records": query_governance_projection(
                    args.db, kind=args.kind, outcome_id=args.outcome_id
                ),
            }
        elif args.command == "benchmark":
            result = benchmark_registry(args.records, args.root)
        else:  # pragma: no cover - argparse enforces command choices
            raise RegistryError("invalid_arguments", "unknown command")
    except RegistryError as exc:
        print(_canonical_json({"ok": False, "error": exc.as_dict()}))
        return 2
    except (OSError, sqlite3.Error) as exc:
        print(_canonical_json({"ok": False, "error": {"code": "io_error", "message": str(exc)}}))
        return 2
    print(_canonical_json(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
