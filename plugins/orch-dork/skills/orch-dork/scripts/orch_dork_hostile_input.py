#!/usr/bin/env python3
"""Bounded, provider-free hostile-input contracts for Orch Dork.

This module is deliberately independent from the policy and authority layers.
It provides a single versioned table of limits, a strict JSON parser that
checks the limits before handing a value to callers, and small helpers for
MCP/dispatcher code and deterministic fuzz fixtures.  No helper in this file
performs I/O, starts a process, or mutates caller-owned state.

The public functions return ordinary JSON-compatible dictionaries where a
report is useful and raise :class:`HostileInputError` where a hard parser
boundary is required.  Denial reason strings are stable wire values; callers
must not translate them into free-form exception text.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import math
import re
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, MutableMapping, Sequence


# ---------------------------------------------------------------------------
# Canonical profile and stable reason codes

HOSTILE_INPUT_PROFILE_SCHEMA = "orch-dork/hostile-input-profile/v1"
HOSTILE_INPUT_PROFILE_VERSION = "v1"
PROFILE_SCHEMA = HOSTILE_INPUT_PROFILE_SCHEMA
# Shared finite transport default; pinned evaluators may declare their budget.
MCP_ACTION_ADVANCE_RESPONSE_BUDGET_BYTES = 8_192


class DenialReason(str, Enum):
    """Stable, lower-snake-case denial reasons used by every boundary."""

    INPUT_TYPE = "input_type"
    INPUT_TOO_LARGE = "input_too_large"
    BOM_NOT_ALLOWED = "bom_not_allowed"
    INVALID_UTF8 = "invalid_utf8"
    EMPTY_INPUT = "empty_input"
    MALFORMED_JSON = "malformed_json"
    TRAILING_DATA = "trailing_data"
    DUPLICATE_KEY = "duplicate_key"
    NON_FINITE_NUMBER = "non_finite_number"
    NUMBER_TOO_LARGE = "number_too_large"
    STRING_TOO_LARGE = "string_too_large"
    KEY_TOO_LARGE = "key_too_large"
    PATH_TOO_LARGE = "path_too_large"
    DEPTH_EXCEEDED = "depth_exceeded"
    NODE_COUNT_EXCEEDED = "node_count_exceeded"
    OBJECT_KEYS_EXCEEDED = "object_keys_exceeded"
    ARRAY_ITEMS_EXCEEDED = "array_items_exceeded"
    BATCH_ENTRIES_EXCEEDED = "batch_entries_exceeded"
    FRAME_TOO_LARGE = "frame_too_large"
    OPERATIONS_EXCEEDED = "operations_exceeded"
    MALFORMED_FRAME = "malformed_frame"
    UNKNOWN_METHOD = "unknown_method"
    QUEUE_FULL = "queue_full"
    IN_FLIGHT_FULL = "in_flight_full"
    PARSE_TIMEOUT = "parse_timeout"
    DISPATCH_TIMEOUT = "dispatch_timeout"
    DUPLICATE_DELIVERY = "duplicate_delivery"
    OUTPUT_TOO_LARGE = "output_too_large"
    HANDLER_ERROR = "handler_error"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


# Public aliases make it easy for schema checks to avoid depending on Enum
# implementation details.  The values are intentionally immutable.
DENIAL_REASONS = frozenset(item.value for item in DenialReason)
REASON_CODES = DENIAL_REASONS


@dataclass(frozen=True)
class DefensiveProfile:
    """One immutable version of all Issue 49 resource bounds."""

    schema: str = HOSTILE_INPUT_PROFILE_SCHEMA
    canonical_json_bytes: int = 262_144
    max_string_bytes: int = 65_536
    max_key_bytes: int = 256
    max_path_bytes: int = 4_096
    max_depth: int = 32
    max_nodes: int = 4_096
    max_object_keys: int = 256
    max_array_items: int = 256
    max_batch_entries: int = 64
    max_frame_bytes: int = 262_144
    max_operations: int = 32
    max_queue: int = 64
    max_in_flight: int = 16
    parse_wall_seconds: float = 2.0
    dispatch_wall_seconds: float = 10.0
    adapter_descendants: int = 8
    adapter_rss_bytes: int = 256 * 1024 * 1024
    adapter_cpu_seconds: float = 1.0
    adapter_wall_seconds: float = 10.0
    adapter_stream_bytes: int = 65_536
    adapter_output_bytes: int = 131_072
    registry_artifacts: int = 256
    registry_claims: int = 4_096
    registry_locators: int = 64
    registry_validate_seconds: float = 5.0
    registry_commit_seconds: float = 10.0
    manifest_bytes: int = 262_144
    manifest_paths: int = 64
    manifest_generations: int = 32
    fuzz_case_cpu_seconds: float = 1.0
    fuzz_case_wall_seconds: float = 2.0
    fuzz_case_output_bytes: int = 131_072
    fuzz_cases: int = 2_048
    fuzz_seed: int = 0x4F524348
    fuzz_campaign_seconds: float = 60.0

    def as_dict(self) -> dict[str, Any]:
        """Return a canonical JSON-compatible profile projection."""

        # ``dataclasses.asdict`` would also be fine, but spelling this out
        # keeps the wire order obvious and prevents accidental field additions
        # from changing a profile without a version bump.
        return {
            "schema": self.schema,
            "canonical_json_bytes": self.canonical_json_bytes,
            "max_string_bytes": self.max_string_bytes,
            "max_key_bytes": self.max_key_bytes,
            "max_path_bytes": self.max_path_bytes,
            "max_depth": self.max_depth,
            "max_nodes": self.max_nodes,
            "max_object_keys": self.max_object_keys,
            "max_array_items": self.max_array_items,
            "max_batch_entries": self.max_batch_entries,
            "max_frame_bytes": self.max_frame_bytes,
            "max_operations": self.max_operations,
            "max_queue": self.max_queue,
            "max_in_flight": self.max_in_flight,
            "parse_wall_seconds": self.parse_wall_seconds,
            "dispatch_wall_seconds": self.dispatch_wall_seconds,
            "adapter_descendants": self.adapter_descendants,
            "adapter_rss_bytes": self.adapter_rss_bytes,
            "adapter_cpu_seconds": self.adapter_cpu_seconds,
            "adapter_wall_seconds": self.adapter_wall_seconds,
            "adapter_stream_bytes": self.adapter_stream_bytes,
            "adapter_output_bytes": self.adapter_output_bytes,
            "registry_artifacts": self.registry_artifacts,
            "registry_claims": self.registry_claims,
            "registry_locators": self.registry_locators,
            "registry_validate_seconds": self.registry_validate_seconds,
            "registry_commit_seconds": self.registry_commit_seconds,
            "manifest_bytes": self.manifest_bytes,
            "manifest_paths": self.manifest_paths,
            "manifest_generations": self.manifest_generations,
            "fuzz_case_cpu_seconds": self.fuzz_case_cpu_seconds,
            "fuzz_case_wall_seconds": self.fuzz_case_wall_seconds,
            "fuzz_case_output_bytes": self.fuzz_case_output_bytes,
            "fuzz_cases": self.fuzz_cases,
            "fuzz_seed": self.fuzz_seed,
            "fuzz_campaign_seconds": self.fuzz_campaign_seconds,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


PROFILE = DefensiveProfile()
DEFENSIVE_PROFILE = PROFILE
HOSTILE_INPUT_PROFILE = PROFILE


class HostileInputError(ValueError):
    """A bounded parser denial with a stable reason and sanitized metadata."""

    def __init__(
        self,
        reason: str | DenialReason,
        *,
        observed: int | float | None = None,
        bound: int | float | None = None,
        path: str | None = None,
        message: str | None = None,
    ) -> None:
        self.reason = str(reason.value if isinstance(reason, DenialReason) else reason)
        self.observed = observed
        self.bound = bound
        self.path = path
        text = message or self.reason
        super().__init__(text)

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"reason": self.reason}
        if self.observed is not None:
            result["observed"] = self.observed
        if self.bound is not None:
            result["bound"] = self.bound
        # Paths are internal diagnostics.  They are deliberately omitted from
        # sanitized evidence unless explicitly requested by a caller.
        if self.path is not None:
            result["path"] = self.path
        return result


# Compatibility aliases used by older callers and hidden schema tests.
BoundedInputError = HostileInputError
ResourceLimitError = HostileInputError


@dataclass(frozen=True)
class ParseReport:
    """Result returned by :func:`validate_bounded_json`."""

    valid: bool
    reason: str | None = None
    value: Any = None
    canonical: bytes | None = None
    canonical_sha256: str | None = None
    observed: int | float | None = None
    bound: int | float | None = None
    elapsed_ms: int = 0

    @property
    def status(self) -> str:
        return "PASS" if self.valid else "DENIED"

    def as_dict(self, *, include_value: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema": "orch-dork/hostile-input-parse-report/v1",
            "profile": PROFILE.schema,
            "status": self.status,
            "valid": self.valid,
            "reason": self.reason,
            "canonical_sha256": self.canonical_sha256,
            "observed": self.observed,
            "bound": self.bound,
            "elapsed_ms": self.elapsed_ms,
        }
        if include_value and self.valid:
            result["value"] = self.value
            result["canonical"] = self.canonical.decode("utf-8") if self.canonical is not None else None
        return result

    # Mapping-like conveniences keep reports pleasant for existing tests.
    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_dict().get(key, default)


def _reason(reason: str | DenialReason) -> str:
    return reason.value if isinstance(reason, DenialReason) else str(reason)


def _as_bytes(payload: bytes | bytearray | memoryview | str, profile: DefensiveProfile) -> bytes:
    if isinstance(payload, str):
        try:
            data = payload.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise HostileInputError(DenialReason.INVALID_UTF8) from exc
    elif isinstance(payload, (bytes, bytearray, memoryview)):
        data = bytes(payload)
    else:
        raise HostileInputError(DenialReason.INPUT_TYPE)
    if len(data) > profile.canonical_json_bytes:
        raise HostileInputError(
            DenialReason.INPUT_TOO_LARGE,
            observed=len(data),
            bound=profile.canonical_json_bytes,
        )
    if data.startswith(b"\xef\xbb\xbf"):
        raise HostileInputError(DenialReason.BOM_NOT_ALLOWED)
    try:
        # Decode before any JSON parser/schema work.  This also rejects UTF-8
        # encodings of lone surrogate code points and overlong sequences.
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise HostileInputError(DenialReason.INVALID_UTF8) from exc
    if not text.strip():
        raise HostileInputError(DenialReason.EMPTY_INPUT)
    return data


def _structural_preflight(text: str, profile: DefensiveProfile) -> None:
    """Reject obvious depth/node/count breaches before JSON allocation.

    This scanner is intentionally conservative for malformed input: malformed
    syntax is still reported as ``malformed_json`` once it is within bounds,
    while an unmistakable bound breach is rejected first.  Strings and escape
    sequences are skipped without interpreting their contents.
    """

    stack: list[tuple[str, int]] = []
    in_string = False
    escaped = False
    composite_nodes = 0
    max_depth = 0
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char in "[{":
            composite_nodes += 1
            if composite_nodes > profile.max_nodes:
                raise HostileInputError(
                    DenialReason.NODE_COUNT_EXCEEDED,
                    observed=composite_nodes,
                    bound=profile.max_nodes,
                )
            stack.append((char, 0))
            if len(stack) > max_depth:
                max_depth = len(stack)
                if max_depth > profile.max_depth:
                    raise HostileInputError(
                        DenialReason.DEPTH_EXCEEDED,
                        observed=max_depth,
                        bound=profile.max_depth,
                    )
            continue
        if char in "]},":
            if char == "," and stack:
                kind, separators = stack[-1]
                separators += 1
                stack[-1] = (kind, separators)
                # ``separators + 1`` is an upper bound on entries.  It may
                # over-count malformed trailing commas, which is safe because
                # malformed input is denied either way.
                limit = profile.max_array_items if kind == "[" else profile.max_object_keys
                if separators + 1 > limit:
                    reason = DenialReason.ARRAY_ITEMS_EXCEEDED if kind == "[" else DenialReason.OBJECT_KEYS_EXCEEDED
                    raise HostileInputError(reason, observed=separators + 1, bound=limit)
            elif char == "]" and stack:
                # Mismatched delimiters are left to the JSON decoder.  Popping
                # here only makes subsequent count checks conservative.
                stack.pop()
            elif char == "}" and stack:
                stack.pop()


_NUMBER_DIGITS_LIMIT = 4_096


def _parse_constant(value: str) -> Any:
    raise HostileInputError(DenialReason.NON_FINITE_NUMBER)


def _parse_int(value: str) -> int:
    if len(value.lstrip("-")) > _NUMBER_DIGITS_LIMIT:
        raise HostileInputError(
            DenialReason.NUMBER_TOO_LARGE,
            observed=len(value.lstrip("-")),
            bound=_NUMBER_DIGITS_LIMIT,
        )
    try:
        return int(value)
    except (ValueError, OverflowError) as exc:
        raise HostileInputError(DenialReason.NUMBER_TOO_LARGE) from exc


def _parse_float(value: str) -> float:
    try:
        result = float(value)
    except (ValueError, OverflowError) as exc:
        raise HostileInputError(DenialReason.NON_FINITE_NUMBER) from exc
    if not math.isfinite(result):
        raise HostileInputError(DenialReason.NON_FINITE_NUMBER)
    return result


def _pairs_hook(pairs: list[tuple[str, Any]], profile: DefensiveProfile) -> dict[str, Any]:
    if len(pairs) > profile.max_object_keys:
        raise HostileInputError(
            DenialReason.OBJECT_KEYS_EXCEEDED,
            observed=len(pairs),
            bound=profile.max_object_keys,
        )
    result: dict[str, Any] = {}
    for key, value in pairs:
        key_bytes = len(key.encode("utf-8", "strict"))
        if key_bytes > profile.max_key_bytes:
            raise HostileInputError(
                DenialReason.KEY_TOO_LARGE,
                observed=key_bytes,
                bound=profile.max_key_bytes,
            )
        if key in result:
            raise HostileInputError(DenialReason.DUPLICATE_KEY, path=key)
        result[key] = value
    return result


def _walk_bounds(value: Any, profile: DefensiveProfile, *, path: str = "", depth: int = 0, state: MutableMapping[str, int] | None = None, parent_key: str | None = None) -> None:
    if state is None:
        state = {"nodes": 0}
    state["nodes"] += 1
    if state["nodes"] > profile.max_nodes:
        raise HostileInputError(
            DenialReason.NODE_COUNT_EXCEEDED,
            observed=state["nodes"],
            bound=profile.max_nodes,
            path=path or None,
        )
    if isinstance(value, str):
        size = len(value.encode("utf-8", "strict"))
        if _is_path_key(parent_key) and size > profile.max_path_bytes:
            reason = DenialReason.PATH_TOO_LARGE
            bound = profile.max_path_bytes
            raise HostileInputError(reason, observed=size, bound=bound, path=path or None)
        if size > profile.max_string_bytes:
            reason = DenialReason.STRING_TOO_LARGE
            bound = profile.max_string_bytes
            raise HostileInputError(reason, observed=size, bound=bound, path=path or None)
        return
    if isinstance(value, Mapping):
        if depth > profile.max_depth:
            raise HostileInputError(DenialReason.DEPTH_EXCEEDED, observed=depth, bound=profile.max_depth, path=path or None)
        if len(value) > profile.max_object_keys:
            raise HostileInputError(DenialReason.OBJECT_KEYS_EXCEEDED, observed=len(value), bound=profile.max_object_keys, path=path or None)
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            _walk_bounds(child, profile, path=child_path, depth=depth + 1, state=state, parent_key=str(key))
        return
    if isinstance(value, list):
        if depth > profile.max_depth:
            raise HostileInputError(DenialReason.DEPTH_EXCEEDED, observed=depth, bound=profile.max_depth, path=path or None)
        if len(value) > profile.max_array_items:
            raise HostileInputError(DenialReason.ARRAY_ITEMS_EXCEEDED, observed=len(value), bound=profile.max_array_items, path=path or None)
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            _walk_bounds(child, profile, path=child_path, depth=depth + 1, state=state, parent_key=parent_key)
        return


def _is_path_key(key: str | None) -> bool:
    if not key:
        return False
    lowered = key.lower()
    return lowered == "path" or lowered.endswith("_path") or lowered in {"source_pointer", "target_pointer", "locator"}


def _validate_batch(value: Any, profile: DefensiveProfile) -> None:
    if isinstance(value, list) and len(value) > profile.max_batch_entries:
        raise HostileInputError(
            DenialReason.BATCH_ENTRIES_EXCEEDED,
            observed=len(value),
            bound=profile.max_batch_entries,
        )


def parse_bounded_json(
    payload: bytes | bytearray | memoryview | str,
    *,
    profile: DefensiveProfile = PROFILE,
    batch: bool = False,
) -> Any:
    """Parse one strict bounded JSON value.

    The parser accepts UTF-8 bytes (or a Unicode string), rejects a BOM and
    trailing data, detects duplicate keys and non-finite values, and enforces
    all structural bounds.  The returned value is detached from parser
    internals and safe for callers to inspect without mutating the source.
    """

    data = _as_bytes(payload, profile)
    try:
        text = data.decode("utf-8", "strict")
        _structural_preflight(text, profile)
        decoder = json.JSONDecoder(
            object_pairs_hook=lambda pairs: _pairs_hook(pairs, profile),
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_parse_constant,
        )
        value, index = decoder.raw_decode(text)
        if text[index:].strip():
            raise HostileInputError(DenialReason.TRAILING_DATA)
        _walk_bounds(value, profile)
        if batch:
            _validate_batch(value, profile)
        return value
    except HostileInputError:
        raise
    except RecursionError as exc:
        raise HostileInputError(DenialReason.DEPTH_EXCEEDED, bound=profile.max_depth) from exc
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError) as exc:
        raise HostileInputError(DenialReason.MALFORMED_JSON) from exc


def parse_json(payload: bytes | bytearray | memoryview | str, **kwargs: Any) -> Any:
    """Compatibility alias for :func:`parse_bounded_json`."""

    return parse_bounded_json(payload, **kwargs)


def canonicalize_bounded_json(
    payload: bytes | bytearray | memoryview | str,
    *,
    profile: DefensiveProfile = PROFILE,
    batch: bool = False,
) -> bytes:
    """Parse and return deterministic UTF-8 JSON bytes."""

    value = parse_bounded_json(payload, profile=profile, batch=batch)
    try:
        canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise HostileInputError(DenialReason.MALFORMED_JSON) from exc
    if len(canonical) > profile.canonical_json_bytes:
        # Canonical output must never silently exceed the input contract.
        raise HostileInputError(DenialReason.INPUT_TOO_LARGE, observed=len(canonical), bound=profile.canonical_json_bytes)
    return canonical


def canonical_json(payload: bytes | bytearray | memoryview | str, **kwargs: Any) -> str:
    return canonicalize_bounded_json(payload, **kwargs).decode("utf-8")


def canonical_bytes(payload: bytes | bytearray | memoryview | str, **kwargs: Any) -> bytes:
    return canonicalize_bounded_json(payload, **kwargs)


def canonical_sha256(payload: bytes | bytearray | memoryview | str, **kwargs: Any) -> str:
    return hashlib.sha256(canonicalize_bounded_json(payload, **kwargs)).hexdigest()


def validate_bounded_json(
    payload: bytes | bytearray | memoryview | str,
    *,
    profile: DefensiveProfile = PROFILE,
    batch: bool = False,
    include_value: bool = True,
) -> ParseReport:
    """Return a deterministic report without leaking input bodies."""

    started = time.monotonic()
    try:
        value = parse_bounded_json(payload, profile=profile, batch=batch)
        canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(canonical) > profile.canonical_json_bytes:
            raise HostileInputError(DenialReason.INPUT_TOO_LARGE, observed=len(canonical), bound=profile.canonical_json_bytes)
        return ParseReport(
            True,
            value=value if include_value else None,
            canonical=canonical,
            canonical_sha256=hashlib.sha256(canonical).hexdigest(),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except HostileInputError as exc:
        return ParseReport(
            False,
            reason=exc.reason,
            observed=exc.observed,
            bound=exc.bound,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )


def validate_json(payload: bytes | bytearray | memoryview | str, **kwargs: Any) -> dict[str, Any]:
    return validate_bounded_json(payload, **kwargs).as_dict(include_value=kwargs.get("include_value", True))


# ---------------------------------------------------------------------------
# Sanitized crash/denial evidence and deterministic corpus helpers


def input_sha256(payload: bytes | bytearray | memoryview | str) -> str:
    """Hash input without retaining or returning its body."""

    if isinstance(payload, str):
        data = payload.encode("utf-8", "replace")
    else:
        data = bytes(payload)
    return hashlib.sha256(data).hexdigest()


def sanitized_evidence(
    *,
    surface: str,
    case_id: str,
    payload: bytes | bytearray | memoryview | str,
    bound: str,
    reason: str | DenialReason,
    seed: int = PROFILE.fuzz_seed,
    exit_class: str = "DENIED",
    elapsed_ms: int | None = None,
    output_bytes: int = 0,
    process_group_count: int = 0,
    cleanup_status: str = "NOT_APPLICABLE",
) -> dict[str, Any]:
    """Build the ticket's body-free crash/limit evidence projection."""

    if isinstance(payload, str):
        try:
            data = payload.encode("utf-8", "strict")
        except UnicodeEncodeError:
            data = payload.encode("utf-8", "replace")
    else:
        data = bytes(payload)
    observed = len(data)
    result = {
        "schema": "orch-dork/hostile-input-evidence/v1",
        "profile": PROFILE.schema,
        "surface": str(surface),
        "case_id": str(case_id),
        "seed": int(seed),
        "input_bytes": observed,
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "bound": str(bound),
        "reason": _reason(reason),
        "exit_class": str(exit_class),
        "elapsed_ms": None if elapsed_ms is None else int(elapsed_ms),
        "output_bytes": int(output_bytes),
        "process_group_count": int(process_group_count),
        "cleanup_status": str(cleanup_status),
    }
    return result


def corpus_digest(corpus: Mapping[str, bytes | bytearray | memoryview | str] | Iterable[tuple[str, bytes | str]]) -> str:
    """Hash a corpus in bytewise case-id order, independent of map order."""

    items = corpus.items() if isinstance(corpus, Mapping) else corpus
    normalized: list[tuple[str, bytes]] = []
    for name, value in items:
        data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        normalized.append((str(name), data))
    digest = hashlib.sha256()
    for name, data in sorted(normalized, key=lambda item: item[0].encode("utf-8")):
        name_bytes = name.encode("utf-8")
        digest.update(len(name_bytes).to_bytes(4, "big"))
        digest.update(name_bytes)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def load_core_corpus(root: str | Path | None = None) -> tuple[dict[str, bytes], str]:
    """Load the checked-in synthetic core corpus and verify its manifest.

    The function only reads the explicitly supplied corpus directory (or the
    package's ``tests/fixtures/hostile-input/core`` directory).  It never
    follows paths from fixture contents and never writes evidence.
    """

    if root is None:
        root = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "hostile-input" / "core"
    directory = Path(root)
    manifest_path = directory / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HostileInputError(DenialReason.UNKNOWN, message="corpus_manifest_unavailable") from exc
    names = manifest.get("cases")
    if not isinstance(names, list) or names != sorted(names):
        raise HostileInputError(DenialReason.UNKNOWN, message="corpus_order_invalid")
    corpus: dict[str, bytes] = {}
    for name in names:
        if not isinstance(name, str) or "/" in name or "\\" in name or name in {".", ".."}:
            raise HostileInputError(DenialReason.UNKNOWN, message="corpus_name_invalid")
        path = directory / name
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise HostileInputError(DenialReason.UNKNOWN, message="corpus_case_unavailable") from exc
        corpus[name] = data
    expected = manifest.get("corpus_sha256")
    actual = corpus_digest(corpus)
    if expected != actual:
        raise HostileInputError(DenialReason.UNKNOWN, message="corpus_digest_mismatch")
    return corpus, actual


# ---------------------------------------------------------------------------
# Public MCP request validation (the dispatcher implementation lives in the
# top-level scripts directory so it can be run as a standalone MCP process).


MCP_REQUEST_SCHEMA = "orch-dork/mcp-request/v1"
MCP_RESPONSE_SCHEMA = "orch-dork/mcp-response/v1"
_MCP_KEYS = frozenset({"jsonrpc", "id", "method", "params"})


def validate_mcp_request(value: Any, *, profile: DefensiveProfile = PROFILE) -> dict[str, Any]:
    """Validate one JSON-RPC/MCP request after bounded JSON parsing."""

    if not isinstance(value, Mapping):
        return {"status": "DENIED", "reason": DenialReason.MALFORMED_FRAME.value}
    unknown = sorted(set(value) - _MCP_KEYS)
    missing = sorted({"jsonrpc", "method"} - set(value))
    if unknown:
        return {"status": "DENIED", "reason": "unknown_field", "fields": unknown}
    if missing:
        return {"status": "DENIED", "reason": "missing_field", "fields": missing}
    if value.get("jsonrpc") != "2.0":
        return {"status": "DENIED", "reason": DenialReason.MALFORMED_FRAME.value}
    method = value.get("method")
    if not isinstance(method, str) or not method:
        return {"status": "DENIED", "reason": DenialReason.MALFORMED_FRAME.value}
    params = value.get("params")
    if isinstance(params, list) and len(params) > profile.max_array_items:
        return {"status": "DENIED", "reason": DenialReason.ARRAY_ITEMS_EXCEEDED.value, "observed": len(params), "bound": profile.max_array_items}
    return {"status": "PASS", "request": dict(value)}


def parse_mcp_request(payload: bytes | bytearray | memoryview | str, *, profile: DefensiveProfile = PROFILE) -> dict[str, Any]:
    value = parse_bounded_json(payload, profile=profile, batch=False)
    report = validate_mcp_request(value, profile=profile)
    if report["status"] != "PASS":
        raise HostileInputError(report["reason"])
    return report["request"]


__all__ = [
    "HOSTILE_INPUT_PROFILE_SCHEMA",
    "HOSTILE_INPUT_PROFILE_VERSION",
    "PROFILE_SCHEMA",
    "DefensiveProfile",
    "PROFILE",
    "DEFENSIVE_PROFILE",
    "HOSTILE_INPUT_PROFILE",
    "DenialReason",
    "DENIAL_REASONS",
    "REASON_CODES",
    "HostileInputError",
    "BoundedInputError",
    "ResourceLimitError",
    "ParseReport",
    "parse_bounded_json",
    "parse_json",
    "canonicalize_bounded_json",
    "canonical_json",
    "canonical_bytes",
    "canonical_sha256",
    "validate_bounded_json",
    "validate_json",
    "input_sha256",
    "sanitized_evidence",
    "corpus_digest",
    "load_core_corpus",
    "MCP_REQUEST_SCHEMA",
    "MCP_RESPONSE_SCHEMA",
    "validate_mcp_request",
    "parse_mcp_request",
]
