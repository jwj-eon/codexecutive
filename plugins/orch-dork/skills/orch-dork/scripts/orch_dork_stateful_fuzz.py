#!/usr/bin/env python3
"""Provider-free hostile-input bounds and deterministic stateful campaigns.

The module is intentionally self contained.  It is used by the registry,
project-ground, and maintenance fixtures as a small, deterministic contract;
it does not start a process, contact a provider, read credentials, or infer
authority.  A caller may use a stricter limit, but never a wider one.

The public helpers return plain JSON-safe values so they can be consumed by a
later release-time integration without making this test surface an authority
or mutation gateway.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import random
import re
import time
from typing import Any, Callable, Iterable, Iterator, Mapping, MutableMapping, Sequence


try:
    from orch_dork_hostile_input import (  # type: ignore
        PROFILE as HOSTILE_INPUT_PROFILE,
        HostileInputError as CanonicalHostileInputError,
        parse_bounded_json as canonical_parse_bounded_json,
    )
except ImportError:  # pragma: no cover - standalone source execution
    HOSTILE_INPUT_PROFILE = None
    CanonicalHostileInputError = ValueError  # type: ignore[misc,assignment]
    canonical_parse_bounded_json = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Canonical defensive profile

PROFILE = HOSTILE_INPUT_PROFILE
PROFILE_SCHEMA = PROFILE.schema if PROFILE is not None else "orch-dork/hostile-input-profile/v1"
DEFENSIVE_PROFILE_SCHEMA = PROFILE_SCHEMA
PROFILE_VERSION = PROFILE_SCHEMA
DEFENSIVE_PROFILE_VERSION = PROFILE_VERSION

SEED = PROFILE.fuzz_seed if PROFILE is not None else 0x4F524348
PRNG_SEED = SEED
FUZZ_SEED = SEED

MAX_JSON_BYTES = PROFILE.canonical_json_bytes if PROFILE is not None else 262_144
MAX_STRUCTURED_INPUT_BYTES = MAX_JSON_BYTES
MAX_FRAME_BYTES = PROFILE.max_frame_bytes if PROFILE is not None else MAX_JSON_BYTES
MAX_STRING_BYTES = PROFILE.max_string_bytes if PROFILE is not None else 65_536
MAX_KEY_BYTES = PROFILE.max_key_bytes if PROFILE is not None else 256
MAX_PATH_BYTES = PROFILE.max_path_bytes if PROFILE is not None else 4_096
MAX_NESTING_DEPTH = PROFILE.max_depth if PROFILE is not None else 32
MAX_NODES = PROFILE.max_nodes if PROFILE is not None else 4_096
MAX_KEYS_PER_OBJECT = PROFILE.max_object_keys if PROFILE is not None else 256
MAX_ITEMS_PER_ARRAY = PROFILE.max_array_items if PROFILE is not None else 256
MAX_BATCH_ENTRIES = PROFILE.max_batch_entries if PROFILE is not None else 64

MAX_OPERATIONS = PROFILE.max_operations if PROFILE is not None else 32
MAX_QUEUE = PROFILE.max_queue if PROFILE is not None else 64
MAX_IN_FLIGHT = PROFILE.max_in_flight if PROFILE is not None else 16
PARSE_TIMEOUT_SECONDS = PROFILE.parse_wall_seconds if PROFILE is not None else 2
DISPATCH_TIMEOUT_SECONDS = PROFILE.dispatch_wall_seconds if PROFILE is not None else 10

MAX_RECORDS = PROFILE.registry_artifacts if PROFILE is not None else 256
MAX_ARTIFACT_RECORDS = MAX_RECORDS
MAX_CLAIMS_EDGES = PROFILE.registry_claims if PROFILE is not None else 4_096
MAX_CLAIMS = MAX_CLAIMS_EDGES
MAX_LOCATORS = PROFILE.registry_locators if PROFILE is not None else 64
MAX_SOURCE_LOCATORS = MAX_LOCATORS
REGISTRY_VALIDATION_TIMEOUT_SECONDS = PROFILE.registry_validate_seconds if PROFILE is not None else 5
REGISTRY_COMMIT_TIMEOUT_SECONDS = PROFILE.registry_commit_seconds if PROFILE is not None else 10

MAX_DECLARED_PATHS = PROFILE.manifest_paths if PROFILE is not None else 64
MAX_GENERATIONS = PROFILE.manifest_generations if PROFILE is not None else 32
MAX_TRANSITIONS = MAX_GENERATIONS
MAX_STAGED_OPERATIONS = 1
MAINTENANCE_VALIDATION_TIMEOUT_SECONDS = 5
MAINTENANCE_TRANSACTION_TIMEOUT_SECONDS = 10

MAX_CASE_CPU_SECONDS = PROFILE.fuzz_case_cpu_seconds if PROFILE is not None else 1
MAX_CASE_WALL_SECONDS = PROFILE.fuzz_case_wall_seconds if PROFILE is not None else 2
MAX_CASE_OUTPUT_BYTES = PROFILE.fuzz_case_output_bytes if PROFILE is not None else 131_072
FUZZ_CASE_COUNT = PROFILE.fuzz_cases if PROFILE is not None else 2_048
CAMPAIGN_WALL_SECONDS = PROFILE.fuzz_campaign_seconds if PROFILE is not None else 60

# Names are stable evidence selectors.  Do not put input bodies or paths in a
# reason code: those values are deliberately unsuitable for human approval.
REASON_CODES = frozenset(
    {
        "input:bytes_limit",
        "input:utf8_invalid",
        "input:bom_forbidden",
        "input:duplicate_key",
        "input:malformed_json",
        "input:trailing_data",
        "input:non_finite_number",
        "input:string_limit",
        "input:key_limit",
        "input:path_limit",
        "input:depth_limit",
        "input:nodes_limit",
        "input:object_items_limit",
        "input:array_items_limit",
        "input:batch_limit",
        "registry:records_limit",
        "registry:claims_edges_limit",
        "registry:locators_limit",
        "registry:continuation_required",
        "registry:staged_operation_limit",
        "state:stale_continuation",
        "state:partial_commit_forbidden",
        "state:prior_generation_preserved",
        "state:retry_forbidden",
        "maintenance:manifest_bytes_limit",
        "maintenance:declared_paths_limit",
        "maintenance:generations_limit",
        "maintenance:staged_operation_limit",
        "maintenance:validation_timeout",
        "maintenance:transaction_timeout",
        "maintenance:unknown_state",
        "fuzz:campaign_timeout",
        "fuzz:output_limit",
        "fuzz:crash",
        "fuzz:unknown_cleanup",
    }
)


def _profile_limits() -> dict[str, Any]:
    return {
        "structured_input": {
            "max_bytes": MAX_JSON_BYTES,
            "max_string_bytes": MAX_STRING_BYTES,
            "max_key_bytes": MAX_KEY_BYTES,
            "max_path_bytes": MAX_PATH_BYTES,
            "max_depth": MAX_NESTING_DEPTH,
            "max_nodes": MAX_NODES,
            "max_keys_per_object": MAX_KEYS_PER_OBJECT,
            "max_items_per_array": MAX_ITEMS_PER_ARRAY,
            "max_batch_entries": MAX_BATCH_ENTRIES,
        },
        "dispatcher": {
            "max_frame_bytes": MAX_FRAME_BYTES,
            "max_operations": MAX_OPERATIONS,
            "max_queue": MAX_QUEUE,
            "max_in_flight": MAX_IN_FLIGHT,
            "parse_timeout_seconds": PARSE_TIMEOUT_SECONDS,
            "dispatch_timeout_seconds": DISPATCH_TIMEOUT_SECONDS,
        },
        "registry": {
            "max_records": MAX_RECORDS,
            "max_claims_edges": MAX_CLAIMS_EDGES,
            "max_locators": MAX_LOCATORS,
            "validation_timeout_seconds": REGISTRY_VALIDATION_TIMEOUT_SECONDS,
            "commit_timeout_seconds": REGISTRY_COMMIT_TIMEOUT_SECONDS,
        },
        "maintenance": {
            "max_manifest_bytes": MAX_JSON_BYTES,
            "max_declared_paths": MAX_DECLARED_PATHS,
            "max_generations": MAX_GENERATIONS,
            "max_transitions": MAX_TRANSITIONS,
            "max_staged_operations": MAX_STAGED_OPERATIONS,
            "validation_timeout_seconds": MAINTENANCE_VALIDATION_TIMEOUT_SECONDS,
            "transaction_timeout_seconds": MAINTENANCE_TRANSACTION_TIMEOUT_SECONDS,
        },
        "fuzz": {
            "case_cpu_seconds": MAX_CASE_CPU_SECONDS,
            "case_wall_seconds": MAX_CASE_WALL_SECONDS,
            "case_output_bytes": MAX_CASE_OUTPUT_BYTES,
            "generated_cases": FUZZ_CASE_COUNT,
            "campaign_wall_seconds": CAMPAIGN_WALL_SECONDS,
            "seed": SEED,
        },
    }


LIMITS = _profile_limits()
CANONICAL_LIMITS = LIMITS
RESOURCE_LIMITS = LIMITS
BOUNDS = LIMITS


class StatefulFuzzError(ValueError):
    """A fail-closed, stable hostile-input denial."""

    def __init__(self, reason_code: str, message: str | None = None, **details: Any):
        if reason_code not in REASON_CODES:
            # Keep ad-hoc callers deterministic without allowing an input value
            # to become a diagnostic code.
            reason_code = "fuzz:crash"
        self.reason_code = reason_code
        self.code = reason_code
        self.details = {key: value for key, value in details.items() if key not in {"input", "body", "path", "prompt", "message"}}
        super().__init__(message or reason_code)

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.reason_code, "reason_code": self.reason_code}
        if self.details:
            result["details"] = _safe_json(self.details)
        return result


HostileInputError = StatefulFuzzError
BoundViolation = StatefulFuzzError


def _safe_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {str(key): _safe_json(item) for key, item in value.items() if not _looks_sensitive(str(key))}
    if isinstance(value, (list, tuple)):
        return [_safe_json(item) for item in value]
    return str(type(value).__name__)


_SENSITIVE = re.compile(
    r"(?:prompt|message|body|reasoning|credential|password|secret|token|private|authorization|environment)",
    re.IGNORECASE,
)


def _looks_sensitive(key: str) -> bool:
    return bool(_SENSITIVE.search(key))


def _bytes(value: Any, *, field: str = "input") -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    raise StatefulFuzzError("input:malformed_json", f"{field} must be bytes or text")


class _DuplicateKey(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise StatefulFuzzError("input:non_finite_number", "non-finite JSON number")


def _validate_tree(value: Any, *, batch: bool = False) -> None:
    """Validate an already decoded value without copying or side effects."""

    stack: list[tuple[Any, int, str, bool]] = [(value, 0, "$", False)]
    active: set[int] = set()
    nodes = 0
    while stack:
        current, depth, path, leaving = stack.pop()
        if leaving:
            active.discard(id(current))
            continue
        if depth > MAX_NESTING_DEPTH:
            raise StatefulFuzzError("input:depth_limit", depth=depth, bound=MAX_NESTING_DEPTH)
        if isinstance(current, (dict, list)):
            marker = id(current)
            if marker in active:
                raise StatefulFuzzError("input:malformed_json", "cyclic value")
            active.add(marker)
            stack.append((current, depth, path, True))
            nodes += 1
            if nodes > MAX_NODES:
                raise StatefulFuzzError("input:nodes_limit", observed=nodes, bound=MAX_NODES)
            if isinstance(current, dict):
                if len(current) > MAX_KEYS_PER_OBJECT:
                    raise StatefulFuzzError("input:object_items_limit", observed=len(current), bound=MAX_KEYS_PER_OBJECT)
                for key, child in reversed(list(current.items())):
                    if not isinstance(key, str):
                        raise StatefulFuzzError("input:key_limit", "object key must be text")
                    key_bytes = len(key.encode("utf-8"))
                    if key_bytes > MAX_KEY_BYTES:
                        raise StatefulFuzzError("input:key_limit", observed=key_bytes, bound=MAX_KEY_BYTES)
                    child_path = f"{path}.{key}"
                    if any(part in key.lower() for part in ("path", "locator", "root", "file")):
                        if isinstance(child, str) and len(child.encode("utf-8")) > MAX_PATH_BYTES:
                            raise StatefulFuzzError("input:path_limit", observed=len(child.encode("utf-8")), bound=MAX_PATH_BYTES)
                    stack.append((child, depth + 1, child_path, False))
            else:
                if len(current) > MAX_ITEMS_PER_ARRAY:
                    raise StatefulFuzzError("input:array_items_limit", observed=len(current), bound=MAX_ITEMS_PER_ARRAY)
                for index, child in reversed(list(enumerate(current))):
                    stack.append((child, depth + 1, f"{path}[{index}]", False))
            continue
        if isinstance(current, str):
            encoded = len(current.encode("utf-8"))
            if encoded > MAX_STRING_BYTES:
                raise StatefulFuzzError("input:string_limit", observed=encoded, bound=MAX_STRING_BYTES)
        elif isinstance(current, float) and not math.isfinite(current):
            raise StatefulFuzzError("input:non_finite_number")
    if batch and isinstance(value, list) and len(value) > MAX_BATCH_ENTRIES:
        raise StatefulFuzzError("input:batch_limit", observed=len(value), bound=MAX_BATCH_ENTRIES)


def validate_bounded_value(value: Any, *, batch: bool = False) -> Any:
    """Check an in-memory JSON-shaped value and return it unchanged."""

    _validate_tree(value, batch=batch)
    return value


validate_input = validate_bounded_value


def parse_bounded_json(payload: Any, *, batch: bool = False) -> Any:
    """Parse canonical UTF-8 JSON under the structured-input contract."""

    if canonical_parse_bounded_json is not None:
        try:
            return canonical_parse_bounded_json(payload, profile=PROFILE, batch=batch)
        except CanonicalHostileInputError as exc:
            reason_map = {
                "input_type": "input:malformed_json",
                "input_too_large": "input:bytes_limit",
                "frame_too_large": "input:bytes_limit",
                "bom_not_allowed": "input:bom_forbidden",
                "invalid_utf8": "input:utf8_invalid",
                "empty_input": "input:malformed_json",
                "malformed_json": "input:malformed_json",
                "trailing_data": "input:trailing_data",
                "duplicate_key": "input:duplicate_key",
                "non_finite_number": "input:non_finite_number",
                "number_too_large": "input:malformed_json",
                "string_too_large": "input:string_limit",
                "key_too_large": "input:key_limit",
                "path_too_large": "input:path_limit",
                "depth_exceeded": "input:depth_limit",
                "node_count_exceeded": "input:nodes_limit",
                "object_keys_exceeded": "input:object_items_limit",
                "array_items_exceeded": "input:array_items_limit",
                "batch_entries_exceeded": "input:batch_limit",
            }
            reason = reason_map.get(exc.reason, "input:malformed_json")
            raise StatefulFuzzError(reason, observed=exc.observed, bound=exc.bound) from exc

    raw = _bytes(payload)
    if len(raw) > MAX_JSON_BYTES:
        raise StatefulFuzzError("input:bytes_limit", observed=len(raw), bound=MAX_JSON_BYTES)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise StatefulFuzzError("input:bom_forbidden")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StatefulFuzzError("input:utf8_invalid", observed=len(raw)) from exc
    decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_reject_constant)
    try:
        value, end = decoder.raw_decode(text)
    except _DuplicateKey as exc:
        raise StatefulFuzzError("input:duplicate_key") from exc
    except StatefulFuzzError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise StatefulFuzzError("input:malformed_json") from exc
    if text[end:].strip():
        raise StatefulFuzzError("input:trailing_data")
    _validate_tree(value, batch=batch)
    return value


parse_canonical_json = parse_bounded_json


def canonical_bytes(value: Any, *, batch: bool = False) -> bytes:
    """Validate then serialize canonical JSON bytes under the input bound."""

    _validate_tree(value, batch=batch)
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise StatefulFuzzError("input:malformed_json") from exc
    if len(encoded) > MAX_JSON_BYTES:
        raise StatefulFuzzError("input:bytes_limit", observed=len(encoded), bound=MAX_JSON_BYTES)
    return encoded


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _continuation_token(generation: int, offset: int, digest: str) -> str:
    return hashlib.sha256(f"{PROFILE_SCHEMA}:{generation}:{offset}:{digest}".encode("ascii")).hexdigest()


def continuation_token(*, generation: int, offset: int, digest: str) -> str:
    """Create a deterministic opaque token for an explicitly chunked input."""

    if type(generation) is not int or generation < 0 or type(offset) is not int or offset < 0 or not isinstance(digest, str):
        raise StatefulFuzzError("state:stale_continuation")
    return _continuation_token(generation, offset, digest)


# ---------------------------------------------------------------------------
# Fixed corpus and deterministic generated cases


@dataclass(frozen=True)
class FuzzCase:
    case_id: str
    payload: bytes
    generated: bool = False

    @property
    def input_bytes(self) -> int:
        return len(self.payload)

    @property
    def input_sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def _nested_json(depth: int) -> bytes:
    return ("{" * depth + "\"x\":0" + "}" * depth).encode("ascii")


def _make_corpus() -> tuple[FuzzCase, ...]:
    values: dict[str, bytes] = {
        "empty": b"",
        "truncated": b"{\"x\":",
        "invalid-utf8": b"{\xff}",
        "duplicate-keys": b'{"x":1,"x":2}',
        "unknown-fields": b'{"unknown":true}',
        "max-size": b'"' + (b"a" * (MAX_JSON_BYTES - 2)) + b'"',
        "max-plus-one-size": b" " * (MAX_JSON_BYTES + 1),
        "max-depth": _nested_json(MAX_NESTING_DEPTH),
        "max-plus-one-depth": _nested_json(MAX_NESTING_DEPTH + 1),
        "max-nodes": (b"[" + b"0," * (MAX_NODES - 2) + b"0]"),
        "max-plus-one-nodes": (b"[" + b"0," * (MAX_NODES - 1) + b"0]"),
        "huge-integer": b"{" + b'"n":' + (b"9" * 100_000) + b"}",
        "path-traversal": b'{"path":"../outside"}',
        "symlink-escape": b'{"locator":"/tmp/link"}',
        "malformed-frame": b"frame\x00payload",
        "queue-saturation": b'{"operations":' + b"[0," * 32 + b"0]}",
        "registry-conflict": b'{"binding_status":"CONTRADICTORY","claims":[]}',
        "enrollment-collision": b'{"control":"unknown-entry"}',
        "interrupted-maintenance": b'{"operation":"migrate","staged_operations":2}',
        "trailing-data": b"{}{}",
        "bom": b"\xef\xbb\xbf{}",
        "non-finite": b"{\"x\":NaN}",
    }
    return tuple(FuzzCase(name, payload, False) for name, payload in sorted(values.items(), key=lambda pair: pair[0].encode("utf-8")))


FIXED_CORPUS = _make_corpus()
CORPUS = FIXED_CORPUS


def corpus_manifest(corpus: Iterable[FuzzCase] = FIXED_CORPUS) -> list[dict[str, Any]]:
    rows = [
        {"case_id": case.case_id, "input_bytes": case.input_bytes, "input_sha256": case.input_sha256}
        for case in corpus
    ]
    return sorted(rows, key=lambda row: row["case_id"].encode("utf-8"))


CORPUS_MANIFEST = corpus_manifest()
CORPUS_DIGEST = hashlib.sha256(json.dumps(CORPUS_MANIFEST, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
FIXED_CORPUS_DIGEST = CORPUS_DIGEST


def fixed_corpus() -> tuple[FuzzCase, ...]:
    return FIXED_CORPUS


def _generated_payload(rng: random.Random, index: int) -> bytes:
    choice = index % 8
    if choice == 0:
        value = {"operation": rng.choice(("inspect", "query", "rebuild")), "index": index, "ok": True}
    elif choice == 1:
        value = [rng.randrange(0, 1_000_000) for _ in range(rng.randrange(0, 8))]
    elif choice == 2:
        value = {"path": "fixture/" + str(rng.randrange(0, 1000)), "generation": rng.randrange(0, 40)}
    elif choice == 3:
        # Deliberately malformed JSON; the parser must return one stable denial.
        return b"{\"case\":" + str(index).encode("ascii")
    elif choice == 4:
        value = {"claims": [{"name": f"c{rng.randrange(0, 16)}", "value": rng.randrange(0, 4)}]}
    elif choice == 5:
        value = {"locator": "fixture:" + str(rng.randrange(0, 1000)), "sha256": "0" * 64}
    elif choice == 6:
        value = {"depth": {"value": [index % 3, index % 5]}}
    else:
        value = {"unknown": bool(rng.randrange(2)), "seed": SEED}
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generated_cases(count: int = FUZZ_CASE_COUNT, *, seed: int = SEED) -> Iterator[FuzzCase]:
    if type(count) is not int or count < 0 or count > FUZZ_CASE_COUNT:
        raise StatefulFuzzError("fuzz:campaign_timeout", "generated case count exceeds canonical campaign")
    if type(seed) is not int or seed < 0:
        raise StatefulFuzzError("fuzz:crash", "seed must be a non-negative integer")
    rng = random.Random(seed)
    for index in range(count):
        payload = _generated_payload(rng, index)
        yield FuzzCase(f"generated-{index:04d}", payload, True)


# ---------------------------------------------------------------------------
# Sanitized evidence and campaign runner


def sanitize_failure_evidence(
    *,
    surface: str,
    case_id: str,
    seed: int = SEED,
    input_bytes: int = 0,
    input_sha256: str | None = None,
    bound_name: str = "unknown",
    reason_code: str = "fuzz:crash",
    exit_class: str = "unknown",
    elapsed_ms: float | None = None,
    output_bytes: int = 0,
    process_group_count: int = 0,
    cleanup_status: str = "not_applicable",
) -> dict[str, Any]:
    """Return the only crash/limit evidence shape permitted by Issue 49."""

    if not isinstance(surface, str) or not surface or _looks_sensitive(surface):
        surface = "unknown"
    if not isinstance(case_id, str) or not case_id or _looks_sensitive(case_id):
        case_id = "unknown"
    if reason_code not in REASON_CODES:
        reason_code = "fuzz:crash"
    digest = input_sha256 if isinstance(input_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", input_sha256) else None
    return {
        "surface": surface,
        "case_id": case_id,
        "seed": int(seed) if isinstance(seed, int) else SEED,
        "input_bytes": max(0, int(input_bytes)) if isinstance(input_bytes, (int, float)) else 0,
        "input_sha256": digest,
        "bound_name": str(bound_name)[:128],
        "reason_code": reason_code,
        "exit_class": str(exit_class)[:64],
        "elapsed_ms": None if elapsed_ms is None else max(0.0, float(elapsed_ms)),
        "output_bytes": max(0, int(output_bytes)) if isinstance(output_bytes, (int, float)) else 0,
        "process_group_count": max(0, int(process_group_count)) if isinstance(process_group_count, (int, float)) else 0,
        "cleanup_status": str(cleanup_status)[:64],
    }


sanitize_evidence = sanitize_failure_evidence


def _handler_result_size(result: Any) -> int:
    try:
        if isinstance(result, (bytes, bytearray, memoryview, str)):
            return len(result if isinstance(result, (bytes, bytearray, memoryview)) else result.encode("utf-8"))
        return len(json.dumps(_safe_json(result), sort_keys=True, separators=(",", ":")).encode("utf-8"))
    except Exception:
        return MAX_CASE_OUTPUT_BYTES + 1


def run_fuzz_campaign(
    surface: str,
    handler: Callable[[bytes, FuzzCase], Any] | None = None,
    *,
    count: int = FUZZ_CASE_COUNT,
    seed: int = SEED,
    corpus: Iterable[FuzzCase] = FIXED_CORPUS,
) -> dict[str, Any]:
    """Run one bounded deterministic campaign with no retries or entropy."""

    if count != FUZZ_CASE_COUNT:
        raise StatefulFuzzError("fuzz:campaign_timeout", "campaign must run exactly 2048 generated cases")
    started = time.monotonic()
    corpus_cases = sorted(tuple(corpus), key=lambda case: case.case_id.encode("utf-8"))
    cases = corpus_cases + list(generated_cases(count, seed=seed))
    failures: list[dict[str, Any]] = []
    completed = 0
    for case in cases:
        case_started = time.monotonic()
        reason: str | None = None
        exit_class = "completed"
        output_bytes = 0
        try:
            result = handler(case.payload, case) if handler is not None else None
            output_bytes = _handler_result_size(result)
            if output_bytes > MAX_CASE_OUTPUT_BYTES:
                reason = "fuzz:output_limit"
                exit_class = "limit"
        except StatefulFuzzError as exc:
            reason = exc.reason_code
            exit_class = "denied"
        except Exception:
            reason = "fuzz:crash"
            exit_class = "exception"
        elapsed_ms = (time.monotonic() - case_started) * 1000.0
        if elapsed_ms > MAX_CASE_WALL_SECONDS * 1000:
            reason = "fuzz:campaign_timeout"
            exit_class = "timeout"
        if reason is not None:
            failures.append(
                sanitize_failure_evidence(
                    surface=surface,
                    case_id=case.case_id,
                    seed=seed,
                    input_bytes=len(case.payload),
                    input_sha256=case.input_sha256,
                    bound_name="case_wall_or_output",
                    reason_code=reason,
                    exit_class=exit_class,
                    elapsed_ms=elapsed_ms,
                    output_bytes=output_bytes,
                    process_group_count=0,
                    cleanup_status="not_applicable",
                )
            )
        completed += 1
        if time.monotonic() - started > CAMPAIGN_WALL_SECONDS:
            failures.append(
                sanitize_failure_evidence(
                    surface=surface,
                    case_id=case.case_id,
                    seed=seed,
                    input_bytes=len(case.payload),
                    input_sha256=case.input_sha256,
                    bound_name="campaign_wall",
                    reason_code="fuzz:campaign_timeout",
                    exit_class="timeout",
                    elapsed_ms=(time.monotonic() - started) * 1000.0,
                    cleanup_status="not_applicable",
                )
            )
            break
    elapsed_ms = (time.monotonic() - started) * 1000.0
    return {
        "schema": PROFILE_SCHEMA,
        "profile_version": PROFILE_VERSION,
        "surface": surface,
        "seed": seed,
        "corpus_digest": CORPUS_DIGEST,
        "corpus_case_count": len(corpus_cases),
        "generated_case_count": count,
        "case_count": len(corpus_cases) + count,
        "completed_cases": completed,
        "campaign_wall_budget_ms": CAMPAIGN_WALL_SECONDS * 1000,
        # Wall-clock telemetry is intentionally unknown in this replay
        # surface: recording it would make the same seed/corpus produce
        # different evidence on every host.  Process/integration runners may
        # attach their own observed value without changing the campaign hash.
        "elapsed_ms": None,
        "elapsed_known": False,
        "deterministic": True,
        "external_entropy": False,
        "retry_count": 0,
        "fallback_count": 0,
        "failure_count": len(failures),
        "failures": failures,
        "status": "PASS" if not failures and completed == len(cases) else "FAIL",
        "provider_free": True,
    }


run_campaign = run_fuzz_campaign


# ---------------------------------------------------------------------------
# Stateful bounded models.  These models make atomicity/continuation checks
# executable without opening a real registry or enrolled project.


def _count_path_like(value: Any, *, _seen: set[int] | None = None) -> int:
    if _seen is None:
        _seen = set()
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in _seen:
            return 0
        _seen.add(marker)
        total = 0
        for key, child in value.items():
            key_text = str(key).lower()
            if any(part in key_text for part in ("path", "locator", "root", "file")):
                if isinstance(child, str):
                    total += 1
                elif isinstance(child, list):
                    total += sum(isinstance(item, str) for item in child)
            total += _count_path_like(child, _seen=_seen)
        return total
    if isinstance(value, (list, tuple)):
        marker = id(value)
        if marker in _seen:
            return 0
        _seen.add(marker)
        return sum(_count_path_like(item, _seen=_seen) for item in value)
    return 0


def validate_registry_chunk(
    *,
    records: Sequence[Any],
    claims_edges: int = 0,
    locators: Sequence[Any] = (),
    continuation: str | None = None,
    expected_continuation: str | None = None,
) -> dict[str, Any]:
    """Validate one registry/rebuild chunk before any projection mutation."""

    if len(records) > MAX_RECORDS:
        raise StatefulFuzzError("registry:records_limit", observed=len(records), bound=MAX_RECORDS)
    if type(claims_edges) is not int or claims_edges < 0:
        raise StatefulFuzzError("registry:claims_edges_limit")
    if claims_edges > MAX_CLAIMS_EDGES:
        raise StatefulFuzzError("registry:claims_edges_limit", observed=claims_edges, bound=MAX_CLAIMS_EDGES)
    if len(locators) > MAX_LOCATORS:
        raise StatefulFuzzError("registry:locators_limit", observed=len(locators), bound=MAX_LOCATORS)
    if expected_continuation is not None and continuation != expected_continuation:
        raise StatefulFuzzError("state:stale_continuation")
    return {
        "records": len(records),
        "claims_edges": claims_edges,
        "locators": len(locators),
        "continuation": continuation,
        "bounded": True,
    }


@dataclass
class ProjectionSnapshot:
    generation: int = 0
    records: tuple[Any, ...] = ()
    claims_edges: int = 0
    locators: tuple[Any, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "generation": self.generation,
            "record_count": len(self.records),
            "claims_edges": self.claims_edges,
            "locator_count": len(self.locators),
        }


class StatefulRegistryProjection:
    """Small atomic state model for projection/rebuild property tests."""

    def __init__(self) -> None:
        self._snapshot = ProjectionSnapshot()
        self._history: list[ProjectionSnapshot] = [self._snapshot]
        self._staged: ProjectionSnapshot | None = None

    @property
    def snapshot(self) -> ProjectionSnapshot:
        return ProjectionSnapshot(
            self._snapshot.generation,
            tuple(self._snapshot.records),
            self._snapshot.claims_edges,
            tuple(self._snapshot.locators),
        )

    @property
    def prior_generation_preserved(self) -> bool:
        return bool(self._history)

    def stage(
        self,
        records: Sequence[Any],
        *,
        claims_edges: int = 0,
        locators: Sequence[Any] = (),
        continuation: str | None = None,
        expected_continuation: str | None = None,
    ) -> dict[str, Any]:
        if self._staged is not None:
            raise StatefulFuzzError("registry:staged_operation_limit", observed=2, bound=1)
        validate_registry_chunk(
            records=records,
            claims_edges=claims_edges,
            locators=locators,
            continuation=continuation,
            expected_continuation=expected_continuation,
        )
        self._staged = ProjectionSnapshot(
            generation=self._snapshot.generation + 1,
            records=tuple(records),
            claims_edges=claims_edges,
            locators=tuple(locators),
        )
        return {"status": "STAGED", "generation": self._staged.generation}

    def commit(self) -> dict[str, Any]:
        if self._staged is None:
            raise StatefulFuzzError("state:partial_commit_forbidden")
        self._history.append(self._snapshot)
        self._snapshot = self._staged
        self._staged = None
        return {"status": "COMMITTED", **self._snapshot.as_dict(), "prior_generation_preserved": True}

    def abort(self, reason_code: str = "state:partial_commit_forbidden") -> dict[str, Any]:
        self._staged = None
        return {"status": "PRESERVED", "reason_code": reason_code, **self._snapshot.as_dict(), "prior_generation_preserved": True}


def validate_enrollment_bounds(manifest: Any, *, declared_paths: int | None = None, generations: int | None = None, staged_operations: int = 0) -> dict[str, Any]:
    raw = canonical_bytes(manifest)
    if len(raw) > MAX_JSON_BYTES:
        raise StatefulFuzzError("maintenance:manifest_bytes_limit", observed=len(raw), bound=MAX_JSON_BYTES)
    paths = _count_path_like(manifest) if declared_paths is None else declared_paths
    if paths > MAX_DECLARED_PATHS:
        raise StatefulFuzzError("maintenance:declared_paths_limit", observed=paths, bound=MAX_DECLARED_PATHS)
    generation_count = generations
    if generation_count is None:
        generation_count = _count_transitions(manifest)
    if generation_count > MAX_GENERATIONS:
        raise StatefulFuzzError("maintenance:generations_limit", observed=generation_count, bound=MAX_GENERATIONS)
    if type(staged_operations) is not int or staged_operations < 0 or staged_operations > MAX_STAGED_OPERATIONS:
        raise StatefulFuzzError("maintenance:staged_operation_limit", observed=staged_operations, bound=MAX_STAGED_OPERATIONS)
    return {"manifest_bytes": len(raw), "declared_paths": paths, "generations": generation_count, "staged_operations": staged_operations, "bounded": True}


def _count_transitions(value: Any) -> int:
    if isinstance(value, Mapping):
        total = sum(_count_transitions(child) for child in value.values())
        for key in ("generations", "transitions", "events"):
            child = value.get(key)
            if isinstance(child, (list, tuple)):
                total += len(child)
        return total
    if isinstance(value, (list, tuple)):
        return sum(_count_transitions(child) for child in value)
    return 0


def validate_maintenance_bounds(program: Any, *, operation: str | None = None, started_at: float | None = None) -> dict[str, Any]:
    result = validate_enrollment_bounds(program)
    if started_at is not None and time.monotonic() - started_at > MAINTENANCE_VALIDATION_TIMEOUT_SECONDS:
        raise StatefulFuzzError("maintenance:validation_timeout", observed=MAINTENANCE_VALIDATION_TIMEOUT_SECONDS + 1, bound=MAINTENANCE_VALIDATION_TIMEOUT_SECONDS)
    if operation is not None:
        result["operation"] = operation
    return result


@dataclass
class StatefulMaintenanceState:
    generation: int = 1
    transitions: int = 0
    staged_operations: int = 0

    def stage(self, *, generations: int = 1, declared_paths: int = 0) -> dict[str, Any]:
        if self.staged_operations >= MAX_STAGED_OPERATIONS:
            raise StatefulFuzzError("maintenance:staged_operation_limit", observed=self.staged_operations + 1, bound=MAX_STAGED_OPERATIONS)
        if generations < 0 or self.transitions + generations > MAX_GENERATIONS:
            raise StatefulFuzzError("maintenance:generations_limit", observed=self.transitions + generations, bound=MAX_GENERATIONS)
        if declared_paths > MAX_DECLARED_PATHS:
            raise StatefulFuzzError("maintenance:declared_paths_limit", observed=declared_paths, bound=MAX_DECLARED_PATHS)
        self.staged_operations += 1
        return {"status": "STAGED", "generation": self.generation + generations}

    def commit(self, *, generations: int = 1) -> dict[str, Any]:
        if self.staged_operations != 1:
            raise StatefulFuzzError("state:partial_commit_forbidden")
        self.generation += generations
        self.transitions += generations
        self.staged_operations = 0
        return {"status": "COMMITTED", "generation": self.generation, "prior_generation_preserved": True}

    def abort(self) -> dict[str, Any]:
        self.staged_operations = 0
        return {"status": "PRESERVED", "generation": self.generation, "prior_generation_preserved": True}


def run_stateful_campaign(*, surfaces: Sequence[str] = ("registry", "enrollment", "maintenance"), seed: int = SEED) -> dict[str, Any]:
    """Run deterministic model checks for each stateful surface."""

    reports: dict[str, Any] = {}
    for surface in surfaces:
        model = StatefulRegistryProjection() if surface == "registry" else StatefulMaintenanceState()
        before = model.snapshot.as_dict() if surface == "registry" else {"generation": model.generation, "transitions": model.transitions}
        failures: list[dict[str, Any]] = []
        try:
            if surface == "registry":
                model.stage([{"id": seed}], claims_edges=1, locators=["fixture:stateful"])
                model.commit()
                try:
                    model.stage([{"id": "oversized"}] * (MAX_RECORDS + 1))
                except StatefulFuzzError:
                    pass
                else:
                    failures.append({"reason_code": "registry:records_limit"})
            else:
                model.stage(generations=1, declared_paths=1)
                model.commit()
                try:
                    model.stage(generations=MAX_GENERATIONS + 1)
                except StatefulFuzzError:
                    pass
                else:
                    failures.append({"reason_code": "maintenance:generations_limit"})
        except Exception:
            failures.append({"reason_code": "fuzz:crash"})
        after = model.snapshot.as_dict() if surface == "registry" else {"generation": model.generation, "transitions": model.transitions}
        reports[surface] = {"surface": surface, "seed": seed, "before": before, "after": after, "failures": failures, "prior_state_preserved_on_denial": not failures, "status": "PASS" if not failures else "FAIL"}
    return {"schema": PROFILE_SCHEMA, "profile_version": PROFILE_VERSION, "seed": seed, "surfaces": reports, "status": "PASS" if all(row["status"] == "PASS" for row in reports.values()) else "FAIL", "provider_free": True}


stateful_campaign = run_stateful_campaign


__all__ = [
    "BOUNDS",
    "CANONICAL_LIMITS",
    "CORPUS",
    "CORPUS_DIGEST",
    "CORPUS_MANIFEST",
    "DEFENSIVE_PROFILE_SCHEMA",
    "DEFENSIVE_PROFILE_VERSION",
    "FIXED_CORPUS",
    "FIXED_CORPUS_DIGEST",
    "FuzzCase",
    "FUZZ_CASE_COUNT",
    "HostileInputError",
    "LIMITS",
    "MAX_ARTIFACT_RECORDS",
    "MAX_BATCH_ENTRIES",
    "MAX_CASE_OUTPUT_BYTES",
    "MAX_CLAIMS_EDGES",
    "MAX_DECLARED_PATHS",
    "MAX_FRAME_BYTES",
    "MAX_GENERATIONS",
    "MAX_IN_FLIGHT",
    "MAX_JSON_BYTES",
    "MAX_KEY_BYTES",
    "MAX_LOCATORS",
    "MAX_NESTING_DEPTH",
    "MAX_NODES",
    "MAX_OPERATIONS",
    "MAX_PATH_BYTES",
    "MAX_QUEUE",
    "MAX_RECORDS",
    "MAX_SOURCE_LOCATORS",
    "MAX_STAGED_OPERATIONS",
    "MAX_STRING_BYTES",
    "PROFILE",
    "PRNG_SEED",
    "PROFILE_SCHEMA",
    "PROFILE_VERSION",
    "REASON_CODES",
    "RESOURCE_LIMITS",
    "SEED",
    "StatefulFuzzError",
    "StatefulMaintenanceState",
    "StatefulRegistryProjection",
    "BoundViolation",
    "canonical_bytes",
    "canonical_sha256",
    "continuation_token",
    "corpus_manifest",
    "fixed_corpus",
    "generated_cases",
    "parse_bounded_json",
    "parse_canonical_json",
    "run_campaign",
    "run_fuzz_campaign",
    "run_stateful_campaign",
    "sanitize_evidence",
    "sanitize_failure_evidence",
    "stateful_campaign",
    "validate_bounded_value",
    "validate_enrollment_bounds",
    "validate_input",
    "validate_maintenance_bounds",
    "validate_registry_chunk",
]
