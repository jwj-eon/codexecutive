#!/usr/bin/env python3
"""Immutable evidence objects plus a bounded, non-authoritative freshness cache."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import unicodedata
from typing import Any

try:
    from orch_dork_hostile_input import PROFILE, HostileInputError, canonicalize_bounded_json, parse_bounded_json
except ImportError:  # pragma: no cover - isolated policy loader.
    _hostile_path = Path(__file__).resolve().with_name("orch_dork_hostile_input.py")
    _hostile_spec = importlib.util.spec_from_file_location("orch_dork_hostile_input", _hostile_path)
    if _hostile_spec is None or _hostile_spec.loader is None:
        raise
    _hostile = importlib.util.module_from_spec(_hostile_spec)
    sys.modules.setdefault("orch_dork_hostile_input", _hostile)
    _hostile_spec.loader.exec_module(_hostile)
    PROFILE = _hostile.PROFILE
    HostileInputError = _hostile.HostileInputError
    canonicalize_bounded_json = _hostile.canonicalize_bounded_json
    parse_bounded_json = _hostile.parse_bounded_json


SNAPSHOT_OBJECT_SCHEMA = "orch-dork/evidence-snapshot-object/v1"
VOLATILE_FACTS_SCHEMA = "orch-dork/volatile-facts/v1"
VOLATILE_OBSERVATION_SCHEMA = "orch-dork/volatile-observation/v1"
FRESHNESS_SCHEMA = "orch-dork/snapshot-freshness/v1"
RECEIPT_SCHEMA = "orch-dork/evidence-snapshot-receipt/v1"

FRESH = "FRESH"
REFRESH_REQUIRED = "REFRESH_REQUIRED"
REFUSE = "REFUSE"

REQUIRED_STATIC_SOURCES = (
    "acceptance_criteria",
    "authority_scope",
    "clean_baseline",
    "dependencies",
    "descriptor_identity",
    "installed_identity",
    "instructions",
    "invocation_identity",
    "manifest_identity",
    "repository",
    "repository_inventory",
    "source_identity",
    "task",
    "ticket_spec",
    "writable_scope",
)
ADMISSION_MATERIALS = (
    "acceptance_criteria",
    "authority_scope",
    "installed_identity",
    "instructions",
    "invocation_identity",
    "repository_inventory",
    "source_identity",
    "ticket_spec",
    "writable_scope",
)
REQUIRED_VOLATILE_KINDS = (
    "authority",
    "capacity",
    "lease",
    "runtime",
    "task_state",
    "working_tree",
)
MAX_VALIDITY_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 5

_SNAPSHOT_KEYS = frozenset({"schema", "profile_schema", "attempt_id", "root_task_id", "objects", "static_digest"})
_OBJECT_KEYS = frozenset({"name", "source_locator", "content_sha256", "content_bytes", "object_sha256"})
_VOLATILE_KEYS = frozenset({"schema", "attempt_id", "root_task_id", "observed_at", "clock", "observations"})
_CLOCK_KEYS = frozenset({"id", "kind", "unit", "origin"})
_OBSERVATION_KEYS = frozenset(
    {
        "schema",
        "kind",
        "source",
        "event_id",
        "clock_id",
        "unit",
        "origin",
        "observed_at",
        "expires_at",
        "status",
        "value",
        "value_sha256",
        "observation_sha256",
    }
)
_REASON_BY_STATIC = {
    "task": "STATIC_BYTES_CHANGED",
    "instructions": "STATIC_BYTES_CHANGED",
    "repository": "STATIC_BYTES_CHANGED",
    "repository_inventory": "INVENTORY_CHANGED",
    "clean_baseline": "INVENTORY_CHANGED",
    "dependencies": "DEPENDENCY_CHANGED",
    "source_identity": "SOURCE_INSTALLED_MISMATCH",
    "installed_identity": "SOURCE_INSTALLED_MISMATCH",
}
_REASON_BY_VOLATILE = {
    "authority": "AUTHORITY_CHANGED",
    "capacity": "CAPACITY_CHANGED",
    "lease": "LEASE_CHANGED",
    "runtime": "RUNTIME_CHANGED",
    "task_state": "TASK_STATE_CHANGED",
    "working_tree": "WORKTREE_CHANGED",
}
_SENSITIVE_BYTES = re.compile(
    rb"-----BEGIN [^-]{1,80}PRIVATE KEY-----|"
    rb"(?i:\bBearer\s+[A-Za-z0-9._~+/=-]{12,})|"
    rb"(?i:\b(?:sk|gh[pousr]|xox[baprs])[-_][A-Za-z0-9_-]{12,})"
)


def canonical_bytes(value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return canonicalize_bounded_json(raw, profile=PROFILE, batch=isinstance(value, list))


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value.encode("utf-8")) <= PROFILE.max_string_bytes


def _closed(value: Any, keys: frozenset[str], label: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        issues.append(f"{label}:TYPE_INVALID")
        return {}
    for field in sorted(set(value) - keys):
        issues.append(f"{label}:UNKNOWN_FIELD:{field}")
    return value


def _time(value: Any, label: str, issues: list[str]) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        issues.append(f"{label}:TIMESTAMP_INVALID")
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        issues.append(f"{label}:TIMESTAMP_INVALID")
        return None


class MemoryObjectStore:
    """Create-only in-memory adapter for immutable evidence objects."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def put(self, value: bytes) -> str:
        data = bytes(value)
        digest = bytes_sha256(data)
        existing = self._objects.get(digest)
        if existing is not None and existing != data:
            raise ValueError("object_digest_collision")
        self._objects.setdefault(digest, data)
        return digest

    def get(self, digest: str) -> bytes | None:
        value = self._objects.get(digest)
        return None if value is None else bytes(value)

    def __len__(self) -> int:
        return len(self._objects)


class DirectoryObjectStore:
    """Create-only local adapter; cache eviction never deletes these objects."""

    def __init__(self, root: str | os.PathLike[str] | Path) -> None:
        raw_root = Path(root)
        if raw_root.is_symlink():
            raise ValueError("object_store_symlink")
        self.root = raw_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if not _is_sha(digest):
            raise ValueError("object_digest_invalid")
        return self.root / digest[:2] / digest[2:]

    def put(self, value: bytes) -> str:
        data = bytes(value)
        if len(data) > PROFILE.canonical_json_bytes:
            raise ValueError("object_too_large")
        digest = bytes_sha256(data)
        target = self._path(digest)
        if target.exists():
            existing = target.read_bytes()
            if existing != data:
                raise ValueError("object_digest_collision")
            return digest
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".snapshot-", dir=str(target.parent))
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o444)
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.read_bytes() != data:
                    raise ValueError("object_digest_collision")
            target.chmod(0o444)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return digest

    def get(self, digest: str) -> bytes | None:
        try:
            target = self._path(digest)
            info = target.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o222:
                return None
            data = target.read_bytes()
        except (OSError, ValueError):
            return None
        return data if bytes_sha256(data) == digest else None


class MemoryStaticObserver:
    """Exact-byte test adapter keyed by bounded logical locator."""

    def __init__(self, values: Mapping[str, bytes | bytearray | memoryview | str]) -> None:
        self.values = {
            str(key): value.encode("utf-8") if isinstance(value, str) else bytes(value)
            for key, value in values.items()
        }

    def read(self, locator: str) -> tuple[str, bytes | None]:
        value = self.values.get(locator)
        return ("UNAVAILABLE", None) if value is None else ("PASS", bytes(value))


class LocalStaticObserver:
    """Read bounded regular files under named roots without following links."""

    def __init__(self, roots: Mapping[str, str | os.PathLike[str] | Path]) -> None:
        self.roots = {str(name): Path(root).resolve() for name, root in roots.items()}

    def read(self, locator: str) -> tuple[str, bytes | None]:
        if not isinstance(locator, str) or ":" not in locator or len(locator.encode("utf-8")) > PROFILE.max_path_bytes:
            return "UNAVAILABLE", None
        root_name, relative_text = locator.split(":", 1)
        root = self.roots.get(root_name)
        relative = PurePosixPath(relative_text)
        if root is None or relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            return "UNAVAILABLE", None
        current = root
        try:
            for part in relative.parts:
                current = current / part
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode):
                    return "REFUSE", None
            resolved = current.resolve(strict=True)
            if os.path.commonpath((str(root), str(resolved))) != str(root):
                return "REFUSE", None
            info = resolved.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > PROFILE.canonical_json_bytes:
                return "REFUSE", None
            return "PASS", resolved.read_bytes()
        except (OSError, ValueError):
            return "UNAVAILABLE", None


class FreshnessCache:
    """Bounded evidence index; entries never become authority."""

    def __init__(self, max_entries: int = 64) -> None:
        self.max_entries = min(max(1, int(max_entries)), PROFILE.registry_artifacts)
        self._entries: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def previous(self, snapshot_digest: str) -> dict[str, Any] | None:
        value = self._entries.get(snapshot_digest)
        return None if value is None else deepcopy(value)

    def remember(self, snapshot_digest: str, value: Mapping[str, Any]) -> bool:
        cache_hit = snapshot_digest in self._entries and self._entries[snapshot_digest].get("volatile_digest") == value.get("volatile_digest")
        self._entries[snapshot_digest] = deepcopy(dict(value))
        self._entries.move_to_end(snapshot_digest)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return cache_hit

    def __len__(self) -> int:
        return len(self._entries)


def capture_snapshot(
    store: MemoryObjectStore | DirectoryObjectStore,
    observer: MemoryStaticObserver | LocalStaticObserver,
    *,
    attempt_id: str,
    root_task_id: str,
    sources: Mapping[str, str],
) -> str:
    """Private creation adapter used by trusted local collectors."""

    if set(sources) != set(REQUIRED_STATIC_SOURCES) or not _is_text(attempt_id) or not _is_text(root_task_id):
        raise ValueError("snapshot_sources_invalid")
    objects: list[dict[str, Any]] = []
    staged: list[tuple[str, str, bytes]] = []
    normalized_names: set[str] = set()
    for name in REQUIRED_STATIC_SOURCES:
        locator = sources[name]
        if not _is_text(locator):
            raise ValueError("snapshot_locator_invalid")
        normalized = unicodedata.normalize("NFC", locator).casefold()
        if normalized in normalized_names:
            raise ValueError("snapshot_locator_collision")
        normalized_names.add(normalized)
        status, data = observer.read(locator)
        if status != "PASS" or data is None:
            raise ValueError(f"snapshot_source_{status.lower()}:{name}")
        if len(data) > PROFILE.canonical_json_bytes:
            raise ValueError("snapshot_source_too_large")
        if _SENSITIVE_BYTES.search(data):
            raise ValueError(f"snapshot_sensitive_material:{name}")
        staged.append((name, locator, data))
    # Validation is transactional with respect to the immutable store: a
    # refused source set writes no prefix objects.
    for name, locator, data in staged:
        content_digest = bytes_sha256(data)
        object_digest = store.put(data)
        objects.append(
            {
                "name": name,
                "source_locator": locator,
                "content_sha256": content_digest,
                "content_bytes": len(data),
                "object_sha256": object_digest,
            }
        )
    static_material = {"objects": objects, "profile_schema": PROFILE.schema}
    core = {
        "schema": SNAPSHOT_OBJECT_SCHEMA,
        "profile_schema": PROFILE.schema,
        "attempt_id": attempt_id,
        "root_task_id": root_task_id,
        "objects": objects,
        "static_digest": json_sha256(static_material),
    }
    return store.put(canonical_bytes(core))


class EvidenceSnapshot:
    """Deep snapshot module; ``resolve`` is its only decision interface."""

    def __init__(
        self,
        store: MemoryObjectStore | DirectoryObjectStore,
        observer: MemoryStaticObserver | LocalStaticObserver,
        *,
        cache: FreshnessCache | None = None,
        now: datetime | None = None,
    ) -> None:
        self.store = store
        self.observer = observer
        self.cache = cache or FreshnessCache()
        self.now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    def resolve(self, snapshot_digest: Any, live_runtime_facts: Any) -> dict[str, Any]:
        refuse: list[dict[str, Any]] = []
        refresh: list[dict[str, Any]] = []
        snapshot = self._load_snapshot(snapshot_digest, refuse, refresh)
        static_digest = snapshot.get("static_digest") if snapshot else None
        static_observed: dict[str, str] = {}
        if snapshot:
            static_observed = self._verify_static(snapshot, refuse, refresh)
        volatile_projection, volatile_digest = self._validate_volatile(snapshot, live_runtime_facts, refuse, refresh)
        previous = self.cache.previous(str(snapshot_digest)) if _is_sha(snapshot_digest) else None
        deltas = self._deltas(previous, volatile_projection, refuse, refresh)
        status = REFUSE if refuse else REFRESH_REQUIRED if refresh else FRESH
        admission_snapshot = self._admission_projection(snapshot) if status == FRESH else None
        core = {
            "schema": FRESHNESS_SCHEMA,
            "status": status,
            "fresh": status == FRESH,
            "snapshot_digest": snapshot_digest if _is_sha(snapshot_digest) else None,
            "static_digest": static_digest,
            "volatile_digest": volatile_digest,
            "deltas": sorted(deltas, key=lambda item: (item["path"], item["reason"], item["state"])),
            "issues": sorted({item["reason"] for item in refuse + refresh}),
            "evidence_tier": "runtime-observed-sanitized" if status == FRESH else "provider-free-deterministic",
            "cache_hit": False,
            "mutation_permitted": False,
            "authority_granted": False,
            "admission_snapshot": admission_snapshot,
            "static_identities": self._static_identities(snapshot),
            "volatile_expiries": {
                kind: {
                    "source": volatile_projection[kind].get("source"),
                    "expires_at": volatile_projection[kind].get("expires_at"),
                }
                for kind in sorted(volatile_projection)
            },
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        if snapshot and volatile_digest:
            core["cache_hit"] = self.cache.remember(
                str(snapshot_digest),
                {"volatile_digest": volatile_digest, "volatile": volatile_projection, "status": status},
            )
        core["freshness_digest"] = json_sha256(core)
        if len(canonical_bytes(core)) > PROFILE.canonical_json_bytes:
            return self._bounded_refusal(snapshot_digest, static_digest)
        return core

    def _load_snapshot(self, digest: Any, refuse: list[dict[str, Any]], refresh: list[dict[str, Any]]) -> Mapping[str, Any]:
        if not _is_sha(digest):
            refuse.append(self._delta("snapshot", "CONTRADICTORY", "digest_invalid"))
            return {}
        raw = self.store.get(str(digest))
        if raw is None:
            refresh.append(self._delta("snapshot", "RUNTIME_UNAVAILABLE", "object_unavailable"))
            return {}
        if bytes_sha256(raw) != digest:
            refuse.append(self._delta("snapshot", "CONTRADICTORY", "object_digest_mismatch"))
            return {}
        try:
            value = parse_bounded_json(raw, profile=PROFILE)
        except HostileInputError:
            refuse.append(self._delta("snapshot", "CONTRADICTORY", "object_malformed"))
            return {}
        local_issues: list[str] = []
        snapshot = _closed(value, _SNAPSHOT_KEYS, "snapshot", local_issues)
        refuse.extend(self._delta("snapshot", "CONTRADICTORY", item) for item in local_issues)
        if snapshot.get("schema") != SNAPSHOT_OBJECT_SCHEMA or snapshot.get("profile_schema") != PROFILE.schema:
            refuse.append(self._delta("snapshot", "CONTRADICTORY", "schema_invalid"))
        objects = snapshot.get("objects")
        if not isinstance(objects, list) or len(objects) != len(REQUIRED_STATIC_SOURCES):
            refuse.append(self._delta("snapshot.objects", "CONTRADICTORY", "objects_incomplete"))
        expected_static = json_sha256({"objects": objects, "profile_schema": snapshot.get("profile_schema")}) if isinstance(objects, list) else None
        if snapshot.get("static_digest") != expected_static:
            refuse.append(self._delta("snapshot.static_digest", "CONTRADICTORY", "static_digest_mismatch"))
        return snapshot

    def _verify_static(self, snapshot: Mapping[str, Any], refuse: list[dict[str, Any]], refresh: list[dict[str, Any]]) -> dict[str, str]:
        observed: dict[str, str] = {}
        objects = snapshot.get("objects") if isinstance(snapshot.get("objects"), list) else []
        seen_names: set[str] = set()
        seen_locators: set[str] = set()
        for index, raw in enumerate(objects):
            local_issues: list[str] = []
            item = _closed(raw, _OBJECT_KEYS, f"snapshot.objects[{index}]", local_issues)
            if local_issues:
                refuse.extend(self._delta(f"objects[{index}]", "CONTRADICTORY", reason) for reason in local_issues)
            name = item.get("name")
            locator = item.get("source_locator")
            if name not in REQUIRED_STATIC_SOURCES or name in seen_names:
                refuse.append(self._delta(f"objects[{index}].name", "CONTRADICTORY", "name_invalid_or_duplicate"))
                continue
            seen_names.add(str(name))
            normalized = unicodedata.normalize("NFC", str(locator)).casefold() if isinstance(locator, str) else ""
            if not normalized or normalized in seen_locators:
                refuse.append(self._delta(f"objects.{name}.source_locator", "CONTRADICTORY", "locator_invalid_or_collision"))
                continue
            seen_locators.add(normalized)
            stored = self.store.get(str(item.get("object_sha256"))) if _is_sha(item.get("object_sha256")) else None
            if stored is None or bytes_sha256(stored) != item.get("content_sha256") or len(stored) != item.get("content_bytes"):
                refuse.append(self._delta(f"static.{name}", "CONTRADICTORY", "stored_object_mismatch"))
                continue
            status, current = self.observer.read(str(locator))
            if status == "UNAVAILABLE" or current is None:
                refresh.append(self._delta(f"static.{name}", "RUNTIME_UNAVAILABLE", "source_unavailable"))
                continue
            if status != "PASS":
                refuse.append(self._delta(f"static.{name}", "CONTRADICTORY", "source_unsafe"))
                continue
            current_digest = bytes_sha256(current)
            observed[str(name)] = current_digest
            if current_digest != item.get("content_sha256") or len(current) != item.get("content_bytes"):
                refuse.append(self._delta(f"static.{name}", _REASON_BY_STATIC.get(str(name), "STATIC_BYTES_CHANGED"), "changed"))
        if seen_names != set(REQUIRED_STATIC_SOURCES):
            refuse.append(self._delta("snapshot.objects", "CONTRADICTORY", "required_source_missing"))
        if observed.get("source_identity") and observed.get("installed_identity") and observed["source_identity"] != observed["installed_identity"]:
            refuse.append(self._delta("static.source_installed", "SOURCE_INSTALLED_MISMATCH", "changed"))
        return observed

    def _validate_volatile(
        self,
        snapshot: Mapping[str, Any],
        facts: Any,
        refuse: list[dict[str, Any]],
        refresh: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], str | None]:
        issues: list[str] = []
        value = _closed(facts, _VOLATILE_KEYS, "volatile", issues)
        refuse.extend(self._delta("volatile", "CONTRADICTORY", item) for item in issues)
        if value.get("schema") != VOLATILE_FACTS_SCHEMA:
            refuse.append(self._delta("volatile.schema", "CONTRADICTORY", "schema_invalid"))
        if snapshot and (value.get("attempt_id") != snapshot.get("attempt_id") or value.get("root_task_id") != snapshot.get("root_task_id")):
            refuse.append(self._delta("volatile.binding", "CONTRADICTORY", "attempt_or_root_mismatch"))
        clock_issues: list[str] = []
        clock = _closed(value.get("clock"), _CLOCK_KEYS, "volatile.clock", clock_issues)
        refuse.extend(self._delta("volatile.clock", "CONTRADICTORY", item) for item in clock_issues)
        if clock.get("kind") != "wall" or clock.get("unit") != "seconds" or clock.get("origin") != "UTC" or not _is_text(clock.get("id")):
            refuse.append(self._delta("volatile.clock", "CONTRADICTORY", "clock_invalid"))
        envelope_time = _time(value.get("observed_at"), "volatile.observed_at", issues)
        if envelope_time and envelope_time > self.now and (envelope_time - self.now).total_seconds() > MAX_FUTURE_SKEW_SECONDS:
            refuse.append(self._delta("volatile.observed_at", "CONTRADICTORY", "future_dated"))
        observations = value.get("observations")
        if not isinstance(observations, list) or len(observations) > PROFILE.max_operations:
            refuse.append(self._delta("volatile.observations", "CONTRADICTORY", "observations_invalid"))
            observations = []
        by_kind: dict[str, dict[str, Any]] = {}
        event_digests: dict[tuple[str, str], str] = {}
        for index, raw in enumerate(observations):
            row_issues: list[str] = []
            row = _closed(raw, _OBSERVATION_KEYS, f"volatile.observations[{index}]", row_issues)
            refuse.extend(self._delta(f"volatile.observations[{index}]", "CONTRADICTORY", item) for item in row_issues)
            kind = row.get("kind")
            if kind not in REQUIRED_VOLATILE_KINDS:
                refuse.append(self._delta(f"volatile.observations[{index}].kind", "CONTRADICTORY", "kind_invalid"))
                continue
            expected_value = json_sha256(row.get("value"))
            if row.get("value_sha256") != expected_value:
                refuse.append(self._delta(f"volatile.{kind}.value", "CONTRADICTORY", "value_digest_mismatch"))
            expected_observation = json_sha256({key: deepcopy(item) for key, item in row.items() if key != "observation_sha256"})
            if row.get("observation_sha256") != expected_observation:
                refuse.append(self._delta(f"volatile.{kind}", "CONTRADICTORY", "observation_digest_mismatch"))
            event_key = (str(row.get("source")), str(row.get("event_id")))
            prior_digest = event_digests.get(event_key)
            if prior_digest is not None:
                if prior_digest != expected_observation:
                    refuse.append(self._delta(f"volatile.{kind}", "CONTRADICTORY", "conflicting_duplicate"))
                continue
            event_digests[event_key] = expected_observation
            if kind in by_kind:
                refuse.append(self._delta(f"volatile.{kind}", "CONTRADICTORY", "duplicate_kind"))
                continue
            by_kind[str(kind)] = dict(row)
            if row.get("clock_id") != clock.get("id") or row.get("unit") != clock.get("unit") or row.get("origin") != clock.get("origin"):
                refuse.append(self._delta(f"volatile.{kind}.clock", "CONTRADICTORY", "clock_mismatch"))
            observed_at = _time(row.get("observed_at"), f"volatile.{kind}.observed_at", row_issues)
            expires_at = _time(row.get("expires_at"), f"volatile.{kind}.expires_at", row_issues)
            refuse.extend(self._delta(f"volatile.{kind}", "CONTRADICTORY", item) for item in row_issues)
            if observed_at and expires_at:
                interval = (expires_at - observed_at).total_seconds()
                if interval <= 0 or interval > MAX_VALIDITY_SECONDS:
                    refuse.append(self._delta(f"volatile.{kind}.expiry", "CONTRADICTORY", "validity_invalid"))
                elif self.now > expires_at:
                    reason = "AUTHORITY_EXPIRED" if kind == "authority" else f"{str(kind).upper()}_EXPIRED"
                    refresh.append(self._delta(f"volatile.{kind}.expiry", reason, "expired"))
                if observed_at > self.now and (observed_at - self.now).total_seconds() > MAX_FUTURE_SKEW_SECONDS:
                    refuse.append(self._delta(f"volatile.{kind}.observed_at", "CONTRADICTORY", "future_dated"))
            if row.get("status") == "UNAVAILABLE":
                reason = "RUNTIME_UNAVAILABLE" if kind == "runtime" else f"{str(kind).upper()}_UNAVAILABLE"
                refresh.append(self._delta(f"volatile.{kind}", reason, "unavailable"))
            elif row.get("status") != "PASS":
                refuse.append(self._delta(f"volatile.{kind}", "CONTRADICTORY", "status_invalid"))
            if kind == "working_tree" and isinstance(row.get("value"), Mapping) and row["value"].get("clean") is not True:
                refuse.append(self._delta("volatile.working_tree", "WORKTREE_DIRTY", "dirty"))
        if set(by_kind) != set(REQUIRED_VOLATILE_KINDS):
            refresh.append(self._delta("volatile.observations", "RUNTIME_UNAVAILABLE", "required_observation_missing"))
        projection = {kind: by_kind[kind] for kind in sorted(by_kind)}
        return projection, json_sha256(projection) if projection else None

    def _deltas(
        self,
        previous: Mapping[str, Any] | None,
        current: Mapping[str, Any],
        refuse: list[dict[str, Any]],
        refresh: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        result = list(refuse) + list(refresh)
        if not previous or not isinstance(previous.get("volatile"), Mapping):
            return result
        prior = previous["volatile"]
        for kind in sorted(set(prior) | set(current)):
            before = prior.get(kind)
            after = current.get(kind)
            if before != after:
                result.append(self._delta(f"volatile.{kind}", _REASON_BY_VOLATILE.get(kind, "CONTRADICTORY"), "changed"))
        return result[: PROFILE.registry_claims]

    def _admission_projection(self, snapshot: Mapping[str, Any]) -> dict[str, Any]:
        by_name = {item["name"]: item for item in snapshot.get("objects", []) if isinstance(item, Mapping) and item.get("name") in ADMISSION_MATERIALS}
        materials = []
        for name in ADMISSION_MATERIALS:
            item = by_name[name]
            value = {
                "content_sha256": item["content_sha256"],
                "content_bytes": item["content_bytes"],
                "object_sha256": item["object_sha256"],
                "source_locator": item["source_locator"],
            }
            if name == "authority_scope":
                value["available"] = True
            if name == "writable_scope":
                value = [item["source_locator"]]
            materials.append({"name": name, "value": value, "sha256": json_sha256(value)})
        core = {
            "schema": "orch-dork/evidence-snapshot/v1",
            "attempt_id": snapshot["attempt_id"],
            "root_task_id": snapshot["root_task_id"],
            "materials": materials,
        }
        core["snapshot_sha256"] = json_sha256(core)
        return core

    @staticmethod
    def _static_identities(snapshot: Mapping[str, Any]) -> dict[str, str]:
        selected = {
            "dependencies",
            "descriptor_identity",
            "installed_identity",
            "manifest_identity",
            "repository_inventory",
            "source_identity",
        }
        return {
            str(item["name"]): str(item["content_sha256"])
            for item in snapshot.get("objects", [])
            if isinstance(item, Mapping) and item.get("name") in selected and _is_sha(item.get("content_sha256"))
        }

    @staticmethod
    def _delta(path: str, reason: str, state: str) -> dict[str, Any]:
        return {"path": str(path)[:256], "reason": str(reason)[:96], "state": str(state)[:96]}

    @staticmethod
    def _bounded_refusal(snapshot_digest: Any, static_digest: Any) -> dict[str, Any]:
        core = {
            "schema": FRESHNESS_SCHEMA,
            "status": REFUSE,
            "fresh": False,
            "snapshot_digest": snapshot_digest if _is_sha(snapshot_digest) else None,
            "static_digest": static_digest if _is_sha(static_digest) else None,
            "volatile_digest": None,
            "deltas": [{"path": "result", "reason": "CONTRADICTORY", "state": "output_too_large"}],
            "issues": ["CONTRADICTORY"],
            "evidence_tier": "provider-free-deterministic",
            "cache_hit": False,
            "mutation_permitted": False,
            "authority_granted": False,
            "admission_snapshot": None,
            "static_identities": {},
            "volatile_expiries": {},
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        core["freshness_digest"] = json_sha256(core)
        return core


def resolve_evidence_snapshot(
    program: Any,
    *,
    store: MemoryObjectStore | DirectoryObjectStore,
    observer: MemoryStaticObserver | LocalStaticObserver,
    cache: FreshnessCache | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(program, Mapping) or set(program) != {"snapshot_digest", "live_runtime_facts"}:
        return EvidenceSnapshot(store, observer, cache=cache, now=now).resolve(None, {})
    return EvidenceSnapshot(store, observer, cache=cache, now=now).resolve(
        program["snapshot_digest"], program["live_runtime_facts"]
    )


def snapshot_receipt(freshness: Any) -> dict[str, Any]:
    """Return a body-free machine receipt for one resolved snapshot."""

    value = freshness if isinstance(freshness, Mapping) else {}
    core = {
        "schema": RECEIPT_SCHEMA,
        "status": value.get("status") if value.get("status") in {FRESH, REFRESH_REQUIRED, REFUSE} else REFUSE,
        "snapshot_digest": value.get("snapshot_digest") if _is_sha(value.get("snapshot_digest")) else None,
        "static_digest": value.get("static_digest") if _is_sha(value.get("static_digest")) else None,
        "volatile_digest": value.get("volatile_digest") if _is_sha(value.get("volatile_digest")) else None,
        "freshness_digest": value.get("freshness_digest") if _is_sha(value.get("freshness_digest")) else None,
        "static_identities": deepcopy(value.get("static_identities")) if isinstance(value.get("static_identities"), Mapping) else {},
        "volatile_expiries": deepcopy(value.get("volatile_expiries")) if isinstance(value.get("volatile_expiries"), Mapping) else {},
        "deltas": deepcopy(value.get("deltas")) if isinstance(value.get("deltas"), list) else [],
        "unresolved": list(value.get("issues", [])) if isinstance(value.get("issues"), list) else ["CONTRADICTORY"],
        "evidence_tier": value.get("evidence_tier"),
        "mutation_permitted": False,
        "authority_granted": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    core["receipt_digest"] = json_sha256(core)
    return core


__all__ = [
    "SNAPSHOT_OBJECT_SCHEMA",
    "VOLATILE_FACTS_SCHEMA",
    "VOLATILE_OBSERVATION_SCHEMA",
    "FRESHNESS_SCHEMA",
    "RECEIPT_SCHEMA",
    "FRESH",
    "REFRESH_REQUIRED",
    "REFUSE",
    "REQUIRED_STATIC_SOURCES",
    "REQUIRED_VOLATILE_KINDS",
    "MemoryObjectStore",
    "DirectoryObjectStore",
    "MemoryStaticObserver",
    "LocalStaticObserver",
    "FreshnessCache",
    "capture_snapshot",
    "EvidenceSnapshot",
    "resolve_evidence_snapshot",
    "snapshot_receipt",
    "canonical_bytes",
    "json_sha256",
]
