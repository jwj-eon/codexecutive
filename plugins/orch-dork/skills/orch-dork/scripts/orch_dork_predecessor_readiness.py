#!/usr/bin/env python3
"""Observe the canonical predecessor without creating or repairing state.

This module is executed from an exact projected candidate by the fixed Stage L
owner.  It deliberately does not construct ``GovernedNativeController``:
controller construction initializes missing stores and ledgers, which is not a
read-only preflight.  Existing SQLite authorities are opened in read-only mode
and any replay validation runs against a private copy.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
from typing import Any


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_control_tower as control_tower  # noqa: E402
import orch_dork_native_grant_store as native_grant_store  # noqa: E402
import orch_dork_observer_receipt as observer_receipt  # noqa: E402
import orch_dork_owned_file as owned_file  # noqa: E402
import orch_dork_run_store as run_store  # noqa: E402
import orch_dork_runtime_package as runtime_package  # noqa: E402
import orch_dork_shared_capacity as shared_capacity  # noqa: E402


SCHEMA = "orch-dork/live-predecessor-readiness/v1"
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_PREDECESSOR_FIELDS = {
    "controller_id",
    "controller_run_id",
    "root_task_id",
    "attempt_id",
    "run_id",
    "binding_sha256",
    "authority_sha256",
}
_ZERO_COUNTERS = {
    "credential_reads": 0,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_calls": 0,
    "network_calls": 0,
    "release_calls": 0,
    "installation_calls": 0,
    "qualification_calls": 0,
    "task_creations": 0,
    "worker_creations": 0,
}


class PredecessorReadinessError(ValueError):
    """Stable observation-only refusal."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_predecessor(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == _PREDECESSOR_FIELDS
        and all(
            _text(value.get(field))
            for field in (
                "controller_id",
                "controller_run_id",
                "root_task_id",
                "attempt_id",
                "run_id",
            )
        )
        and all(
            isinstance(value.get(field), str)
            and _SHA256.fullmatch(value[field]) is not None
            for field in ("binding_sha256", "authority_sha256")
        )
    )


def _predecessor_identity(
    authority: Any,
    activation: Any,
) -> dict[str, str] | None:
    identity = (
        authority.get("identity")
        if isinstance(authority, Mapping)
        and isinstance(authority.get("identity"), Mapping)
        else None
    )
    projection = (
        authority.get("hook_projection")
        if isinstance(authority, Mapping)
        and isinstance(authority.get("hook_projection"), Mapping)
        else None
    )
    attempt = (
        activation.get("identity")
        if isinstance(activation, Mapping)
        and isinstance(activation.get("identity"), Mapping)
        else None
    )
    value = {
        "controller_id": (
            identity.get("controller_id")
            if isinstance(identity, Mapping) else None
        ),
        "controller_run_id": (
            identity.get("controller_run_id")
            if isinstance(identity, Mapping) else None
        ),
        "root_task_id": (
            attempt.get("root_thread_id")
            if isinstance(attempt, Mapping) else None
        ),
        "attempt_id": (
            attempt.get("attempt_id")
            if isinstance(attempt, Mapping) else None
        ),
        "run_id": (
            attempt.get("run_id")
            if isinstance(attempt, Mapping) else None
        ),
        "binding_sha256": (
            projection.get("binding_sha256")
            if isinstance(projection, Mapping) else None
        ),
        "authority_sha256": (
            _sha(authority) if isinstance(authority, Mapping) else None
        ),
    }
    return dict(value) if _valid_predecessor(value) else None


def _owned_existing(
    path: Path,
    *,
    directory: bool,
    writable_mask: int = 0o022,
) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise PredecessorReadinessError("predecessor:state_unsafe")
    try:
        resolved = path.resolve(strict=True)
        details = path.lstat()
    except FileNotFoundError as error:
        raise PredecessorReadinessError(
            "predecessor:store_missing"
        ) from error
    except OSError as error:
        raise PredecessorReadinessError(
            "predecessor:state_unavailable"
        ) from error
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        resolved != path
        or not expected_type(details.st_mode)
        or (hasattr(os, "getuid") and details.st_uid != os.getuid())
        or stat.S_IMODE(details.st_mode) & writable_mask
    ):
        raise PredecessorReadinessError("predecessor:state_unsafe")
    return resolved


def _tree_snapshot(path: Path) -> str:
    """Hash names, bytes, and stable metadata without following links."""

    if not path.exists() and not path.is_symlink():
        return _sha({"root": str(path), "state": "ABSENT"})
    root = _owned_existing(path, directory=path.is_dir())
    rows: list[dict[str, Any]] = []
    pending = [root]
    while pending:
        current = pending.pop()
        details = current.lstat()
        relative = "." if current == root else current.relative_to(root).as_posix()
        if current.is_symlink():
            raise PredecessorReadinessError("predecessor:state_unsafe")
        row: dict[str, Any] = {
            "path": relative,
            "mode": stat.S_IMODE(details.st_mode),
            "uid": details.st_uid,
            "size": details.st_size,
            "mtime_ns": details.st_mtime_ns,
            "ctime_ns": details.st_ctime_ns,
        }
        if stat.S_ISDIR(details.st_mode):
            row["type"] = "directory"
            try:
                children = sorted(current.iterdir(), key=lambda child: child.name)
            except OSError as error:
                raise PredecessorReadinessError(
                    "predecessor:state_unavailable"
                ) from error
            pending.extend(reversed(children))
        elif stat.S_ISREG(details.st_mode):
            row["type"] = "file"
            digest = hashlib.sha256()
            try:
                descriptor = os.open(
                    current,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                with os.fdopen(descriptor, "rb", closefd=True) as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
            except OSError as error:
                raise PredecessorReadinessError(
                    "predecessor:state_unavailable"
                ) from error
            row["sha256"] = digest.hexdigest()
        else:
            row["type"] = "special"
            raise PredecessorReadinessError("predecessor:state_unsafe")
        rows.append(row)
    return _sha(rows)


def _readonly_connection(path: Path) -> sqlite3.Connection:
    before = owned_file.verify_owned_regular_file(path)
    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro",
        uri=True,
        timeout=5.0,
        check_same_thread=False,
    )
    try:
        after = owned_file.verify_owned_regular_file(path)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise PredecessorReadinessError(
                "predecessor:store_changed"
            )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
    except BaseException:
        connection.close()
        raise
    return connection


class _ReadOnlyNativeGrantStore(native_grant_store.NativeGrantStore):
    """Native authority reader that skips every initialization path."""

    def __init__(self, path: Path) -> None:
        self.path = _owned_existing(path, directory=False)
        self.store_identity_sha256 = (
            native_grant_store.physical_store_sha256(self.path)
        )
        self.authority_marker_path = (
            self.path.parent / native_grant_store.AUTHORITY_MARKER_NAME
        )
        self.authority_tombstone_path = (
            self.path.parent.parent
            / native_grant_store.AUTHORITY_TOMBSTONE_RELATIVE
        )
        self.controller_run_marker_root = (
            self.path.parent.parent
            / native_grant_store.CONTROLLER_RUN_MARKER_RELATIVE
        )
        witness_base = native_grant_store.canonical_witness_root()
        self.external_witness_root = (
            witness_base / self.store_identity_sha256
        )
        self.external_witness_manifest_path = (
            self.external_witness_root / "manifest.json"
        )
        self.external_controller_run_witness_root = (
            self.external_witness_root / "controller-runs"
        )
        self.grant_transition_witness_root = (
            self.external_witness_root / "grant-transitions"
        )

    def _connect(self) -> sqlite3.Connection:
        return _readonly_connection(self.path)


class _ReadOnlyRunStore(run_store.SQLiteRunStore):
    """Run-store projection with no schema creation or stale-claim reap."""

    def __init__(self, path: Path) -> None:
        run_store._Validation.__init__(
            self,
            max_payload_bytes=16 * 1024 * 1024,
        )
        self._path = _owned_existing(path, directory=False)
        details = self._path.stat()
        self._database_identity = (details.st_dev, details.st_ino)
        self._claim_authorization = None
        self._lock = threading.Lock()
        self._claim_lock = threading.RLock()
        self._runs = {}
        self._claimed = {}
        self._active_claim = None
        self._active_claim_owner = None
        self._conn = _readonly_connection(self._path)
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        # Version1 retains the same read projection before lock enrollment.
        # Observe either supported layout without migration or lock creation.
        if version not in (1, 2):
            self._conn.close()
            self._conn = None
            raise PredecessorReadinessError(
                "predecessor:store_schema_unsupported"
            )
        self._rebuild(release_stale=False)


class _ReadOnlyArtifacts:
    durable = True


def _capacity_authority(
    store: _ReadOnlyRunStore,
    *,
    plugin_data: Path,
    observer_trust_store: Path,
    evaluation_time: datetime,
) -> dict[str, Any]:
    trust = observer_receipt.ObserverTrustStore.from_host_file(
        observer_trust_store
    )
    replay_source = plugin_data / "governed-native/cleanup-replay.sqlite3"
    with tempfile.TemporaryDirectory(
        prefix="orch-dork-predecessor-replay-"
    ) as temporary:
        replay_guard = None
        if replay_source.is_file() and not replay_source.is_symlink():
            replay_copy = Path(temporary) / "cleanup-replay.sqlite3"
            shutil.copyfile(replay_source, replay_copy, follow_symlinks=False)
            os.chmod(replay_copy, 0o600)
            replay_guard = observer_receipt.SQLiteReplayGuard(replay_copy)
        tower = control_tower.ControlTower(
            store=store,
            artifacts=_ReadOnlyArtifacts(),
            cleanup_observer_trust_store=trust,
            cleanup_observer_replay_guard=replay_guard,
            cleanup_observer_evaluation_time=evaluation_time,
        )
        run_id = tower._lane_ledger_run_id()
        if not store.exists(run_id):
            raise PredecessorReadinessError(
                "capacity:authority_unverified"
            )
        ready, issues = tower._ensure_lane_ledger_run()
        if not ready:
            raise PredecessorReadinessError(
                "capacity:authority_unverified"
            )
        _events, _active, authority_state = tower._lane_ledger_state()
        report = shared_capacity.authority_read_report(
            authority_state,
            store_id=run_id,
        )
        if issues:
            raise PredecessorReadinessError(
                "capacity:authority_unverified"
            )
        return report


def _runtime_identity(runtime_root: Path) -> dict[str, str]:
    entries, version, _modes = runtime_package._projectable_source_entries(
        runtime_root,
        runtime_package.RUNTIME_ALLOWLIST,
    )
    report = runtime_package._report(version, entries)
    return {
        "generation": report["version"],
        "runtime_package_digest": report["package_digest"],
    }


def _report(
    *,
    runtime_identity: Mapping[str, str] | None,
    authority: Any,
    predecessor: Mapping[str, str] | None,
    capacity: Any,
    active_lane_ids: list[str] | None,
    state_snapshot_sha256: str | None,
    state_unchanged: bool,
    issues: list[str],
) -> dict[str, Any]:
    normalized_issues = sorted(set(issues))
    ready = not normalized_issues
    identity = (
        authority.get("identity")
        if isinstance(authority, Mapping)
        and isinstance(authority.get("identity"), Mapping)
        else {}
    )
    core = {
        "schema": SCHEMA,
        "status": "READY" if ready else "NOT_READY",
        "decision": (
            "PREDECESSOR_CLEAN_TERMINAL"
            if ready
            else "PREDECESSOR_REFUSED"
        ),
        "observer_runtime": (
            dict(runtime_identity)
            if isinstance(runtime_identity, Mapping)
            else None
        ),
        "controller_id": identity.get("controller_id"),
        "predecessor": (
            dict(predecessor)
            if isinstance(predecessor, Mapping) else None
        ),
        "authority_sha256": (
            _sha(authority) if isinstance(authority, Mapping) else None
        ),
        "capacity_sha256": (
            _sha(capacity) if isinstance(capacity, Mapping) else None
        ),
        "active_lane_ids": active_lane_ids,
        "state_snapshot_sha256": state_snapshot_sha256,
        "state_unchanged": state_unchanged,
        "issues": normalized_issues,
        "provider_free": True,
        "counters": dict(_ZERO_COUNTERS),
    }
    return {**core, "report_sha256": _sha(core)}


def validate_report(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    fields = {
        "schema",
        "status",
        "decision",
        "observer_runtime",
        "controller_id",
        "predecessor",
        "authority_sha256",
        "capacity_sha256",
        "active_lane_ids",
        "state_snapshot_sha256",
        "state_unchanged",
        "issues",
        "provider_free",
        "counters",
        "report_sha256",
    }
    core = {key: child for key, child in value.items() if key != "report_sha256"}
    runtime = value.get("observer_runtime")
    ready = value.get("status") == "READY"
    return (
        set(value) == fields
        and value.get("schema") == SCHEMA
        and value.get("status") in {"READY", "NOT_READY"}
        and value.get("decision")
        == (
            "PREDECESSOR_CLEAN_TERMINAL"
            if ready
            else "PREDECESSOR_REFUSED"
        )
        and (
            runtime is None
            or (
                isinstance(runtime, Mapping)
                and set(runtime)
                == {"generation", "runtime_package_digest"}
                and _text(runtime.get("generation"))
                and isinstance(runtime.get("runtime_package_digest"), str)
                and _SHA256.fullmatch(runtime["runtime_package_digest"])
                is not None
            )
        )
        and (
            value.get("controller_id") is None
            or _text(value.get("controller_id"))
        )
        and (
            value.get("predecessor") is None
            or _valid_predecessor(value.get("predecessor"))
        )
        and (
            value.get("predecessor") is None
            or (
                value["predecessor"].get("controller_id")
                == value.get("controller_id")
                and value["predecessor"].get("authority_sha256")
                == value.get("authority_sha256")
            )
        )
        and all(
            child is None
            or isinstance(child, str)
            and _SHA256.fullmatch(child) is not None
            for child in (
                value.get("authority_sha256"),
                value.get("capacity_sha256"),
                value.get("state_snapshot_sha256"),
            )
        )
        and (
            value.get("active_lane_ids") is None
            or isinstance(value.get("active_lane_ids"), list)
            and value["active_lane_ids"]
            == sorted(set(value["active_lane_ids"]))
            and all(_text(lane) for lane in value["active_lane_ids"])
        )
        and type(value.get("state_unchanged")) is bool
        and isinstance(value.get("issues"), list)
        and value["issues"] == sorted(set(value["issues"]))
        and all(_text(issue) for issue in value["issues"])
        and value.get("provider_free") is True
        and value.get("counters") == _ZERO_COUNTERS
        and value.get("report_sha256") == _sha(core)
        and ready
        == (
            value["issues"] == []
            and isinstance(runtime, Mapping)
            and _text(value.get("controller_id"))
            and _valid_predecessor(value.get("predecessor"))
            and isinstance(value.get("authority_sha256"), str)
            and isinstance(value.get("capacity_sha256"), str)
            and value.get("active_lane_ids") == []
            and isinstance(value.get("state_snapshot_sha256"), str)
            and value.get("state_unchanged") is True
        )
    )


def observe_predecessor_readiness(
    *,
    plugin_data: str | os.PathLike[str],
    observer_trust_store: str | os.PathLike[str],
    expected_generation: str,
    expected_runtime_package_digest: str,
    runtime_root: str | os.PathLike[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return one sealed readiness result without changing canonical state."""

    authority: Any = None
    activation: Any = None
    predecessor: dict[str, str] | None = None
    capacity: Any = None
    active_lane_ids: list[str] | None = None
    snapshot_before: str | None = None
    snapshot_after: str | None = None
    runtime_identity: dict[str, str] | None = None
    issues: list[str] = []
    witness_root: Path | None = None
    data = Path(plugin_data).absolute()
    trust_path = Path(observer_trust_store).absolute()
    runtime = (
        Path(runtime_root).absolute()
        if runtime_root is not None
        else Path(__file__).resolve().parents[3]
    )
    store: _ReadOnlyRunStore | None = None
    try:
        # Runtime projections and Codex plugin cache roots may be
        # owner-controlled but group-writable.  World-writable remains unsafe;
        # canonical plugin data and authority files retain the stricter rule.
        runtime = _owned_existing(
            runtime,
            directory=True,
            writable_mask=0o002,
        )
        runtime_identity = _runtime_identity(runtime)
        if runtime_identity != {
            "generation": expected_generation,
            "runtime_package_digest": expected_runtime_package_digest,
        }:
            issues.append("observer:runtime_identity_mismatch")
        data = _owned_existing(data, directory=True)
        trust_path = _owned_existing(trust_path, directory=False)
        database = native_grant_store.canonical_database_path(data)
        database = _owned_existing(database, directory=False)
        witness_root = (
            native_grant_store.canonical_witness_root()
            / native_grant_store.physical_store_sha256(database)
        )
        snapshot_before = _sha(
            {
                "plugin_data": _tree_snapshot(data),
                "witness": _tree_snapshot(witness_root),
                "trust_store": _tree_snapshot(trust_path),
            }
        )
        store = _ReadOnlyRunStore(database)
        grants = _ReadOnlyNativeGrantStore(database)
        authority = grants.canonical_authority()
        owner = (
            authority.get("owner")
            if isinstance(authority, Mapping)
            and isinstance(authority.get("owner"), Mapping)
            else None
        )
        if isinstance(owner, Mapping):
            activation = grants.verified_owner_activation(
                str(owner.get("controller_id")),
                str(owner.get("controller_run_id")),
            )
        predecessor = _predecessor_identity(authority, activation)
        capacity = _capacity_authority(
            store,
            plugin_data=data,
            observer_trust_store=trust_path,
            evaluation_time=(now or datetime.now(timezone.utc)).astimezone(
                timezone.utc
            ),
        )
    except PredecessorReadinessError as error:
        issues.append(str(error))
    except run_store.StoreError as error:
        issues.append(
            "predecessor:store_schema_unsupported"
            if "unsupported schema" in str(error)
            else "predecessor:store_unreadable"
        )
    except (sqlite3.DatabaseError, json.JSONDecodeError):
        issues.append("predecessor:store_unreadable")
    except (OSError, RuntimeError, TypeError, ValueError):
        issues.append("predecessor:authority_unverified")
    finally:
        if store is not None:
            store.close()
        if snapshot_before is not None and witness_root is not None:
            try:
                snapshot_after = _sha(
                    {
                        "plugin_data": _tree_snapshot(data),
                        "witness": _tree_snapshot(witness_root),
                        "trust_store": _tree_snapshot(trust_path),
                    }
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                snapshot_after = None

    state_unchanged = (
        snapshot_before is not None
        and snapshot_after is not None
        and snapshot_before == snapshot_after
    )
    if snapshot_before is not None and not state_unchanged:
        issues.append("observation:state_changed")

    identity = (
        authority.get("identity")
        if isinstance(authority, Mapping)
        and isinstance(authority.get("identity"), Mapping)
        else None
    )
    lifecycle = (
        authority.get("lifecycle")
        if isinstance(authority, Mapping)
        and isinstance(authority.get("lifecycle"), Mapping)
        else None
    )
    if (
        not isinstance(authority, Mapping)
        or authority.get("status") != "VERIFIED"
        or not isinstance(authority.get("owner"), Mapping)
        or not isinstance(identity, Mapping)
        or not _text(identity.get("controller_id"))
        or predecessor is None
    ):
        issues.append("predecessor:authority_unverified")
    if (
        not isinstance(lifecycle, Mapping)
        or lifecycle.get("expected_binding_status") != "TERMINAL"
        or lifecycle.get("terminal") is not True
        or lifecycle.get("pending_intent") is not False
        or lifecycle.get("cleanup_required") is not False
        or lifecycle.get("action_sha256") is not None
        or lifecycle.get("tool_use_id") is not None
    ):
        issues.append("predecessor:lifecycle_not_clean_terminal")

    capacity_state = (
        capacity.get("state")
        if isinstance(capacity, Mapping)
        and isinstance(capacity.get("state"), Mapping)
        else None
    )
    validated = (
        shared_capacity.validate_authority_state(capacity_state)
        if isinstance(capacity_state, Mapping)
        else {"status": "UNKNOWN", "active_lane_ids": None}
    )
    if (
        not isinstance(capacity, Mapping)
        or capacity.get("schema") != shared_capacity.AUTHORITY_READ_SCHEMA
        or capacity.get("status") != "VERIFIED"
        or capacity.get("continuity_verified") is not True
        or capacity.get("reason_codes") != []
        or validated.get("status") != "RESOLVED"
    ):
        issues.append("capacity:authority_unverified")
    active = validated.get("active_lane_ids")
    if isinstance(active, set) and all(isinstance(lane, str) for lane in active):
        active_lane_ids = sorted(active)
    if active_lane_ids is None or active_lane_ids:
        issues.append("capacity:active_lanes")

    report = _report(
        runtime_identity=runtime_identity,
        authority=authority,
        predecessor=predecessor,
        capacity=capacity,
        active_lane_ids=active_lane_ids,
        state_snapshot_sha256=(
            snapshot_after if state_unchanged else snapshot_before
        ),
        state_unchanged=state_unchanged,
        issues=issues,
    )
    if not validate_report(report):
        raise PredecessorReadinessError("predecessor:report_invalid")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-data", type=Path, required=True)
    parser.add_argument("--observer-trust-store", type=Path, required=True)
    parser.add_argument("--expected-generation", required=True)
    parser.add_argument("--expected-runtime-package-digest", required=True)
    args = parser.parse_args(argv)
    try:
        report = observe_predecessor_readiness(
            plugin_data=args.plugin_data,
            observer_trust_store=args.observer_trust_store,
            expected_generation=args.expected_generation,
            expected_runtime_package_digest=(
                args.expected_runtime_package_digest
            ),
        )
    except BaseException:
        report = _report(
            runtime_identity=None,
            authority=None,
            predecessor=None,
            capacity=None,
            active_lane_ids=None,
            state_snapshot_sha256=None,
            state_unchanged=False,
            issues=["predecessor:observer_unavailable"],
        )
    sys.stdout.buffer.write(_canonical(report) + b"\n")
    return 0 if report.get("status") == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
