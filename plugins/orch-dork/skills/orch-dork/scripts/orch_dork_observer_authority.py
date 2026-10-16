#!/usr/bin/env python3
"""Provision and discover one host-owned observer receipt authority.

The private Ed25519 seed, pinned public trust store, and durable replay
database live outside the plugin cache.  Provisioning is create-once and
idempotent: an existing authority is validated, never overwritten or rotated.
Public reports contain identity metadata only and never include private key
bytes or host paths.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
from typing import Any, MutableMapping


def _load_sibling(name: str):
    """Load one runtime sibling when this file has no package context."""

    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name + " unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


try:
    import orch_dork_artifact_attestation as attestation
    import orch_dork_evidence_core as evidence
    import orch_dork_observer_receipt as receipts
except ModuleNotFoundError:  # isolated spec loading and clean package probes.
    attestation = _load_sibling("orch_dork_artifact_attestation")
    evidence = _load_sibling("orch_dork_evidence_core")
    receipts = _load_sibling("orch_dork_observer_receipt")


PROVISION_SCHEMA = "orch-dork/observer-authority-provision/v1"
DISCOVERY_SCHEMA = "orch-dork/observer-authority-discovery/v1"
STATE_RELATIVE_PATH = Path(".local/state/orch-dork/observer-authority")
SEED_FILENAME = "observer-ed25519.seed"
TRUST_STORE_FILENAME = "observer-trust.json"
REPLAY_DB_FILENAME = "observer-replay.sqlite3"
_HOST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}$")


class ObserverAuthorityError(ValueError):
    """A sanitized, stable provisioning failure."""


def _owner_home() -> Path:
    try:
        import pwd

        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, OSError, AttributeError):  # pragma: no cover - non-POSIX fallback.
        return Path.home()


def default_state_dir(*, home: str | os.PathLike[str] | Path | None = None) -> Path:
    """Return the fixed per-owner state directory without consulting XDG."""

    owner_home = Path(home) if home is not None else _owner_home()
    return owner_home / STATE_RELATIVE_PATH


def _target(value: str | os.PathLike[str] | Path | None) -> Path:
    target = default_state_dir() if value is None else Path(value)
    if not target.is_absolute() or target.name != "observer-authority":
        raise ObserverAuthorityError("authority:state_dir_invalid")
    return target


def _owned(info: os.stat_result) -> bool:
    return not hasattr(os, "getuid") or info.st_uid == os.getuid()


def _validate_directory(path: Path, *, exact_mode: int, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ObserverAuthorityError(f"authority:missing:{label}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ObserverAuthorityError(f"authority:unsafe_type:{label}")
    if not _owned(info):
        raise ObserverAuthorityError(f"authority:wrong_owner:{label}")
    if stat.S_IMODE(info.st_mode) != exact_mode:
        raise ObserverAuthorityError(f"authority:unsafe_permissions:{label}")


def _validate_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ObserverAuthorityError(f"authority:missing:{path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ObserverAuthorityError(f"authority:unsafe_type:{path.name}")
    if not _owned(info):
        raise ObserverAuthorityError(f"authority:wrong_owner:{path.name}")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ObserverAuthorityError(f"authority:unsafe_permissions:{path.name}")
    return info


def _read_exact(path: Path, size: int) -> bytes:
    info = _validate_file(path)
    if info.st_size != size:
        raise ObserverAuthorityError(f"authority:size_invalid:{path.name}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        observed = os.fstat(descriptor)
        # Repeat the path-level checks on the open descriptor intentionally:
        # this is the TOCTOU boundary, not duplicated business validation.
        if (
            not stat.S_ISREG(observed.st_mode)
            or not _owned(observed)
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_dev != info.st_dev
            or observed.st_ino != info.st_ino
        ):
            raise ObserverAuthorityError(f"authority:changed_during_read:{path.name}")
        data = b""
        while len(data) <= size:
            chunk = os.read(descriptor, size + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError as exc:
        raise ObserverAuthorityError(f"authority:read_failed:{path.name}") from exc
    finally:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
    if len(data) != size:
        raise ObserverAuthorityError(f"authority:size_invalid:{path.name}")
    return data


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ObserverAuthorityError(f"authority:write_failed:{path.name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _identity(seed: bytes, host_id: str) -> tuple[dict[str, Any], str, str, str]:
    public_key = attestation.ed25519_public_key(seed)
    fingerprint = attestation.sha256_hex(public_key)
    key_id = "observer-" + fingerprint[:24]
    generation = f"observer-v1:{host_id}:{fingerprint[:16]}"
    trust_store = {
        "schema": receipts.TRUST_STORE_SCHEMA,
        "generation": generation,
        "host_id": host_id,
        "keys": [
            {
                "key_id": key_id,
                "algorithm": "ed25519",
                "public_key": base64.b64encode(public_key).decode("ascii"),
                "fingerprint": fingerprint,
                "status": "active",
            }
        ],
    }
    return trust_store, generation, key_id, fingerprint


def _report(
    *,
    disposition: str,
    host_id: str,
    generation: str,
    key_id: str,
    fingerprint: str,
) -> dict[str, Any]:
    return {
        "schema": PROVISION_SCHEMA,
        "status": "PASS",
        "disposition": disposition,
        "host_id": host_id,
        "generation": generation,
        "key_id": key_id,
        "fingerprint": fingerprint,
        "seed_file": SEED_FILENAME,
        "trust_store_file": TRUST_STORE_FILENAME,
        "replay_db_file": REPLAY_DB_FILENAME,
        "private_material_exposed": False,
        "provider_free": True,
        "network_attempts": 0,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def inspect_authority(
    *,
    state_dir: str | os.PathLike[str] | Path | None = None,
    expected_host_id: str | None = None,
) -> dict[str, Any]:
    """Validate an existing complete authority without changing it."""

    target = _target(state_dir)
    _validate_directory(target, exact_mode=0o700, label="state_dir")
    seed_path = target / SEED_FILENAME
    trust_path = target / TRUST_STORE_FILENAME
    replay_path = target / REPLAY_DB_FILENAME
    seed = _read_exact(seed_path, 32)
    _validate_file(trust_path)
    _validate_file(replay_path)
    try:
        store = receipts.ObserverTrustStore.from_host_file(trust_path)
    except receipts.ObserverReceiptError as exc:
        raise ObserverAuthorityError("authority:" + exc.reason) from exc
    if expected_host_id is not None and store.host_id != expected_host_id:
        raise ObserverAuthorityError("authority:host_id_mismatch")
    expected, generation, key_id, fingerprint = _identity(seed, store.host_id)
    if (
        store.generation != generation
        or set(store.keys) != {key_id}
        or store.keys[key_id]["fingerprint"] != fingerprint
        or store.keys[key_id]["public"]
        != base64.b64decode(expected["keys"][0]["public_key"])
    ):
        raise ObserverAuthorityError("authority:trust_seed_mismatch")
    try:
        with sqlite3.connect(
            "file:" + replay_path.as_posix() + "?mode=ro",
            uri=True,
            timeout=1.0,
        ) as connection:
            row = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='observer_nonce'"
            ).fetchone()
    except sqlite3.Error as exc:
        raise ObserverAuthorityError("authority:replay_db_invalid") from exc
    if row != ("observer_nonce",):
        raise ObserverAuthorityError("authority:replay_schema_missing")
    return _report(
        disposition="EXISTING",
        host_id=store.host_id,
        generation=generation,
        key_id=key_id,
        fingerprint=fingerprint,
    )


def _prepare_parent(target: Path) -> None:
    parent = target.parent
    if parent.exists():
        try:
            info = parent.lstat()
        except OSError as exc:
            raise ObserverAuthorityError("authority:parent_unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ObserverAuthorityError("authority:unsafe_parent")
        if not _owned(info) or stat.S_IMODE(info.st_mode) & 0o022:
            raise ObserverAuthorityError("authority:unsafe_parent")
        os.chmod(parent, 0o700)
    else:
        parent.mkdir(mode=0o700, parents=True)
        os.chmod(parent, 0o700)
    _validate_directory(parent, exact_mode=0o700, label="parent")


def _initialize_replay(path: Path) -> None:
    _write_exclusive(path, b"")
    try:
        with sqlite3.connect(path, timeout=1.0) as connection:
            connection.execute(
                "CREATE TABLE observer_nonce (namespace TEXT NOT NULL, nonce TEXT NOT NULL, receipt_sha256 TEXT NOT NULL, PRIMARY KEY(namespace, nonce))"
            )
    except sqlite3.Error as exc:
        raise ObserverAuthorityError("authority:replay_db_create_failed") from exc
    os.chmod(path, 0o600)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def provision_authority(
    *,
    host_id: str,
    state_dir: str | os.PathLike[str] | Path | None = None,
    seed: bytes | None = None,
) -> dict[str, Any]:
    """Create one authority or validate the existing authority in place."""

    if not isinstance(host_id, str) or _HOST_ID.fullmatch(host_id) is None:
        raise ObserverAuthorityError("authority:host_id_invalid")
    if seed is not None and (not isinstance(seed, bytes) or len(seed) != 32):
        raise ObserverAuthorityError("authority:seed_invalid")
    target = _target(state_dir)
    _prepare_parent(target)
    if os.path.lexists(target):
        return inspect_authority(state_dir=target, expected_host_id=host_id)

    selected_seed = os.urandom(32) if seed is None else seed
    trust_store, generation, key_id, fingerprint = _identity(selected_seed, host_id)
    staging = Path(tempfile.mkdtemp(prefix=".observer-authority-", dir=target.parent))
    os.chmod(staging, 0o700)
    try:
        _write_exclusive(staging / SEED_FILENAME, selected_seed)
        _write_exclusive(
            staging / TRUST_STORE_FILENAME,
            evidence.canonical_bytes(trust_store),
        )
        _initialize_replay(staging / REPLAY_DB_FILENAME)
        _fsync_directory(staging)
        try:
            os.rename(staging, target)
        except OSError as exc:
            if os.path.lexists(target):
                return inspect_authority(
                    state_dir=target,
                    expected_host_id=host_id,
                )
            raise ObserverAuthorityError("authority:publish_failed") from exc
        _fsync_directory(target.parent)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    report = inspect_authority(state_dir=target, expected_host_id=host_id)
    report["disposition"] = "CREATED"
    if report["generation"] != generation or report["key_id"] != key_id or report["fingerprint"] != fingerprint:
        raise ObserverAuthorityError("authority:published_identity_mismatch")
    return report


def configure_verifier_environment(
    environ: MutableMapping[str, str] | None = None,
    *,
    state_dir: str | os.PathLike[str] | Path | None = None,
) -> dict[str, Any]:
    """Set missing verifier paths from a validated fixed authority."""

    environment = os.environ if environ is None else environ
    names = (receipts.REPLAY_DB_ENV, receipts.TRUST_STORE_ENV)
    preserved = sorted(name for name in names if environment.get(name))
    missing = [name for name in names if not environment.get(name)]
    if preserved and missing:
        return {
            "schema": DISCOVERY_SCHEMA,
            "status": "REFUSED",
            "disposition": "NOT_CONFIGURED",
            "configured": [],
            "preserved": preserved,
            "issues": ["authority:partial_explicit_environment"],
            "provider_free": True,
        }
    if not missing:
        return {
            "schema": DISCOVERY_SCHEMA,
            "status": "PASS",
            "disposition": "EXPLICIT",
            "configured": [],
            "preserved": preserved,
            "issues": [],
            "provider_free": True,
        }
    target = _target(state_dir)
    try:
        identity = inspect_authority(state_dir=target)
    except ObserverAuthorityError as exc:
        return {
            "schema": DISCOVERY_SCHEMA,
            "status": "REFUSED" if os.path.lexists(target) else "UNAVAILABLE",
            "disposition": "NOT_CONFIGURED",
            "configured": [],
            "preserved": preserved,
            "issues": [str(exc)],
            "provider_free": True,
        }
    defaults = {
        receipts.TRUST_STORE_ENV: str(target / TRUST_STORE_FILENAME),
        receipts.REPLAY_DB_ENV: str(target / REPLAY_DB_FILENAME),
    }
    configured: list[str] = []
    for name in missing:
        environment[name] = defaults[name]
        configured.append(name)
    return {
        "schema": DISCOVERY_SCHEMA,
        "status": "PASS",
        "disposition": "DISCOVERED",
        "configured": sorted(configured),
        "preserved": preserved,
        "host_id": identity["host_id"],
        "generation": identity["generation"],
        "issues": [],
        "provider_free": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--state-dir", default=None)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = provision_authority(
            host_id=args.host_id,
            state_dir=args.state_dir,
        )
    except ObserverAuthorityError as exc:
        report = {
            "schema": PROVISION_SCHEMA,
            "status": "FAIL",
            "disposition": "REFUSED",
            "issues": [str(exc)],
            "private_material_exposed": False,
            "provider_free": True,
        }
    indent = None if args.compact else 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":") if args.compact else None, indent=indent))
    return 0 if report["status"] == "PASS" else 2


__all__ = [
    "DISCOVERY_SCHEMA",
    "PROVISION_SCHEMA",
    "REPLAY_DB_FILENAME",
    "SEED_FILENAME",
    "STATE_RELATIVE_PATH",
    "TRUST_STORE_FILENAME",
    "ObserverAuthorityError",
    "configure_verifier_environment",
    "default_state_dir",
    "inspect_authority",
    "provision_authority",
]


if __name__ == "__main__":
    raise SystemExit(main())
