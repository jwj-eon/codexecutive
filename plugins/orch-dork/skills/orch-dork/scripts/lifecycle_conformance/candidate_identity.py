"""Verify the one permitted cachebuster-only candidate transition.

The runtime package digest intentionally changes across this transition: it
binds both the manifest bytes and the version.  This module records both exact
identities and proves the narrowly allowed relationship between them.  It is
not an execution, release, installation, campaign, or qualification gate.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping

import orch_dork_runtime_package as runtime_package
from lifecycle_conformance import reference_values as rv
from lifecycle_conformance.values import LifecycleContractError, canonical_digest


SCHEMA = "orch-dork/cachebuster-candidate-identity-transition/v1"
_MANIFEST = runtime_package.MANIFEST_PATH
_TOKEN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_REPORT_FIELDS = frozenset(
    {"version", "inventory_hash", "descriptor_hash", "package_digest"}
)


def _require(condition: bool, issue: str) -> None:
    if not condition:
        raise LifecycleContractError("candidate_identity:" + issue)


def _strict_object(data: bytes, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise LifecycleContractError(
                    "candidate_identity:" + label + ":duplicate_key"
                )
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except LifecycleContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleContractError(
            "candidate_identity:" + label + ":invalid_json"
        ) from error
    _require(type(value) is dict, label + ":not_object")
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _public_report(report: Mapping[str, str], label: str) -> dict[str, str]:
    _require(type(report) is dict, label + ":report_type")
    _require(set(report) == _REPORT_FIELDS, label + ":report_shape")
    for field in _REPORT_FIELDS:
        _require(type(report[field]) is str and report[field], label + ":report_field")
    return dict(report)


def _source_manifest(root: Path, label: str) -> tuple[bytes, int]:
    """Read raw bytes and mode through directory descriptors without links."""
    try:
        with ExitStack() as stack:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory = os.open(root, directory_flags)
            stack.callback(os.close, directory)
            parts = Path(_MANIFEST).parts
            for part in parts[:-1]:
                directory = os.open(part, directory_flags, dir_fd=directory)
                stack.callback(os.close, directory)
            descriptor = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
            handle = stack.enter_context(os.fdopen(descriptor, "rb"))
            before = os.fstat(handle.fileno())
            _require(stat.S_ISREG(before.st_mode), label + ":source_manifest_not_regular")
            data = handle.read()
            after = os.fstat(handle.fileno())
            # Reading may update access time; only content/mode changes count.
            _require(
                (before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                label + ":source_manifest_changed",
            )
            return data, stat.S_IMODE(before.st_mode)
    except OSError as error:
        raise LifecycleContractError(
            "candidate_identity:" + label + ":source_manifest_unavailable"
        ) from error


def _side(root: Path, projection: Path, allowlist: tuple[str, ...], label: str) -> dict[str, Any]:
    source_bytes, source_mode = _source_manifest(root, label)
    projection_report = _public_report(
        runtime_package.project_runtime_source(root, projection, allowlist=allowlist),
        label + ":projection",
    )
    validation_report = _public_report(
        runtime_package.validate_runtime_package(
            projection, projection, allowlist=allowlist
        ),
        label + ":validation",
    )
    _require(
        projection_report == validation_report,
        label + ":public_report_mismatch",
    )
    inventory = runtime_package.inventory_runtime(projection, allowlist=allowlist)
    manifest_bytes = (projection / _MANIFEST).read_bytes()
    _require(
        (source_bytes, source_mode) == _source_manifest(root, label)
        and source_bytes == manifest_bytes,
        label + ":source_manifest_changed",
    )
    projected_mode = next(row["mode"] for row in inventory if row["path"] == _MANIFEST)
    manifest = _strict_object(manifest_bytes, label + ":manifest")
    _require(manifest.get("version") == projection_report["version"], label + ":version")
    return {
        "project_runtime_source_report": projection_report,
        "validate_runtime_package_report": validation_report,
        "inventory": inventory,
        "inventory_sha256": canonical_digest(inventory),
        "manifest": {
            "bytes_sha256": _sha256(manifest_bytes),
            "size": len(manifest_bytes),
            "version": manifest["version"],
            # Projection removes umask-dependent group/world write bits from
            # every runtime file; source custody must retain the actual
            # manifest mode preserved by the cachebuster writer.
            "source_mode": source_mode,
            "projected_mode": projected_mode,
        },
        "_manifest_bytes": manifest_bytes,
        "_manifest_object": manifest,
    }


def _plain_side(side: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in side.items() if not key.startswith("_")}


def verify_cachebuster_identity_transition(
    original_root: str | Path,
    candidate_root: str | Path,
) -> rv.FrozenValue:
    """Recompute and seal one exact manifest-only cachebuster transition."""

    original_root = Path(original_root)
    candidate_root = Path(candidate_root)
    paths = tuple(runtime_package.RUNTIME_ALLOWLIST)
    original_declared = runtime_package.read_declared_runtime_allowlist(original_root)
    candidate_declared = runtime_package.read_declared_runtime_allowlist(candidate_root)
    _require(original_declared == paths, "original:declared_allowlist_drift")
    _require(candidate_declared == paths, "candidate:declared_allowlist_drift")
    _require(original_declared == candidate_declared, "declared_allowlist_mismatch")
    _require(_MANIFEST in paths, "manifest_not_allowlisted")
    with tempfile.TemporaryDirectory(prefix="orch-dork-identity-") as temporary:
        temporary_root = Path(temporary)
        original = _side(
            original_root, temporary_root / "original", paths, "original"
        )
        candidate = _side(
            candidate_root, temporary_root / "candidate", paths, "candidate"
        )

    original_manifest = original["_manifest_object"]
    candidate_manifest = candidate["_manifest_object"]
    original_version = original_manifest.get("version")
    candidate_version = candidate_manifest.get("version")
    _require(type(original_version) is str, "original:version")
    _require(type(candidate_version) is str, "candidate:version")
    version_prefix = original_version.split("+", 1)[0]
    prefix = version_prefix + "+codex."
    _require(candidate_version.startswith(prefix), "version_prefix")
    cachebuster = candidate_version[len(prefix) :]
    _require(bool(_TOKEN.fullmatch(cachebuster)), "cachebuster_token")
    _require(candidate_version != original_version, "same_version_noop")

    expected_manifest = dict(original_manifest)
    expected_manifest["version"] = prefix + cachebuster
    expected_bytes = (json.dumps(expected_manifest, indent=2) + "\n").encode("utf-8")
    _require(candidate["_manifest_bytes"] == expected_bytes, "manifest_serialization")
    _require(original["_manifest_bytes"] != candidate["_manifest_bytes"], "manifest_unchanged")

    original_inventory = {row["path"]: row for row in original["inventory"]}
    candidate_inventory = {row["path"]: row for row in candidate["inventory"]}
    _require(set(original_inventory) == set(candidate_inventory), "allowlist_drift")
    changed = [
        path
        for path in sorted(original_inventory)
        if original_inventory[path] != candidate_inventory[path]
    ]
    _require(changed == [_MANIFEST], "projected_runtime_drift")
    _require(
        original["manifest"]["source_mode"] == candidate["manifest"]["source_mode"],
        "source_manifest_mode_drift",
    )
    _require(
        original_inventory[_MANIFEST]["mode"]
        == candidate_inventory[_MANIFEST]["mode"],
        "manifest_mode_drift",
    )

    original_report = original["project_runtime_source_report"]
    candidate_report = candidate["project_runtime_source_report"]
    _require(
        original_report["package_digest"] != candidate_report["package_digest"],
        "package_digest_not_distinct",
    )
    _require(
        original_report["descriptor_hash"] == candidate_report["descriptor_hash"],
        "descriptor_drift",
    )

    return rv.freeze(
        {
            "schema": SCHEMA,
            "status": "CACHEBUSTER_TRANSITION_VERIFIED",
            "original": _plain_side(original),
            "candidate": _plain_side(candidate),
            "transition": {
                "changed_projected_paths": changed,
                "version_prefix": version_prefix,
                "cachebuster": cachebuster,
                "package_digests_distinct": True,
                "metadata_only": True,
            },
            "allowlist": list(paths),
            "allowlist_sha256": canonical_digest(list(paths)),
            "campaign_authority": False,
            "release_authority": False,
            "live_authority": False,
            "qualification_authority": False,
        }
    )


def validate_cachebuster_identity_transition(
    original_root: str | Path,
    candidate_root: str | Path,
    report: rv.FrozenValue,
) -> rv.FrozenValue:
    """Re-read both trees and require the exact immutable derived report."""

    _require(type(report) is rv.FrozenValue, "report_not_immutable")
    rebuilt = verify_cachebuster_identity_transition(original_root, candidate_root)
    _require(report == rebuilt, "report_binding")
    return rebuilt
