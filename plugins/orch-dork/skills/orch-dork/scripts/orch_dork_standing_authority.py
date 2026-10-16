#!/usr/bin/env python3
"""Deterministically bind known bounded run classes to standing Owner authority."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


STANDING_OWNER_AUTHORITY_SCHEMA = "orch-dork/standing-owner-authority/v1"
STANDING_OWNER_POLICY_SCHEMA = "orch-dork/standing-owner-policy/v1"
STANDING_OWNER_REGISTRATION_CLAIM_SCHEMA = (
    "orch-dork/standing-owner-registration-claim/v1"
)
STANDING_OWNER_POLICY_SHA256 = (
    "d8c535db1ed867fd76dc9059d5c5f4560687bb79375130937dfca894cf5269a3"
)
TRANCHE_DISPATCH_AUTHORITY_CLASS = "tranche-dispatch"
QUALIFIED_RECOVERY_AUTHORITY_CLASS = "issue111-v8-qualified-recovery"

_ELIGIBLE_AUTHORITY_CLASSES = (
    QUALIFIED_RECOVERY_AUTHORITY_CLASS,
    TRANCHE_DISPATCH_AUTHORITY_CLASS,
)
_AUTHORITY_CLASSES = frozenset(_ELIGIBLE_AUTHORITY_CLASSES)
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_STATE_RELATIVE_PATH = Path(".local/state/orch-dork/standing-authority")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def standing_owner_policy() -> dict[str, Any]:
    """Return the closed versioned policy that permits automatic bindings."""

    core = {
        "schema": STANDING_OWNER_POLICY_SCHEMA,
        "eligible_authority_classes": list(_ELIGIBLE_AUTHORITY_CLASSES),
        "scope_admission": "exact_class_contract_validation",
        "grant_cardinality_per_binding": 1,
        "registration_claim": "fixed_owner_local_create_only",
        "continuing_authority_after_terminal": False,
    }
    if _sha256(core) != STANDING_OWNER_POLICY_SHA256:
        raise RuntimeError("standing Owner policy changed without a version bump")
    return {
        "policy": core,
        "policy_sha256": STANDING_OWNER_POLICY_SHA256,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def standing_owner_binding_material(value: Any) -> dict[str, Any] | None:
    """Project and validate the exact binding carried by a standing grant."""

    if not isinstance(value, Mapping):
        return None
    material_fields = {
        "schema",
        "policy_sha256",
        "authority_class",
        "authority_scope_sha256",
        "authority_source_sha256",
    }
    report_fields = material_fields | {
        "status",
        "issues",
        "provider_free",
        "model_calls",
        "hosted_calls",
    }
    fields = set(value)
    if fields == report_fields:
        if (
            value.get("status") != "PASS"
            or value.get("issues") != []
            or value.get("provider_free") is not True
            or type(value.get("model_calls")) is not int
            or value.get("model_calls") != 0
            or type(value.get("hosted_calls")) is not int
            or value.get("hosted_calls") != 0
        ):
            return None
    elif fields != material_fields:
        return None
    core = {
        "schema": value.get("schema"),
        "policy_sha256": value.get("policy_sha256"),
        "authority_class": value.get("authority_class"),
        "authority_scope_sha256": value.get("authority_scope_sha256"),
    }
    source = value.get("authority_source_sha256")
    if (
        core["schema"] != STANDING_OWNER_AUTHORITY_SCHEMA
        or core["policy_sha256"] != STANDING_OWNER_POLICY_SHA256
        or core["authority_class"] not in _AUTHORITY_CLASSES
        or not isinstance(core["authority_scope_sha256"], str)
        or _SHA256.fullmatch(core["authority_scope_sha256"]) is None
        or not isinstance(source, str)
        or _SHA256.fullmatch(source) is None
        or source != _sha256(core)
    ):
        return None
    return {**core, "authority_source_sha256": source}


def bind_standing_owner_authority(
    *, authority_class: Any, authority_scope_sha256: Any
) -> dict[str, Any]:
    """Bind one known, already-validated scope to the standing Owner policy."""

    issues: list[str] = []
    if authority_class not in _AUTHORITY_CLASSES:
        issues.append("standing_authority:class_invalid")
    if (
        not isinstance(authority_scope_sha256, str)
        or _SHA256.fullmatch(authority_scope_sha256) is None
    ):
        issues.append("standing_authority:scope_invalid")
    if issues:
        return {
            "schema": STANDING_OWNER_AUTHORITY_SCHEMA,
            "status": "FAIL",
            "issues": sorted(set(issues)),
            "authority_class": None,
            "authority_scope_sha256": None,
            "authority_source_sha256": None,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }

    policy = standing_owner_policy()
    binding_core = {
        "schema": STANDING_OWNER_AUTHORITY_SCHEMA,
        "policy_sha256": policy["policy_sha256"],
        "authority_class": authority_class,
        "authority_scope_sha256": authority_scope_sha256,
    }
    return {
        **binding_core,
        "status": "PASS",
        "issues": [],
        "authority_source_sha256": _sha256(binding_core),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _owner_home() -> Path:
    try:
        import pwd

        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, OSError, AttributeError):  # pragma: no cover
        return Path.home()


def default_state_dir() -> Path:
    """Return the fixed owner-local root for atomic registration claims."""

    return _owner_home() / _STATE_RELATIVE_PATH


def _owned(info: os.stat_result) -> bool:
    return not hasattr(os, "getuid") or info.st_uid == os.getuid()


def _claim_report(
    *, status: str, issues: list[str], claim_sha256: str | None
) -> dict[str, Any]:
    return {
        "schema": STANDING_OWNER_REGISTRATION_CLAIM_SCHEMA,
        "status": status,
        "issues": sorted(set(issues)),
        "claim_sha256": claim_sha256,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def claim_standing_owner_registration(
    value: Any,
    *,
    campaign_sha256: Any,
    grant_sha256: Any,
    registered_at_ms: Any,
) -> dict[str, Any]:
    """Atomically consume one standing binding before campaign registration."""

    binding = standing_owner_binding_material(value)
    if (
        binding is None
        or not isinstance(campaign_sha256, str)
        or _SHA256.fullmatch(campaign_sha256) is None
        or not isinstance(grant_sha256, str)
        or _SHA256.fullmatch(grant_sha256) is None
        or type(registered_at_ms) is not int
        or registered_at_ms < 0
    ):
        return _claim_report(
            status="FAIL",
            issues=["standing_authority:registration_invalid"],
            claim_sha256=None,
        )
    target = default_state_dir()
    try:
        if not target.is_absolute() or target.name != "standing-authority":
            raise OSError
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = target.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or not _owned(info)
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise OSError
        core = {
            "schema": STANDING_OWNER_REGISTRATION_CLAIM_SCHEMA,
            "binding": binding,
            "campaign_sha256": campaign_sha256,
            "grant_sha256": grant_sha256,
            "registered_at_ms": registered_at_ms,
        }
        claim_sha256 = _sha256(core)
        payload = _canonical({**core, "claim_sha256": claim_sha256}) + b"\n"
        path = target / (binding["authority_source_sha256"] + ".json")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
    except OSError:
        return _claim_report(
            status="FAIL",
            issues=["standing_authority:state_unavailable"],
            claim_sha256=None,
        )
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return _claim_report(
            status="FAIL",
            issues=["standing_authority:already_registered"],
            claim_sha256=None,
        )
    except OSError:
        return _claim_report(
            status="FAIL",
            issues=["standing_authority:state_unavailable"],
            claim_sha256=None,
        )
    try:
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(target, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        return _claim_report(
            status="FAIL",
            issues=["standing_authority:state_unavailable"],
            claim_sha256=None,
        )
    return _claim_report(
        status="PASS", issues=[], claim_sha256=claim_sha256
    )


__all__ = [
    "STANDING_OWNER_AUTHORITY_SCHEMA",
    "STANDING_OWNER_POLICY_SCHEMA",
    "STANDING_OWNER_POLICY_SHA256",
    "STANDING_OWNER_REGISTRATION_CLAIM_SCHEMA",
    "TRANCHE_DISPATCH_AUTHORITY_CLASS",
    "QUALIFIED_RECOVERY_AUTHORITY_CLASS",
    "standing_owner_policy",
    "standing_owner_binding_material",
    "bind_standing_owner_authority",
    "default_state_dir",
    "claim_standing_owner_registration",
]
