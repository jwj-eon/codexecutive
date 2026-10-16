#!/usr/bin/env python3
"""Provider-free clean-machine update acceptance.

Issue 45 deliberately exercises updates in *disposable* roots.  The module is
an acceptance seam, not an update service: it never chooses a marketplace,
reads credentials, contacts a provider, or writes the installed cache.  A
candidate is verified completely before it is staged.  A compatible candidate
is activated only when the caller explicitly supplies a fresh task boundary;
every refusal leaves the active generation byte-for-byte unchanged.

The public helpers accept ordinary JSON mappings so a later integration lane
can feed evidence from the clean-install and adoption lanes without importing
their implementation details.  Paths are optional.  When a disposable root
is supplied, ``apply_clean_update`` uses an fsynced temporary file and an
atomic replace, and records only generic (sanitised) resource-access labels
in its receipt.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Mapping, MutableMapping, Sequence


SCHEMA = "orch-dork/clean-update-acceptance/v1"
PROGRAM_SCHEMA = "orch-dork/clean-update-program/v1"
REPORT_SCHEMA = "orch-dork/clean-update-report/v1"
ACCEPTANCE_SCHEMA = "orch-dork/clean-update-acceptance-report/v1"
POLICY_VERSION = "clean-update-policy/v1"

PASS = "PASS"
DENY = "DENY"
DEFERRED = "DEFERRED"
UNAVAILABLE = "UNAVAILABLE"

READ_ONLY_DISPOSITION = "READ_ONLY_PRIOR_GENERATION_PRESERVED"
COMMITTED_DISPOSITION = "COMMITTED_COMPATIBLE_UPDATE"
FRESH_BOUNDARY_DISPOSITION = "DEFERRED_UNTIL_FRESH_BOUNDARY"

# These names are stable evidence selectors.  They intentionally contain no
# user paths, prompts, digests, or other values unsuitable for approval text.
FAILURE_CASES: tuple[str, ...] = (
    "incompatible_newer",
    "security_rollback",
    "interrupted_install",
    "stale_cache",
    "missing_interpreter",
    "source_package_mismatch",
    "deleted_binding",
    "deleted_adapter",
    "disabled_untrusted_hook",
    "registry_loss",
    "failed_migration",
    "tampered_artifact",
)

REASON_CODES = frozenset(
    {
        "update:compatible_newer",
        "update:fresh_boundary_required",
        "update:incompatible_newer",
        "update:security_rollback",
        "update:interrupted_install",
        "update:stale_cache",
        "update:missing_interpreter",
        "update:source_package_mismatch",
        "update:deleted_binding",
        "update:deleted_adapter",
        "update:hook_untrusted_or_disabled",
        "update:registry_loss",
        "update:failed_migration",
        "update:artifact_tampered",
        "update:artifact_signature_missing",
        "update:artifact_signature_invalid",
        "update:artifact_digest_mismatch",
        "update:project_generation_changed",
        "update:profile_not_disposable",
        "update:malformed_program",
        "update:cache_write_forbidden",
        "update:source_revision_mismatch",
        "update:unknown_failure",
    }
)

_HEX64 = re.compile(r"\A[0-9a-fA-F]{64}\Z")
_VERSION = re.compile(r"\A(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?(?P<tail>.*)\Z")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode JSON deterministically without a provider or filesystem read."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8", "strict")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(canonical_json_bytes(value))


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX64.fullmatch(value.removeprefix("sha256:")))


def _normalise_digest(value: Any) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("sha256")
    if not isinstance(value, str):
        return None
    value = value.strip().lower().removeprefix("sha256:")
    return value if _HEX64.fullmatch(value) else None


def _label_digest(value: Any) -> str | None:
    digest = _normalise_digest(value)
    return f"sha256:{digest[:12]}" if digest else None


def _version_key(value: Any) -> tuple[int, int, int, int, str]:
    """Return a deterministic comparison key for package versions.

    The package uses conventional ``major.minor.patch`` versions with optional
    prerelease/build suffixes.  Build metadata is not allowed to make a lower
    release appear newer; prereleases sort before the corresponding final.
    """

    text = str(value or "0.0.0").strip()
    match = _VERSION.match(text)
    if not match:
        return (0, 0, 0, 0, text)
    major = int(match.group("major") or 0)
    minor = int(match.group("minor") or 0)
    patch = int(match.group("patch") or 0)
    tail = match.group("tail") or ""
    # ``-rc`` is a prerelease; ``+build`` is ignored for ordering.
    prerelease = 0 if tail.startswith("-") else 1
    label = tail.split("+", 1)[0]
    return (major, minor, patch, prerelease, label)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first(mapping: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _bool(mapping: Mapping[str, Any], *keys: str, default: bool = False) -> bool:
    value = _first(mapping, *keys, default=default)
    return bool(value)


def _int(mapping: Mapping[str, Any], *keys: str, default: int = 0) -> int:
    value = _first(mapping, *keys, default=default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _section(program: Mapping[str, Any], *names: str) -> dict[str, Any]:
    """Normalise a section while allowing compact fixture mappings."""

    for name in names:
        candidate = program.get(name)
        if isinstance(candidate, Mapping):
            return dict(candidate)
    return dict(program)


def _current(program: Mapping[str, Any]) -> dict[str, Any]:
    return _section(program, "current", "active", "prior_generation", "pinned_generation")


def _candidate(program: Mapping[str, Any]) -> dict[str, Any]:
    return _section(program, "candidate", "update", "new_generation", "new")


def _field(mapping: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    return _first(mapping, *keys, default=default)


def _generation(mapping: Mapping[str, Any], *, default: int = 0) -> int:
    return _int(mapping, "generation", "plugin_generation", "runtime_generation", default=default)


def _project_generation(mapping: Mapping[str, Any], *, default: Any = None) -> Any:
    return _field(
        mapping,
        "project_generation",
        "pinned_project_generation",
        "project_pin",
        default=default,
    )


def _security_generation(mapping: Mapping[str, Any], *, default: int = 0) -> int:
    return _int(mapping, "security_generation", "minimum_security_generation", "security", default=default)


def _package_digest(mapping: Mapping[str, Any]) -> str | None:
    return _normalise_digest(
        _field(
            mapping,
            "package_sha256",
            "package_digest",
            "artifact_sha256",
            "artifact_digest",
            "installed_package_sha256",
        )
    )


def _source_digest(mapping: Mapping[str, Any]) -> str | None:
    return _normalise_digest(
        _field(mapping, "source_package_sha256", "source_digest", "source_tree_sha256", "source_package_digest")
    )


def _project_pin(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Extract fields whose exact equality protects a pinned project ground."""

    pin: dict[str, Any] = {}
    for key in (
        "project_generation",
        "pinned_project_generation",
        "project_protocol",
        "protocol",
        "binding_sha256",
        "project_binding_sha256",
        "adapter_sha256",
        "project_adapter_sha256",
        "authority",
        "writable_scope_sha256",
    ):
        if key in mapping and mapping[key] is not None:
            pin[key] = copy.deepcopy(mapping[key])
    nested = mapping.get("project")
    if isinstance(nested, Mapping):
        pin["project"] = copy.deepcopy(dict(nested))
    return pin


def _fresh_boundary(program: Mapping[str, Any]) -> bool:
    boundary = _as_mapping(program.get("boundary"))
    if boundary:
        return _bool(boundary, "fresh_task", "fresh_boundary", "new_task", default=False)
    return _bool(program, "fresh_task", "fresh_boundary", "new_task_boundary", default=False)


def _fault(program: Mapping[str, Any], candidate: Mapping[str, Any], *keys: str) -> bool:
    faults = _as_mapping(program.get("faults"))
    for mapping in (faults, candidate, program):
        for key in keys:
            if key in mapping and bool(mapping[key]):
                return True
    return False


def _failure_case(program: Mapping[str, Any], candidate: Mapping[str, Any]) -> str | None:
    value = _first(program, "failure_case", "case", "scenario", default=None)
    if value is None:
        value = _first(candidate, "failure_case", "case", "scenario", default=None)
    if value is None:
        return None
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "incompatible": "incompatible_newer",
        "rollback": "security_rollback",
        "security_rollback": "security_rollback",
        "interrupted": "interrupted_install",
        "stale": "stale_cache",
        "missing": "missing_interpreter",
        "source_mismatch": "source_package_mismatch",
        "binding_deleted": "deleted_binding",
        "adapter_deleted": "deleted_adapter",
        "untrusted_hook": "disabled_untrusted_hook",
        "hook_disabled": "disabled_untrusted_hook",
        "registry_missing": "registry_loss",
        "migration_failed": "failed_migration",
        "tampered": "tampered_artifact",
    }
    return aliases.get(text, text)


def _safe_resource_access(*, committed: bool = False) -> list[dict[str, str]]:
    access = [
        {"operation": "read", "phase": "preflight", "resource": "disposable update metadata"},
        {"operation": "read", "phase": "verification", "resource": "signed artifact and local trust evidence"},
        {"operation": "read", "phase": "preservation", "resource": "pinned project generation"},
    ]
    if committed:
        access.extend(
            [
                {"operation": "write", "phase": "stage", "resource": "disposable staged generation"},
                {"operation": "write", "phase": "commit", "resource": "disposable active generation"},
            ]
        )
    return access


def _receipt(
    status: str,
    reason: str,
    *,
    disposition: str,
    preserved: bool,
    committed: bool,
    current: Mapping[str, Any],
    candidate: Mapping[str, Any],
    reason_details: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the human-safe portion of an evidence record."""

    details = tuple(str(item) for item in reason_details if item)
    return {
        "schema": "orch-dork/clean-update-receipt/v1",
        "status": status,
        "reason": reason,
        "disposition": disposition,
        "prior_generation_preserved": bool(preserved),
        "committed": bool(committed),
        "current_generation": _generation(current),
        "candidate_generation": _generation(candidate),
        "pinned_project_generation": _project_generation(current),
        "reason_details": list(details),
        "network_attempts": 0,
        "credential_reads": 0,
        "hosted_calls": 0,
    }


def _report(
    status: str,
    reason: str,
    *,
    current: Mapping[str, Any],
    candidate: Mapping[str, Any],
    disposition: str = READ_ONLY_DISPOSITION,
    preserved: bool = True,
    committed: bool = False,
    issues: Iterable[str] = (),
    evidence: Mapping[str, Any] | None = None,
    reason_details: Iterable[str] = (),
) -> dict[str, Any]:
    issue_list = [str(issue) for issue in issues if issue]
    result: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "policy_version": POLICY_VERSION,
        "status": status,
        "decision": reason,
        "reason": reason,
        "disposition": disposition,
        "read_only": not committed,
        "prior_generation_preserved": bool(preserved),
        "mutation_performed": bool(committed),
        "committed": bool(committed),
        "issues": issue_list,
        "network_attempts": 0,
        "credential_reads": 0,
        "hosted_calls": 0,
        "provider_free": True,
        "resource_access": _safe_resource_access(committed=committed),
        "receipt": _receipt(
            status,
            reason,
            disposition=disposition,
            preserved=preserved,
            committed=committed,
            current=current,
            candidate=candidate,
            reason_details=reason_details,
        ),
    }
    if evidence:
        # Evidence is machine-facing.  Keep the receipt above intentionally
        # free of paths, signatures, and full cryptographic identities.
        result["evidence"] = dict(evidence)
    return result


def _artifact_bytes(candidate: Mapping[str, Any]) -> bytes | None:
    value = _field(candidate, "artifact_bytes", "package_bytes", "artifact", "package", default=None)
    if value is None:
        path = _field(candidate, "artifact_path", "package_path", default=None)
        if path is None:
            return None
        try:
            return Path(str(path)).read_bytes()
        except OSError:
            return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        # JSON fixtures use UTF-8 package bodies.  A caller may opt into
        # base64 explicitly for binary packages.
        if _bool(candidate, "artifact_base64", "package_base64", default=False):
            try:
                return base64.b64decode(value.encode("ascii"), validate=True)
            except (ValueError, UnicodeError):
                return None
        return value.encode("utf-8", "strict")
    return None


def _verify_detached_attestation(candidate: Mapping[str, Any], data: bytes) -> tuple[bool, str]:
    """Verify Issue 50 detached evidence when supplied.

    The import is intentionally optional: clean-update fixtures can use the
    compact local signer marker, while a packaged integration may provide the
    full offline DSSE envelope and trust store from Issue 50.
    """

    envelope = _first(candidate, "envelope", "attestation", "dsse", default=None)
    trust_store = _first(candidate, "trust_store", "trust", default=None)
    if not isinstance(envelope, Mapping) or not isinstance(trust_store, Mapping):
        signed = _first(candidate, "signature_status", "signed_status", default=None)
        marker = _bool(candidate, "signed", "artifact_verified", "signature_verified", default=False)
        expected = _normalise_digest(_first(candidate, "signature_digest", "signed_artifact_sha256", default=None))
        actual = _sha256_bytes(data)
        if marker and (expected is None or expected == actual):
            return True, "local_fixture_signature"
        if signed is not None and str(signed).upper() in {PASS, "VERIFIED", "VALID"} and (expected is None or expected == actual):
            return True, "local_fixture_signature"
        return False, "update:artifact_signature_missing"
    try:
        script_dir = Path(__file__).resolve().parent
        import importlib.util

        module_path = script_dir / "orch_dork_artifact_attestation.py"
        spec = importlib.util.spec_from_file_location("orch_dork_artifact_attestation_for_issue45", module_path)
        if spec is None or spec.loader is None:
            return False, "update:artifact_signature_invalid"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.verify_artifact_attestation(
            data,
            envelope,
            trust_store,
            expected_subject=_first(candidate, "subject", "expected_subject", default="orch-dork-package"),
            expected_sbom_digest=_first(candidate, "sbom_digest", "expected_sbom_digest", default=None),
            expected_provenance_digest=_first(candidate, "provenance_digest", "expected_provenance_digest", default=None),
        )
        return result.get("status") == PASS, "update:artifact_signature_invalid" if result.get("status") != PASS else "attestation"
    except Exception:  # pragma: no cover - defensive boundary for hostile fixture input
        return False, "update:artifact_signature_invalid"


def verify_signed_artifact(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Verify bytes, digest declaration, source/package parity, and signature."""

    data = _artifact_bytes(candidate)
    if data is None:
        return {"status": DENY, "reason": "update:artifact_signature_missing", "verified_before_staging": False}
    actual_digest = _sha256_bytes(data)
    declared_digest = _package_digest(candidate)
    if declared_digest is None:
        return {
            "status": DENY,
            "reason": "update:artifact_digest_mismatch",
            "artifact_digest": actual_digest,
            "verified_before_staging": False,
        }
    if declared_digest != actual_digest:
        return {
            "status": DENY,
            "reason": "update:artifact_digest_mismatch",
            "artifact_digest": actual_digest,
            "declared_artifact_digest": declared_digest,
            "verified_before_staging": False,
        }
    source_digest = _source_digest(candidate)
    if source_digest is not None and source_digest != actual_digest:
        return {
            "status": DENY,
            "reason": "update:source_package_mismatch",
            "artifact_digest": actual_digest,
            "source_digest": source_digest,
            "verified_before_staging": False,
        }
    verified, mode = _verify_detached_attestation(candidate, data)
    if not verified:
        return {
            "status": DENY,
            "reason": mode,
            "artifact_digest": actual_digest,
            "verified_before_staging": False,
        }
    return {
        "status": PASS,
        "reason": "update:artifact_verified",
        "artifact_digest": actual_digest,
        "signature_mode": mode,
        "verified_before_staging": True,
    }


def compatibility_decision(
    current: Mapping[str, Any] | Mapping[str, Mapping[str, Any]],
    candidate: Mapping[str, Any] | None = None,
) -> tuple[str, list[str]]:
    """Classify a candidate without mutating anything.

    The return shape mirrors the Issue 43 migration seam: a stable decision
    string followed by named issues.  Callers may pass ``program`` as the
    first mapping or pass ``current, candidate`` separately.
    """

    if candidate is None and isinstance(current.get("candidate"), Mapping):  # type: ignore[union-attr]
        program = _as_mapping(current)
        current = _current(program)
        candidate = _candidate(program)
    elif candidate is None:
        candidate = {}
    old = _as_mapping(current)
    new = _as_mapping(candidate)
    old_version = _version_key(_field(old, "version", "plugin_version", default="0.0.0"))
    new_version = _version_key(_field(new, "version", "plugin_version", default="0.0.0"))
    old_security = _security_generation(old)
    new_security = _security_generation(new, default=old_security)
    if new_security < old_security or new_version < old_version:
        return "SECURITY_ROLLBACK", ["update:security_rollback"]
    if new_version == old_version and _generation(new) <= _generation(old):
        return "NOT_NEWER", ["update:security_rollback"]
    protocol_old = _field(old, "protocol", "project_protocol", default=None)
    protocol_new = _field(new, "protocol", "project_protocol", default=protocol_old)
    if _bool(new, "incompatible", "incompatible_newer", "protocol_incompatible", default=False):
        return "INCOMPATIBLE_NEWER", ["update:incompatible_newer"]
    if protocol_old and protocol_new and str(protocol_old) != str(protocol_new):
        # A caller can explicitly mark a protocol as supported.  Otherwise a
        # changed project-ground protocol is an incompatible update.
        supported = _first(new, "supported_protocols", "compatible_protocols", default=())
        if str(protocol_new) not in {str(item) for item in supported}:
            return "INCOMPATIBLE_NEWER", ["update:incompatible_newer"]
    old_pin = _project_pin(old)
    new_pin = _project_pin(new)
    for key, old_value in old_pin.items():
        if key in new_pin and new_pin[key] != old_value:
            return "PROJECT_GENERATION_CHANGED", ["update:project_generation_changed"]
    if _bool(new, "compatible", "compatible_newer", default=True) is False:
        return "INCOMPATIBLE_NEWER", ["update:incompatible_newer"]
    return "COMPATIBLE_NEWER", []


def _profile_is_disposable(program: Mapping[str, Any]) -> bool:
    if _bool(program, "allow_real_cache", "real_cache", "installed_cache", default=False):
        return False
    if "disposable" in program and not bool(program.get("disposable")):
        return False
    root = _first(program, "profile_root", "root", "disposable_root", default=None)
    if root is None:
        # Pure in-memory evaluation is safe; applying it still requires a
        # disposable marker when a filesystem destination is requested.
        return True
    path = Path(str(root))
    marker = path / ".clean-machine-disposable"
    return bool(program.get("disposable", False)) or marker.exists()


def _failure_checks(program: Mapping[str, Any], current: Mapping[str, Any], candidate: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Return ordered named stops; the first is the authoritative reason."""

    failure = _failure_case(program, candidate)
    checks: list[tuple[str, str]] = []
    if failure in {"incompatible_newer"} or _fault(program, candidate, "incompatible_newer", "incompatible", "protocol_incompatible"):
        checks.append(("update:incompatible_newer", "incompatible_newer"))
    if failure in {"security_rollback"}:
        checks.append(("update:security_rollback", "security_rollback"))
    if failure in {"interrupted_install"} or _fault(program, candidate, "interrupted_install", "interrupt_before_commit", "simulate_interruption"):
        checks.append(("update:interrupted_install", "interrupted_install"))
    if failure in {"stale_cache"} or _fault(program, candidate, "stale_cache", "cache_stale"):
        checks.append(("update:stale_cache", "stale_cache"))
    if failure in {"missing_interpreter"} or _fault(program, candidate, "missing_interpreter", "interpreter_missing", "interpreter_unavailable"):
        checks.append(("update:missing_interpreter", "missing_interpreter"))
    interpreter = _as_mapping(_first(candidate, "interpreter", default={}))
    if interpreter and (_bool(interpreter, "available", "present", default=True) is False):
        checks.append(("update:missing_interpreter", "missing_interpreter"))
    if failure in {"source_package_mismatch"} or _fault(program, candidate, "source_package_mismatch", "source_mismatch"):
        checks.append(("update:source_package_mismatch", "source_package_mismatch"))
    if failure in {"deleted_binding"} or _fault(program, candidate, "deleted_binding", "binding_deleted", "project_binding_missing"):
        checks.append(("update:deleted_binding", "deleted_binding"))
    if failure in {"deleted_adapter"} or _fault(program, candidate, "deleted_adapter", "adapter_deleted", "project_adapter_missing"):
        checks.append(("update:deleted_adapter", "deleted_adapter"))
    if failure in {"disabled_untrusted_hook"} or _fault(program, candidate, "disabled_untrusted_hook", "hook_disabled", "hook_untrusted", "untrusted_hook"):
        checks.append(("update:hook_untrusted_or_disabled", "disabled_untrusted_hook"))
    hook = _as_mapping(_first(candidate, "hook", default={}))
    if hook and (_bool(hook, "enabled", default=True) is False or _bool(hook, "trusted", default=True) is False):
        checks.append(("update:hook_untrusted_or_disabled", "disabled_untrusted_hook"))
    if failure in {"registry_loss"} or _fault(program, candidate, "registry_loss", "registry_missing", "enrollment_registry_missing"):
        checks.append(("update:registry_loss", "registry_loss"))
    registry = _as_mapping(_first(candidate, "registry", default={}))
    if registry and (_bool(registry, "present", "available", default=True) is False):
        checks.append(("update:registry_loss", "registry_loss"))
    if failure in {"failed_migration"} or _fault(program, candidate, "failed_migration", "migration_failed"):
        checks.append(("update:failed_migration", "failed_migration"))
    migration = _as_mapping(_first(candidate, "migration", default={}))
    if migration and str(_first(migration, "status", "result", default=PASS)).upper() not in {PASS, "READY", "OK"}:
        checks.append(("update:failed_migration", "failed_migration"))
    # The exact security/version comparison is deliberately last among the
    # semantic checks, after explicit fixture faults have named their case.
    decision, issues = compatibility_decision(current, candidate)
    if decision == "SECURITY_ROLLBACK":
        checks.append((issues[0], "security_rollback"))
    elif decision == "INCOMPATIBLE_NEWER":
        checks.append((issues[0], "incompatible_newer"))
    return checks


def evaluate_clean_update(program: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only validation of a candidate update."""

    if not isinstance(program, Mapping):
        empty: dict[str, Any] = {}
        return _report(DENY, "update:malformed_program", current=empty, candidate=empty, issues=["program:not_mapping"])
    current = _current(program)
    candidate = _candidate(program)
    if not current or not candidate:
        return _report(DENY, "update:malformed_program", current=current, candidate=candidate, issues=["program:current_or_candidate_missing"])
    if not _profile_is_disposable(program):
        return _report(DENY, "update:profile_not_disposable", current=current, candidate=candidate, issues=["profile:real_cache_or_marker_missing"])

    checks = _failure_checks(program, current, candidate)
    if checks:
        reason, case = checks[0]
        # A source/package mismatch can be proven by bytes even when the
        # fixture did not set an explicit fault.
        return _report(
            DENY,
            reason,
            current=current,
            candidate=candidate,
            issues=[reason, f"failure_case:{case}"],
            evidence={"failure_case": case},
        )

    artifact = verify_signed_artifact(candidate)
    if artifact["status"] != PASS:
        reason = str(artifact.get("reason") or "update:artifact_signature_invalid")
        if reason not in REASON_CODES:
            reason = "update:artifact_signature_invalid"
        return _report(
            DENY,
            reason,
            current=current,
            candidate=candidate,
            issues=[reason],
            evidence=artifact,
        )

    # Preserve every pinned project field.  A candidate may omit fields (the
    # active pin is then inherited), but it may never change one silently.
    old_pin = _project_pin(current)
    new_pin = _project_pin(candidate)
    for key, old_value in old_pin.items():
        if key in new_pin and new_pin[key] != old_value:
            return _report(
                DENY,
                "update:project_generation_changed",
                current=current,
                candidate=candidate,
                issues=["update:project_generation_changed"],
            )

    if not _fresh_boundary(program):
        return _report(
            DEFERRED,
            "update:fresh_boundary_required",
            current=current,
            candidate=candidate,
            disposition=FRESH_BOUNDARY_DISPOSITION,
            issues=["update:fresh_boundary_required"],
            evidence=artifact,
        )
    return _report(
        PASS,
        "update:compatible_newer",
        current=current,
        candidate=candidate,
        disposition=COMMITTED_DISPOSITION,
        preserved=True,
        committed=False,
        evidence=artifact,
    )


def _state_file(root: Path, program: Mapping[str, Any]) -> Path:
    explicit = _first(program, "active_state_path", "state_path", default=None)
    if explicit:
        return Path(str(explicit))
    return root / "state" / "active.json"


def _read_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".clean-update-stage-", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # The data replacement is still atomic on platforms without an
            # fsync-able directory; the acceptance report names no path.
            pass
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _state_for_commit(current: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    state = copy.deepcopy(dict(current))
    for key, value in candidate.items():
        if key in {"project", "project_generation", "pinned_project_generation", "project_protocol", "protocol", "binding_sha256", "project_binding_sha256", "adapter_sha256", "project_adapter_sha256", "authority", "writable_scope_sha256"}:
            # Exact project-ground pin is inherited from the active state.
            continue
        state[key] = copy.deepcopy(value)
    state["generation"] = _generation(candidate, default=_generation(current) + 1)
    state["version"] = _field(candidate, "version", "plugin_version", default=_field(current, "version", "plugin_version", default="0.0.0"))
    state["project_generation"] = _project_generation(current)
    state["pinned_project_generation"] = _project_generation(current)
    state["project"] = copy.deepcopy(current.get("project")) if isinstance(current.get("project"), Mapping) else current.get("project")
    state["schema"] = _field(current, "schema", default="orch-dork/clean-update-state/v1")
    return state


def apply_clean_update(program: Mapping[str, Any]) -> dict[str, Any]:
    """Verify, stage, and atomically commit one disposable update.

    No path is touched for a denial or a deferred fresh-boundary result.  A
    simulated interruption deletes only the temporary stage and reports the
    original active bytes as preserved.
    """

    preview = evaluate_clean_update(program)
    if preview.get("status") != PASS:
        return preview
    root_value = _first(program, "profile_root", "root", "disposable_root", default=None)
    if root_value is None:
        # In-memory callers still receive a meaningful pass; no real cache can
        # be mutated without an explicit disposable destination.
        result = dict(preview)
        result["disposition"] = FRESH_BOUNDARY_DISPOSITION if not _fresh_boundary(program) else COMMITTED_DISPOSITION
        result["read_only"] = True
        result["mutation_performed"] = False
        result["committed"] = False
        result["reason"] = "update:compatible_newer"
        result["receipt"] = dict(preview["receipt"])
        return result
    root = Path(str(root_value))
    if not _profile_is_disposable(program):
        return _report(DENY, "update:profile_not_disposable", current=_current(program), candidate=_candidate(program), issues=["profile:real_cache_or_marker_missing"])
    current = _current(program)
    candidate = _candidate(program)
    active_path = _state_file(root, program)
    before = _read_bytes(active_path)
    if before is None:
        # A caller can seed the active state from the program mapping; this is
        # still confined to the disposable root.
        before = canonical_json_bytes(current) + b"\n"
        _write_atomic(active_path, before)
    candidate_state = _state_for_commit(current, candidate)
    staged = canonical_json_bytes(candidate_state) + b"\n"
    if _fault(program, candidate, "interrupted_install", "interrupt_before_commit", "simulate_interruption"):
        # Deliberately create and remove a stage file to exercise cleanup,
        # while never replacing the active generation.
        stage_path = active_path.with_name(".clean-update-interrupted-stage")
        try:
            stage_path.write_bytes(staged)
            stage_path.unlink()
        except OSError:
            pass
        return _report(
            DENY,
            "update:interrupted_install",
            current=current,
            candidate=candidate,
            issues=["update:interrupted_install"],
            evidence={"previous_state_sha256": _sha256_bytes(before), "stage_cleaned": not stage_path.exists()},
        )
    _write_atomic(active_path, staged)
    generations = root / "state" / "generations"
    generation_path = generations / f"{_generation(candidate, default=_generation(current) + 1)}.json"
    _write_atomic(generation_path, staged)
    result = _report(
        PASS,
        "update:compatible_newer",
        current=current,
        candidate=candidate,
        disposition=COMMITTED_DISPOSITION,
        preserved=True,
        committed=True,
        evidence={
            "verified_before_staging": True,
            "previous_state_sha256": _sha256_bytes(before),
            "new_state_sha256": _sha256_bytes(staged),
            "pinned_project_generation": _project_generation(current),
        },
    )
    return result


# Compatibility aliases make this seam convenient for callers that use the
# terminology from the ticket or the Issue 43 maintenance module.
evaluate_update = evaluate_clean_update
apply_update = apply_clean_update
verify_artifact_before_staging = verify_signed_artifact


def _fixture_candidate(*, version: str = "1.1.0", generation: int = 2) -> dict[str, Any]:
    body = f"orch-dork package {version}\n".encode("utf-8")
    digest = _sha256_bytes(body)
    return {
        "version": version,
        "generation": generation,
        "security_generation": 2,
        "protocol": "project-ground/v1",
        "project_generation": 7,
        "artifact_bytes": body.decode("utf-8"),
        "package_sha256": digest,
        "source_package_sha256": digest,
        "signed": True,
        "signature_digest": digest,
        "interpreter": {"available": True, "contract": "python>=3.10"},
        "hook": {"enabled": True, "trusted": True},
        "registry": {"present": True},
        "migration": {"status": PASS},
        "cache_generation": 1,
    }


def _fixture_program(root: Path | None = None, *, fresh_task: bool = True) -> dict[str, Any]:
    current = {
        "schema": "orch-dork/clean-update-state/v1",
        "version": "1.0.0",
        "generation": 1,
        "security_generation": 2,
        "protocol": "project-ground/v1",
        "project_generation": 7,
        "project_binding_sha256": "1" * 64,
        "project_adapter_sha256": "2" * 64,
        "authority": "fixture-authority",
        "writable_scope_sha256": "3" * 64,
        "package_sha256": _sha256_bytes(b"orch-dork package 1.0.0\n"),
    }
    candidate = _fixture_candidate()
    program: dict[str, Any] = {
        "schema": PROGRAM_SCHEMA,
        "disposable": True,
        "fresh_task": fresh_task,
        "current": current,
        "candidate": candidate,
        "provider_free": True,
    }
    if root is not None:
        program["profile_root"] = str(root)
    return program


def build_fixture_program(root: str | os.PathLike[str] | None = None, *, fresh_task: bool = True) -> dict[str, Any]:
    """Public deterministic fixture builder used by tests and integrations."""

    return _fixture_program(Path(root) if root is not None else None, fresh_task=fresh_task)


def _seed_disposable(root: Path, program: Mapping[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / ".clean-machine-disposable").write_text("issue45\n", encoding="utf-8")
    active = root / "state" / "active.json"
    _write_atomic(active, canonical_json_bytes(_current(program)) + b"\n")


def _scenario_program(root: Path, case: str) -> dict[str, Any]:
    fresh = case not in {"fresh_boundary_required"}
    program = build_fixture_program(root, fresh_task=fresh)
    candidate = program["candidate"]
    assert isinstance(candidate, dict)
    if case == "incompatible_newer":
        candidate["incompatible"] = True
    elif case == "security_rollback":
        candidate["security_generation"] = 1
    elif case == "interrupted_install":
        candidate["interrupted_install"] = True
    elif case == "stale_cache":
        candidate["stale_cache"] = True
    elif case == "missing_interpreter":
        candidate["interpreter"] = {"available": False}
    elif case == "source_package_mismatch":
        candidate["source_package_sha256"] = "f" * 64
    elif case == "deleted_binding":
        candidate["binding_deleted"] = True
    elif case == "deleted_adapter":
        candidate["adapter_deleted"] = True
    elif case == "disabled_untrusted_hook":
        candidate["hook"] = {"enabled": False, "trusted": False}
    elif case == "registry_loss":
        candidate["registry"] = {"present": False}
    elif case == "failed_migration":
        candidate["migration"] = {"status": "FAIL"}
    elif case == "tampered_artifact":
        candidate["artifact_bytes"] = "tampered package\n"
    program["failure_case"] = None if case == "fresh_boundary_required" else case
    return program


def run_clean_update_acceptance(root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Run the complete disposable update and refusal matrix."""

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if root is None:
        temporary = tempfile.TemporaryDirectory(prefix="orch-dork-issue45-update-")
        root_path = Path(temporary.name)
    else:
        root_path = Path(root)
        root_path.mkdir(parents=True, exist_ok=True)
    scenarios: dict[str, Any] = {}
    checks: dict[str, str] = {}
    try:
        # A successful update proves the positive path and exact project pin.
        compatible_root = root_path / "compatible"
        compatible_program = _scenario_program(compatible_root, "compatible_newer")
        _seed_disposable(compatible_root, compatible_program)
        compatible = apply_clean_update(compatible_program)
        active_after = _read_bytes(compatible_root / "state" / "active.json") or b""
        expected_state = _state_for_commit(_current(compatible_program), _candidate(compatible_program))
        checks["compatible_newer"] = PASS if (
            compatible.get("status") == PASS
            and compatible.get("mutation_performed") is True
            and json.loads(active_after.decode("utf-8"))["generation"] == _generation(_candidate(compatible_program))
            and json.loads(active_after.decode("utf-8")).get("project_generation") == _project_generation(_current(compatible_program))
            and json.loads(active_after.decode("utf-8")).get("project_binding_sha256") == _field(_current(compatible_program), "project_binding_sha256")
            and json.loads(active_after.decode("utf-8")) == expected_state
        ) else DENY
        scenarios["compatible_newer"] = compatible
        # A compatible candidate is verified while waiting at a non-fresh
        # boundary; no active bytes are touched.
        boundary_root = root_path / "fresh-boundary"
        boundary_program = _scenario_program(boundary_root, "fresh_boundary_required")
        _seed_disposable(boundary_root, boundary_program)
        before_boundary = _read_bytes(boundary_root / "state" / "active.json")
        boundary = apply_clean_update(boundary_program)
        checks["fresh_boundary_required"] = PASS if (
            boundary.get("status") == DEFERRED
            and boundary.get("disposition") == FRESH_BOUNDARY_DISPOSITION
            and boundary.get("prior_generation_preserved") is True
            and _read_bytes(boundary_root / "state" / "active.json") == before_boundary
        ) else DENY
        scenarios["fresh_boundary_required"] = boundary

        for case in FAILURE_CASES:
            case_root = root_path / case
            program = _scenario_program(case_root, case)
            _seed_disposable(case_root, program)
            before = _read_bytes(case_root / "state" / "active.json")
            result = apply_clean_update(program)
            after = _read_bytes(case_root / "state" / "active.json")
            expected_reason = {
                "incompatible_newer": "update:incompatible_newer",
                "security_rollback": "update:security_rollback",
                "interrupted_install": "update:interrupted_install",
                "stale_cache": "update:stale_cache",
                "missing_interpreter": "update:missing_interpreter",
                "source_package_mismatch": "update:source_package_mismatch",
                "deleted_binding": "update:deleted_binding",
                "deleted_adapter": "update:deleted_adapter",
                "disabled_untrusted_hook": "update:hook_untrusted_or_disabled",
                "registry_loss": "update:registry_loss",
                "failed_migration": "update:failed_migration",
                "tampered_artifact": "update:artifact_digest_mismatch",
            }[case]
            checks[case] = PASS if (
                result.get("status") == DENY
                and result.get("reason") == expected_reason
                and result.get("disposition") == READ_ONLY_DISPOSITION
                and result.get("prior_generation_preserved") is True
                and after == before
                and result.get("mutation_performed") is False
            ) else DENY
            scenarios[case] = result
        all_pass = all(value == PASS for value in checks.values())
        return {
            "schema": ACCEPTANCE_SCHEMA,
            "policy_version": POLICY_VERSION,
            "status": PASS if all_pass else DENY,
            "provider_free": True,
            "network_attempts": 0,
            "credential_reads": 0,
            "hosted_calls": 0,
            "real_cache_mutated": False,
            "checks": checks,
            "scenarios": scenarios,
            "failure_cases": list(FAILURE_CASES),
            "prior_generation_preserved_for_refusals": all(
                scenarios[name].get("prior_generation_preserved") is True for name in FAILURE_CASES
            ),
            "resource_access": [
                {"operation": "read", "phase": "acceptance", "resource": "disposable update fixtures"},
                {"operation": "write", "phase": "acceptance", "resource": "disposable acceptance roots"},
            ],
            "receipt": {
                "schema": "orch-dork/clean-update-acceptance-receipt/v1",
                "status": PASS if all_pass else DENY,
                "scenario_count": len(checks),
                "failure_case_count": len(FAILURE_CASES),
                "all_refusals_read_only": all_pass,
                "real_cache_mutated": False,
                "network_attempts": 0,
                "credential_reads": 0,
                "hosted_calls": 0,
            },
        }
    finally:
        if temporary is not None:
            temporary.cleanup()


def _load_program(path: Path) -> Mapping[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", type=Path, help="JSON update program to evaluate")
    parser.add_argument("--apply", action="store_true", help="apply a verified disposable update")
    parser.add_argument("--root", type=Path, help="disposable acceptance root")
    args = parser.parse_args(argv)
    if args.program is not None:
        program = _load_program(args.program)
        result = apply_clean_update(program) if args.apply else evaluate_clean_update(program)
    else:
        result = run_clean_update_acceptance(args.root)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("status") in {PASS, DEFERRED} else 1


if __name__ == "__main__":  # pragma: no cover - CLI smoke path
    raise SystemExit(main())

