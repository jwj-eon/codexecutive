#!/usr/bin/env python3
"""Create and verify closed, tamper-evident Orch Dork evidence bundles.

The bundle format deliberately uses only the Python standard library.  A
bundle is a directory containing ``manifest.json``, ``seal.json`` and the
listed regular evidence files.  The manifest and seal are themselves covered
by the seal; copying a sealed directory therefore preserves its identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


BUNDLE_SCHEMA = "orch-dork/evidence-bundle/v1"
MANIFEST_NAME = "manifest.json"
SEAL_NAME = "seal.json"
SERVER_VERSION = "0.1.0"

_CREDENTIAL_KEY = re.compile(
    r"(?:api[_-]?key|api[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key|password|passwd|authorization|"
    r"credential|cookie|bearer[_-]?token|(^|[_-])token$)",
    re.IGNORECASE,
)
# Match the complete basename (including an optional extension).  The old
# expression only matched ``secrets`` and missed the common ``secrets.json``
# and ``private_key.pem`` forms, allowing a credential-bearing file to enter a
# bundle when its contents were not JSON or a known token spelling.
_CREDENTIAL_FILENAME = re.compile(
    r"^(?:\.?(?:env|credentials?|secrets?|private[_-]?key|id[_-]?rsa)|"
    r"(?:api|access|refresh)[_-]?tokens?|(?:api|client)[_-]?keys?|"
    r"client[_-]?secrets?|\.?(?:pem|p12|pfx))(?:\.[^.]+)*$",
    re.IGNORECASE,
)
_CREDENTIAL_VALUE = re.compile(
    r"(?:-----BEGIN [^-]*PRIVATE KEY-----|\bBearer\s+\S+|\b(?:sk|gh[pousr]|xox[baprs])[-_][A-Za-z0-9_-]{8,}|\bAKIA[0-9A-Z]{12,})"
)


def _is_credential_key(key: Any) -> bool:
    # This is custody accounting, not a credential.  Keeping it explicit also
    # lets a sealed bundle prove that redaction happened without retaining the
    # removed fields.
    return str(key).lower() != "credential_fields_removed" and bool(_CREDENTIAL_KEY.search(str(key)))


class BundleError(ValueError):
    """Raised when a bundle cannot be safely created or verified."""


class BundleVerificationError(BundleError):
    """Raised when a sealed bundle is not closed and internally consistent."""

    def __init__(self, issues: Iterable[str]):
        self.issues = tuple(sorted(set(str(issue) for issue in issues)))
        super().__init__("invalid evidence bundle: " + ", ".join(self.issues))


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_sha256(value: Any) -> str:
    return hashlib.sha256(compact_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relative(path: str, *, require_canonical: bool = True) -> str:
    if not isinstance(path, str) or not path or "\\" in path:
        raise BundleError("evidence path must be a non-empty POSIX relative path")
    posix = PurePosixPath(path)
    canonical = posix.as_posix()
    if (
        posix.is_absolute()
        or not posix.parts
        or any(part in {"", ".", ".."} for part in posix.parts)
        or (require_canonical and canonical != path)
    ):
        raise BundleError("evidence path escapes bundle: %s" % path)
    return canonical


def _credential_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(
        _CREDENTIAL_FILENAME.search(part)
        or part.lower().endswith((".env", ".env.local", ".env.production", ".env.development", ".pem", ".p12", ".pfx"))
        for part in parts
    )


def _metadata_object(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a mutable metadata object or fail with the public error type."""
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise BundleError("metadata must be an object")
    return dict(metadata)


def _parse_evidence_bytes(data: bytes, relative: str) -> Any:
    """Parse JSON evidence, accepting one JSON value per JSONL line."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleError("invalid JSON evidence: %s" % relative) from exc
    if relative.lower().endswith(".jsonl"):
        values = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise BundleError("invalid JSON evidence: %s:%d" % (relative, line_number)) from exc
        if not values and text.strip():
            raise BundleError("invalid JSON evidence: %s" % relative)
        return values
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise BundleError("invalid JSON evidence: %s" % relative) from exc


def credential_paths(value: Any, prefix: str = "") -> list[str]:
    """Return paths to credential-bearing keys or values in JSON-like data."""
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_path = "%s.%s" % (prefix, key) if prefix else str(key)
            if _is_credential_key(key):
                found.append(key_path)
            found.extend(credential_paths(item, key_path))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(credential_paths(item, "%s[%d]" % (prefix, index)))
    elif isinstance(value, str) and _CREDENTIAL_VALUE.search(value):
        found.append(prefix or "<value>")
    return found


def redact_credentials(value: Any) -> tuple[Any, tuple[str, ...]]:
    """Remove credential fields before evidence is serialized.

    This is useful for callers holding a raw runtime record.  Sealing a
    directory is stricter: credentials already present on disk are rejected,
    rather than silently rewritten.
    """
    removed: list[str] = []

    def visit(item: Any, prefix: str) -> Any:
        if isinstance(item, Mapping):
            result = {}
            for key, child in item.items():
                key_path = "%s.%s" % (prefix, key) if prefix else str(key)
                if _is_credential_key(key):
                    removed.append(key_path)
                    continue
                result[key] = visit(child, key_path)
            return result
        if isinstance(item, list):
            return [visit(child, "%s[%d]" % (prefix, i)) for i, child in enumerate(item)]
        if isinstance(item, tuple):
            return [visit(child, "%s[%d]" % (prefix, i)) for i, child in enumerate(item)]
        if isinstance(item, str) and _CREDENTIAL_VALUE.search(item):
            removed.append(prefix or "<value>")
            return "[REDACTED]"
        return item

    return visit(value, ""), tuple(removed)


def _walk_regular_files(root: Path) -> list[tuple[str, Path]]:
    issues: list[str] = []
    result: list[tuple[str, Path]] = []
    try:
        children = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise BundleError("cannot read bundle directory: %s" % exc) from exc
    for path in children:
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            issues.append("symlink:%s" % relative)
            continue
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            issues.append("unreadable:%s" % relative)
            continue
        if stat.S_ISDIR(mode):
            nested, nested_issues = _walk_directory(path, relative)
            result.extend(nested)
            issues.extend(nested_issues)
            if not nested and not nested_issues:
                issues.append("empty-directory:%s" % relative)
        elif not stat.S_ISREG(mode):
            issues.append("special:%s" % relative)
        else:
            result.append((relative, path))
    if issues:
        raise BundleVerificationError(issues)
    return result


def _walk_directory(root: Path, prefix: str) -> tuple[list[tuple[str, Path]], list[str]]:
    result: list[tuple[str, Path]] = []
    issues: list[str] = []
    try:
        children = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return [], ["unreadable:%s" % prefix]
    for path in children:
        relative = "%s/%s" % (prefix, path.name) if prefix else path.name
        if path.is_symlink():
            issues.append("symlink:%s" % relative)
            continue
        try:
            mode = path.lstat().st_mode
        except OSError:
            issues.append("unreadable:%s" % relative)
            continue
        if stat.S_ISDIR(mode):
            nested, nested_issues = _walk_directory(path, relative)
            result.extend(nested)
            issues.extend(nested_issues)
            if not nested and not nested_issues:
                issues.append("empty-directory:%s" % relative)
        elif stat.S_ISREG(mode):
            result.append((relative, path))
        else:
            issues.append("special:%s" % relative)
    return result, issues


def _write_json(path: Path, value: Any) -> None:
    path.write_text(compact_json(value) + "\n", encoding="utf-8")


def create_bundle(
    destination: os.PathLike[str] | str,
    evidence: Mapping[str, Any] | Any,
    *,
    metadata: Mapping[str, Any] | None = None,
    bundle_id: str | None = None,
) -> dict[str, Any]:
    """Write JSON evidence files and seal them in one operation.

    A mapping is interpreted as ``relative-path -> JSON value``.  Other values
    are written to ``evidence.json``.  Credential fields are removed before
    serialization and the returned metadata records only the count, never the
    secret or its value.
    """
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=False)
    removed: list[str] = []
    if isinstance(evidence, Mapping) and evidence and all(
        isinstance(k, str) and ("/" in k or k.lower().endswith((".json", ".jsonl"))) for k in evidence
    ):
        items = evidence.items()
    elif isinstance(evidence, Mapping) and not evidence:
        items = (("evidence.json", evidence),)
    else:
        items = (("evidence.json", evidence),)
    seen_paths: set[str] = set()
    for raw_path, value in items:
        relative = _safe_relative(raw_path)
        if relative in seen_paths:
            raise BundleError("duplicate evidence path: %s" % relative)
        seen_paths.add(relative)
        if _credential_path(relative):
            raise BundleError("credential-bearing evidence path: %s" % relative)
        target = root / Path(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        safe_value, redactions = redact_credentials(value)
        removed.extend("%s:%s" % (relative, item) for item in redactions)
        _write_json(target, safe_value)
    safe_metadata, metadata_redactions = redact_credentials(_metadata_object(metadata))
    removed.extend("metadata:%s" % item for item in metadata_redactions)
    if not isinstance(safe_metadata, dict):
        raise BundleError("metadata must be an object")
    safe_metadata["credential_fields_removed"] = len(removed)
    return seal_bundle(root, metadata=safe_metadata, bundle_id=bundle_id)


def seal_bundle(
    destination: os.PathLike[str] | str,
    *,
    metadata: Mapping[str, Any] | None = None,
    bundle_id: str | None = None,
) -> dict[str, Any]:
    """Seal an unsealed directory, rejecting credentials and unsafe files."""
    root = Path(destination)
    if not root.is_dir() or root.is_symlink():
        raise BundleError("bundle destination must be a real directory")
    if (root / MANIFEST_NAME).exists() or (root / SEAL_NAME).exists():
        raise BundleError("bundle is already sealed or contains reserved files")
    pairs, walk_issues = _walk_directory(root, "")
    if walk_issues:
        raise BundleVerificationError(walk_issues)
    if not pairs:
        raise BundleError("bundle must contain at least one evidence file")
    entries: list[dict[str, Any]] = []
    for relative, path in pairs:
        if relative in {MANIFEST_NAME, SEAL_NAME} or _credential_path(relative):
            raise BundleError("credential or reserved evidence path: %s" % relative)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise BundleError("cannot read evidence file: %s" % relative) from exc
        if relative.lower().endswith((".json", ".jsonl")):
            parsed = _parse_evidence_bytes(data, relative)
            if credential_paths(parsed):
                raise BundleError("credential-bearing evidence: %s" % relative)
        elif _CREDENTIAL_VALUE.search(data.decode("utf-8", errors="ignore")):
            raise BundleError("credential-bearing evidence: %s" % relative)
        entries.append({"path": relative, "sha256": _sha256_bytes(data), "size": len(data)})
    entries.sort(key=lambda item: item["path"])
    safe_metadata, redactions = redact_credentials(_metadata_object(metadata))
    if redactions:
        raise BundleError("credentials in bundle metadata: %s" % ",".join(redactions))
    if not isinstance(safe_metadata, dict):
        raise BundleError("metadata must be an object")
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "bundle_id": bundle_id or "bundle-" + uuid.uuid4().hex,
        "entries": entries,
        "metadata": safe_metadata,
    }
    if not isinstance(manifest["bundle_id"], str) or not manifest["bundle_id"].strip():
        raise BundleError("bundle_id must be a non-empty string")
    _write_json(root / MANIFEST_NAME, manifest)
    seal = {
        "schema": BUNDLE_SCHEMA,
        "algorithm": "sha256",
        "manifest_sha256": _sha256_bytes((root / MANIFEST_NAME).read_bytes()),
        "entries_sha256": json_sha256(entries),
    }
    _write_json(root / SEAL_NAME, seal)
    return verify_bundle(root)


def _load_json_file(path: Path, issue: str) -> tuple[Any | None, list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, [issue]


def verify_bundle(destination: os.PathLike[str] | str) -> dict[str, Any]:
    """Verify closure, ordering, hashes, file kinds, and credential absence."""
    root = Path(destination)
    issues: list[str] = []
    if not root.is_dir() or root.is_symlink():
        raise BundleVerificationError(["bundle:not_directory"])
    pairs, walk_issues = _walk_directory(root, "")
    issues.extend(walk_issues)
    actual = {relative: path for relative, path in pairs}
    for name in (MANIFEST_NAME, SEAL_NAME):
        path = root / name
        if path.is_symlink():
            issues.append("symlink:%s" % name)
        elif not path.is_file():
            issues.append("missing:%s" % name)
    manifest: Any = None
    seal: Any = None
    if not issues or (root / MANIFEST_NAME).is_file():
        manifest, manifest_issues = _load_json_file(root / MANIFEST_NAME, "manifest:invalid_json")
        issues.extend(manifest_issues)
    if not issues or (root / SEAL_NAME).is_file():
        seal, seal_issues = _load_json_file(root / SEAL_NAME, "seal:invalid_json")
        issues.extend(seal_issues)
    if isinstance(manifest, dict):
        if manifest.get("schema") != BUNDLE_SCHEMA:
            issues.append("manifest:schema_invalid")
        if not isinstance(manifest.get("bundle_id"), str) or not manifest["bundle_id"].strip():
            issues.append("manifest:bundle_id_invalid")
        metadata = manifest.get("metadata", {})
        if not isinstance(metadata, dict):
            issues.append("manifest:metadata_not_object")
        else:
            if credential_paths(metadata):
                issues.append("credentials:metadata")
            removed_count = metadata.get("credential_fields_removed", 0)
            if type(removed_count) is not int or removed_count < 0:
                issues.append("manifest:credential_fields_removed_invalid")
        entries = manifest.get("entries")
        if not isinstance(entries, list):
            issues.append("manifest:entries_not_array")
            entries = []
        elif not entries:
            issues.append("manifest:entries_empty")
        paths = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
                issues.append("manifest:entry_invalid:%d" % index)
                continue
            path = entry["path"]
            try:
                # Keep the canonicality diagnostic distinct from traversal:
                # callers need to know whether an otherwise safe manifest path
                # was rewritten after sealing.
                path = _safe_relative(path, require_canonical=False)
            except BundleError:
                issues.append("manifest:path_invalid:%d" % index)
                continue
            if path != entry["path"]:
                issues.append("manifest:path_not_canonical:%d" % index)
            paths.append(path)
            if path in {MANIFEST_NAME, SEAL_NAME}:
                issues.append("manifest:reserved_path:%s" % path)
            if _credential_path(path):
                issues.append("credentials:path:%s" % path)
            if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
                issues.append("manifest:hash_invalid:%s" % path)
            if type(entry["size"]) is not int or entry["size"] < 0:
                issues.append("manifest:size_invalid:%s" % path)
        if paths != sorted(paths):
            issues.append("manifest:entries_not_sorted")
        if len(paths) != len(set(paths)):
            issues.append("manifest:duplicate_paths")
        expected = set(paths) | {MANIFEST_NAME, SEAL_NAME}
        actual_paths = set(actual) | ({MANIFEST_NAME} if (root / MANIFEST_NAME).is_file() else set()) | ({SEAL_NAME} if (root / SEAL_NAME).is_file() else set())
        for path in sorted(expected - actual_paths):
            if path not in {MANIFEST_NAME, SEAL_NAME}:
                issues.append("missing:%s" % path)
        for path in sorted(actual_paths - expected):
            issues.append("extra:%s" % path)
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("path") not in actual:
                continue
            path = entry["path"]
            try:
                data = actual[path].read_bytes()
            except OSError:
                issues.append("unreadable:%s" % path)
                continue
            if len(data) != entry.get("size") or _sha256_bytes(data) != entry.get("sha256"):
                issues.append("modified:%s" % path)
            if path.lower().endswith((".json", ".jsonl")):
                try:
                    parsed = _parse_evidence_bytes(data, path)
                except BundleError:
                    issues.append("invalid-json:%s" % path)
                    parsed = None
                if parsed is not None and credential_paths(parsed):
                    issues.append("credentials:content:%s" % path)
            elif _CREDENTIAL_VALUE.search(data.decode("utf-8", errors="ignore")):
                issues.append("credentials:content:%s" % path)
    if isinstance(seal, dict):
        if seal.get("schema") != BUNDLE_SCHEMA:
            issues.append("seal:schema_invalid")
        if seal.get("algorithm") != "sha256":
            issues.append("seal:algorithm_invalid")
        if (root / MANIFEST_NAME).is_file():
            manifest_bytes = (root / MANIFEST_NAME).read_bytes()
            if seal.get("manifest_sha256") != _sha256_bytes(manifest_bytes):
                issues.append("seal:manifest_mismatch")
        if isinstance(manifest, dict) and seal.get("entries_sha256") != json_sha256(manifest.get("entries")):
            issues.append("seal:entries_mismatch")
    if issues:
        raise BundleVerificationError(issues)
    return {
        "schema": BUNDLE_SCHEMA,
        "status": "PASS",
        "verified": True,
        "bundle_id": manifest["bundle_id"],
        "manifest_sha256": _sha256_bytes((root / MANIFEST_NAME).read_bytes()),
        "entries": len(manifest["entries"]),
        "metadata": manifest.get("metadata", {}),
    }


def read_bundle(destination: os.PathLike[str] | str) -> dict[str, Any]:
    """Verify and load a bundle into a provider-independent Python object."""
    verification = verify_bundle(destination)
    root = Path(destination)
    manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    files: dict[str, bytes] = {}
    parsed: dict[str, Any] = {}
    for entry in manifest["entries"]:
        relative = entry["path"]
        data = (root / Path(*PurePosixPath(relative).parts)).read_bytes()
        files[relative] = data
        if relative.lower().endswith((".json", ".jsonl")):
            try:
                parsed[relative] = _parse_evidence_bytes(data, relative)
            except BundleError:
                pass
    return {"root": root, "manifest": manifest, "verification": verification, "files": files, "parsed": parsed}


# Descriptive aliases keep the small module convenient for adapters and callers
# that use the domain term instead of the shorter CLI verb.
create_evidence_bundle = create_bundle
seal_evidence_bundle = seal_bundle
verify_evidence_bundle = verify_bundle
load_evidence_bundle = read_bundle


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal_parser = subparsers.add_parser("seal")
    seal_parser.add_argument("bundle")
    seal_parser.add_argument("--bundle-id")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("bundle")
    args = parser.parse_args(argv)
    try:
        result = seal_bundle(args.bundle, bundle_id=getattr(args, "bundle_id", None)) if args.command == "seal" else verify_bundle(args.bundle)
    except BundleError as exc:
        result = {"schema": BUNDLE_SCHEMA, "status": "FAIL", "verified": False, "issues": list(getattr(exc, "issues", (str(exc),)))}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
