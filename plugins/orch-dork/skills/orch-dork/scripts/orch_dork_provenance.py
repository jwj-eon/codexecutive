"""Deterministic source, archive, and in-toto provenance helpers.

This module deliberately has no dependency on a package manager, network
service, VCS command, or signing provider.  It is the provider-free identity
layer used by Issue 50: source files are normalized into a canonical
inventory, an archive is emitted with stable ZIP metadata, and a versioned
in-toto/SLSA-style statement binds the resulting package to its inputs.

The public functions return ordinary dictionaries so that callers can retain
machine evidence without depending on a class pickling format.  All
diagnostics are safe to display: they contain paths and lengths/offsets, never
file contents, and never embed the caller's absolute checkout path.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import zipfile
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "orch-dork/provenance/v1"
IN_TOTO_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://orch-dork.dev/build/reproducible/v1"
DEFAULT_SOURCE_DATE_EPOCH = 0
NORMALIZED_FILE_MODE = 0o755
NORMALIZED_DATA_MODE = 0o644
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_ABSOLUTE_USER_PATH = re.compile(
    rb"(?:^|[\"'\s(=,:])/(?:Users|home|private/var|tmp)/[A-Za-z0-9._~+%/@-]+"
)
_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|token|secret|api[_-]?key|private[_-]?key|credential|prompt|conversation|reasoning)",
    re.IGNORECASE,
)


class ProvenanceError(ValueError):
    """Raised when source or provenance identity cannot be made canonical."""

    def __init__(self, *issues: str):
        self.issues = tuple(str(issue) for issue in issues) or ("invalid_provenance",)
        super().__init__("; ".join(self.issues))


class InventoryError(ProvenanceError):
    pass


class ArchiveError(ProvenanceError):
    pass


class ProvenanceVerificationError(ProvenanceError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    """Return the one canonical JSON representation used for all digests.

    ``allow_nan=False`` prevents platform-specific NaN spellings.  UTF-8 is
    emitted directly and no trailing newline is added, so bytewise identity is
    independent of locale and pretty-printing choices.
    """

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProvenanceError("canonical_json:invalid_value") from exc
    return encoded


def canonical_json(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _hash_or_none(value: Any, field: str, *, allow_empty: bool = False) -> str | None:
    if value is None and allow_empty:
        return None
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value.lower()):
        raise ProvenanceError(f"{field}:invalid_sha256")
    return value.lower()


def _digest(value: Any, field: str) -> str:
    """Digest bytes, JSON, or an already supplied SHA-256 digest."""

    if isinstance(value, bytes):
        return sha256_bytes(value)
    if isinstance(value, str):
        if SHA256_RE.fullmatch(value.lower()):
            return value.lower()
        return sha256_bytes(value.encode("utf-8"))
    return sha256_json(value)


def validate_relative_path(path: str | os.PathLike[str]) -> str:
    """Canonicalize a package path and reject traversal/host paths."""

    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ProvenanceError("path:invalid")
    # Archives are POSIX namespaces.  Backslashes are rejected rather than
    # interpreted as separators differently on different hosts.
    if "\\" in path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        raise ProvenanceError(f"path:not_relative:{path if len(path) < 80 else '<path>'}")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in path):
        raise ProvenanceError("path:control_character")
    pure = PurePosixPath(path)
    parts = pure.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ProvenanceError("path:not_canonical")
    normalized = pure.as_posix()
    if normalized != path:
        raise ProvenanceError("path:not_canonical")
    return normalized


def _safe_root(root: str | os.PathLike[str]) -> Path:
    path = Path(root)
    if not path.exists() or not path.is_dir() or path.is_symlink():
        raise InventoryError("root:not_directory")
    return path


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (FileNotFoundError, ValueError, RuntimeError):
        return False
    return True


def _normalized_epoch(source_date_epoch: int | str | None = None) -> int:
    value: int | str | None = source_date_epoch
    if value is None:
        value = os.environ.get("SOURCE_DATE_EPOCH")
    if value is None:
        value = DEFAULT_SOURCE_DATE_EPOCH
    # bool is an int subclass but is not a meaningful build epoch.
    if isinstance(value, bool):
        raise ProvenanceError("source_date_epoch:invalid")
    try:
        epoch = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProvenanceError("source_date_epoch:invalid") from exc
    if epoch < 0 or epoch > 0x7FFFFFFFFFFFFFFF:
        raise ProvenanceError("source_date_epoch:out_of_range")
    return epoch


def normalize_file_bytes(data: bytes, *, path: str = "<file>") -> bytes:
    """Normalize a UTF-8 file to LF and canonical UTF-8 bytes.

    Package source is expected to be text.  Rejecting malformed UTF-8 avoids
    two independent builders making different normalization decisions for the
    same byte stream.  A UTF-8 BOM is rejected as a non-canonical encoding.
    """

    if not isinstance(data, bytes):
        raise ProvenanceError(f"encoding:{path}")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProvenanceError(f"encoding:{path}") from exc
    if text.startswith("\ufeff"):
        raise ProvenanceError(f"encoding:bom:{path}")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = text.encode("utf-8")
    if b"\x00" in normalized:
        # NUL bytes are not source text and are almost always an accidental
        # binary/credential payload in a portable plugin tree.
        raise ProvenanceError(f"encoding:nul:{path}")
    return normalized


def _normalized_mode(mode: int, *, path: str) -> int:
    if not stat.S_ISREG(mode):
        raise InventoryError(f"special:{path}")
    # Preserve only executable intent; every entry is emitted as one of two
    # canonical modes, so host permission bits cannot reach the archive.
    # World-write and set-id/sticky bits still fail closed because they change
    # who may modify or execute the packaged file.  Group-write is normal under
    # a `002` umask and carries no such authority, so it is not an error.
    permissions = stat.S_IMODE(mode)
    if permissions & (stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise InventoryError(f"mode:unsafe:{path}")
    return NORMALIZED_FILE_MODE if permissions & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) else NORMALIZED_DATA_MODE


def _validate_content_safety(data: bytes, *, path: str) -> None:
    if _ABSOLUTE_USER_PATH.search(data):
        raise InventoryError(f"absolute_path:{path}")


def _discover_paths(root: Path) -> list[str]:
    found: list[str] = []
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        # Reject symlinked directories instead of allowing os.walk to choose a
        # host-dependent traversal policy.
        for name in list(dirs):
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                raise InventoryError(f"symlink:{validate_relative_path(relative)}")
            if not candidate.is_dir():
                raise InventoryError(f"special:{validate_relative_path(relative)}")
        for name in files:
            candidate = current_path / name
            relative = validate_relative_path(candidate.relative_to(root).as_posix())
            if candidate.is_symlink():
                raise InventoryError(f"symlink:{relative}")
            if not _inside(root, candidate):
                raise InventoryError(f"path_escape:{relative}")
            found.append(relative)
    return sorted(found)


def _validate_allowlist(root: Path, allowlist: Iterable[str | os.PathLike[str]]) -> list[str]:
    try:
        values = list(allowlist)
    except TypeError as exc:
        raise InventoryError("allowlist:invalid") from exc
    canonical = [validate_relative_path(value) for value in values]
    if canonical != sorted(canonical) or len(set(canonical)) != len(canonical):
        raise InventoryError("allowlist:not_sorted_or_duplicate")
    actual = _discover_paths(root)
    missing = sorted(set(canonical) - set(actual))
    extra = sorted(set(actual) - set(canonical))
    if missing:
        raise InventoryError("missing:" + missing[0])
    if extra:
        raise InventoryError("unexpected:" + extra[0])
    return canonical


def canonical_inventory(
    root: str | os.PathLike[str],
    allowlist: Iterable[str | os.PathLike[str]] | None = None,
    *,
    source_date_epoch: int | str | None = None,
) -> list[dict[str, Any]]:
    """Return a sorted path/size/mode/SHA-256 inventory.

    The epoch argument is intentionally accepted and validated even though
    file timestamps are not included in an inventory.  This keeps callers from
    accidentally constructing a build with an invalid epoch and then emitting
    a seemingly valid receipt.
    """

    _normalized_epoch(source_date_epoch)
    root_path = _safe_root(root)
    paths = _discover_paths(root_path) if allowlist is None else _validate_allowlist(root_path, allowlist)
    entries: list[dict[str, Any]] = []
    for relative in paths:
        path = root_path / Path(relative)
        try:
            mode = _normalized_mode(path.lstat().st_mode, path=relative)
            raw = path.read_bytes()
        except ProvenanceError:
            raise
        except (OSError, ValueError) as exc:
            raise InventoryError(f"read:{relative}") from exc
        normalized = normalize_file_bytes(raw, path=relative)
        _validate_content_safety(normalized, path=relative)
        entries.append({
            "path": relative,
            "size": len(normalized),
            "mode": mode,
            "sha256": sha256_bytes(normalized),
        })
    return entries


def inventory_digest(inventory: Sequence[Mapping[str, Any]]) -> str:
    """Digest a validated, bytewise-sorted inventory."""

    normalized: list[dict[str, Any]] = []
    previous = None
    for index, entry in enumerate(inventory):
        if not isinstance(entry, Mapping):
            raise InventoryError(f"inventory:entry:{index}")
        path = validate_relative_path(entry.get("path"))
        if previous is not None and path <= previous:
            raise InventoryError("inventory:not_sorted")
        previous = path
        try:
            size = int(entry["size"])
            mode = int(entry["mode"])
        except (KeyError, TypeError, ValueError) as exc:
            raise InventoryError(f"inventory:fields:{path}") from exc
        if size < 0 or mode not in (NORMALIZED_DATA_MODE, NORMALIZED_FILE_MODE):
            raise InventoryError(f"inventory:fields:{path}")
        digest = _hash_or_none(entry.get("sha256"), f"inventory:{path}:sha256")
        normalized.append({"path": path, "size": size, "mode": mode, "sha256": digest})
    return sha256_json(normalized)


def source_tree_digest(
    root_or_inventory: str | os.PathLike[str] | Sequence[Mapping[str, Any]],
    allowlist: Iterable[str | os.PathLike[str]] | None = None,
    *,
    source_date_epoch: int | str | None = None,
) -> str:
    """Digest the canonical source tree identity independently of its path."""

    if isinstance(root_or_inventory, (str, os.PathLike)):
        inventory = canonical_inventory(root_or_inventory, allowlist, source_date_epoch=source_date_epoch)
    else:
        inventory = list(root_or_inventory)
    # Include a schema marker so a future inventory layout cannot silently
    # collide with this tree digest.
    return sha256_json({"schema": "orch-dork/source-tree/v1", "inventory": inventory})


# Friendly aliases used by callers and older fixture drafts.
build_inventory = canonical_inventory
canonical_source_inventory = canonical_inventory
digest_inventory = inventory_digest
digest_source_tree = source_tree_digest


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    # ZIP timestamps cannot represent pre-1980 values.  They are not identity
    # inputs, so clamp to the earliest valid DOS timestamp while preserving the
    # requested epoch in the build report/provenance.
    import datetime as _datetime

    # DOS timestamps cover 1980-01-01 through 2107-12-31.  The requested
    # epoch remains recorded in the build record; clamping here only prevents
    # a host zip implementation from rejecting an otherwise valid receipt.
    bounded = min(max(epoch, 315532800), 4354819199)
    dt = _datetime.datetime.fromtimestamp(bounded, tz=_datetime.timezone.utc)
    return dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second


def _archive_bytes(root: Path, inventory: Sequence[Mapping[str, Any]], epoch: int) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        date_time = _zip_datetime(epoch)
        for item in inventory:
            relative = validate_relative_path(item["path"])
            path = root / Path(relative)
            data = normalize_file_bytes(path.read_bytes(), path=relative)
            if sha256_bytes(data) != item["sha256"] or len(data) != int(item["size"]):
                raise ArchiveError(f"source_changed:{relative}")
            info = zipfile.ZipInfo(relative, date_time=date_time)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3  # Unix, independent of the host OS.
            info.create_version = 20
            info.extract_version = 20
            info.flag_bits = 0x800  # UTF-8 filename marker.
            info.external_attr = (int(item["mode"]) & 0xFFFF) << 16
            info.internal_attr = 0
            info.extra = b""
            info.comment = b""
            archive.writestr(info, data)
    return out.getvalue()


def build_reproducible_archive_bytes(
    source_root: str | os.PathLike[str],
    allowlist: Iterable[str | os.PathLike[str]] | None = None,
    *,
    source_date_epoch: int | str | None = None,
) -> tuple[bytes, list[dict[str, Any]], int]:
    epoch = _normalized_epoch(source_date_epoch)
    root = _safe_root(source_root)
    inventory = canonical_inventory(root, allowlist, source_date_epoch=epoch)
    return _archive_bytes(root, inventory, epoch), inventory, epoch


def build_archive(
    source_root: str | os.PathLike[str],
    output: str | os.PathLike[str] | None = None,
    allowlist: Iterable[str | os.PathLike[str]] | None = None,
    *,
    source_date_epoch: int | str | None = None,
) -> dict[str, Any]:
    """Build a deterministic ZIP and return machine-verifiable identity."""

    archive_data, inventory, epoch = build_reproducible_archive_bytes(
        source_root, allowlist, source_date_epoch=source_date_epoch
    )
    package_digest = sha256_bytes(archive_data)
    if output is not None:
        destination = Path(output)
        source_path = Path(source_root).resolve()
        try:
            destination.resolve().relative_to(source_path)
        except ValueError:
            pass
        else:
            raise ArchiveError("output:inside_source")
        destination.parent.mkdir(parents=True, exist_ok=True)
        # A direct write is deterministic; replacement is atomic on normal
        # local filesystems and does not expose a partially written archive.
        temporary = destination.with_name(destination.name + ".tmp")
        try:
            temporary.write_bytes(archive_data)
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {
        "schema": "orch-dork/archive-build/v1",
        "status": "PASS",
        "source_date_epoch": epoch,
        "inventory": inventory,
        "inventory_sha256": inventory_digest(inventory),
        "source_tree_sha256": source_tree_digest(inventory),
        "package_digest": package_digest,
        "package_size": len(archive_data),
        "archive_bytes": archive_data,
        "archive_path": str(output) if output is not None else None,
    }


build_reproducible_archive = build_archive
create_reproducible_archive = build_archive


def _archive_entries(value: str | os.PathLike[str] | bytes | bytearray) -> dict[str, bytes]:
    if isinstance(value, (str, os.PathLike)):
        path = Path(value)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ArchiveError("archive:read") from exc
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise ArchiveError("archive:invalid")
    try:
        stream = io.BytesIO(raw)
        with zipfile.ZipFile(stream, "r") as archive:
            names = archive.namelist()
            if names != sorted(names) or len(names) != len(set(names)):
                raise ArchiveError("archive:entries_not_sorted")
            result: dict[str, bytes] = {}
            for name in names:
                relative = validate_relative_path(name)
                if relative != name:
                    raise ArchiveError("archive:path_not_canonical")
                info = archive.getinfo(name)
                if info.is_dir() or info.create_system not in (0, 3):
                    raise ArchiveError(f"archive:entry:{relative}")
                result[relative] = archive.read(name)
            return result
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        raise ArchiveError("archive:malformed") from exc


def first_difference(
    left: str | os.PathLike[str] | bytes | bytearray,
    right: str | os.PathLike[str] | bytes | bytearray,
) -> dict[str, Any] | None:
    """Return sanitized first differing path/byte range, without bodies."""

    left_entries = _archive_entries(left)
    right_entries = _archive_entries(right)
    for path in sorted(set(left_entries) | set(right_entries)):
        if path not in left_entries:
            return {"path": path, "kind": "missing_left", "byte_range": [0, len(right_entries[path])], "left_size": 0, "right_size": len(right_entries[path])}
        if path not in right_entries:
            return {"path": path, "kind": "missing_right", "byte_range": [0, len(left_entries[path])], "left_size": len(left_entries[path]), "right_size": 0}
        left_data = left_entries[path]
        right_data = right_entries[path]
        if left_data == right_data:
            continue
        limit = min(len(left_data), len(right_data))
        index = next((offset for offset in range(limit) if left_data[offset] != right_data[offset]), limit)
        end = max(len(left_data), len(right_data))
        if index < limit:
            # Extend to the first common suffix byte.  This gives a useful,
            # deterministic range while avoiding any content disclosure.
            tail = index + 1
            while tail < limit and left_data[tail] != right_data[tail]:
                tail += 1
            end = max(tail, index + 1)
        return {
            "path": path,
            "kind": "content_mismatch",
            "byte_range": [index, end],
            "byte_offset": index,
            "left_size": len(left_data),
            "right_size": len(right_data),
        }
    # Equal entries can still have different ZIP metadata (for example a
    # malicious timestamp/extra field).  Compare raw bytes last and report the
    # archive namespace rather than exposing ZIP headers.
    left_raw = Path(left).read_bytes() if isinstance(left, (str, os.PathLike)) else bytes(left)
    right_raw = Path(right).read_bytes() if isinstance(right, (str, os.PathLike)) else bytes(right)
    if left_raw != right_raw:
        limit = min(len(left_raw), len(right_raw))
        index = next((offset for offset in range(limit) if left_raw[offset] != right_raw[offset]), limit)
        return {"path": "<archive-metadata>", "kind": "metadata_mismatch", "byte_range": [index, max(len(left_raw), len(right_raw))], "byte_offset": index, "left_size": len(left_raw), "right_size": len(right_raw)}
    return None


def compare_archives(
    left: str | os.PathLike[str] | bytes | bytearray,
    right: str | os.PathLike[str] | bytes | bytearray,
) -> dict[str, Any]:
    left_raw = Path(left).read_bytes() if isinstance(left, (str, os.PathLike)) else bytes(left)
    right_raw = Path(right).read_bytes() if isinstance(right, (str, os.PathLike)) else bytes(right)
    difference = first_difference(left_raw, right_raw)
    report = {
        "schema": "orch-dork/archive-comparison/v1",
        "equal": difference is None,
        "left_sha256": sha256_bytes(left_raw),
        "right_sha256": sha256_bytes(right_raw),
        "left_size": len(left_raw),
        "right_size": len(right_raw),
        "first_difference": difference,
    }
    return report


compare_reproducible_builds = compare_archives
compare_archives_safely = compare_archives


def _safe_scalar(value: Any, field: str) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str):
            if _SENSITIVE_KEY.search(field):
                raise ProvenanceError(f"metadata:sensitive:{field}")
            if "\x00" in value or value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value):
                raise ProvenanceError(f"metadata:path:{field}")
            if _ABSOLUTE_USER_PATH.search(value.encode("utf-8")):
                raise ProvenanceError(f"metadata:path:{field}")
        return value
    if isinstance(value, Mapping):
        return _safe_mapping(value, field)
    if isinstance(value, (list, tuple)):
        return [_safe_scalar(item, field) for item in value]
    raise ProvenanceError(f"metadata:type:{field}")


def _safe_mapping(value: Mapping[str, Any], prefix: str = "metadata") -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in sorted(value):
        if not isinstance(key, str) or not key or _SENSITIVE_KEY.search(key):
            raise ProvenanceError(f"metadata:key:{prefix}")
        result[key] = _safe_scalar(value[key], f"{prefix}.{key}")
    return result


def _find_unsafe_statement_value(value: Any, path: str = "statement") -> str | None:
    """Find a secret/private-reasoning key or host path in an existing record."""

    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str) or _SENSITIVE_KEY.search(key):
                return f"{path}:sensitive_key"
            found = _find_unsafe_statement_value(nested, f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            found = _find_unsafe_statement_value(nested, f"{path}[{index}]")
            if found:
                return found
        return None
    if isinstance(value, str):
        if value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value) or _ABSOLUTE_USER_PATH.search(value.encode("utf-8")):
            return f"{path}:host_path"
    return None


def _source_descriptor(
    *,
    source_artifact_digest: str | None,
    source_revision: str | None,
    source_archive_digest: str | None,
    source_uri: str | None,
) -> dict[str, Any]:
    if source_revision is not None:
        if not isinstance(source_revision, str) or not REVISION_RE.fullmatch(source_revision):
            raise ProvenanceError("source_revision:invalid")
    archive_digest = _hash_or_none(source_archive_digest, "source_archive_digest", allow_empty=True)
    artifact_digest = _hash_or_none(source_artifact_digest, "source_artifact_digest", allow_empty=True)
    if artifact_digest is None and archive_digest is None and source_revision is None:
        raise ProvenanceError("source:identity_missing")
    descriptor: dict[str, Any] = {}
    if source_uri is not None:
        if (
            not isinstance(source_uri, str)
            or source_uri.startswith("/")
            or "\\" in source_uri
            or _ABSOLUTE_USER_PATH.search(source_uri.encode("utf-8"))
        ):
            raise ProvenanceError("source_uri:invalid")
        descriptor["uri"] = source_uri
    if artifact_digest is not None:
        descriptor["digest"] = {"sha256": artifact_digest}
    if archive_digest is not None:
        descriptor["archiveDigest"] = {"sha256": archive_digest}
    if source_revision is not None:
        descriptor["revision"] = source_revision.lower()
    return descriptor


def create_provenance(
    package_digest: str,
    *,
    source_artifact_digest: str | None = None,
    source_revision: str | None = None,
    source_archive_digest: str | None = None,
    source_uri: str | None = None,
    allowlist: Iterable[str] | None = None,
    inventory: Sequence[Mapping[str, Any]] | None = None,
    inventory_sha256: str | None = None,
    source_tree_sha256: str | None = None,
    manifest_sha256: str | None = None,
    descriptor_sha256: str | None = None,
    marketplace_revision: str | None = None,
    builder: Mapping[str, Any] | None = None,
    builder_version: str = "1",
    build_recipe: Any = None,
    recipe_sha256: str | None = None,
    toolchain: Mapping[str, Any] | None = None,
    source_date_epoch: int | str | None = None,
    isolated_root: str = "isolated-root",
    parameters: Mapping[str, Any] | None = None,
    sbom_digest: str | None = None,
    dependencies: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create a deterministic in-toto statement with an SLSA-style predicate."""

    package = _hash_or_none(package_digest, "package_digest")
    epoch = _normalized_epoch(source_date_epoch)
    source = _source_descriptor(
        source_artifact_digest=source_artifact_digest,
        source_revision=source_revision,
        source_archive_digest=source_archive_digest,
        source_uri=source_uri,
    )
    if not isinstance(isolated_root, str) or not isolated_root or isolated_root.startswith("/") or "\\" in isolated_root:
        raise ProvenanceError("isolated_root:invalid")
    if marketplace_revision is not None and (not isinstance(marketplace_revision, str) or not REVISION_RE.fullmatch(marketplace_revision)):
        raise ProvenanceError("marketplace_revision:invalid")
    if inventory is not None:
        canonical_inventory_digest = inventory_digest(inventory)
        if inventory_sha256 is not None and _hash_or_none(inventory_sha256, "inventory_sha256") != canonical_inventory_digest:
            raise ProvenanceError("inventory_sha256:mismatch")
        inventory_sha256 = canonical_inventory_digest
    elif inventory_sha256 is not None:
        inventory_sha256 = _hash_or_none(inventory_sha256, "inventory_sha256")
    source_tree_sha256 = _hash_or_none(source_tree_sha256, "source_tree_sha256", allow_empty=True)
    manifest_sha256 = _hash_or_none(manifest_sha256, "manifest_sha256", allow_empty=True)
    descriptor_sha256 = _hash_or_none(descriptor_sha256, "descriptor_sha256", allow_empty=True)
    sbom_digest = _hash_or_none(sbom_digest, "sbom_digest", allow_empty=True)
    if recipe_sha256 is not None:
        recipe_sha256 = _hash_or_none(recipe_sha256, "recipe_sha256")
    elif build_recipe is not None:
        recipe_sha256 = _digest(build_recipe, "build_recipe")
    else:
        # An explicit empty recipe is still a deterministic recipe identity.
        recipe_sha256 = sha256_json({"schema": "orch-dork/build-recipe/v1", "steps": []})
    if builder is None:
        builder = {"id": "orch-dork/provenance-builder", "version": builder_version}
    builder_value = _safe_mapping(builder, "builder")
    toolchain_value = _safe_mapping(toolchain or {"interpreter": "python3", "implementation": "CPython"}, "toolchain")
    allowlist_value = sorted(validate_relative_path(item) for item in (allowlist or []))
    if len(allowlist_value) != len(set(allowlist_value)):
        raise ProvenanceError("allowlist:duplicate")
    external: dict[str, Any] = {
        "source": source,
        "sourceDateEpoch": epoch,
        "allowlist": allowlist_value,
        "isolatedRoot": isolated_root,
        "parameters": _safe_mapping(parameters or {}, "parameters"),
    }
    if marketplace_revision is not None:
        external["marketplaceRevision"] = marketplace_revision.lower()
    for key, value in (
        ("inventorySha256", inventory_sha256),
        ("sourceTreeSha256", source_tree_sha256),
        ("manifestSha256", manifest_sha256),
        ("descriptorSha256", descriptor_sha256),
    ):
        if value is not None:
            external[key] = value
    resolved: list[dict[str, Any]] = []
    if sbom_digest is not None:
        resolved.append({"uri": "urn:orch-dork:sbom", "digest": {"sha256": sbom_digest}})
    for dependency in dependencies or ():
        if not isinstance(dependency, Mapping):
            raise ProvenanceError("dependency:invalid")
        dep = _safe_mapping(dependency, "dependency")
        if "digest" not in dep:
            raise ProvenanceError("dependency:digest_missing")
        resolved.append(dep)
    resolved.sort(key=canonical_json)
    predicate = {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": external,
            "internalParameters": {"builderVersion": builder_version},
            "resolvedDependencies": resolved,
        },
        "runDetails": {
            "builder": builder_value,
            "metadata": {
                "sourceDateEpoch": epoch,
                "isolatedRoot": isolated_root,
                "recipeSha256": recipe_sha256,
                "toolchain": toolchain_value,
            },
        },
        # The explicit digest makes the package binding easy for small local
        # verifiers while retaining the standard subject binding above.
        "packageDigest": package,
        "sbomDigest": sbom_digest,
    }
    statement = {
        "_type": IN_TOTO_TYPE,
        "subject": [{"name": "package", "digest": {"sha256": package}}],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": predicate,
    }
    # Round-trip through canonical JSON ensures no caller-controlled mapping
    # ordering or mutable list can influence future digest calculations.
    return json.loads(canonical_json(statement))


build_provenance = create_provenance
make_provenance = create_provenance


def provenance_digest(statement: Mapping[str, Any]) -> str:
    return sha256_json(statement)


def _get_digest(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        digest = value.get("sha256")
    else:
        digest = value
    return _hash_or_none(digest, field, allow_empty=True)


def verify_provenance(
    statement: Mapping[str, Any],
    *,
    package_digest: str | None = None,
    source_revision: str | None = None,
    source_artifact_digest: str | None = None,
    source_archive_digest: str | None = None,
    inventory_sha256: str | None = None,
    source_tree_sha256: str | None = None,
    manifest_sha256: str | None = None,
    descriptor_sha256: str | None = None,
    marketplace_revision: str | None = None,
    sbom_digest: str | None = None,
    recipe_sha256: str | None = None,
    source_date_epoch: int | str | None = None,
) -> dict[str, Any]:
    """Validate a statement and optionally its expected Issue 44 bindings."""

    issues: list[str] = []
    digest = None
    try:
        digest = provenance_digest(statement)
        if not isinstance(statement, Mapping):
            raise ProvenanceVerificationError("statement:not_object")
        unsafe = _find_unsafe_statement_value(statement)
        if unsafe:
            issues.append(unsafe)
        if statement.get("_type") != IN_TOTO_TYPE:
            issues.append("statement:type")
        if statement.get("predicateType") != SLSA_PREDICATE_TYPE:
            issues.append("statement:predicate_type")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], Mapping):
            issues.append("subject:invalid")
            subject_digest = None
        else:
            subject_digest = _get_digest(subjects[0].get("digest"), "subject.sha256")
            if subjects[0].get("name") != "package":
                issues.append("subject:name")
        predicate = statement.get("predicate")
        if not isinstance(predicate, Mapping):
            issues.append("predicate:invalid")
            predicate = {}
        definition = predicate.get("buildDefinition")
        details = predicate.get("runDetails")
        if not isinstance(definition, Mapping):
            issues.append("build_definition:missing")
            definition = {}
        if not isinstance(details, Mapping):
            issues.append("run_details:missing")
            details = {}
        if definition.get("buildType") != BUILD_TYPE:
            issues.append("build_definition:type")
        external = definition.get("externalParameters")
        if not isinstance(external, Mapping):
            issues.append("external_parameters:missing")
            external = {}
        epoch = external.get("sourceDateEpoch")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
            issues.append("source_date_epoch:invalid")
        if source_date_epoch is not None and epoch != _normalized_epoch(source_date_epoch):
            issues.append("source_date_epoch:mismatch")
        source = external.get("source")
        if not isinstance(source, Mapping):
            issues.append("source:missing")
            source = {}
        for expected, actual in (
            (source_revision, source.get("revision")),
            (marketplace_revision, external.get("marketplaceRevision")),
        ):
            if expected is not None and (not isinstance(actual, str) or actual.lower() != str(expected).lower()):
                issues.append("source_identity:mismatch")
        for expected, actual, label in (
            (source_artifact_digest, source.get("digest"), "source_artifact"),
            (source_archive_digest, source.get("archiveDigest"), "source_archive"),
            (inventory_sha256, external.get("inventorySha256"), "inventory"),
            (source_tree_sha256, external.get("sourceTreeSha256"), "source_tree"),
            (manifest_sha256, external.get("manifestSha256"), "manifest"),
            (descriptor_sha256, external.get("descriptorSha256"), "descriptor"),
        ):
            if expected is not None:
                try:
                    actual_digest = _get_digest(actual, label)
                except ProvenanceError:
                    actual_digest = None
                if actual_digest != _hash_or_none(expected, label):
                    issues.append(f"{label}:mismatch")
        resolved = definition.get("resolvedDependencies")
        if not isinstance(resolved, list) or resolved != sorted(resolved, key=canonical_json):
            issues.append("dependencies:not_sorted")
        if sbom_digest is not None:
            target = _hash_or_none(sbom_digest, "sbom_digest")
            if predicate.get("sbomDigest") != target or not any(
                isinstance(item, Mapping) and isinstance(item.get("digest"), Mapping) and item.get("digest", {}).get("sha256") == target
                for item in (resolved or [])
            ):
                issues.append("sbom:mismatch")
        if recipe_sha256 is not None:
            metadata = details.get("metadata")
            actual_recipe = metadata.get("recipeSha256") if isinstance(metadata, Mapping) else None
            if actual_recipe != _hash_or_none(recipe_sha256, "recipe_sha256"):
                issues.append("recipe:mismatch")
        if package_digest is not None:
            expected_package = _hash_or_none(package_digest, "package_digest")
            if subject_digest != expected_package or predicate.get("packageDigest") != expected_package:
                issues.append("package:mismatch")
        if subject_digest is None:
            issues.append("subject:digest_missing")
    except (ProvenanceError, TypeError, ValueError, KeyError):
        issues.append("statement:malformed")
    return {
        "schema": "orch-dork/provenance-verification/v1",
        "status": "PASS" if not issues else "DENY",
        "verified": not issues,
        "issues": sorted(set(issues)),
        "statement_sha256": digest,
        "provider_free": True,
        "network_attempts": 0,
    }


validate_provenance = verify_provenance
verify_statement = verify_provenance


def sanitized_difference(report: Mapping[str, Any]) -> dict[str, Any]:
    """Strip any accidental non-diagnostic fields from a comparison report."""

    difference = report.get("first_difference")
    if not isinstance(difference, Mapping):
        return {"equal": bool(report.get("equal")), "first_difference": None}
    allowed = ("path", "kind", "byte_range", "byte_offset", "left_size", "right_size")
    clean = {key: difference[key] for key in allowed if key in difference}
    if isinstance(clean.get("path"), str) and (clean["path"].startswith("/") or "\\" in clean["path"]):
        clean["path"] = "<path>"
    return {"equal": bool(report.get("equal")), "first_difference": clean}


def _command_inventory(args: argparse.Namespace) -> int:
    inventory = canonical_inventory(args.source, args.allowlist, source_date_epoch=args.epoch)
    payload = {"schema": "orch-dork/inventory/v1", "inventory": inventory, "inventorySha256": inventory_digest(inventory), "sourceTreeSha256": source_tree_digest(inventory), "sourceDateEpoch": _normalized_epoch(args.epoch)}
    print(canonical_json(payload))
    return 0


def _command_archive(args: argparse.Namespace) -> int:
    report = build_archive(args.source, args.output, args.allowlist, source_date_epoch=args.epoch)
    report = dict(report)
    report.pop("archive_bytes", None)
    print(canonical_json(report))
    return 0


def _command_compare(args: argparse.Namespace) -> int:
    print(canonical_json(compare_archives(args.left, args.right)))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provider-free deterministic provenance helpers")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("inventory", "archive"):
        sub = subparsers.add_parser(name)
        sub.add_argument("source")
        sub.add_argument("--allowlist", action="append")
        sub.add_argument("--epoch", type=int)
        if name == "archive":
            sub.add_argument("output")
            sub.set_defaults(func=_command_archive)
        else:
            sub.set_defaults(func=_command_inventory)
    compare = subparsers.add_parser("compare")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.set_defaults(func=_command_compare)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ProvenanceError as exc:
        print(canonical_json({"status": "DENY", "issues": list(exc.issues)}), file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
