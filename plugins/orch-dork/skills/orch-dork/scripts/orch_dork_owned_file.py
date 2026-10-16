#!/usr/bin/env python3
"""Fail-closed reads for owner-controlled runtime and evidence files."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

MAX_PRIVATE_ROLLOUT_BYTES = 128 * 1024 * 1024


def read_private_rollout(
    path: str | Path, *, private_root: str | Path,
) -> dict[str, Any]:
    """Read a twice-matching prefix under an owned private native-session root.

    Native Codex files can be group writable inside its private directory.
    This separate interface retains that directory and every path descriptor
    across both reads. Appends beyond the initially observed size are excluded.
    The result proves an observed prefix snapshot, not future file immutability,
    valid JSON, complete turns, model routing or lifecycle closure.
    """
    def components(value: str | Path) -> list[str]:
        if not isinstance(value, (str, Path)):
            raise ValueError("private_rollout:absolute_path_required")
        name = str(value)
        parts = name.split("/")[1:]
        if (not name.startswith("/") or "\x00" in name or not parts
                or any(part in ("", ".", "..") for part in parts)):
            raise ValueError("private_rollout:absolute_path_required")
        return parts

    parts, root_parts = components(path), components(private_root)
    if len(parts) <= len(root_parts) or parts[:len(root_parts)] != root_parts:
        raise ValueError("private_rollout:containment_required")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptors: list[int] = []
    links: list[tuple[int, str, int]] = []
    root_fd = None
    uid = os.getuid()
    try:
        directory = os.open("/", flags | os.O_DIRECTORY)
        descriptors.append(directory)
        for index, part in enumerate(parts, 1):
            is_directory = index < len(parts)
            descriptor = os.open(part, flags | (os.O_DIRECTORY if is_directory else 0), dir_fd=directory)
            descriptors.append(descriptor)
            links.append((directory, part, descriptor))
            metadata = os.fstat(descriptor)
            if index >= len(root_parts) and metadata.st_uid != uid:
                raise ValueError("private_rollout:owner_required")
            if index == len(root_parts):
                root_fd = descriptor
                if stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise ValueError("private_rollout:private_root_required")
            if is_directory:
                if index > len(root_parts) and metadata.st_mode & 0o002:
                    raise ValueError("private_rollout:directory_mode")
                directory = descriptor
        assert root_fd is not None
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o002
                or before.st_nlink != 1):
            raise ValueError("private_rollout:regular_owned_file_required")
        size = before.st_size
        if not 0 < size <= MAX_PRIVATE_ROLLOUT_BYTES:
            raise ValueError("private_rollout:extent_invalid")
        # One bounded allocation avoids retaining both a chunk list and its
        # joined copy at the maximum rollout size.
        raw = os.pread(descriptor, size, 0)
        if len(raw) != size:
            raise ValueError("private_rollout:prefix_changed")
        offset = 0
        while offset < size:
            chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
            if not chunk or chunk != raw[offset:offset + len(chunk)]:
                raise ValueError("private_rollout:prefix_changed")
            offset += len(chunk)
        for index, (parent, name, child) in enumerate(links, 1):
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(child)
            if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
                raise ValueError("private_rollout:path_changed")
            if index >= len(root_parts) and held.st_uid != uid:
                raise ValueError("private_rollout:owner_required")
            if len(root_parts) < index < len(parts) and held.st_mode & 0o002:
                raise ValueError("private_rollout:directory_mode")
        root_stat = os.fstat(root_fd)
        after = os.fstat(descriptor)
        if root_stat.st_uid != uid or root_stat.st_mode & 0o077:
            raise ValueError("private_rollout:private_root_required")
        if (after.st_uid != uid or after.st_mode != before.st_mode or after.st_nlink != 1
                or after.st_size < size):
            raise ValueError("private_rollout:prefix_changed")
        return {
            "raw": raw, "prefix_bytes": size, "file_sha256": hashlib.sha256(raw).hexdigest(),
            "custody": {"status": "observed", "scope": "owned_prefix_snapshot", "owner_uid": uid,
                        "private_root_mode": stat.S_IMODE(root_stat.st_mode), "file_mode": stat.S_IMODE(after.st_mode),
                        "device": after.st_dev, "inode": after.st_ino, "links": 1, "read_passes": 2,
                        "prefix_bytes": size, "link_identity_checked": True},
        }
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _open_owned_regular(
    path: str | os.PathLike[str],
    *,
    max_bytes: int | None,
    required_mode: int | None = None,
) -> tuple[int, os.stat_result]:
    candidate = Path(path)
    descriptor = os.open(
        candidate,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o022
            or (
                hasattr(os, "getuid")
                and metadata.st_uid != os.getuid()
            )
            or (
                max_bytes is not None
                and metadata.st_size > max_bytes
            )
            or (
                required_mode is not None
                and stat.S_IMODE(metadata.st_mode) != required_mode
            )
        ):
            raise ValueError("owned regular file required")
        return descriptor, metadata
    except Exception:
        os.close(descriptor)
        raise


def verify_owned_regular_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int | None = None,
    required_mode: int | None = None,
) -> os.stat_result:
    descriptor, metadata = _open_owned_regular(
        path, max_bytes=max_bytes, required_mode=required_mode
    )
    os.close(descriptor)
    return metadata


def read_owned_bytes(
    path: str | os.PathLike[str],
    *,
    max_bytes: int,
    required_mode: int | None = None,
) -> bytes:
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("positive byte limit required")
    descriptor, _metadata = _open_owned_regular(
        path, max_bytes=max_bytes, required_mode=required_mode
    )
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(max_bytes + 1)
    finally:
        os.close(descriptor)
    if len(payload) > max_bytes:
        raise ValueError("owned file exceeds byte limit")
    return payload


def read_owned_json(
    path: str | os.PathLike[str],
    *,
    max_bytes: int,
    required_mode: int | None = None,
) -> Any:
    return json.loads(
        read_owned_bytes(
            path, max_bytes=max_bytes, required_mode=required_mode
        ).decode("utf-8")
    )


def sha256_owned_file(
    path: str | os.PathLike[str], *, max_bytes: int
) -> str:
    return hashlib.sha256(
        read_owned_bytes(path, max_bytes=max_bytes)
    ).hexdigest()


__all__ = [
    "MAX_PRIVATE_ROLLOUT_BYTES",
    "read_private_rollout",
    "read_owned_bytes",
    "read_owned_json",
    "sha256_owned_file",
    "verify_owned_regular_file",
]


def source_root_custody(roots: Mapping[str, Any]) -> dict[str, Any]:
    """Snapshot named canonical directories without reading their contents."""
    if not isinstance(roots, Mapping) or not roots:
        raise ValueError("source_roots:invalid")
    result = {}
    for name, raw in roots.items():
        if not isinstance(name, str) or not name or not isinstance(raw, (str, os.PathLike)):
            raise ValueError("source_roots:invalid")
        path = Path(raw)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("source_roots:invalid")
        canonical = path.resolve(strict=True)
        if path != canonical:
            raise ValueError("source_roots:invalid")
        metadata = path.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("source_roots:invalid")
        result[name] = {"path": str(canonical), "device": metadata.st_dev, "inode": metadata.st_ino}
    return result


def sealed_source_root_paths(sealed: Any) -> dict[str, Path]:
    """Validate the closed directory snapshot shape without filesystem I/O."""
    if not isinstance(sealed, Mapping) or not sealed:
        raise ValueError("source_roots:mismatch")
    result = {}
    for name, entry in sealed.items():
        if (not isinstance(name, str) or not name or not isinstance(entry, Mapping)
                or set(entry) != {"path", "device", "inode"}
                or not isinstance(entry["path"], str)
                or type(entry["device"]) is not int or type(entry["inode"]) is not int):
            raise ValueError("source_roots:mismatch")
        path = Path(entry["path"])
        if (not path.is_absolute() or str(path) != entry["path"]
                or ".." in path.parts or "\x00" in entry["path"]):
            raise ValueError("source_roots:mismatch")
        result[name] = path
    return result


def activated_source_roots(roots: Mapping[str, Any], sealed: Any) -> dict[str, Path]:
    """Resolve host-default roots and check the exact activation snapshot."""
    supplied_paths = sealed_source_root_paths(sealed)
    if not isinstance(roots, Mapping):
        raise ValueError("source_roots:mismatch")
    supplied = dict(roots)
    # These two defaults are derived by the host at activation. Other named
    # roots are required exactly; a request cannot add, drop or substitute one.
    for name in ("source", "plugin"):
        if name not in supplied and name in sealed:
            supplied[name] = sealed[name]["path"]
    if source_root_custody(supplied) != sealed:
        raise ValueError("source_roots:mismatch")
    return supplied_paths
