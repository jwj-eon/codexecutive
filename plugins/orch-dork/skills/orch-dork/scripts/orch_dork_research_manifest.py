#!/usr/bin/env python3
"""Exhaustive, sealed Markdown inventories for bounded research tasks.

The manifest records identities, not document bodies. Validation re-reads the
named root and therefore detects corpus drift instead of merely accepting a
caller-authored list. No path outside the supplied root is followed.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any, Mapping, Sequence


MANIFEST_SCHEMA = "orch-dork/research-manifest/v1"
REPORT_SCHEMA = "orch-dork/research-manifest-report/v1"
MAX_FILES = 4_096
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_CLAIMS = 1_024
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "manifest_id",
        "selection",
        "files",
        "file_count",
        "total_bytes",
        "corpus_sha256",
        "claims",
        "used_claim_ids",
        "source_pointer",
        "manifest_sha256",
    }
)
_SELECTION_FIELDS = frozenset(
    {"engine", "suffix", "case_sensitive", "recursive", "symlink_policy"}
)
_FILE_FIELDS = frozenset({"path", "size_bytes", "sha256"})
_CLAIM_FIELDS = frozenset({"claim_id", "statement_sha256", "source_paths"})


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, *, limit: int = 4096) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= limit
        and "\x00" not in value
        and "\r" not in value
    )


def _relative_path(value: Any) -> str | None:
    if not _text(value, limit=8192):
        return None
    candidate = PurePosixPath(str(value))
    if candidate.is_absolute() or not candidate.parts or any(
        part in {"", ".", ".."} for part in candidate.parts
    ):
        return None
    return candidate.as_posix()


def _selected_paths(base: Path, engine: str) -> list[Path]:
    if engine == "filesystem_all":
        selected: list[Path] = []
        for current, directories, files in os.walk(base, followlinks=False):
            current_path = Path(current)
            for name in list(directories):
                if (current_path / name).is_symlink():
                    raise ValueError("research:symlink_refused")
            selected.extend(
                current_path / name
                for name in files
                if Path(name).suffix.casefold() == ".md"
            )
        return selected
    if engine == "ripgrep_default_visible":
        try:
            completed = subprocess.run(
                ["rg", "--files", "-g", "*.md"],
                cwd=base,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise ValueError("research:ripgrep_inventory_failed") from exc
        if completed.returncode not in {0, 1} or completed.stderr:
            raise ValueError("research:ripgrep_inventory_failed")
        return [base / row for row in completed.stdout.splitlines() if row]
    raise ValueError("research:selection_engine_invalid")


def _scan(
    root: str | os.PathLike[str] | Path,
    *,
    selection_engine: str,
) -> list[dict[str, Any]]:
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise ValueError("research:root_not_directory")
    rows: list[dict[str, Any]] = []
    total = 0
    for candidate in _selected_paths(base, selection_engine):
        if candidate.suffix.casefold() != ".md":
            raise ValueError("research:non_markdown_selected")
        if candidate.is_symlink():
            raise ValueError("research:symlink_refused")
        resolved = candidate.resolve(strict=True)
        try:
            relative = resolved.relative_to(base).as_posix()
        except ValueError as exc:
            raise ValueError("research:path_escape") from exc
        stat = resolved.stat()
        if not resolved.is_file():
            raise ValueError("research:non_regular_file")
        if stat.st_size > MAX_FILE_BYTES:
            raise ValueError("research:file_too_large")
        total += stat.st_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("research:corpus_too_large")
        with resolved.open("rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        rows.append({"path": relative, "size_bytes": stat.st_size, "sha256": digest})
        if len(rows) > MAX_FILES:
            raise ValueError("research:too_many_files")
    return sorted(rows, key=lambda row: row["path"])


def _normalize_claims(
    claims: Any,
    *,
    paths: set[str],
    used_claim_ids: Any,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(claims, Sequence) or isinstance(claims, (str, bytes)):
        raise ValueError("research:claims_not_array")
    if len(claims) > MAX_CLAIMS:
        raise ValueError("research:too_many_claims")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in claims:
        if not isinstance(raw, Mapping) or set(raw) != _CLAIM_FIELDS:
            raise ValueError("research:claim_shape_invalid")
        claim_id = raw.get("claim_id")
        if not isinstance(claim_id, str) or _IDENTIFIER.fullmatch(claim_id) is None or claim_id in seen:
            raise ValueError("research:claim_id_invalid")
        seen.add(claim_id)
        statement_sha = raw.get("statement_sha256")
        if not isinstance(statement_sha, str) or _SHA256.fullmatch(statement_sha) is None:
            raise ValueError("research:claim_statement_digest_invalid")
        source_values = raw.get("source_paths")
        if not isinstance(source_values, list) or not source_values:
            raise ValueError("research:claim_sources_empty")
        parsed_paths = [_relative_path(item) for item in source_values]
        if any(path is None for path in parsed_paths) or len(set(parsed_paths)) != len(source_values):
            raise ValueError("research:claim_source_invalid")
        source_paths = sorted(str(path) for path in parsed_paths)
        if any(path not in paths for path in source_paths):
            raise ValueError("research:claim_source_missing")
        normalized.append(
            {
                "claim_id": claim_id,
                "statement_sha256": statement_sha,
                "source_paths": source_paths,
            }
        )
    if not isinstance(used_claim_ids, list):
        raise ValueError("research:used_claims_not_array")
    used = sorted(used_claim_ids)
    if (
        any(not isinstance(item, str) or _IDENTIFIER.fullmatch(item) is None for item in used)
        or len(used) != len(set(used))
    ):
        raise ValueError("research:used_claim_invalid")
    if not set(used).issubset(seen):
        raise ValueError("research:used_claim_unknown")
    return sorted(normalized, key=lambda row: row["claim_id"]), used


def build_markdown_manifest(
    root: str | os.PathLike[str] | Path,
    *,
    manifest_id: str,
    claims: Sequence[Mapping[str, Any]],
    used_claim_ids: Sequence[str],
    source_pointer: str,
    selection_engine: str = "filesystem_all",
) -> dict[str, Any]:
    """Scan and seal the exact recursive Markdown corpus beneath ``root``."""

    if not isinstance(manifest_id, str) or _IDENTIFIER.fullmatch(manifest_id) is None:
        raise ValueError("research:manifest_id_invalid")
    if not _text(source_pointer):
        raise ValueError("research:source_pointer_invalid")
    files = _scan(root, selection_engine=selection_engine)
    normalized_claims, used = _normalize_claims(
        claims,
        paths={row["path"] for row in files},
        used_claim_ids=list(used_claim_ids),
    )
    core = {
        "schema": MANIFEST_SCHEMA,
        "manifest_id": manifest_id,
        "selection": {
            "engine": selection_engine,
            "suffix": ".md",
            "case_sensitive": selection_engine == "ripgrep_default_visible",
            "recursive": True,
            "symlink_policy": "reject",
        },
        "files": files,
        "file_count": len(files),
        "total_bytes": sum(row["size_bytes"] for row in files),
        "corpus_sha256": _sha(files),
        "claims": normalized_claims,
        "used_claim_ids": used,
        "source_pointer": source_pointer,
    }
    return {**core, "manifest_sha256": _sha(core)}


def validate_markdown_manifest(
    manifest: Any,
    root: str | os.PathLike[str] | Path,
) -> dict[str, Any]:
    """Validate a seal and independently re-read its exact Markdown corpus."""

    issues: list[str] = []
    value = dict(manifest) if isinstance(manifest, Mapping) else {}
    if set(value) != _MANIFEST_FIELDS:
        issues.append("manifest:shape_invalid")
    if value.get("schema") != MANIFEST_SCHEMA:
        issues.append("manifest:schema_invalid")
    supplied_seal = value.get("manifest_sha256")
    core = {key: child for key, child in value.items() if key != "manifest_sha256"}
    try:
        expected_seal = _sha(core)
    except (TypeError, ValueError, OverflowError):
        expected_seal = None
    if supplied_seal != expected_seal:
        issues.append("manifest:seal_mismatch")
    selection = value.get("selection")
    if not isinstance(selection, Mapping) or set(selection) != _SELECTION_FIELDS:
        issues.append("manifest:selection_invalid")
        selection_engine = "invalid"
    else:
        selection_engine = selection.get("engine")
        expected_selection = {
            "engine": selection_engine,
            "suffix": ".md",
            "case_sensitive": selection_engine == "ripgrep_default_visible",
            "recursive": True,
            "symlink_policy": "reject",
        }
        if selection_engine not in {"filesystem_all", "ripgrep_default_visible"}:
            issues.append("manifest:selection_invalid")
        elif dict(selection) != expected_selection:
            issues.append("manifest:selection_invalid")

    declared = value.get("files") if isinstance(value.get("files"), list) else []
    declared_paths: set[str] = set()
    for index, row in enumerate(declared):
        if not isinstance(row, Mapping) or set(row) != _FILE_FIELDS:
            issues.append(f"manifest:files[{index}]:shape_invalid")
            continue
        path = _relative_path(row.get("path"))
        if path is None or not path.casefold().endswith(".md"):
            issues.append(f"manifest:files[{index}]:path_invalid")
        elif path in declared_paths:
            issues.append("manifest:duplicate_path")
        else:
            declared_paths.add(path)
        if type(row.get("size_bytes")) is not int or row.get("size_bytes") < 0:
            issues.append(f"manifest:files[{index}]:size_invalid")
        if not isinstance(row.get("sha256"), str) or _SHA256.fullmatch(row["sha256"]) is None:
            issues.append(f"manifest:files[{index}]:digest_invalid")
    if value.get("file_count") != len(declared):
        issues.append("manifest:file_count_mismatch")
    if value.get("total_bytes") != sum(
        row.get("size_bytes", 0) for row in declared if isinstance(row, Mapping)
    ):
        issues.append("manifest:total_bytes_mismatch")
    if value.get("corpus_sha256") != _sha(declared):
        issues.append("manifest:corpus_digest_mismatch")
    try:
        _normalize_claims(
            value.get("claims"),
            paths=declared_paths,
            used_claim_ids=value.get("used_claim_ids"),
        )
    except ValueError as exc:
        issues.append(str(exc))
    if not _text(value.get("source_pointer")):
        issues.append("manifest:source_pointer_invalid")

    try:
        observed = _scan(root, selection_engine=str(selection_engine))
    except (OSError, ValueError) as exc:
        issues.append(str(exc))
        observed = []
    declared_by_path = {
        str(row.get("path")): row for row in declared if isinstance(row, Mapping)
    }
    observed_by_path = {row["path"]: row for row in observed}
    if set(declared_by_path) != set(observed_by_path):
        issues.append("research:inventory_changed")
    for path in sorted(set(declared_by_path) & set(observed_by_path)):
        if declared_by_path[path].get("sha256") != observed_by_path[path]["sha256"]:
            issues.append("research:file_digest_changed:" + path)
        if declared_by_path[path].get("size_bytes") != observed_by_path[path]["size_bytes"]:
            issues.append("research:file_size_changed:" + path)
    unique = sorted(set(issues))
    return {
        "schema": REPORT_SCHEMA,
        "status": "PASS" if not unique else "FAIL",
        "manifest_id": value.get("manifest_id"),
        "manifest_sha256": supplied_seal,
        "corpus_sha256": value.get("corpus_sha256"),
        "file_count": len(observed),
        "used_claim_ids": list(value.get("used_claim_ids", []))
        if isinstance(value.get("used_claim_ids"), list)
        else [],
        "issues": unique,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


__all__ = [
    "MANIFEST_SCHEMA",
    "REPORT_SCHEMA",
    "build_markdown_manifest",
    "validate_markdown_manifest",
]
