#!/usr/bin/env python3
"""Deterministic SPDX 2.3 SBOM generation and verification.

This module is deliberately self contained.  It is used at release time when
the portable package is still an ordinary local directory, so it does not ask a
package manager, contact a registry, or consult a network license service.
Inputs are normalized into a small, closed SPDX document and every digest and
identifier is derived from bytes supplied by the caller.

The public API is intentionally forgiving about the spelling of input fields
(``license``, ``license_expression`` and ``licenseDeclared`` are accepted),
while the emitted document has one canonical shape.  ``build_sbom`` and
``generate_sbom`` are aliases; ``validate_sbom`` raises a structured error and
``verify_sbom`` returns a compact machine result.
"""

from __future__ import annotations

import argparse
import ast
import datetime as _datetime
import hashlib
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


SPDX_VERSION = "SPDX-2.3"
SPDX_SCHEMA = "orch-dork/spdx-sbom/v1"
SBOM_SCHEMA = SPDX_SCHEMA
SCHEMA = SPDX_SCHEMA
DATA_LICENSE = "CC0-1.0"
DEFAULT_PACKAGE_NAME = "orch-dork"
DEFAULT_PACKAGE_VERSION = "0.0.0"
DEFAULT_BUILDER = "orch-dork-sbom/1"
NOASSERTION = "NOASSERTION"
NONE = "NONE"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9.-]{1,200}$")
_LICENSE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9.+-]{0,127}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_ABSOLUTE = re.compile(
    r"(?:^|[^A-Za-z0-9_.-])(?:/(?:Users|home|root|tmp|var|private|opt|etc|usr|bin|sbin|Applications|Library|System|Volumes|dev|proc|run)(?:[/\\]|$)|[A-Za-z]:[/\\]|~/[/\\])"
)
_SHA256_FIELDS = ("sha256", "checksum", "checksumValue", "digest", "package_digest")
_LICENSE_NAMES = {
    "0BSD",
    "AFL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-2.0",
    "Apache-1.1",
    "Artistic-2.0",
    "BSL-1.1",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "CC-BY-4.0",
    "CC-BY-SA-4.0",
    "CC-BY-NC-4.0",
    "CDDL-1.0",
    "EPL-1.0",
    "EPL-2.0",
    "CPL-1.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MIT-0",
    "MPL-2.0",
    "OSL-3.0",
    "PSF-2.0",
    "Ruby",
    "PHP-3.01",
    "OpenSSL",
    "WTFPL",
    "Unicode-DFS-2016",
    "LLVM-exception",
    "Classpath-exception-2.0",
    "GCC-exception-3.1",
    "Autoconf-exception-3.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
    "NOASSERTION",
    "NONE",
}
_INCOMPATIBLE_MARKERS = re.compile(r"(?:^|[-+.]|\b)(?:AGPL|GPL|SSPL)(?:[-+.]|\b)", re.I)
_NOTICE_BASENAMES = frozenset(
    {"license", "license.txt", "license.md", "copying", "copying.txt", "notice", "notice.txt"}
)


class SBOMError(ValueError):
    """Base class for deterministic SBOM input and verification failures."""

    def __init__(self, issues: str | Iterable[str], *, message: str | None = None):
        if isinstance(issues, str):
            values = [issues]
        else:
            values = [str(item) for item in issues]
        self.issues = tuple(sorted(set(item for item in values if item))) or ("sbom:invalid",)
        super().__init__(message or "SBOM rejected: " + ", ".join(self.issues))


class SBOMValidationError(SBOMError):
    """Raised when an SPDX document or package closure is not valid."""


class SBOMBuildError(SBOMError):
    """Raised when package inputs cannot produce a complete SBOM."""


# Compatibility names used by callers that model all failures as one error.
SPDXError = SBOMError
SPDXValidationError = SBOMValidationError


def canonical_json(value: Any) -> bytes:
    """Return strict, stable UTF-8 JSON bytes for a JSON-compatible value."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SBOMError("json:not_canonical") from exc


def canonical_json_text(value: Any) -> str:
    return canonical_json(value).decode("utf-8")


def sha256(value: bytes | bytearray | str | Mapping[str, Any] | Sequence[Any]) -> str:
    """Hash bytes or the canonical JSON representation of a value."""

    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, bytearray):
        raw = bytes(value)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = canonical_json(value)
    return hashlib.sha256(raw).hexdigest()


def json_sha256(value: Any) -> str:
    return sha256(canonical_json(value))


def _issue(*values: str) -> SBOMError:
    return SBOMBuildError(values)


def _text(value: Any, field: str, *, max_length: int = 512, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > max_length or (not value and not allow_empty):
        raise SBOMBuildError(f"{field}:invalid_text")
    if _CONTROL.search(value):
        raise SBOMBuildError(f"{field}:control_character")
    return value


def _safe_metadata(value: Any, field: str, *, max_length: int = 512, allow_url: bool = True) -> str:
    text = _text(value, field, max_length=max_length)
    if _ABSOLUTE.search(text) or "\\" in text or ".." in text.split("/"):
        raise SBOMBuildError(f"{field}:absolute_or_path")
    if text.startswith("file://"):
        raise SBOMBuildError(f"{field}:local_source_path")
    if _SCHEME.match(text) and not allow_url:
        raise SBOMBuildError(f"{field}:remote_value")
    return text


def _canonical_path(value: Any, field: str = "path") -> str:
    text = _text(value, field, max_length=1024)
    if "\\" in text or text.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", text):
        raise SBOMBuildError(f"{field}:not_relative")
    path = PurePosixPath(text)
    normalized = path.as_posix()
    if path.is_absolute() or normalized != text or text in {"", "."} or any(part in {"", ".", ".."} for part in path.parts):
        raise SBOMBuildError(f"{field}:not_canonical")
    return normalized


def _digest(value: Any, field: str, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise SBOMBuildError(f"{field}:sha256_required")
    return value


def _spdx_id(value: str) -> str:
    if not _ID.fullmatch(value):
        raise SBOMBuildError(f"spdx_id:invalid:{value[:32]}")
    return value


def _stable_id(prefix: str, *parts: Any) -> str:
    digest = sha256({"prefix": prefix, "parts": list(parts)})
    return _spdx_id(f"SPDXRef-{prefix}-{digest[:40]}")


def _spdx_license_atom(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SBOMBuildError(f"{field}:missing")
    value = value.strip()
    if value in {NOASSERTION, NONE}:
        return value
    # SPDX expressions are deliberately parsed as a closed small grammar.  A
    # full expression parser would add a dependency; this covers identifiers,
    # AND/OR, WITH and parentheses while rejecting arbitrary source text.
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9.+-]*|\(|\)|\bAND\b|\bOR\b|\bWITH\b", value)
    if "".join(tokens).replace("AND", "").replace("OR", "").replace("WITH", "") == "":
        raise SBOMBuildError(f"{field}:missing")
    scrubbed = re.sub(r"[A-Za-z][A-Za-z0-9.+-]*|\(|\)|\bAND\b|\bOR\b|\bWITH\b", "", value)
    if scrubbed.strip():
        raise SBOMBuildError(f"{field}:invalid_expression")
    atoms = [token for token in tokens if token not in {"AND", "OR", "WITH", "(", ")"}]
    if not atoms:
        raise SBOMBuildError(f"{field}:invalid_expression")
    for atom in atoms:
        if atom.startswith("LicenseRef-"):
            continue
        if atom not in _LICENSE_NAMES:
            raise SBOMBuildError(f"{field}:unknown_license:{atom}")
    # NOASSERTION cannot be hidden in a compound expression.
    if NOASSERTION in atoms or NONE in atoms:
        raise SBOMBuildError(f"{field}:invalid_noassertion_expression")
    return value


def validate_license_expression(value: Any, field: str = "license") -> str:
    return _spdx_license_atom(value, field)


def _license_compatible(expression: str, package_expression: str) -> bool:
    # A MIT-distributed runtime cannot silently absorb strong copyleft code.
    # LGPL is intentionally allowed for a dynamically linked dependency; GPL/
    # AGPL/SSPL are denied unless the package itself declares that expression.
    if expression == package_expression:
        return True
    return not bool(_INCOMPATIBLE_MARKERS.search(expression))


def _fixed_epoch(value: Any) -> tuple[int, str]:
    if value is None:
        value = os.environ.get("SOURCE_DATE_EPOCH", "0")
    if isinstance(value, bool):
        raise SBOMBuildError("fixed_epoch:invalid")
    try:
        epoch = int(value)
    except (TypeError, ValueError) as exc:
        raise SBOMBuildError("fixed_epoch:invalid") from exc
    if epoch < 0 or epoch > 253402300799:
        raise SBOMBuildError("fixed_epoch:out_of_range")
    created = _datetime.datetime.fromtimestamp(epoch, _datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return epoch, created


def _read_json_no_duplicates(path: Path) -> Mapping[str, Any]:
    class _Duplicate(ValueError):
        pass

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _Duplicate(key)
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=hook)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, _Duplicate) as exc:
        raise SBOMBuildError(f"metadata:{path.name}:invalid_json") from exc
    if not isinstance(value, Mapping):
        raise SBOMBuildError(f"metadata:{path.name}:not_object")
    return value


def _read_package_files(root: Path) -> list[dict[str, Any]]:
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise SBOMBuildError("package_root:invalid")
    files: list[dict[str, Any]] = []
    for base, directories, names in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        names.sort()
        for name in list(directories):
            path = Path(base) / name
            if path.is_symlink():
                raise SBOMBuildError(f"file:symlink:{_canonical_path(path.relative_to(root).as_posix())}")
        for name in names:
            path = Path(base) / name
            relative = _canonical_path(path.relative_to(root).as_posix())
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise SBOMBuildError(f"file:special:{relative}")
                data = path.read_bytes()
            except SBOMError:
                raise
            except OSError as exc:
                raise SBOMBuildError(f"file:unreadable:{relative}") from exc
            mode = 0o755 if stat.S_IMODE(info.st_mode) & 0o111 else 0o644
            files.append({"path": relative, "size": len(data), "mode": mode, "sha256": sha256(data)})
    files.sort(key=lambda row: row["path"])
    return files


def _coerce_file_records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        # A path -> bytes/string or path -> record mapping is convenient for
        # tests and callers that already hold a canonical inventory.
        records: list[Any] = []
        for path, item in value.items():
            if isinstance(item, Mapping):
                record = dict(item)
                record.setdefault("path", path)
            else:
                record = {"path": path, "content": item}
            records.append(record)
    elif isinstance(value, (list, tuple)):
        records = list(value)
    else:
        raise SBOMBuildError("files:must_be_array_or_mapping")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(records):
        if not isinstance(raw, Mapping):
            raise SBOMBuildError(f"files[{index}]:must_be_object")
        row = dict(raw)
        path = _canonical_path(row.get("path", row.get("fileName")), f"files[{index}].path")
        if path in seen:
            raise SBOMBuildError(f"file:duplicate:{path}")
        seen.add(path)
        content = row.get("content", row.get("bytes"))
        if content is not None:
            if isinstance(content, str):
                data = content.encode("utf-8")
            elif isinstance(content, (bytes, bytearray)):
                data = bytes(content)
            else:
                raise SBOMBuildError(f"files[{index}].content:invalid")
            expected = row.get("sha256", row.get("checksum", row.get("checksumValue")))
            if expected is not None and expected != sha256(data):
                raise SBOMBuildError(f"checksum:mismatch:{path}")
            digest = sha256(data)
            size = len(data)
        else:
            digest = row.get("sha256", row.get("checksum", row.get("checksumValue")))
            digest = _digest(digest, f"files[{index}].sha256")
            size = row.get("size")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise SBOMBuildError(f"files[{index}].size:invalid")
        mode = row.get("mode", 0o644)
        if isinstance(mode, str):
            try:
                mode = int(mode, 8)
            except ValueError as exc:
                raise SBOMBuildError(f"files[{index}].mode:invalid") from exc
        if not isinstance(mode, int) or isinstance(mode, bool) or mode < 0 or mode > 0o7777:
            raise SBOMBuildError(f"files[{index}].mode:invalid")
        mode = 0o755 if mode & 0o111 else 0o644
        license_value = row.get("license", row.get("license_expression", row.get("licenseConcluded")))
        output.append({"path": path, "size": size, "mode": mode, "sha256": digest, "license": license_value})
    output.sort(key=lambda row: row["path"])
    return output


def _manifest_metadata(root: Path) -> dict[str, Any]:
    manifest_path = root / ".codex-plugin/plugin.json"
    if not manifest_path.exists():
        return {}
    manifest = _read_json_no_duplicates(manifest_path)
    result: dict[str, Any] = {}
    for key in ("name", "version", "license", "licenseExpression", "supplier", "originator"):
        if key in manifest:
            result[key] = manifest[key]
    result["manifest_sha256"] = sha256(manifest_path.read_bytes())
    return result


def _bundled_module_names(root: Path) -> set[str]:
    """Include regular Python packages as well as standalone bundled modules."""
    names = set()
    for path in root.rglob("*.py"):
        if path.is_file():
            names.add(path.parent.name if path.name == "__init__.py" else path.stem)
    return names


def discover_stdlib_modules(root: Path) -> tuple[str, ...]:
    """Return top-level standard-library modules imported by bundled Python."""

    bundled = _bundled_module_names(root)
    known = set(getattr(sys, "stdlib_module_names", ()))
    # Python 3.9 and older do not expose stdlib_module_names.  These are the
    # modules used by the portable runtime and keep the fallback deterministic.
    known.update(
        {
            "argparse", "ast", "asyncio", "base64", "collections", "concurrent", "contextlib",
            "copy", "dataclasses", "datetime", "enum", "functools", "hashlib", "importlib", "io",
            "itertools", "json", "logging", "math", "os", "pathlib", "re", "secrets", "selectors",
            "shutil", "signal", " stat", "subprocess", "sys", "tempfile", "threading", "time", "types",
            "typing", "unicodedata", "uuid", "warnings", "weakref", "xml", "zlib",
        }
    )
    imported: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
    return tuple(sorted(module for module in imported if module in known and module not in bundled and module != " stat"))


def _normalise_records(value: Any, *, field: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        # A mapping keyed by package name is the common dependency-lock shape.
        rows: list[Any] = []
        for name, item in value.items():
            if isinstance(item, Mapping):
                record = dict(item)
                record.setdefault("name", name)
            else:
                record = {"name": name, "version": item}
            rows.append(record)
    elif isinstance(value, (list, tuple)):
        rows = list(value)
    else:
        raise SBOMBuildError(f"{field}:must_be_array_or_mapping")
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(rows):
        if isinstance(raw, str):
            raw = {"name": raw}
        if not isinstance(raw, Mapping):
            raise SBOMBuildError(f"{field}[{index}]:must_be_object")
        row = dict(raw)
        name = row.get("name", row.get("id", row.get("package")))
        name = _text(name, f"{field}[{index}].name", max_length=256)
        version = row.get("version", row.get("versionInfo", "unknown"))
        version = _text(version, f"{field}[{index}].version", max_length=128)
        kind = str(row.get("kind", row.get("type", "third-party"))).lower()
        if kind in {"stdlib", "standard-library", "standard_library"}:
            kind = "standard-library"
        elif kind in {"runtime", "interpreter", "python"}:
            kind = "interpreter"
        elif kind not in {"third-party", "standard-library", "interpreter"}:
            raise SBOMBuildError(f"{field}[{index}].kind:invalid")
        identity = (kind, name.casefold(), version)
        if identity in seen:
            raise SBOMBuildError(f"dependency:duplicate_identity:{name}@{version}")
        seen.add(identity)
        if row.get("verified") is False or row.get("package_manager_verified") is False:
            raise SBOMBuildError(f"dependency:unverified:{name}")
        if row.get("package_manager_summary") is not None and not row.get("package_manager_verified", False):
            raise SBOMBuildError(f"dependency:unverified_package_manager_summary:{name}")
        expression = row.get("license", row.get("license_expression", row.get("licenseDeclared")))
        if expression is None:
            if kind in {"standard-library", "interpreter"}:
                expression = NOASSERTION
            else:
                raise SBOMBuildError(f"license:missing:{name}")
        expression = _spdx_license_atom(expression, f"{field}[{index}].license")
        evidence = row.get("license_evidence", row.get("evidence"))
        rationale = row.get("noassertion_rationale", row.get("rationale"))
        pointer = row.get("evidence_pointer", row.get("pointer"))
        if expression == NOASSERTION and (not isinstance(evidence, Mapping) or not evidence.get("pointer", pointer) or not evidence.get("rationale", rationale)):
            raise SBOMBuildError(f"license:noassertion_requires_rationale:{name}")
        checksum = row.get("sha256", row.get("checksum", row.get("checksumValue", row.get("digest"))))
        content = row.get("content", row.get("bytes"))
        if checksum is None and content is not None:
            checksum = sha256(content.encode("utf-8") if isinstance(content, str) else bytes(content))
        if checksum is None and kind in {"standard-library", "interpreter"}:
            checksum = sha256({"name": name, "version": version, "kind": kind, "origin": row.get("origin", "")})
        checksum = _digest(checksum, f"{field}[{index}].sha256")
        supplier = row.get("supplier", row.get("originator", "NOASSERTION"))
        supplier = _safe_metadata(supplier, f"{field}[{index}].supplier", max_length=256) if supplier != NOASSERTION else NOASSERTION
        origin = row.get("origin", row.get("source", row.get("downloadLocation", "NOASSERTION")))
        if origin != NOASSERTION:
            origin = _safe_metadata(origin, f"{field}[{index}].origin", max_length=1024)
        if "direct" in row or "direct_dependency" in row:
            direct = bool(row.get("direct", row.get("direct_dependency")))
        elif "transitive" in row:
            direct = False
        else:
            # A flat dependency lock is a direct closure unless it explicitly
            # marks a row transitive.  Requiring callers to add a redundant
            # ``direct: true`` would make ordinary lockfiles unusable.
            direct = True
        requires = row.get("dependencies", row.get("requires", row.get("transitive", [])))
        if requires is None:
            requires = []
        if isinstance(requires, str):
            requires = [requires]
        if not isinstance(requires, (list, tuple)) or any(not isinstance(item, str) for item in requires):
            raise SBOMBuildError(f"{field}[{index}].dependencies:invalid")
        notice = row.get("notice", row.get("notice_file", row.get("notice_pointer")))
        result.append(
            {
                "name": name,
                "version": version,
                "kind": kind,
                "license": expression,
                "license_evidence": dict(evidence) if isinstance(evidence, Mapping) else None,
                "noassertion_rationale": rationale,
                "evidence_pointer": pointer,
                "sha256": checksum,
                "supplier": supplier,
                "origin": origin,
                "direct": direct,
                "dependencies": tuple(sorted(set(requires))),
                "notice": notice,
            }
        )
    return sorted(result, key=lambda row: (row["kind"], row["name"].casefold(), row["version"]))


def _normalise_evidence(value: Any, *, field: str, kind: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    rows: list[Any]
    if isinstance(value, Mapping):
        rows = []
        for key, item in value.items():
            if isinstance(item, Mapping):
                row = dict(item)
                row.setdefault("subject", key)
            else:
                row = {"subject": key, "pointer": item}
            rows.append(row)
    elif isinstance(value, (list, tuple)):
        rows = list(value)
    else:
        raise SBOMBuildError(f"{field}:must_be_array_or_mapping")
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise SBOMBuildError(f"{field}[{index}]:must_be_object")
        subject = _text(raw.get("subject", raw.get("path", raw.get("package", ""))), f"{field}[{index}].subject", max_length=512)
        pointer = _text(raw.get("pointer", raw.get("evidence_pointer", raw.get("file", ""))), f"{field}[{index}].pointer", max_length=1024)
        if pointer and not _SCHEME.match(pointer):
            pointer = _canonical_path(pointer, f"{field}[{index}].pointer")
        digest = raw.get("sha256", raw.get("checksum", raw.get("checksumValue")))
        digest = _digest(digest, f"{field}[{index}].sha256")
        rationale = _text(raw.get("rationale", raw.get("reason", "")), f"{field}[{index}].rationale", max_length=1024)
        expression = raw.get("license", raw.get("license_expression"))
        if expression is not None:
            expression = _spdx_license_atom(expression, f"{field}[{index}].license")
        key = (subject.casefold(), pointer)
        if key in seen:
            raise SBOMBuildError(f"{field}:duplicate")
        seen.add(key)
        result.append({"subject": subject, "pointer": pointer, "sha256": digest, "rationale": rationale, "license": expression, "kind": kind})
    return sorted(result, key=lambda row: (row["subject"].casefold(), row["pointer"]))


def _auto_notice_evidence(root: Path | None, files: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in files:
        path = str(row["path"])
        if Path(path).name.casefold() not in _NOTICE_BASENAMES:
            continue
        result.append({"subject": path, "pointer": path, "sha256": row["sha256"], "rationale": "bundled license or notice file", "license": "MIT", "kind": "notice"})
    return sorted(result, key=lambda row: row["subject"])


def _package_input(package: Any, package_root: Any) -> tuple[dict[str, Any], Path | None]:
    metadata: dict[str, Any] = {}
    root: Path | None = None
    if isinstance(package, (str, os.PathLike, Path)) and package_root is None:
        package_root = package
        package = None
    if package_root is not None:
        root = Path(package_root)
    if package is not None:
        if not isinstance(package, Mapping):
            raise SBOMBuildError("package:must_be_object")
        metadata.update(dict(package))
        if root is None:
            candidate = metadata.get("root", metadata.get("package_root"))
            if candidate is not None:
                root = Path(candidate)
    if root is not None:
        metadata.update({key: value for key, value in _manifest_metadata(root).items() if key not in metadata})
    return metadata, root


def _dependency_name_index(records: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    index: dict[str, Mapping[str, Any]] = {}
    for row in records:
        key = str(row["name"]).casefold()
        if key in index:
            raise SBOMBuildError(f"dependency:duplicate_identity:{row['name']}")
        index[key] = row
    return index


def _build_document(
    package: Any = None,
    package_root: Any = None,
    *,
    files: Any = None,
    dependencies: Any = None,
    interpreter: Any = None,
    stdlib_modules: Any = None,
    license_evidence: Any = None,
    notices: Any = None,
    required_notices: Any = None,
    package_digest: str | None = None,
    fixed_epoch: Any = None,
    source: str | None = None,
    source_revision: str | None = None,
    builder: str = DEFAULT_BUILDER,
    manifest_digest: str | None = None,
    strict_dependency_closure: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    if dependencies is None:
        dependencies = kwargs.pop("declared_dependencies", kwargs.pop("dependency_lock", None))
    package_manager_summary = kwargs.pop("package_manager_summary", None)
    if package_manager_summary is not None and not kwargs.pop("package_manager_verified", False):
        raise SBOMBuildError("dependency:unverified_package_manager_summary")
    if kwargs.pop("allow_unverified_package_manager_summary", False):
        raise SBOMBuildError("dependency:unverified_package_manager_summary")
    metadata, root = _package_input(package, package_root)
    if files is None:
        files = metadata.get("files", metadata.get("inventory"))
    if root is not None:
        root_files = _read_package_files(root)
        if files is None:
            files = root_files
        else:
            supplied = _coerce_file_records(files)
            actual = {row["path"]: row for row in root_files}
            declared = {row["path"]: row for row in supplied}
            if set(actual) != set(declared):
                missing = sorted(set(actual) - set(declared))
                extra = sorted(set(declared) - set(actual))
                raise SBOMBuildError([*(f"file:missing:{path}" for path in missing), *(f"file:undeclared:{path}" for path in extra)])
            for path in sorted(actual):
                if actual[path]["sha256"] != declared[path]["sha256"] or actual[path]["size"] != declared[path]["size"]:
                    raise SBOMBuildError(f"checksum:mismatch:{path}")
            files = root_files
    file_rows = _coerce_file_records(files)
    if not file_rows:
        raise SBOMBuildError("files:empty")
    file_by_path = {row["path"]: row for row in file_rows}

    name = metadata.get("name", metadata.get("package_name", DEFAULT_PACKAGE_NAME))
    name = _safe_metadata(name, "package.name", max_length=256, allow_url=False)
    version = metadata.get("version", metadata.get("package_version", DEFAULT_PACKAGE_VERSION))
    version = _safe_metadata(version, "package.version", max_length=128, allow_url=False)
    package_expression = metadata.get(
        "license",
        metadata.get("license_expression", metadata.get("licenseExpression", metadata.get("licenseDeclared", "MIT"))),
    )
    package_expression = _spdx_license_atom(package_expression, "package.license")
    supplier = metadata.get("supplier", metadata.get("originator", "NOASSERTION"))
    supplier = supplier if supplier == NOASSERTION else _safe_metadata(supplier, "package.supplier", max_length=256)
    origin = metadata.get("origin", metadata.get("source", metadata.get("downloadLocation", "NOASSERTION")))
    origin = origin if origin == NOASSERTION else _safe_metadata(origin, "package.origin", max_length=1024)
    package_digest = package_digest or metadata.get("package_digest", metadata.get("digest"))
    if package_digest is None:
        package_digest = sha256({"files": [{key: row[key] for key in ("path", "size", "mode", "sha256")} for row in file_rows]})
    package_digest = _digest(package_digest, "package_digest")
    manifest_digest = manifest_digest or metadata.get("manifest_sha256", metadata.get("manifest_digest"))
    if manifest_digest is not None:
        manifest_digest = _digest(manifest_digest, "manifest_digest")
    epoch, created = _fixed_epoch(fixed_epoch)
    builder = _safe_metadata(builder, "builder", max_length=256, allow_url=False)

    dep_value = dependencies if dependencies is not None else metadata.get("dependencies", metadata.get("packages"))
    dep_rows = _normalise_records(dep_value, field="dependencies")
    interpreter_value = interpreter if interpreter is not None else metadata.get("interpreter", metadata.get("runtime"))
    if interpreter_value is None:
        interpreter_value = {"name": "CPython", "version": platform.python_version(), "kind": "interpreter", "license": NOASSERTION, "rationale": "runtime identity from executing interpreter", "evidence": {"pointer": "runtime:python", "rationale": "runtime identity from executing interpreter"}}
    if isinstance(interpreter_value, Mapping) and "evidence" not in interpreter_value and interpreter_value.get("license") == NOASSERTION:
        interpreter_value = dict(interpreter_value)
        interpreter_value["evidence"] = {"pointer": "runtime:python", "rationale": "runtime identity from executing interpreter"}
    interpreter_rows = _normalise_records([interpreter_value], field="interpreter")
    if stdlib_modules is None:
        stdlib_modules = metadata.get("stdlib_modules")
    if stdlib_modules is None and root is not None:
        stdlib_modules = [{"name": module, "version": platform.python_version(), "kind": "standard-library", "license": NOASSERTION, "evidence": {"pointer": f"stdlib:{module}", "rationale": "standard library is interpreter-provided"}} for module in discover_stdlib_modules(root)]
    elif stdlib_modules is None:
        stdlib_modules = []
    stdlib_rows = _normalise_records(stdlib_modules, field="stdlib_modules")
    records = dep_rows + interpreter_rows + stdlib_rows
    record_index = _dependency_name_index(records)
    # A code import must be represented either by a bundled module or a declared
    # dependency.  This closes the common undeclared-dependency escape hatch.
    if root is not None and strict_dependency_closure:
        bundled_modules = {name.casefold() for name in _bundled_module_names(root)}
        imported: set[str] = set()
        for path in root.rglob("*.py"):
            if not path.is_file():
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".", 1)[0].casefold() for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".", 1)[0].casefold())
        known_stdlib = set(discover_stdlib_modules(root))
        undeclared = sorted(module for module in imported if module not in bundled_modules and module not in known_stdlib and module not in record_index)
        if undeclared:
            raise SBOMBuildError([f"dependency:undeclared:{module}" for module in undeclared])
    for row in records:
        if row["kind"] == "third-party" and not _license_compatible(row["license"], package_expression):
            raise SBOMBuildError(f"license:incompatible:{row['name']}")
        for child in row["dependencies"]:
            if child.casefold() not in record_index:
                raise SBOMBuildError(f"dependency:undeclared:{child}")
    # Check the explicitly marked direct/transitive closure.  A dependency that
    # is not direct must be reachable from a direct package, except runtime
    # declarations which are attached to the plugin itself.
    direct_names = {row["name"].casefold() for row in dep_rows if row["direct"]}
    if dep_rows and strict_dependency_closure:
        reachable: set[str] = set(direct_names)
        pending = list(direct_names)
        while pending:
            current = pending.pop()
            row = record_index.get(current)
            if row is None:
                continue
            for child in row["dependencies"]:
                child_key = child.casefold()
                if child_key not in reachable:
                    reachable.add(child_key)
                    pending.append(child_key)
        for row in dep_rows:
            if not row["direct"] and row["name"].casefold() not in reachable:
                raise SBOMBuildError(f"dependency:unreachable_transitive:{row['name']}")

    # License and notice evidence is machine-readable pointers + hashes only;
    # no source body or user path is copied into this document.
    evidence_rows = _normalise_evidence(license_evidence if license_evidence is not None else metadata.get("license_evidence"), field="license_evidence", kind="license")
    notice_rows = _normalise_evidence(notices if notices is not None else metadata.get("notices"), field="notice_evidence", kind="notice")
    if package_expression == NOASSERTION:
        package_evidence = [row for row in evidence_rows if row["subject"].casefold() in {name.casefold(), "package"}]
        if not package_evidence and not metadata.get("rationale", metadata.get("noassertion_rationale")):
            raise SBOMBuildError("license:noassertion_requires_rationale:package")
    if root is not None:
        auto_notices = _auto_notice_evidence(root, file_rows)
        known_notice_keys = {(row["subject"], row["pointer"]) for row in notice_rows}
        notice_rows.extend(row for row in auto_notices if (row["subject"], row["pointer"]) not in known_notice_keys)
    required_value = required_notices if required_notices is not None else metadata.get("required_notices", [])
    if isinstance(required_value, str):
        required_value = [required_value]
    if required_value is None:
        required_value = []
    if not isinstance(required_value, (list, tuple)):
        raise SBOMBuildError("notice:required_notices_invalid")
    notice_subjects = {row["subject"] for row in notice_rows}
    for required in required_value:
        required_text = _text(required, "required_notices", max_length=1024)
        if required_text not in notice_subjects:
            raise SBOMBuildError(f"notice:missing:{required_text}")
    for row in dep_rows:
        if row["notice"] is not None:
            pointer = str(row["notice"])
            if pointer not in notice_subjects:
                raise SBOMBuildError(f"notice:missing:{pointer}")

    plugin_id = _stable_id("Package", "plugin", name, version, package_digest)
    file_ids = {row["path"]: _stable_id("File", row["path"], row["sha256"]) for row in file_rows}
    package_ids: dict[str, str] = {"plugin": plugin_id}
    for row in records:
        key = f"{row['kind']}:{row['name'].casefold()}@{row['version']}"
        package_ids[key] = _stable_id("Package", row["kind"], row["name"], row["version"], row["sha256"])

    packages: list[dict[str, Any]] = []
    packages.append(
        {
            "SPDXID": plugin_id,
            "checksums": [{"algorithm": "SHA256", "checksumValue": package_digest}],
            "copyrightText": NOASSERTION,
            "downloadLocation": origin,
            "externalRefs": ([{"referenceCategory": "PACKAGE-MANAGER", "referenceLocator": f"sha256:{package_digest}", "referenceType": "purl"}] if False else []),
            "filesAnalyzed": True,
            "licenseConcluded": package_expression,
            "licenseDeclared": package_expression,
            "name": name,
            "originator": supplier,
            "packageFileName": "package",
            "packageVerificationCode": {"packageVerificationCodeValue": package_digest},
            "supplier": supplier,
            "versionInfo": version,
        }
    )
    for row in records:
        key = f"{row['kind']}:{row['name'].casefold()}@{row['version']}"
        package_id = package_ids[key]
        packages.append(
            {
                "SPDXID": package_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": row["sha256"]}],
                "copyrightText": NOASSERTION,
                "downloadLocation": row["origin"],
                "filesAnalyzed": False,
                "licenseConcluded": row["license"],
                "licenseDeclared": row["license"],
                "name": row["name"],
                "originator": row["supplier"],
                "supplier": row["supplier"],
                "versionInfo": row["version"],
            }
        )
    files_out: list[dict[str, Any]] = []
    for row in file_rows:
        expression = row["license"] or package_expression
        if expression is None:
            raise SBOMBuildError(f"license:missing:{row['path']}")
        expression = _spdx_license_atom(expression, f"file.license:{row['path']}")
        if expression == NOASSERTION:
            matches = [item for item in evidence_rows if item["subject"] == row["path"]]
            if not matches or not matches[0]["rationale"]:
                raise SBOMBuildError(f"license:noassertion_requires_rationale:{row['path']}")
        files_out.append(
            {
                "SPDXID": file_ids[row["path"]],
                "checksums": [{"algorithm": "SHA256", "checksumValue": row["sha256"]}],
                "copyrightText": NOASSERTION,
                "fileName": row["path"],
                "licenseConcluded": expression,
                "licenseInfoInFiles": [expression],
            }
        )

    relationships: list[dict[str, Any]] = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": plugin_id}
    ]
    for row in file_rows:
        relationships.append({"spdxElementId": plugin_id, "relationshipType": "CONTAINS", "relatedSpdxElement": file_ids[row["path"]]})
    for row in records:
        key = f"{row['kind']}:{row['name'].casefold()}@{row['version']}"
        dep_id = package_ids[key]
        relationships.append({"spdxElementId": plugin_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": dep_id})
        for child in row["dependencies"]:
            target = record_index[child.casefold()]
            target_key = f"{target['kind']}:{target['name'].casefold()}@{target['version']}"
            relationships.append({"spdxElementId": dep_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": package_ids[target_key]})
    relationships.sort(key=lambda row: (row["spdxElementId"], row["relationshipType"], row["relatedSpdxElement"]))
    identity = {"name": name, "version": version, "package_digest": package_digest, "manifest_digest": manifest_digest or ""}
    namespace = f"https://spdx.org/spdxdocs/{re.sub(r'[^A-Za-z0-9.-]+', '-', name).strip('-')}-{sha256(identity)[:40]}"
    evidence = {
        "fixedEpoch": epoch,
        "license": evidence_rows,
        "notices": notice_rows,
        "packageDigest": package_digest,
        "source": {"origin": origin, "revision": source_revision} if source is None and source_revision is None else {"origin": source or origin, "revision": source_revision},
    }
    if source is not None:
        evidence["source"]["origin"] = _safe_metadata(source, "source", max_length=1024)
    if source_revision is not None:
        evidence["source"]["revision"] = _safe_metadata(source_revision, "source_revision", max_length=256, allow_url=False)
    document: dict[str, Any] = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": SPDX_VERSION,
        "creationInfo": {"created": created, "creators": [f"Tool: {builder}"]},
        "dataLicense": DATA_LICENSE,
        "documentDescribes": [plugin_id],
        "documentNamespace": namespace,
        "files": sorted(files_out, key=lambda row: row["fileName"]),
        "name": f"{name}-{version}",
        "packages": sorted(packages, key=lambda row: row["SPDXID"]),
        "relationships": relationships,
        "primaryPackageId": plugin_id,
        "evidence": evidence,
        "sbomSchema": SPDX_SCHEMA,
    }
    validate_sbom(document, package_root=root, expected_package_digest=package_digest)
    return document


def build_sbom(package: Any = None, package_root: Any = None, **kwargs: Any) -> dict[str, Any]:
    """Build a canonical SPDX 2.3 document from package inputs."""

    return _build_document(package, package_root, **kwargs)


generate_sbom = build_sbom
create_sbom = build_sbom
build_spdx_sbom = build_sbom
generate_spdx_sbom = build_sbom


def _json_loaded(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, (str, os.PathLike, Path)):
        path = Path(value)
        try:
            pairs: list[tuple[str, Any]] = []

            def hook(items: list[tuple[str, Any]]) -> dict[str, Any]:
                seen: set[str] = set()
                result: dict[str, Any] = {}
                for key, item in items:
                    if key in seen:
                        raise SBOMValidationError(f"json:duplicate_key:{key}")
                    seen.add(key)
                    result[key] = item
                return result

            return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=hook)
        except SBOMError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SBOMValidationError("json:invalid") from exc
    raise SBOMValidationError("sbom:must_be_object_or_path")


def _walk_values(value: Any, *, key: str = "", depth: int = 0) -> Iterable[tuple[str, Any]]:
    if depth > 12:
        raise SBOMValidationError("json:too_deep")
    if isinstance(value, Mapping):
        if len(value) > 4096:
            raise SBOMValidationError("json:too_many_fields")
        for name, item in value.items():
            yield from _walk_values(item, key=str(name), depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 4096:
            raise SBOMValidationError("json:too_many_items")
        for item in value:
            yield from _walk_values(item, key=key, depth=depth + 1)
    else:
        yield key, value


def _validate_checksums(rows: Any, field: str) -> str:
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
        raise SBOMValidationError(f"{field}:sha256_required")
    checksum = rows[0]
    if checksum.get("algorithm") != "SHA256" or not _HEX64.fullmatch(str(checksum.get("checksumValue", ""))):
        raise SBOMValidationError(f"{field}:sha256_required")
    return str(checksum["checksumValue"])


def validate_sbom(
    document: Any,
    *,
    package_root: Any = None,
    expected_package_digest: str | None = None,
    expected_namespace: str | None = None,
    expected_license: str | None = None,
    strict: bool = True,
) -> dict[str, Any]:
    """Validate schema, closure, licenses, notices, and package bytes."""

    doc = _json_loaded(document)
    if not isinstance(doc, Mapping):
        raise SBOMValidationError("sbom:not_object")
    if doc.get("spdxVersion") != SPDX_VERSION:
        raise SBOMValidationError("schema:spdx_version")
    if "sbomSchema" in doc and doc.get("sbomSchema") != SPDX_SCHEMA:
        raise SBOMValidationError("schema:sbom_schema")
    if doc.get("dataLicense") != DATA_LICENSE:
        raise SBOMValidationError("schema:data_license")
    if not isinstance(doc.get("documentNamespace"), str) or not doc["documentNamespace"].startswith("https://spdx.org/spdxdocs/"):
        raise SBOMValidationError("namespace:invalid")
    if expected_namespace is not None and doc["documentNamespace"] != expected_namespace:
        raise SBOMValidationError("namespace:mismatch")
    creation = doc.get("creationInfo")
    if not isinstance(creation, Mapping) or not isinstance(creation.get("created"), str) or not creation.get("created", "").endswith("Z"):
        raise SBOMValidationError("creation:fixed_epoch_required")
    if not isinstance(creation.get("creators"), list) or not creation["creators"]:
        raise SBOMValidationError("creation:creators_required")
    packages = doc.get("packages")
    files = doc.get("files")
    relationships = doc.get("relationships")
    if not isinstance(packages, list) or not packages or not isinstance(files, list) or not files or not isinstance(relationships, list):
        raise SBOMValidationError("schema:collections_required")
    if len(packages) > 2048 or len(files) > 8192 or len(relationships) > 32768:
        raise SBOMValidationError("schema:bounded_size")
    if [row.get("SPDXID") if isinstance(row, Mapping) else None for row in packages] != sorted(
        (row.get("SPDXID") if isinstance(row, Mapping) else None for row in packages), key=lambda value: str(value)
    ):
        raise SBOMValidationError("arrays:packages_not_canonical")
    if [row.get("fileName") if isinstance(row, Mapping) else None for row in files] != sorted(
        (row.get("fileName") if isinstance(row, Mapping) else None for row in files), key=lambda value: str(value)
    ):
        raise SBOMValidationError("arrays:files_not_canonical")
    ids: set[str] = {"SPDXRef-DOCUMENT"}
    package_map: dict[str, Mapping[str, Any]] = {}
    for index, package in enumerate(packages):
        if not isinstance(package, Mapping):
            raise SBOMValidationError(f"packages[{index}]:not_object")
        package_id = package.get("SPDXID")
        if not isinstance(package_id, str) or not _ID.fullmatch(package_id) or package_id in ids:
            raise SBOMValidationError(f"packages[{index}]:duplicate_or_invalid_id")
        ids.add(package_id)
        package_map[package_id] = package
        for key in ("name", "versionInfo", "licenseConcluded", "licenseDeclared", "originator", "supplier", "downloadLocation"):
            if key not in package:
                raise SBOMValidationError(f"packages[{index}]:missing:{key}")
        _spdx_license_atom(package["licenseConcluded"], f"packages[{index}].licenseConcluded")
        _spdx_license_atom(package["licenseDeclared"], f"packages[{index}].licenseDeclared")
        _validate_checksums(package.get("checksums"), f"packages[{index}].checksums")
    file_map: dict[str, Mapping[str, Any]] = {}
    paths: set[str] = set()
    for index, row in enumerate(files):
        if not isinstance(row, Mapping):
            raise SBOMValidationError(f"files[{index}]:not_object")
        file_id = row.get("SPDXID")
        path = row.get("fileName")
        if not isinstance(file_id, str) or not _ID.fullmatch(file_id) or file_id in ids:
            raise SBOMValidationError(f"files[{index}]:duplicate_or_invalid_id")
        ids.add(file_id)
        if not isinstance(path, str):
            raise SBOMValidationError(f"files[{index}].fileName:missing")
        _canonical_path(path, f"files[{index}].fileName")
        if path in paths:
            raise SBOMValidationError(f"file:duplicate:{path}")
        paths.add(path)
        file_map[path] = row
        _validate_checksums(row.get("checksums"), f"files[{index}].checksums")
        _spdx_license_atom(row.get("licenseConcluded"), f"files[{index}].licenseConcluded")
        infos = row.get("licenseInfoInFiles")
        if not isinstance(infos, list) or not infos:
            raise SBOMValidationError(f"files[{index}].licenseInfoInFiles:missing")
        for expression in infos:
            _spdx_license_atom(expression, f"files[{index}].licenseInfoInFiles")
    if doc.get("primaryPackageId") not in package_map:
        raise SBOMValidationError("subject:primary_package_missing")
    primary = package_map[str(doc["primaryPackageId"])]
    primary_digest = _validate_checksums(primary.get("checksums"), "subject.package.checksums")
    if expected_package_digest is not None:
        expected_package_digest = _digest(expected_package_digest, "expected_package_digest")
        if primary_digest != expected_package_digest:
            raise SBOMValidationError("subject:package_digest_mismatch")
    if expected_license is not None and primary.get("licenseDeclared") != expected_license:
        raise SBOMValidationError("license:package_mismatch")
    relation_keys: set[tuple[str, str, str]] = set()
    relation_order: list[tuple[str, str, str]] = []
    for index, relation in enumerate(relationships):
        if not isinstance(relation, Mapping):
            raise SBOMValidationError(f"relationships[{index}]:not_object")
        source = relation.get("spdxElementId")
        target = relation.get("relatedSpdxElement")
        relation_type = relation.get("relationshipType")
        if source not in ids or target not in ids or not isinstance(relation_type, str):
            raise SBOMValidationError(f"relationships[{index}]:unknown_target")
        key = (str(source), relation_type, str(target))
        if key in relation_keys:
            raise SBOMValidationError("relationships:duplicate")
        relation_keys.add(key)
        relation_order.append(key)
    if relation_order != sorted(relation_order):
        raise SBOMValidationError("arrays:relationships_not_canonical")
    if ("SPDXRef-DOCUMENT", "DESCRIBES", str(doc["primaryPackageId"])) not in relation_keys:
        raise SBOMValidationError("subject:document_not_described")
    contains = {target for source, typ, target in relation_keys if source == doc["primaryPackageId"] and typ == "CONTAINS"}
    if contains != set(file_map.values() and [row["SPDXID"] for row in files]):
        raise SBOMValidationError("file:unrepresented")
    evidence = doc.get("evidence", {})
    if not isinstance(evidence, Mapping):
        raise SBOMValidationError("evidence:invalid")
    for key, item in _walk_values(evidence):
        if key.lower() in {"body", "content", "source", "sourcebody", "raw", "text", "extractedtext"} and item not in {NOASSERTION, NONE}:
            raise SBOMValidationError("evidence:source_body_forbidden")
        if isinstance(item, str) and _ABSOLUTE.search(item):
            raise SBOMValidationError("evidence:absolute_path")
    # Every evidence pointer is a digest-bearing, bounded record.
    for evidence_key in ("license", "notices"):
        rows = evidence.get(evidence_key, [])
        if not isinstance(rows, list):
            raise SBOMValidationError(f"evidence:{evidence_key}:invalid")
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping) or not row.get("subject") or not row.get("pointer"):
                raise SBOMValidationError(f"evidence:{evidence_key}[{index}]:invalid")
            _digest(row.get("sha256"), f"evidence:{evidence_key}[{index}].sha256")
    if package_root is not None:
        actual = {row["path"]: row for row in _read_package_files(Path(package_root))}
        declared = {row["fileName"]: _validate_checksums(row.get("checksums"), f"file:{row['fileName']}.checksums") for row in files}
        for path in sorted(set(actual) - set(declared)):
            raise SBOMValidationError(f"file:undeclared:{path}")
        for path in sorted(set(declared) - set(actual)):
            raise SBOMValidationError(f"file:missing:{path}")
        for path in sorted(actual):
            if actual[path]["sha256"] != declared[path]:
                raise SBOMValidationError(f"checksum:mismatch:{path}")
    canonical = canonical_json(doc)
    return {"status": "PASS", "ok": True, "schema": SPDX_SCHEMA, "sbom_sha256": sha256(canonical), "package_digest": primary_digest, "file_count": len(files), "package_count": len(packages)}


def canonicalize_sbom(document: Any) -> dict[str, Any]:
    """Validate and return a detached JSON-compatible canonical copy."""

    doc = _json_loaded(document)
    validate_sbom(doc)
    return json.loads(canonical_json(doc).decode("utf-8"))


canonical_spdx_json = canonical_json
sbom_digest = lambda document: sha256(canonical_json(document))


def verify_sbom(document: Any, **kwargs: Any) -> dict[str, Any]:
    """Return a sanitized verification receipt instead of raising on failure."""

    try:
        return validate_sbom(document, **kwargs)
    except SBOMError as exc:
        return {"status": "DENY", "ok": False, "schema": SPDX_SCHEMA, "issues": list(exc.issues)}


verify_spdx_sbom = verify_sbom
check_sbom = verify_sbom


def assert_valid_sbom(document: Any, **kwargs: Any) -> dict[str, Any]:
    return validate_sbom(document, **kwargs)


def write_sbom(document: Mapping[str, Any], destination: str | os.PathLike[str]) -> str:
    validate_sbom(document)
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(document) + b"\n")
    return sha256(canonical_json(document))


def load_sbom(path: str | os.PathLike[str]) -> dict[str, Any]:
    value = _json_loaded(path)
    if not isinstance(value, Mapping):
        raise SBOMValidationError("sbom:not_object")
    return dict(value)


read_sbom = load_sbom


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Generate or verify deterministic SPDX 2.3 SBOM")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("package_root")
    build.add_argument("output")
    build.add_argument("--epoch", type=int, default=None)
    build.add_argument("--package-digest", default=None)
    verify = sub.add_parser("verify")
    verify.add_argument("sbom")
    args = parser.parse_args()
    try:
        if args.command == "build":
            document = build_sbom(package_root=args.package_root, fixed_epoch=args.epoch, package_digest=args.package_digest)
            digest = write_sbom(document, args.output)
            print(json.dumps({"status": "PASS", "sbom_sha256": digest}, sort_keys=True))
        else:
            result = verify_sbom(args.sbom)
            print(canonical_json_text(result))
            return 0 if result.get("ok") else 1
    except SBOMError as exc:
        print(canonical_json_text({"status": "DENY", "issues": list(exc.issues)}))
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
