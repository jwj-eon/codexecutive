"""Build and validate an offline, Git-bound local marketplace manifest.

The package builder owns the staged tree.  This module deliberately has a much
smaller responsibility: it binds that tree to a *clean* Git commit, the exact
plugin version declared by ``.codex-plugin/plugin.json``, and a small piece of
sanitized health evidence.  It never talks to a remote Git endpoint and never
changes a checkout.

The public entry points are :func:`construct_local_marketplace` (also exposed
as :func:`build_local_marketplace`) and :func:`validate_local_marketplace`.
The constructor returns a regular marketplace JSON object with an explicit
``binding`` block.  The binding is intentionally strict and portable: it
contains the immutable revision and plugin identity, but no machine-specific
repository path or raw health output.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


SCHEMA = "orch-dork/local-git-marketplace/v1"
DEFAULT_MARKETPLACE_NAME = "orch-dork-local"
DEFAULT_DISPLAY_NAME = "Orch Dork Local"
DEFAULT_INSTALLATION_POLICY = "AVAILABLE"
DEFAULT_AUTHENTICATION_POLICY = "ON_INSTALL"
DEFAULT_CATEGORY = "Productivity"

_SHA1_RE = re.compile(r"[0-9a-f]{40}\Z")
_SLUG_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,127})\Z")
_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# Health evidence and display labels are copied into an installable manifest.
# Keep path detection deliberately conservative: an absolute POSIX/Windows
# path must never be allowed to cross that boundary, even when it appears
# after a ``cwd=``/``path=`` style prefix rather than at the start of a value.
_ABSOLUTE_PATH_RE = re.compile(
    r"(?:^|(?<=[^A-Za-z0-9_]))/(?:[^/\s]|$)|^[A-Za-z]:[\\/]|(?:^|(?<=[^A-Za-z0-9_]))~[\\/]",
    re.I,
)
_REMOTE_RE = re.compile(
    r"(?:^|(?<=[^A-Za-z0-9_]))(?:[A-Za-z][A-Za-z0-9+.-]*://|git@|ssh://)",
    re.I,
)
_SENSITIVE_RE = re.compile(
    r"(?:password|passwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|authorization)",
    re.I,
)

_TOP_LEVEL_FIELDS = {"name", "interface", "plugins", "binding"}
_INTERFACE_FIELDS = {"displayName"}
_ENTRY_FIELDS = {"name", "source", "policy", "category"}
_SOURCE_FIELDS = {"source", "path"}
_POLICY_FIELDS = {"installation", "authentication"}
_BINDING_FIELDS = {"schema", "revision", "plugin", "health"}
_PLUGIN_ID_FIELDS = {"name", "version"}
_HEALTH_FIELDS = {"status", "checks", "tool_inventory", "runtime"}
_HEALTH_CHECK_FIELDS = {"name", "status"}
_HEALTH_RUNTIME_FIELDS = {"status", "name"}


class _DuplicateJSONKey(ValueError):
    """Internal marker used to reject ambiguous JSON objects."""


class LocalMarketplaceError(ValueError):
    """Base error raised for malformed or unsafe marketplace inputs."""

    def __init__(self, message: str, *, issues: Sequence[str] = ()) -> None:
        self.issues = tuple(str(issue) for issue in issues) or (message,)
        super().__init__(message)


class LocalMarketplaceValidationError(LocalMarketplaceError):
    """Raised when a local marketplace or its Git checkout fails validation."""


MarketplaceValidationError = LocalMarketplaceValidationError


def _error(*issues: str) -> LocalMarketplaceValidationError:
    clean = tuple(issue for issue in issues if issue)
    return LocalMarketplaceValidationError(
        "; ".join(clean) if clean else "local marketplace validation failed",
        issues=clean,
    )


def _json_object_no_duplicates(pairs: list[tuple[Any, Any]]) -> dict[Any, Any]:
    """Decode JSON objects without silently accepting duplicate keys.

    ``json.loads`` otherwise keeps only the last occurrence.  That makes a
    manifest's effective name/version depend on parser behaviour rather than
    on its bytes, which is incompatible with deterministic marketplace
    validation.
    """

    result: dict[Any, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(str(key))
        result[key] = value
    return result


def _mapping(value: Any, field: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(f"{field}:must_be_object")
    copied = dict(value)
    unknown = sorted((str(item) for item in set(copied) - allowed), key=str)
    if unknown:
        raise _error(f"{field}:unexpected_fields:{','.join(str(item) for item in unknown)}")
    return copied


def _text(value: Any, field: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise _error(f"{field}:must_be_nonempty_string")
    if _CONTROL_RE.search(value):
        raise _error(f"{field}:control_character")
    return value


def _reject_path_or_remote_text(value: str, field: str) -> str:
    """Reject machine-local paths, URLs, and traversal-looking text.

    This is applied to labels and versions in addition to the health payload;
    all of those values are persisted in the local marketplace manifest.
    """

    if "\\" in value or any(part == ".." for part in value.split("/")):
        raise _error(f"{field}:unsafe_path_text")
    if _ABSOLUTE_PATH_RE.search(value) or _REMOTE_RE.search(value):
        raise _error(f"{field}:path_or_remote_value")
    return value


def _safe_name(value: Any, field: str, *, slug: bool = False, allow_slashes: bool = True) -> str:
    text = _text(value, field, max_length=128)
    if ( _SLUG_RE if slug else _SAFE_NAME_RE).fullmatch(text) is None:
        raise _error(f"{field}:unsafe_name")
    if not allow_slashes and "/" in text:
        raise _error(f"{field}:unsafe_name")
    if ".." in text or text.startswith(("/", "\\")):
        raise _error(f"{field}:unsafe_name")
    if _SENSITIVE_RE.search(text) or _REMOTE_RE.search(text):
        raise _error(f"{field}:sensitive_or_remote_value")
    return text


def _revision(value: Any, field: str = "binding.revision") -> str:
    text = _text(value, field, max_length=40)
    if _SHA1_RE.fullmatch(text) is None:
        raise _error(f"{field}:must_be_full_lowercase_sha1")
    return text


def _assert_no_sensitive_data(value: Any, *, field: str = "health", depth: int = 0) -> None:
    """Reject raw secrets, paths, URLs, and unbounded nested health payloads."""

    if depth > 5:
        raise _error(f"{field}:too_deep")
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise _error(f"{field}:too_many_fields")
        for key, item in value.items():
            key_text = _text(key, f"{field}.key", max_length=64)
            if _SENSITIVE_RE.search(key_text) or key_text.lower() in {"key", "headers", "body", "stdout", "stderr"}:
                raise _error(f"{field}:sensitive_field")
            _assert_no_sensitive_data(item, field=f"{field}.{key_text}", depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise _error(f"{field}:too_many_items")
        for index, item in enumerate(value):
            _assert_no_sensitive_data(item, field=f"{field}[{index}]", depth=depth + 1)
        return
    if isinstance(value, str):
        if len(value) > 256 or _CONTROL_RE.search(value):
            raise _error(f"{field}:unsafe_text")
        if (
            _ABSOLUTE_PATH_RE.search(value)
            or _REMOTE_RE.search(value)
            or "\\" in value
            or any(part == ".." for part in value.split("/"))
        ):
            raise _error(f"{field}:path_or_remote_value")
        if _SENSITIVE_RE.search(value):
            raise _error(f"{field}:sensitive_value")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    raise _error(f"{field}:unsupported_value")


def sanitize_health_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and reduce health evidence to a deterministic safe summary.

    Accepted evidence consists only of a passing status, named passing checks,
    an optional tool-name inventory, and an optional passing runtime marker.
    Check strings are accepted as a convenience and normalized to objects.
    Raw command output, paths, URLs, credentials, and unknown fields are never
    copied into the resulting marketplace manifest.
    """

    _assert_no_sensitive_data(evidence)
    payload = _mapping(evidence, "health", _HEALTH_FIELDS)
    status = payload.get("status")
    if status != "PASS":
        raise _error("health.status:must_be_PASS")

    raw_checks = payload.get("checks", [])
    if isinstance(raw_checks, Mapping):
        # A mapping is useful for small runtime check reports and is normalized
        # to sorted records so output does not depend on insertion order.
        raw_checks = [{"name": key, "status": value} for key, value in sorted(raw_checks.items())]
    if not isinstance(raw_checks, (list, tuple)) or len(raw_checks) > 64:
        raise _error("health.checks:must_be_array")
    checks: list[dict[str, str]] = []
    seen_checks: set[str] = set()
    for index, check in enumerate(raw_checks):
        if isinstance(check, str):
            name = check
            check_status = "PASS"
        else:
            row = _mapping(check, f"health.checks[{index}]", _HEALTH_CHECK_FIELDS)
            name = row.get("name")
            check_status = row.get("status")
        name = _safe_name(name, f"health.checks[{index}].name", allow_slashes=False)
        if name in seen_checks:
            raise _error(f"health.checks:duplicate:{name}")
        seen_checks.add(name)
        if check_status != "PASS":
            raise _error(f"health.checks[{index}].status:must_be_PASS")
        checks.append({"name": name, "status": "PASS"})
    checks.sort(key=lambda row: row["name"])

    inventory = payload.get("tool_inventory", [])
    if not isinstance(inventory, (list, tuple)) or len(inventory) > 128:
        raise _error("health.tool_inventory:must_be_array")
    tools: list[str] = []
    for index, name in enumerate(inventory):
        tools.append(_safe_name(name, f"health.tool_inventory[{index}]", allow_slashes=False))
    if len(set(tools)) != len(tools):
        raise _error("health.tool_inventory:duplicates")
    tools.sort()

    runtime = payload.get("runtime")
    runtime_out: dict[str, str] | None = None
    if runtime is not None:
        if isinstance(runtime, str):
            runtime_out = {
                "name": _safe_name(runtime, "health.runtime", allow_slashes=False),
                "status": "PASS",
            }
        else:
            row = _mapping(runtime, "health.runtime", _HEALTH_RUNTIME_FIELDS)
            if row.get("status") != "PASS":
                raise _error("health.runtime.status:must_be_PASS")
            runtime_out = {
                "name": _safe_name(
                    row.get("name", "runtime"),
                    "health.runtime.name",
                    allow_slashes=False,
                ),
                "status": "PASS",
            }

    result: dict[str, Any] = {"status": "PASS", "checks": checks, "tool_inventory": tools}
    if runtime_out is not None:
        result["runtime"] = runtime_out
    return result


def _path(value: os.PathLike[str] | str, field: str) -> Path:
    if isinstance(value, Path):
        raw = str(value)
    elif isinstance(value, (str, os.PathLike)):
        raw = os.fspath(value)
    else:
        raise _error(f"{field}:must_be_path")
    if not isinstance(raw, str):
        raise _error(f"{field}:must_be_path")
    if not raw or "\x00" in raw or _REMOTE_RE.search(raw):
        raise _error(f"{field}:must_be_local_path")
    path = Path(raw)
    if path.is_symlink():
        raise _error(f"{field}:symlink")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise _error(f"{field}:missing")
    if resolved != path.absolute().resolve():
        raise _error(f"{field}:symlink_or_path_escape")
    return resolved


def _run_git(repository: Path, *args: str) -> str:
    """Run a read-only local Git query with prompts and optional locks disabled."""

    env = os.environ.copy()
    # Ambient repository-selection variables can silently redirect ``git -C``
    # to another checkout.  The marketplace binding must be to the supplied
    # local root, so clear those variables and disable user/system config that
    # could install hooks or alter command semantics.
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        env.pop(key, None)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
        }
    )
    try:
        completed = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(repository), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    except FileNotFoundError as exc:
        raise _error("git:unavailable") from exc
    except OSError as exc:
        raise _error("git:unavailable") from exc
    if completed.returncode != 0:
        raise _error("git:command_failed")
    return completed.stdout.strip()


def _validate_repository(repository_value: os.PathLike[str] | str, revision: str, plugin_name: str) -> tuple[Path, Path]:
    repository = _path(repository_value, "repository")
    if not repository.is_dir():
        raise _error("repository:not_directory")
    try:
        root = Path(_run_git(repository, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except LocalMarketplaceError as exc:
        if "git:unavailable" in exc.issues:
            raise
        raise _error("git:not_repository") from exc
    if root != repository:
        raise _error("repository:must_be_git_root")

    # Porcelain output includes staged, unstaged, and untracked entries.  No
    # path is copied into an error or returned report, keeping output stable.
    try:
        status = _run_git(
            repository,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
            "--no-renames",
        )
    except LocalMarketplaceError as exc:
        raise _error("git:status_unavailable") from exc
    if status:
        raise _error("git:dirty")

    try:
        head = _run_git(repository, "rev-parse", "--verify", "HEAD")
    except LocalMarketplaceError as exc:
        raise _error("revision:unavailable") from exc
    if head != revision:
        raise _error("revision:not_current_head")
    try:
        identity = _run_git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}")
    except LocalMarketplaceError as exc:
        raise _error("revision:not_found") from exc
    if identity != revision:
        raise _error("revision:identity_mismatch")

    plugin_root = repository / "plugins" / plugin_name
    try:
        relative = plugin_root.relative_to(repository)
    except ValueError as exc:  # defensive; plugin_name is constrained above
        raise _error("source:path_escape") from exc
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise _error("source:path_noncanonical")
    current = repository
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise _error(f"source:symlink:{relative.as_posix()}")
    if not plugin_root.is_dir():
        raise _error("source:missing_plugin")
    _reject_symlinks_and_special_files(plugin_root, repository)
    return repository, plugin_root


def _reject_symlinks_and_special_files(plugin_root: Path, repository: Path) -> None:
    for root, directories, files in os.walk(plugin_root, followlinks=False):
        root_path = Path(root)
        for name in list(directories) + list(files):
            path = root_path / name
            try:
                path.lstat()
            except OSError:
                raise _error("source:unreadable")
            relative = path.relative_to(repository).as_posix()
            if path.is_symlink():
                raise _error(f"source:symlink:{relative}")
            if not (path.is_dir() or path.is_file()):
                raise _error(f"source:special_file:{relative}")


def _read_plugin_manifest(plugin_root: Path, plugin_name: str, expected_version: str) -> dict[str, Any]:
    manifest_path = plugin_root / ".codex-plugin" / "plugin.json"
    if manifest_path.is_symlink():
        raise _error("plugin_manifest:symlink")
    if not manifest_path.is_file():
        raise _error("plugin_manifest:missing")
    try:
        value = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_json_object_no_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJSONKey) as exc:
        raise _error("plugin_manifest:malformed_json") from exc
    if not isinstance(value, Mapping):
        raise _error("plugin_manifest:must_be_object")
    manifest = dict(value)
    if manifest.get("name") != plugin_name:
        raise _error("plugin_manifest:name_mismatch")
    if manifest.get("version") != expected_version:
        raise _error("plugin_manifest:version_mismatch")
    _safe_name(manifest.get("name"), "plugin_manifest.name", slug=True)
    _reject_path_or_remote_text(
        _text(manifest.get("version"), "plugin_manifest.version", max_length=128),
        "plugin_manifest.version",
    )
    return manifest


def _canonical_manifest(
    *,
    marketplace_name: str,
    display_name: str,
    plugin_name: str,
    revision: str,
    plugin_version: str,
    health: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "name": marketplace_name,
        "interface": {"displayName": display_name},
        "plugins": [
            {
                "name": plugin_name,
                "source": {"source": "local", "path": f"./plugins/{plugin_name}"},
                "policy": {
                    "installation": DEFAULT_INSTALLATION_POLICY,
                    "authentication": DEFAULT_AUTHENTICATION_POLICY,
                },
                "category": DEFAULT_CATEGORY,
            }
        ],
        "binding": {
            "schema": SCHEMA,
            "revision": revision,
            "plugin": {"name": plugin_name, "version": plugin_version},
            "health": dict(health),
        },
    }


def _write_json(path_value: os.PathLike[str] | str, payload: Mapping[str, Any]) -> Path:
    path = _path_for_write(path_value)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise _error("manifest_path:parent_unavailable") from exc
    encoded = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        try:
            temporary.write_text(encoded, encoding="utf-8")
            os.replace(temporary, path)
        except OSError as exc:
            raise _error("manifest_path:write_failed") from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return path


def _path_for_write(value: os.PathLike[str] | str) -> Path:
    if isinstance(value, (str, os.PathLike)):
        raw = os.fspath(value)
    else:
        raise _error("manifest_path:must_be_path")
    if not isinstance(raw, str):
        raise _error("manifest_path:must_be_path")
    if not raw or "\x00" in raw or _REMOTE_RE.search(raw):
        raise _error("manifest_path:must_be_local_path")
    path = Path(raw)
    if path.exists() and path.is_symlink():
        raise _error("manifest_path:symlink")
    if path.exists() and not path.is_file():
        raise _error("manifest_path:special_file")
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() and (temporary.is_symlink() or not temporary.is_file()):
        raise _error("manifest_path:temporary_special_file")
    return path.absolute()


def construct_local_marketplace(
    repository: os.PathLike[str] | str,
    revision: str,
    plugin_name: str,
    plugin_version: str,
    health_evidence: Mapping[str, Any],
    *,
    marketplace_name: str = DEFAULT_MARKETPLACE_NAME,
    display_name: str = DEFAULT_DISPLAY_NAME,
    manifest_path: os.PathLike[str] | str | None = None,
) -> dict[str, Any]:
    """Construct a canonical local marketplace manifest from a clean Git tree.

    ``revision`` must be the full lowercase Git commit ID and must equal the
    checkout's current ``HEAD``.  The plugin is always sourced from
    ``./plugins/<plugin_name>`` relative to the repository root.  If
    ``manifest_path`` is supplied, the deterministic JSON manifest is written
    there; otherwise this function is pure.
    """

    name = _safe_name(plugin_name, "plugin_name", slug=True)
    version = _reject_path_or_remote_text(
        _text(plugin_version, "plugin_version", max_length=128), "plugin_version"
    )
    rev = _revision(revision, "revision")
    market = _safe_name(marketplace_name, "marketplace_name", slug=True)
    shown = _reject_path_or_remote_text(
        _text(display_name, "display_name", max_length=128), "display_name"
    )
    health = sanitize_health_evidence(health_evidence)
    _validate_repository(repository, rev, name)
    plugin_root = Path(repository).resolve() / "plugins" / name
    _read_plugin_manifest(plugin_root, name, version)
    manifest = _canonical_manifest(
        marketplace_name=market,
        display_name=shown,
        plugin_name=name,
        revision=rev,
        plugin_version=version,
        health=health,
    )
    if manifest_path is not None:
        _write_json(manifest_path, manifest)
    return manifest


build_local_marketplace = construct_local_marketplace


def _load_marketplace(value: Mapping[str, Any] | os.PathLike[str] | str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, (str, os.PathLike)):
        path = _path(value, "marketplace_manifest")
        if not path.is_file():
            if path.exists():
                raise _error("marketplace_manifest:special_file")
            raise _error("marketplace_manifest:missing")
        try:
            loaded = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_json_object_no_duplicates,
            )
        except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJSONKey) as exc:
            raise _error("marketplace_manifest:malformed_json") from exc
        if not isinstance(loaded, Mapping):
            raise _error("marketplace_manifest:must_be_object")
        return dict(loaded)
    raise _error("marketplace_manifest:must_be_object_or_path")


def validate_local_marketplace(
    marketplace: Mapping[str, Any] | os.PathLike[str] | str,
    repository: os.PathLike[str] | str,
    *,
    expected_revision: str | None = None,
    expected_plugin_name: str | None = None,
    expected_plugin_version: str | None = None,
    health_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a canonical marketplace and return sanitized verification data.

    The first two positional arguments may be supplied in either order for
    compatibility with callers that naturally start from a repository path.
    A mapping/path is distinguished from a repository path before validation.
    """

    # Be forgiving about the natural ``validate(repository, manifest)`` call
    # while keeping the documented ``validate(manifest, repository)`` form.
    if isinstance(marketplace, (str, os.PathLike)) and isinstance(repository, Mapping):
        marketplace, repository = repository, marketplace

    payload = _load_marketplace(marketplace)
    top = _mapping(payload, "marketplace", _TOP_LEVEL_FIELDS)
    market_name = _safe_name(top.get("name"), "marketplace.name", slug=True)
    interface = _mapping(top.get("interface"), "marketplace.interface", _INTERFACE_FIELDS)
    _reject_path_or_remote_text(
        _text(interface.get("displayName"), "marketplace.interface.displayName", max_length=128),
        "marketplace.interface.displayName",
    )
    plugins = top.get("plugins")
    if not isinstance(plugins, list) or len(plugins) != 1:
        raise _error("marketplace.plugins:must_contain_one_entry")
    entry = _mapping(plugins[0], "marketplace.plugins[0]", _ENTRY_FIELDS)
    name = _safe_name(entry.get("name"), "marketplace.plugins[0].name", slug=True)
    source = _mapping(entry.get("source"), "marketplace.plugins[0].source", _SOURCE_FIELDS)
    if source.get("source") != "local":
        raise _error("marketplace.plugins[0].source.source:must_be_local")
    source_path = source.get("path")
    if not isinstance(source_path, str) or source_path != f"./plugins/{name}":
        raise _error("marketplace.plugins[0].source.path:must_be_canonical")
    if "\\" in source_path or any(part in {"", ".", ".."} for part in Path(source_path[2:]).parts):
        raise _error("marketplace.plugins[0].source.path:path_escape")
    policy = _mapping(entry.get("policy"), "marketplace.plugins[0].policy", _POLICY_FIELDS)
    if policy.get("installation") != DEFAULT_INSTALLATION_POLICY or policy.get("authentication") != DEFAULT_AUTHENTICATION_POLICY:
        raise _error("marketplace.plugins[0].policy:not_canonical")
    if entry.get("category") != DEFAULT_CATEGORY:
        raise _error("marketplace.plugins[0].category:not_canonical")

    binding = _mapping(top.get("binding"), "binding", _BINDING_FIELDS)
    if binding.get("schema") != SCHEMA:
        raise _error("binding.schema:unsupported")
    revision = _revision(binding.get("revision"))
    plugin = _mapping(binding.get("plugin"), "binding.plugin", _PLUGIN_ID_FIELDS)
    bound_name = _safe_name(plugin.get("name"), "binding.plugin.name", slug=True)
    bound_version = _reject_path_or_remote_text(
        _text(plugin.get("version"), "binding.plugin.version", max_length=128),
        "binding.plugin.version",
    )
    if bound_name != name:
        raise _error("binding.plugin.name_mismatch")
    health = sanitize_health_evidence(binding.get("health"))

    if expected_revision is not None and _revision(expected_revision, "expected_revision") != revision:
        raise _error("revision:unexpected")
    if expected_plugin_name is not None and _safe_name(expected_plugin_name, "expected_plugin_name", slug=True) != name:
        raise _error("plugin_name:unexpected")
    if expected_plugin_version is not None and _reject_path_or_remote_text(
        _text(expected_plugin_version, "expected_plugin_version", max_length=128),
        "expected_plugin_version",
    ) != bound_version:
        raise _error("plugin_version:unexpected")
    if health_evidence is not None and sanitize_health_evidence(health_evidence) != health:
        raise _error("health:does_not_match_binding")

    _repository_path, plugin_root = _validate_repository(repository, revision, name)
    _read_plugin_manifest(plugin_root, name, bound_version)

    # Hash the canonical manifest after parsing and normalization.  The digest
    # is useful evidence to the integrator and contains no source body.  Using
    # the normalized representation keeps the evidence stable when a caller
    # supplies equivalent JSON with different object ordering.
    canonical = _canonical_manifest(
        marketplace_name=market_name,
        display_name=interface["displayName"],
        plugin_name=name,
        revision=revision,
        plugin_version=bound_version,
        health=health,
    )
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return {
        "status": "PASS",
        "schema": SCHEMA,
        "marketplace": market_name,
        "revision": revision,
        "plugin": {"name": name, "version": bound_version},
        "source_path": source_path,
        "git_clean": True,
        "health": health,
        "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
    }


validate_marketplace = validate_local_marketplace
create_local_marketplace = construct_local_marketplace
make_local_marketplace_manifest = construct_local_marketplace
validate_marketplace_manifest = validate_local_marketplace


__all__ = [
    "SCHEMA",
    "DEFAULT_MARKETPLACE_NAME",
    "LocalMarketplaceError",
    "LocalMarketplaceValidationError",
    "MarketplaceValidationError",
    "sanitize_health_evidence",
    "construct_local_marketplace",
    "build_local_marketplace",
    "create_local_marketplace",
    "make_local_marketplace_manifest",
    "validate_local_marketplace",
    "validate_marketplace",
    "validate_marketplace_manifest",
]
