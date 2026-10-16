#!/usr/bin/env python3
"""Build, install, and verify a runtime-projected local Orch Dork release.

The development checkout is never a plugin install source.  This module
composes the public runtime-package and local-marketplace seams into a local
marketplace root and invokes the real Codex plugin flow.  The plugin content is
committed before the marketplace control file is written, so the binding
revision identifies only the installable runtime bytes and cannot become a
self-referential manifest commit.  A top-level release passes only when the
resolved cache and MCP registration match that projection exactly.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
from typing import Any, Mapping, Sequence
import weakref

import orch_dork_local_marketplace as local_marketplace
import orch_dork_runtime_package as runtime_package
from lifecycle_conformance import action_authority, candidate_identity
from lifecycle_conformance import reference_values as rv, values
from lifecycle_conformance.values import LifecycleContractError


SCHEMA = "orch-dork/release-marketplace/v1"
INSTALL_SCHEMA = "orch-dork/release-install/v1"
RELEASE_SCHEMA = "orch-dork/release/v1"
PLUGIN_NAME = "orch-dork"
MARKETPLACE_PATH = Path(".agents/plugins/marketplace.json")
CODEX_TIMEOUT_SECONDS = 60
RELEASE_HOST_CHECK_PATH = Path(
    ".github/scripts/orch_dork_release_host_check.py"
)
RELEASE_HOST_CHECK_SCHEMA = "orch-dork/release-host-check/v1"
RELEASE_HOST_CHECK_TIMEOUT_SECONDS = 330
RELEASE_HOST_TEST_MODULE = "tests.test_orch_dork_release_marketplace"
# The release-host checker imports this module for its bounded-process helpers,
# so this is the single source for the exact ordered real-Codex test manifest.
# The first six test a real install, installed-cache/MCP properties and a
# provider-free rehearsal launched from the installed root. The seventh
# verifies that the composed release entrypoint refuses without campaign
# authority before it can start a recursive release-host check.
REQUIRED_REAL_CODEX_TEST_IDS = (
    f"{RELEASE_HOST_TEST_MODULE}.ReleaseMarketplaceTests.test_home_only_install_binds_the_default_codex_cache_root",
    f"{RELEASE_HOST_TEST_MODULE}.ReleaseMarketplaceTests.test_real_codex_plugin_add_installs_exact_runtime_and_registers_mcp",
    f"{RELEASE_HOST_TEST_MODULE}.ReleaseMarketplaceTests.test_disposable_installed_layout_runs_rehearsal_from_installed_root",
    f"{RELEASE_HOST_TEST_MODULE}.ReleaseMarketplaceTests.test_real_install_gate_blocks_an_undeclared_active_cache_file",
    f"{RELEASE_HOST_TEST_MODULE}.ReleaseMarketplaceTests.test_real_install_removes_direct_checkout_install_after_runtime_validation",
    f"{RELEASE_HOST_TEST_MODULE}.ReleaseMarketplaceTests.test_real_install_repoints_an_existing_local_marketplace",
    f"{RELEASE_HOST_TEST_MODULE}.ReleaseMarketplaceTests.test_release_gate_refuses_before_real_host_or_install_without_campaign_authority",
)
REQUIRED_REAL_CODEX_TEST_COUNT = len(REQUIRED_REAL_CODEX_TEST_IDS)
RELEASE_PROCESS_CLEANUP_SECONDS = 2.0
RELEASE_PROCESS_STDOUT_LIMIT_BYTES = 65_536
RELEASE_PROCESS_STDERR_LIMIT_BYTES = 65_536
PHYSICAL_CONTEXT_SCHEMA = "orch-dork/issue170-release-execution-context/v1"
PHYSICAL_OBSERVATION_SCHEMA = "orch-dork/issue170-release-physical-observation/v1"
BOUNDED_CLEANUP_SCHEMA = "orch-dork/release-bounded-process-cleanup/v1"
INSTALL_PHYSICAL_OBSERVATION_SCHEMA = "orch-dork/release-install-physical-observation/v1"
_PHYSICAL_AUTHORITY = object()
_PHYSICAL_ISSUED: dict[int, tuple[weakref.ReferenceType[object], int, tuple]] = {}
_CLEANUP_ISSUED: dict[int, tuple[weakref.ReferenceType[object], int, tuple]] = {}
_CLEANUP_LOCAL = threading.local()
_FIXED_RELEASE_EXECUTE: list[types.FunctionType] = []
_FIXED_RELEASE_EXECUTE_LOCK = threading.Lock()


class ReleaseMarketplaceError(ValueError):
    """A bounded create or validation failure that preserves prior releases."""

    def __init__(self, *issues: str):
        clean = tuple(str(item) for item in issues if item)
        self.issues = clean or ("release_marketplace:failed",)
        super().__init__("; ".join(self.issues))


def _valid_positive_number(value: Any, *, maximum: float | None = None) -> bool:
    if type(value) not in (int, float):
        return False
    numeric = float(value)
    return math.isfinite(numeric) and numeric > 0 and (
        maximum is None or numeric <= maximum
    )


def _valid_byte_limit(value: Any, *, maximum: int) -> bool:
    return type(value) is int and 0 < value <= maximum


@dataclass(frozen=True)
class ReleaseProcessLimits:
    """Downward-only limits for one Codex release command."""

    timeout_seconds: float = CODEX_TIMEOUT_SECONDS
    stdout_bytes: int = RELEASE_PROCESS_STDOUT_LIMIT_BYTES
    stderr_bytes: int = RELEASE_PROCESS_STDERR_LIMIT_BYTES

    def validated(self) -> "ReleaseProcessLimits":
        if not _valid_positive_number(
            self.timeout_seconds,
            maximum=CODEX_TIMEOUT_SECONDS,
        ):
            raise ReleaseMarketplaceError("codex:command_timeout:invalid")
        for label, value, maximum in (
            ("stdout", self.stdout_bytes, RELEASE_PROCESS_STDOUT_LIMIT_BYTES),
            ("stderr", self.stderr_bytes, RELEASE_PROCESS_STDERR_LIMIT_BYTES),
        ):
            if not _valid_byte_limit(value, maximum=maximum):
                raise ReleaseMarketplaceError(
                    f"codex:command_{label}_limit:invalid"
                )
        return self


class BoundedProcessError(subprocess.SubprocessError):
    """A release child violated its bounded process-group contract."""

    def __init__(self, reason: str, *, underlying_reason: str | None = None):
        self.reason = reason
        self.underlying_reason = underlying_reason
        super().__init__(reason)


def _physical_require(condition: bool, reason: str) -> None:
    if condition is not True:
        raise LifecycleContractError("release_marketplace:" + reason)


def _fixed_source_release_execute(release_execution) -> types.FunctionType:
    """Bind the reviewed source function once; never trust its public name.

    ``release_execution.execute_release`` is mutable module state.  Its current
    value can establish the fixed identity only when its code equals the sole
    top-level ``execute_release`` definition compiled from the guarded source
    file and its globals are the real module dictionary.  A later rebinding,
    including one that reuses that dictionary, cannot replace the retained
    function object.
    """

    expected_path = (
        Path(__file__).resolve(strict=True).parent
        / "lifecycle_conformance"
        / "release_execution.py"
    ).resolve(strict=True)
    module_path = Path(release_execution.__file__).resolve(strict=True)
    _physical_require(module_path == expected_path, "physical_provider_source")
    module_code = compile(
        module_path.read_bytes(),
        str(module_path),
        "exec",
        dont_inherit=True,
        optimize=sys.flags.optimize,
    )
    source_definitions = [
        value
        for value in module_code.co_consts
        if type(value) is types.CodeType
        and value.co_name == "execute_release"
        and value.co_qualname == "execute_release"
    ]
    _physical_require(
        len(source_definitions) == 1,
        "physical_provider_source_definition",
    )
    current = release_execution.execute_release
    _physical_require(
        type(current) is types.FunctionType
        and current.__globals__ is release_execution.__dict__
        and current.__code__ == source_definitions[0],
        "physical_provider_source_identity",
    )

    with _FIXED_RELEASE_EXECUTE_LOCK:
        if not _FIXED_RELEASE_EXECUTE:
            _FIXED_RELEASE_EXECUTE.append(current)
        _physical_require(
            len(_FIXED_RELEASE_EXECUTE) == 1,
            "physical_provider_fixed_identity",
        )
        fixed = _FIXED_RELEASE_EXECUTE[0]
    _physical_require(
        fixed is current,
        "physical_provider_fixed_identity",
    )
    return fixed


def _content_sha256(value: object) -> str:
    """Hash retained JSON-shaped release observations without trusting labels.

    The physical release paths produce plain JSON-compatible dictionaries.
    Returning a deterministic closed marker for an unexpected shape keeps the
    issue registry total while guaranteeing that a later mutation cannot match
    a prior valid digest.
    """

    try:
        return values.canonical_digest(value)
    except BaseException:
        return hashlib.sha256(
            ("release_marketplace:unencodable:" + type(value).__name__).encode("ascii", "replace")
        ).hexdigest()


def _frozen(value: object) -> rv.FrozenValue:
    return value if type(value) is rv.FrozenValue else rv.freeze(value)


@dataclass(frozen=True, init=False)
class BoundedProcessCleanup:
    """Source-issued evidence that one owned process group was observed empty."""

    observation: rv.FrozenValue

    def __init__(self, authority, *, observation):
        _physical_require(authority is _PHYSICAL_AUTHORITY, "cleanup_factory_required")
        _physical_require(type(observation) is rv.FrozenValue, "cleanup_observation")
        object.__setattr__(self, "observation", observation)


@dataclass(frozen=True, init=False)
class ReleasePhysicalResult:
    """The one same-process original returned after claimed release effects.

    The result deliberately retains direct references to the host, build, and
    install outputs.  A frozen summary alone would preserve bytes but not prove
    that the durable authority report still points at the exact observed
    objects.  The issue registry binds both identities and their deep content.
    """

    claim: action_authority.ReleaseInstallClaim
    report: dict
    context: rv.FrozenValue
    physical_observation: rv.FrozenValue
    release_host_check: dict
    marketplace_build: dict
    installation: dict
    cleanup_observations: tuple[BoundedProcessCleanup, ...]

    def __init__(
        self,
        authority,
        *,
        claim,
        report,
        context,
        physical_observation,
        release_host_check,
        marketplace_build,
        installation,
        cleanup_observations,
    ):
        _physical_require(authority is _PHYSICAL_AUTHORITY, "physical_result_factory_required")
        for name, value, expected in (
            ("claim", claim, action_authority.ReleaseInstallClaim),
            ("report", report, dict),
            ("context", context, rv.FrozenValue),
            ("physical_observation", physical_observation, rv.FrozenValue),
            ("release_host_check", release_host_check, dict),
            ("marketplace_build", marketplace_build, dict),
            ("installation", installation, dict),
        ):
            _physical_require(type(value) is expected, name + "_type")
        _physical_require(type(cleanup_observations) is tuple, "cleanup_observations_type")
        _physical_require(
            all(type(row) is BoundedProcessCleanup for row in cleanup_observations),
            "cleanup_observations_type",
        )
        for name, value in {
            "claim": claim,
            "report": report,
            "context": context,
            "physical_observation": physical_observation,
            "release_host_check": release_host_check,
            "marketplace_build": marketplace_build,
            "installation": installation,
            "cleanup_observations": cleanup_observations,
        }.items():
            object.__setattr__(self, name, value)


def _cleanup_fingerprint(cleanup: BoundedProcessCleanup) -> tuple:
    return (cleanup.observation.digest(),)


def _physical_fingerprint(result: ReleasePhysicalResult) -> tuple:
    return (
        id(result.claim),
        result.claim.receipt.digest(),
        id(result.report),
        _content_sha256(result.report),
        result.context.digest(),
        result.physical_observation.digest(),
        id(result.release_host_check),
        _content_sha256(result.release_host_check),
        id(result.marketplace_build),
        _content_sha256(result.marketplace_build),
        id(result.installation),
        _content_sha256(result.installation),
        tuple((id(row), _cleanup_fingerprint(row)) for row in result.cleanup_observations),
    )


def _issue_cleanup(observation: rv.FrozenValue) -> BoundedProcessCleanup:
    cleanup = BoundedProcessCleanup(_PHYSICAL_AUTHORITY, observation=observation)
    identity = id(cleanup)
    _CLEANUP_ISSUED[identity] = (
        weakref.ref(cleanup, lambda _: _CLEANUP_ISSUED.pop(identity, None)),
        os.getpid(),
        _cleanup_fingerprint(cleanup),
    )
    return cleanup


def _require_issued_cleanup(cleanup) -> None:
    record = _CLEANUP_ISSUED.get(id(cleanup))
    _physical_require(
        type(cleanup) is BoundedProcessCleanup
        and record is not None
        and record[0]() is cleanup
        and record[1] == os.getpid()
        and record[2] == _cleanup_fingerprint(cleanup),
        "cleanup_issued_binding",
    )


def _issue_physical_result(**fields) -> ReleasePhysicalResult:
    result = ReleasePhysicalResult(_PHYSICAL_AUTHORITY, **fields)
    identity = id(result)
    _PHYSICAL_ISSUED[identity] = (
        weakref.ref(result, lambda _: _PHYSICAL_ISSUED.pop(identity, None)),
        os.getpid(),
        _physical_fingerprint(result),
    )
    return result


def _require_issued_physical_result(result) -> None:
    record = _PHYSICAL_ISSUED.get(id(result))
    _physical_require(
        type(result) is ReleasePhysicalResult
        and record is not None
        and record[0]() is result
        and record[1] == os.getpid()
        and record[2] == _physical_fingerprint(result),
        "physical_result_issued_binding",
    )
    action_authority._issued(result.claim)
    for cleanup in result.cleanup_observations:
        _require_issued_cleanup(cleanup)


def _clear_physical_process_authority() -> None:
    _PHYSICAL_ISSUED.clear()
    _CLEANUP_ISSUED.clear()
    _CLEANUP_LOCAL.__dict__.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_clear_physical_process_authority)


@contextmanager
def _capture_bounded_cleanups():
    stack = getattr(_CLEANUP_LOCAL, "stack", None)
    if stack is None:
        stack = []
        _CLEANUP_LOCAL.stack = stack
    captured: list[BoundedProcessCleanup] = []
    stack.append(captured)
    try:
        yield captured
    finally:
        if stack and stack[-1] is captured:
            stack.pop()
        else:
            # This is internal bookkeeping, so an invariant violation closes
            # the physical path rather than silently attributing evidence to
            # the wrong release.
            raise LifecycleContractError("release_marketplace:cleanup_capture_binding")


def _record_bounded_cleanup(
    command: Sequence[str],
    completed: subprocess.CompletedProcess[str],
) -> None:
    """Retain success-only cleanup evidence for an active physical release."""

    stack = getattr(_CLEANUP_LOCAL, "stack", ())
    if not stack:
        return
    observation = rv.freeze(
        {
            "schema": BOUNDED_CLEANUP_SCHEMA,
            "status": "PASS",
            "argv_sha256": _content_sha256([str(item) for item in command]),
            "returncode": int(completed.returncode),
            "stdout_sha256": hashlib.sha256(
                completed.stdout.encode("utf-8", errors="replace")
            ).hexdigest(),
            "stderr_sha256": hashlib.sha256(
                completed.stderr.encode("utf-8", errors="replace")
            ).hexdigest(),
            # This value is reached only after run_bounded_process_tree has
            # observed the owned process group absent.
            "owned_process_group_absent": True,
        }
    )
    stack[-1].append(_issue_cleanup(observation))


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _kill_and_verify_process_group(process: subprocess.Popen[Any]) -> bool:
    process_group = process.pid
    started = time.monotonic()
    group_cleanup_known = True
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        group_cleanup_known = False
    if process.poll() is None:
        try:
            if not group_cleanup_known:
                process.kill()
            process.wait(timeout=RELEASE_PROCESS_CLEANUP_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            return False
    if not group_cleanup_known:
        return False
    deadline = started + RELEASE_PROCESS_CLEANUP_SECONDS
    while time.monotonic() < deadline:
        if not _process_group_exists(process_group):
            return True
        time.sleep(0.01)
    return not _process_group_exists(process_group)


def run_bounded_process_tree(
    command: Sequence[str],
    *,
    cwd: os.PathLike[str] | str,
    env: Mapping[str, str],
    timeout: float,
    stdout_limit_bytes: int = RELEASE_PROCESS_STDOUT_LIMIT_BYTES,
    stderr_limit_bytes: int = RELEASE_PROCESS_STDERR_LIMIT_BYTES,
) -> subprocess.CompletedProcess[str]:
    """Run one bounded POSIX process group and verify complete cleanup."""

    argv = list(command)
    if not _valid_positive_number(timeout):
        raise BoundedProcessError("limits_invalid")
    for value, maximum in (
        (stdout_limit_bytes, RELEASE_PROCESS_STDOUT_LIMIT_BYTES),
        (stderr_limit_bytes, RELEASE_PROCESS_STDERR_LIMIT_BYTES),
    ):
        if not _valid_byte_limit(value, maximum=maximum):
            raise BoundedProcessError("limits_invalid")

    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=dict(env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=True,
        close_fds=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    streams = (
        (process.stdout, "stdout", stdout, stdout_limit_bytes),
        (process.stderr, "stderr", stderr, stderr_limit_bytes),
    )
    for stream, label, buffer, limit in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, (label, buffer, limit))

    started = time.monotonic()
    leader_exited_at: float | None = None
    reason: str | None = None
    underlying_reason: str | None = None
    try:
        while True:
            now = time.monotonic()
            remaining_time = float(timeout) - (now - started)
            if remaining_time <= 0:
                reason = "timeout"
                break
            events = selector.select(min(0.02, remaining_time))
            for key, _mask in events:
                label, buffer, limit = key.data
                remaining = limit - len(buffer)
                try:
                    chunk = os.read(key.fd, min(16_384, remaining + 1))
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    try:
                        selector.unregister(key.fileobj)
                    except (KeyError, ValueError):
                        pass
                    continue
                if len(chunk) > remaining:
                    buffer.extend(chunk[:remaining])
                    reason = f"{label}_limit"
                    break
                buffer.extend(chunk)
            if reason is not None:
                break

            returncode = process.poll()
            if returncode is None:
                continue
            if _process_group_exists(process.pid):
                reason = "descendant_leak"
                break
            if not selector.get_map():
                break
            if leader_exited_at is None:
                leader_exited_at = time.monotonic()
            elif time.monotonic() - leader_exited_at >= RELEASE_PROCESS_CLEANUP_SECONDS:
                reason = "cleanup_unknown"
                break
    except BaseException:
        _kill_and_verify_process_group(process)
        raise
    finally:
        if reason is not None:
            cleaned = _kill_and_verify_process_group(process)
            if not cleaned:
                underlying_reason = reason
                reason = "cleanup_unknown"
        selector.close()
        for stream, _label, _buffer, _limit in streams:
            stream.close()

    stdout_text = bytes(stdout).decode("utf-8", errors="replace")
    stderr_text = bytes(stderr).decode("utf-8", errors="replace")
    if reason == "timeout":
        raise subprocess.TimeoutExpired(
            argv,
            timeout,
            output=stdout_text,
            stderr=stderr_text,
        )
    if reason is not None:
        raise BoundedProcessError(reason, underlying_reason=underlying_reason)
    completed = subprocess.CompletedProcess(
        argv,
        int(process.returncode),
        stdout_text,
        stderr_text,
    )
    _record_bounded_cleanup(argv, completed)
    return completed


def _path(value: os.PathLike[str] | str, label: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ReleaseMarketplaceError(f"{label}:invalid")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ReleaseMarketplaceError(f"{label}:invalid")
    path = Path(raw).absolute()
    if path.is_symlink():
        raise ReleaseMarketplaceError(f"{label}:symlink")
    return path


def _executable_path(value: os.PathLike[str] | str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ReleaseMarketplaceError("codex_executable:invalid")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ReleaseMarketplaceError("codex_executable:invalid")
    try:
        executable = Path(raw).absolute().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ReleaseMarketplaceError("codex_executable:unresolvable") from exc
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ReleaseMarketplaceError("codex_executable:not_executable")
    return executable


def _run_release_host_check_impl(
    source_root: os.PathLike[str] | str,
    codex_executable: os.PathLike[str] | str,
    *,
    release_root: os.PathLike[str] | str,
    action_claim: action_authority.ReleaseInstallClaim | None = None,
    _operation: action_authority.ReleaseOperationInvocation | None = None,
    _invocation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run and validate the source-bound real-Codex release receipt."""

    try:
        action_authority._enter_release_operation_effect(
            _operation,
            "host",
            source_root=source_root,
            release_root=release_root,
            invocation=_invocation,
        )
    except LifecycleContractError as exc:
        raise ReleaseMarketplaceError(str(exc)) from exc
    source = _path(source_root, "source_root")
    checker = source / RELEASE_HOST_CHECK_PATH
    if checker.is_symlink() or not checker.is_file():
        raise ReleaseMarketplaceError("release_host_check:missing")
    if not isinstance(codex_executable, (str, os.PathLike)):
        raise ReleaseMarketplaceError("release_host_check:codex_executable:invalid")
    raw_codex = os.fspath(codex_executable)
    if not isinstance(raw_codex, str) or not raw_codex or "\x00" in raw_codex:
        raise ReleaseMarketplaceError("release_host_check:codex_executable:invalid")
    try:
        completed = run_bounded_process_tree(
            [
                sys.executable,
                "-B",
                str(checker),
                "--codex-executable",
                raw_codex,
            ],
            cwd=source,
            env=os.environ.copy(),
            timeout=RELEASE_HOST_CHECK_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReleaseMarketplaceError("release_host_check:timeout") from exc
    except BoundedProcessError as exc:
        raise ReleaseMarketplaceError(
            f"release_host_check:{exc.reason}"
        ) from exc
    except OSError as exc:
        raise ReleaseMarketplaceError("release_host_check:unavailable") from exc
    try:
        receipt = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ReleaseMarketplaceError("release_host_check:malformed_result") from exc
    if completed.returncode != 0:
        issues = receipt.get("issues", []) if isinstance(receipt, Mapping) else []
        issue = issues[0] if isinstance(issues, list) and issues else "failed"
        if not isinstance(issue, str) or not issue:
            issue = "failed"
        raise ReleaseMarketplaceError(f"release_host_check:{issue}")

    expected_fields = {
        "codex_executable",
        "real_codex_e2e",
        "required_tests",
        "required_tests_run",
        "schema",
        "skipped",
        "status",
        "test_module",
        "tests_run",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != expected_fields:
        raise ReleaseMarketplaceError("release_host_check:malformed_result")
    required_tests = receipt.get("required_tests")
    if (
        receipt.get("schema") != RELEASE_HOST_CHECK_SCHEMA
        or receipt.get("status") != "PASS"
        or receipt.get("real_codex_e2e") is not True
        or receipt.get("codex_executable") != "validated"
        or receipt.get("test_module") != RELEASE_HOST_TEST_MODULE
        or receipt.get("skipped") != 0
        or type(required_tests) is not list
        or required_tests != list(REQUIRED_REAL_CODEX_TEST_IDS)
        or type(receipt.get("required_tests_run")) is not int
        or receipt["required_tests_run"] != len(required_tests)
        or type(receipt.get("tests_run")) is not int
        or receipt["tests_run"] < len(required_tests)
    ):
        raise ReleaseMarketplaceError("release_host_check:malformed_result")
    return dict(receipt)


def _run_release_host_check(
    source_root: os.PathLike[str] | str,
    codex_executable: os.PathLike[str] | str,
    *,
    release_root: os.PathLike[str] | str,
    action_claim: action_authority.ReleaseInstallClaim | None = None,
) -> dict[str, Any]:
    """Consume and bind the sole release-host operation."""

    invocation = {
        "source_root": str(Path(source_root).absolute()),
        "release_root": str(Path(release_root).absolute()),
        "codex_executable": str(Path(codex_executable).absolute()),
    }
    try:
        operation = action_authority._begin_release_operation(
            action_claim,
            "host",
            source_root=source_root,
            release_root=release_root,
            invocation=invocation,
        )
    except LifecycleContractError as exc:
        raise ReleaseMarketplaceError(str(exc)) from exc
    try:
        output = _run_release_host_check_impl(
            source_root,
            codex_executable,
            release_root=release_root,
            action_claim=action_claim,
            _operation=operation,
            _invocation=invocation,
        )
        return action_authority._complete_release_operation(operation, output)
    except BaseException as exc:
        action_authority._fail_release_operation(operation, exc)
        raise


def _bind_release_host_health(
    health_evidence: Mapping[str, Any],
    release_host_check: Mapping[str, Any],
) -> dict[str, Any]:
    """Replace any caller claim with the directly observed host check."""

    if release_host_check.get("status") != "PASS":
        raise ReleaseMarketplaceError("release_host_check:not_passing")
    health = local_marketplace.sanitize_health_evidence(health_evidence)
    checks = {
        row["name"]: row
        for row in health["checks"]
        if row["name"] != "real-codex-e2e"
    }
    checks["real-codex-e2e"] = {"name": "real-codex-e2e", "status": "PASS"}
    return {**health, "checks": [checks[name] for name in sorted(checks)]}


def _git(repository: Path, *args: str) -> str:
    env = os.environ.copy()
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
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
        }
    )
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    except OSError as exc:
        raise ReleaseMarketplaceError("git:unavailable") from exc
    if completed.returncode != 0:
        raise ReleaseMarketplaceError(f"git:{args[0] if args else 'command'}:failed")
    return completed.stdout.strip()


def _plugin_version(plugin_root: Path) -> str:
    path = plugin_root / ".codex-plugin/plugin.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseMarketplaceError("plugin_manifest:malformed") from exc
    version = manifest.get("version") if isinstance(manifest, Mapping) else None
    if manifest.get("name") != PLUGIN_NAME or not isinstance(version, str) or not version:
        raise ReleaseMarketplaceError("plugin_manifest:identity_invalid")
    return version


def _codex_environment(
    *,
    codex_home: os.PathLike[str] | str | None,
    home_directory: os.PathLike[str] | str | None,
) -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    if codex_home is not None:
        resolved_codex_home = _path(codex_home, "codex_home")
        resolved_codex_home.mkdir(parents=True, exist_ok=True)
        environment["CODEX_HOME"] = str(resolved_codex_home)
    if home_directory is not None:
        resolved_home = _path(home_directory, "home_directory")
        resolved_home.mkdir(parents=True, exist_ok=True)
        environment["HOME"] = str(resolved_home)
        if codex_home is None:
            environment.pop("CODEX_HOME", None)
    return environment


def _resolved_codex_home(
    environment: Mapping[str, str],
    explicit: os.PathLike[str] | str | None,
) -> Path:
    if explicit is not None:
        return _path(explicit, "codex_home")
    configured = environment.get("CODEX_HOME")
    if configured:
        return _path(configured, "codex_home")
    home = environment.get("HOME")
    if not isinstance(home, str) or not home:
        home = str(Path.home())
    return _path(Path(home) / ".codex", "codex_home")


def _run_codex(
    executable: Path,
    args: Sequence[str],
    *,
    environment: Mapping[str, str],
    json_output: bool = True,
    limits: ReleaseProcessLimits | None = None,
) -> Any:
    effective_limits = (limits or ReleaseProcessLimits()).validated()
    command = [str(executable), *args]
    if json_output:
        command.append("--json")
    label = ":".join(args[:3]) if args else "command"
    try:
        completed = run_bounded_process_tree(
            command,
            cwd=Path.cwd(),
            env=dict(environment),
            timeout=effective_limits.timeout_seconds,
            stdout_limit_bytes=effective_limits.stdout_bytes,
            stderr_limit_bytes=effective_limits.stderr_bytes,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReleaseMarketplaceError(f"codex:{label}:timeout") from exc
    except BoundedProcessError as exc:
        raise ReleaseMarketplaceError(f"codex:{label}:{exc.reason}") from exc
    except OSError as exc:
        raise ReleaseMarketplaceError(f"codex:{label}:unavailable") from exc
    if completed.returncode != 0:
        raise ReleaseMarketplaceError(f"codex:{label}:failed")
    if not json_output:
        return completed.stdout
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ReleaseMarketplaceError(f"codex:{label}:malformed_json") from exc
    if not isinstance(payload, Mapping):
        raise ReleaseMarketplaceError(f"codex:{label}:malformed_json")
    return dict(payload)


def _installed_path(value: Any, *, codex_home: Path | None, version: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ReleaseMarketplaceError("installed_cache:path_invalid")
    installed = Path(value)
    if not installed.is_absolute() or installed.is_symlink() or not installed.is_dir():
        raise ReleaseMarketplaceError("installed_cache:path_invalid")
    try:
        resolved = installed.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ReleaseMarketplaceError("installed_cache:path_unresolvable") from exc
    if codex_home is not None:
        expected = (
            codex_home
            / "plugins"
            / "cache"
            / local_marketplace.DEFAULT_MARKETPLACE_NAME
            / PLUGIN_NAME
            / version
        ).resolve(strict=False)
        if resolved != expected:
            raise ReleaseMarketplaceError("installed_cache:path_mismatch")
    return resolved


def _reported_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ReleaseMarketplaceError(f"{label}:path_invalid")
    path = Path(value)
    if not path.is_absolute():
        raise ReleaseMarketplaceError(f"{label}:path_invalid")
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ReleaseMarketplaceError(f"{label}:path_unresolvable") from exc


def _install_release_marketplace_impl(
    release_root: os.PathLike[str] | str,
    *,
    codex_executable: os.PathLike[str] | str,
    codex_home: os.PathLike[str] | str | None = None,
    home_directory: os.PathLike[str] | str | None = None,
    command_limits: ReleaseProcessLimits | None = None,
    action_claim: action_authority.ReleaseInstallClaim | None = None,
    _operation: action_authority.ReleaseOperationInvocation | None = None,
    _invocation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Install one projected release with the real Codex CLI and verify it.

    A passing report is emitted only after a separate ``plugin list`` process
    resolves the installed identity, the cache matches the marketplace runtime
    byte-for-byte with no undeclared files, and a separate ``mcp get`` process
    resolves the server working directory to that exact cache generation.
    """

    try:
        action_authority._enter_release_operation_effect(
            _operation,
            "install",
            release_root=release_root,
            invocation=_invocation,
        )
    except LifecycleContractError as exc:
        raise ReleaseMarketplaceError(str(exc)) from exc
    release = _path(release_root, "release_root")
    executable = _executable_path(codex_executable)
    effective_limits = (command_limits or ReleaseProcessLimits()).validated()
    if not release.is_dir():
        raise ReleaseMarketplaceError("release_root:not_directory")
    plugin_root = release / "plugins" / PLUGIN_NAME
    if plugin_root.is_symlink() or not plugin_root.is_dir():
        raise ReleaseMarketplaceError("plugin_source:missing")
    package = runtime_package.validate_runtime_package(plugin_root, plugin_root)
    version = _plugin_version(plugin_root)
    environment = _codex_environment(
        codex_home=codex_home,
        home_directory=home_directory,
    )
    resolved_codex_home = _resolved_codex_home(environment, codex_home)
    run_codex_command = partial(
        _run_codex,
        executable,
        environment=environment,
        limits=effective_limits,
    )

    marketplace_listing = run_codex_command(
        ("plugin", "marketplace", "list"),
    )
    marketplace_rows = marketplace_listing.get("marketplaces")
    if not isinstance(marketplace_rows, list):
        raise ReleaseMarketplaceError("codex:marketplace_list:malformed")
    configured = [
        row
        for row in marketplace_rows
        if isinstance(row, Mapping)
        and row.get("name") == local_marketplace.DEFAULT_MARKETPLACE_NAME
    ]
    if len(configured) > 1:
        raise ReleaseMarketplaceError("codex:marketplace_list:duplicate_identity")
    prior_root: Path | None = None
    if configured:
        raw_prior = configured[0].get("root")
        if not isinstance(raw_prior, str) or not raw_prior or "\x00" in raw_prior:
            raise ReleaseMarketplaceError("codex:marketplace_list:root_invalid")
        prior_root = Path(raw_prior).absolute()
    marketplace_repointed = prior_root is not None and prior_root.resolve(strict=False) != release.resolve()
    if marketplace_repointed:
        run_codex_command(
            ("plugin", "marketplace", "remove", local_marketplace.DEFAULT_MARKETPLACE_NAME),
        )
    if prior_root is None or marketplace_repointed:
        try:
            added = run_codex_command(
                ("plugin", "marketplace", "add", str(release)),
            )
        except ReleaseMarketplaceError:
            if marketplace_repointed and prior_root is not None and prior_root.is_dir():
                try:
                    run_codex_command(
                        ("plugin", "marketplace", "add", str(prior_root)),
                    )
                except ReleaseMarketplaceError:
                    pass
            raise
        if added.get("marketplaceName") != local_marketplace.DEFAULT_MARKETPLACE_NAME:
            raise ReleaseMarketplaceError("codex:marketplace_add:identity_mismatch")
        if _reported_path(added.get("installedRoot"), "codex:marketplace_add") != release.resolve():
            raise ReleaseMarketplaceError("codex:marketplace_add:root_mismatch")
    installed_result = run_codex_command(
        ("plugin", "add", f"{PLUGIN_NAME}@{local_marketplace.DEFAULT_MARKETPLACE_NAME}"),
    )
    if (
        installed_result.get("pluginId") != f"{PLUGIN_NAME}@{local_marketplace.DEFAULT_MARKETPLACE_NAME}"
        or installed_result.get("name") != PLUGIN_NAME
        or installed_result.get("marketplaceName") != local_marketplace.DEFAULT_MARKETPLACE_NAME
        or installed_result.get("version") != version
    ):
        raise ReleaseMarketplaceError("codex:plugin_add:identity_mismatch")
    installed = _installed_path(
        installed_result.get("installedPath"),
        codex_home=resolved_codex_home,
        version=version,
    )

    listing = run_codex_command(
        ("plugin", "list"),
    )
    installed_rows = listing.get("installed")
    if not isinstance(installed_rows, list):
        raise ReleaseMarketplaceError("codex:plugin_list:malformed")
    active = [
        row
        for row in installed_rows
        if isinstance(row, Mapping)
        and row.get("pluginId") == f"{PLUGIN_NAME}@{local_marketplace.DEFAULT_MARKETPLACE_NAME}"
    ]
    if len(active) != 1 or active[0].get("version") != version:
        raise ReleaseMarketplaceError("installed_cache:active_identity_mismatch")
    active_source = active[0].get("source")
    active_marketplace = active[0].get("marketplaceSource")
    if (
        not isinstance(active_source, Mapping)
        or active_source.get("source") != "local"
        or _reported_path(active_source.get("path"), "codex:plugin_list:source")
        != plugin_root.resolve()
        or not isinstance(active_marketplace, Mapping)
        or active_marketplace.get("sourceType") != "local"
        or _reported_path(
            active_marketplace.get("source"),
            "codex:plugin_list:marketplace_source",
        )
        != release.resolve()
    ):
        raise ReleaseMarketplaceError("installed_cache:source_binding_mismatch")

    installed_package = runtime_package.validate_runtime_package(plugin_root, installed)
    if installed_package != package:
        raise ReleaseMarketplaceError("installed_cache:package_mismatch")
    inventory = runtime_package.inventory_runtime(installed)

    competitors: list[str] = []
    for row in installed_rows:
        if not isinstance(row, Mapping) or row.get("name") != PLUGIN_NAME:
            continue
        if row.get("pluginId") == f"{PLUGIN_NAME}@{local_marketplace.DEFAULT_MARKETPLACE_NAME}":
            continue
        market = row.get("marketplaceName")
        plugin_id = row.get("pluginId")
        if (
            not isinstance(market, str)
            or re.fullmatch(r"[A-Za-z0-9_-]+", market) is None
            or plugin_id != f"{PLUGIN_NAME}@{market}"
        ):
            raise ReleaseMarketplaceError("installed_cache:competing_identity_invalid")
        competitors.append(plugin_id)
    for plugin_id in sorted(competitors):
        removed = run_codex_command(
            ("plugin", "remove", plugin_id),
        )
        if removed.get("pluginId") != plugin_id:
            raise ReleaseMarketplaceError("codex:plugin_remove:identity_mismatch")

    final_listing = run_codex_command(
        ("plugin", "list"),
    )
    final_rows = final_listing.get("installed")
    if not isinstance(final_rows, list):
        raise ReleaseMarketplaceError("codex:plugin_list:malformed")
    final_orch_dork = [
        row
        for row in final_rows
        if isinstance(row, Mapping) and row.get("name") == PLUGIN_NAME
    ]
    if (
        len(final_orch_dork) != 1
        or final_orch_dork[0].get("pluginId")
        != f"{PLUGIN_NAME}@{local_marketplace.DEFAULT_MARKETPLACE_NAME}"
        or final_orch_dork[0].get("version") != version
        or final_orch_dork[0].get("enabled") is not True
    ):
        raise ReleaseMarketplaceError("installed_cache:exclusive_identity_mismatch")

    mcp = run_codex_command(
        ("mcp", "get", PLUGIN_NAME),
        json_output=False,
    )
    cwd_rows = [line.split(":", 1)[1].strip() for line in mcp.splitlines() if line.strip().startswith("cwd:")]
    if len(cwd_rows) != 1:
        raise ReleaseMarketplaceError("codex:mcp_get:cwd_missing")
    try:
        registered_cwd = Path(cwd_rows[0]).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ReleaseMarketplaceError("codex:mcp_get:cwd_invalid") from exc
    if registered_cwd != installed:
        raise ReleaseMarketplaceError("codex:mcp_get:cwd_mismatch")

    cache_inventory_sha256 = values.canonical_digest(inventory)
    mcp_observation = {
        "schema": "orch-dork/release-installed-mcp-observation/v1",
        "registered_cwd": str(registered_cwd),
        "installed_root": str(installed),
        "plugin": {"name": PLUGIN_NAME, "version": version},
        "status": "PASS",
    }
    return {
        "schema": INSTALL_SCHEMA,
        "status": "PASS",
        "installer": "codex plugin add",
        "plugin": {"name": PLUGIN_NAME, "version": version},
        "marketplace": local_marketplace.DEFAULT_MARKETPLACE_NAME,
        "marketplace_repointed": marketplace_repointed,
        "removed_competing_installs": sorted(competitors),
        "package": dict(package),
        "installed": {
            "status": "PASS",
            "file_count": len(inventory),
            "exact_runtime_allowlist": True,
            "projected_marketplace_source": True,
            "codex_home_bound": True,
        },
        "mcp_registration": "PASS",
        # Retain the independently observed cache and MCP facts that the
        # physical-result validator hashes.  These are produced after the
        # separate plugin-list and mcp-get subprocess observations above; they
        # are not caller health labels.
        "physical_observation": {
            "schema": INSTALL_PHYSICAL_OBSERVATION_SCHEMA,
            "installed_root": str(installed),
            "runtime_package": dict(package),
            "cache_inventory": inventory,
            "cache_inventory_sha256": cache_inventory_sha256,
            "mcp": mcp_observation,
            "mcp_observation_sha256": values.canonical_digest(mcp_observation),
        },
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def install_release_marketplace(
    release_root: os.PathLike[str] | str,
    *,
    codex_executable: os.PathLike[str] | str,
    codex_home: os.PathLike[str] | str | None = None,
    home_directory: os.PathLike[str] | str | None = None,
    command_limits: ReleaseProcessLimits | None = None,
    action_claim: action_authority.ReleaseInstallClaim | None = None,
) -> dict[str, Any]:
    """Consume the ordered install slot, run it once, and bind its output."""

    try:
        invocation = {
            "release_root": str(Path(release_root).absolute()),
            "codex_executable": str(Path(codex_executable).absolute()),
            "codex_home": None if codex_home is None else str(Path(codex_home).absolute()),
            "home_directory": None if home_directory is None else str(Path(home_directory).absolute()),
        }
        operation = action_authority._begin_release_operation(
            action_claim,
            "install",
            release_root=release_root,
            invocation=invocation,
        )
    except LifecycleContractError as exc:
        raise ReleaseMarketplaceError(str(exc)) from exc
    try:
        output = _install_release_marketplace_impl(
            release_root,
            codex_executable=codex_executable,
            codex_home=codex_home,
            home_directory=home_directory,
            command_limits=command_limits,
            action_claim=action_claim,
            _operation=operation,
            _invocation=invocation,
        )
        return action_authority._complete_release_operation(operation, output)
    except BaseException as exc:
        action_authority._fail_release_operation(operation, exc)
        raise


def _write_marketplace(path: Path, manifest: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=False)
    encoded = json.dumps(
        manifest,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ) + "\n"
    temporary = path.with_name("." + path.name + ".tmp")
    try:
        temporary.write_text(encoded, encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        raise ReleaseMarketplaceError("marketplace_manifest:write_failed") from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _build_release_marketplace_impl(
    source_root: os.PathLike[str] | str,
    release_root: os.PathLike[str] | str,
    *,
    health_evidence: Mapping[str, Any],
    action_claim: action_authority.ReleaseInstallClaim | None = None,
    _operation: action_authority.ReleaseOperationInvocation | None = None,
    _invocation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create one installable marketplace whose plugin is the runtime package.

    The destination is create-only.  Construction occurs in a sibling
    temporary directory and is copied to a still-absent destination only after
    package, marketplace, and Git-binding checks pass. A concurrent destination
    appearance fails without replacement.
    """

    try:
        action_authority._enter_release_operation_effect(
            _operation,
            "build",
            source_root=source_root,
            release_root=release_root,
            invocation=_invocation,
        )
    except LifecycleContractError as exc:
        raise ReleaseMarketplaceError(str(exc)) from exc
    source = _path(source_root, "source_root")
    destination = _path(release_root, "release_root")
    if not source.is_dir():
        raise ReleaseMarketplaceError("source_root:not_directory")
    if destination.exists():
        raise ReleaseMarketplaceError("release_root:already_exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_parent = Path(
        tempfile.mkdtemp(prefix=".orch-dork-release-", dir=str(destination.parent))
    )
    staged_root = temporary_parent / "marketplace"
    try:
        staged_root.mkdir()
        projected_source = temporary_parent / "runtime-source"
        runtime_package.project_runtime_source(source, projected_source)
        plugin_root = staged_root / "plugins" / PLUGIN_NAME
        package = runtime_package.build_runtime_package(projected_source, plugin_root)
        version = _plugin_version(plugin_root)

        _git(staged_root, "init", "-q")
        _git(staged_root, "config", "user.name", "Orch Dork Release Builder")
        _git(
            staged_root,
            "config",
            "user.email",
            "orch-dork-release@example.invalid",
        )
        _git(staged_root, "add", "plugins/orch-dork")
        _git(staged_root, "commit", "-q", "-m", "runtime-only Orch Dork release")
        revision = _git(staged_root, "rev-parse", "--verify", "HEAD")

        manifest = local_marketplace.construct_local_marketplace(
            staged_root,
            revision,
            PLUGIN_NAME,
            version,
            health_evidence,
        )
        validation = local_marketplace.validate_local_marketplace(
            manifest,
            staged_root,
            expected_revision=revision,
            expected_plugin_name=PLUGIN_NAME,
            expected_plugin_version=version,
            health_evidence=health_evidence,
        )
        _write_marketplace(staged_root / MARKETPLACE_PATH, manifest)
        if _git(staged_root, "status", "--porcelain=v1", "--", "plugins/orch-dork"):
            raise ReleaseMarketplaceError("plugin_source:git_dirty")
        if runtime_package.validate_runtime_package(projected_source, plugin_root) != package:
            raise ReleaseMarketplaceError("package:post_build_mismatch")
        try:
            shutil.copytree(staged_root, destination, symlinks=False)
        except OSError as exc:
            raise ReleaseMarketplaceError("release_root:publish_failed") from exc
        return {
            "schema": SCHEMA,
            "status": "PASS",
            "plugin": {"name": PLUGIN_NAME, "version": version},
            "marketplace": local_marketplace.DEFAULT_MARKETPLACE_NAME,
            "revision": revision,
            "marketplace_manifest_sha256": validation["manifest_sha256"],
            "package": dict(package),
            "git_clean": True,
            "plugin_source": "runtime_allowlist",
            "development_content_included": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    except (
        ReleaseMarketplaceError,
        local_marketplace.LocalMarketplaceError,
        runtime_package.RuntimePackageError,
    ):
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise ReleaseMarketplaceError(
            f"release_marketplace:{type(exc).__name__}"
        ) from exc
    finally:
        shutil.rmtree(temporary_parent, ignore_errors=True)


def build_release_marketplace(
    source_root: os.PathLike[str] | str,
    release_root: os.PathLike[str] | str,
    *,
    health_evidence: Mapping[str, Any],
    action_claim: action_authority.ReleaseInstallClaim | None = None,
) -> dict[str, Any]:
    """Consume the ordered build slot, run it once, and bind its output."""

    try:
        invocation = {
            "source_root": str(Path(source_root).absolute()),
            "release_root": str(Path(release_root).absolute()),
            "health_evidence": dict(health_evidence),
        }
        operation = action_authority._begin_release_operation(
            action_claim,
            "build",
            source_root=source_root,
            release_root=release_root,
            invocation=invocation,
        )
    except LifecycleContractError as exc:
        raise ReleaseMarketplaceError(str(exc)) from exc
    try:
        output = _build_release_marketplace_impl(
            source_root,
            release_root,
            health_evidence=health_evidence,
            action_claim=action_claim,
            _operation=operation,
            _invocation=invocation,
        )
        return action_authority._complete_release_operation(operation, output)
    except BaseException as exc:
        action_authority._fail_release_operation(operation, exc)
        raise


def _resolved_directory(value: os.PathLike[str] | str, label: str) -> Path:
    path = _path(value, label)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ReleaseMarketplaceError(label + ":unresolvable") from exc
    if not resolved.is_dir() or path.is_symlink():
        raise ReleaseMarketplaceError(label + ":not_directory")
    return resolved


def _candidate_source_inventory_sha256(root: Path) -> str:
    """Recompute the complete candidate-tree identity used by the reader."""

    rows: dict[str, dict[str, object]] = {}
    for directory, names, files in os.walk(root):
        names[:] = sorted(name for name in names if name not in (".git", "__pycache__"))
        for name in names:
            if (Path(directory) / name).is_symlink():
                raise ReleaseMarketplaceError("candidate_source:symlink")
        for name in sorted(files):
            if name.endswith(".pyc"):
                continue
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink():
                raise ReleaseMarketplaceError("candidate_source:file")
            data = path.read_bytes()
            rows[path.relative_to(root).as_posix()] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "mode": stat.S_IMODE(info.st_mode),
            }
    if not rows:
        raise ReleaseMarketplaceError("candidate_source:empty")
    return values.canonical_digest(rows)


def _candidate_runtime_package_sha256(root: Path) -> str:
    entries, version, _manifest = runtime_package._projectable_source_entries(
        root, runtime_package.RUNTIME_ALLOWLIST
    )
    return runtime_package._report(version, entries)["package_digest"]


def _candidate_transition_sha256(claim: action_authority.ReleaseInstallClaim) -> str:
    original = action_authority._candidate_original(claim.inputs)
    transition = _frozen(original.get("report"))
    candidate_identity.validate_cachebuster_identity_transition(
        claim.inputs.original_root,
        claim.inputs.candidate_root,
        transition,
    )
    return transition.digest()


def _context_plain(
    context: rv.FrozenValue,
    claim: action_authority.ReleaseInstallClaim,
) -> dict[str, str]:
    _physical_require(type(context) is rv.FrozenValue, "physical_context_type")
    plain = context.to_plain()
    expected = {
        "schema",
        "candidate_root",
        "source_inventory_sha256",
        "runtime_package_sha256",
        "candidate_transition_sha256",
    }
    _physical_require(type(plain) is dict and set(plain) == expected, "physical_context_shape")
    candidate = _resolved_directory(claim.inputs.candidate_root, "candidate_root")
    _physical_require(plain["schema"] == PHYSICAL_CONTEXT_SCHEMA, "physical_context_schema")
    _physical_require(plain["candidate_root"] == str(candidate), "physical_context_root")
    for name in (
        "source_inventory_sha256",
        "runtime_package_sha256",
        "candidate_transition_sha256",
    ):
        _physical_require(
            type(plain[name]) is str and re.fullmatch(r"[0-9a-f]{64}", plain[name]) is not None,
            "physical_context_digest",
        )
    return plain


def _install_observation(installation: dict) -> tuple[str, str]:
    """Validate direct cache and MCP observations retained by the installer."""

    observation = installation.get("physical_observation")
    expected = {
        "schema",
        "installed_root",
        "runtime_package",
        "cache_inventory",
        "cache_inventory_sha256",
        "mcp",
        "mcp_observation_sha256",
    }
    _physical_require(type(observation) is dict and set(observation) == expected, "install_observation_shape")
    _physical_require(
        observation["schema"] == INSTALL_PHYSICAL_OBSERVATION_SCHEMA
        and type(observation["runtime_package"]) is dict
        and observation["runtime_package"] == installation.get("package")
        and type(observation["cache_inventory"]) is list
        and type(observation["installed_root"]) is str
        and Path(observation["installed_root"]).is_absolute(),
        "install_observation_binding",
    )
    cache_sha256 = values.canonical_digest(observation["cache_inventory"])
    _physical_require(
        observation["cache_inventory_sha256"] == cache_sha256,
        "cache_inventory_binding",
    )
    mcp = observation["mcp"]
    _physical_require(
        type(mcp) is dict
        and set(mcp) == {"schema", "registered_cwd", "installed_root", "plugin", "status"}
        and mcp["schema"] == "orch-dork/release-installed-mcp-observation/v1"
        and mcp["status"] == "PASS"
        and mcp["registered_cwd"] == observation["installed_root"]
        and mcp["installed_root"] == observation["installed_root"]
        and mcp["plugin"] == installation.get("plugin"),
        "mcp_observation_binding",
    )
    mcp_sha256 = values.canonical_digest(mcp)
    _physical_require(
        observation["mcp_observation_sha256"] == mcp_sha256,
        "mcp_observation_binding",
    )
    return cache_sha256, mcp_sha256


def _cleanup_sha256(cleanups: tuple[BoundedProcessCleanup, ...]) -> str:
    _physical_require(bool(cleanups), "bounded_cleanup_required")
    rows = []
    expected = {
        "schema",
        "status",
        "argv_sha256",
        "returncode",
        "stdout_sha256",
        "stderr_sha256",
        "owned_process_group_absent",
    }
    for cleanup in cleanups:
        _require_issued_cleanup(cleanup)
        plain = cleanup.observation.to_plain()
        _physical_require(
            type(plain) is dict
            and set(plain) == expected
            and plain["schema"] == BOUNDED_CLEANUP_SCHEMA
            and plain["status"] == "PASS"
            and plain["returncode"] == 0
            and plain["owned_process_group_absent"] is True,
            "bounded_cleanup_observation",
        )
        for name in ("argv_sha256", "stdout_sha256", "stderr_sha256"):
            _physical_require(
                type(plain[name]) is str and re.fullmatch(r"[0-9a-f]{64}", plain[name]) is not None,
                "bounded_cleanup_observation",
            )
        rows.append(plain)
    return values.canonical_digest(rows)


def _physical_observation(
    *,
    claim: action_authority.ReleaseInstallClaim,
    report: dict,
    release_host_check: dict,
    marketplace_build: dict,
    installation: dict,
    cache_inventory_sha256: str,
    mcp_observation_sha256: str,
    cleanup_sha256: str,
) -> rv.FrozenValue:
    return rv.freeze(
        {
            "schema": PHYSICAL_OBSERVATION_SCHEMA,
            "claim_sha256": claim.receipt.digest(),
            "report_sha256": _content_sha256(report),
            "release_host_sha256": _content_sha256(release_host_check),
            "build_sha256": _content_sha256(marketplace_build),
            "install_sha256": _content_sha256(installation),
            "cache_inventory_sha256": cache_inventory_sha256,
            "mcp_observation_sha256": mcp_observation_sha256,
            "cleanup_sha256": cleanup_sha256,
        }
    )


def _run_claimed_release(
    source_root: os.PathLike[str] | str,
    release_root: os.PathLike[str] | str,
    *,
    health_evidence: Mapping[str, Any],
    codex_executable: os.PathLike[str] | str,
    codex_home: os.PathLike[str] | str | None,
    home_directory: os.PathLike[str] | str | None,
    action_claim: action_authority.ReleaseInstallClaim,
    physical_context: rv.FrozenValue,
) -> ReleasePhysicalResult:
    """Run each claimed effect once and retain its exact original evidence.

    Durable success is intentionally absent here.  The caller receives a
    source-issued object that an independent ReleaseExecution must validate.
    """

    action_authority.require_release_install_claim(
        action_claim, source_root=source_root, release_root=release_root
    )
    context = _context_plain(physical_context, action_claim)
    with _capture_bounded_cleanups() as captured:
        release_host_check = _run_release_host_check(
            source_root,
            codex_executable,
            release_root=release_root,
            action_claim=action_claim,
        )
        bound_health = _bind_release_host_health(health_evidence, release_host_check)
        marketplace_build = build_release_marketplace(
            source_root,
            release_root,
            health_evidence=bound_health,
            action_claim=action_claim,
        )
        installation = install_release_marketplace(
            release_root,
            codex_executable=codex_executable,
            codex_home=codex_home,
            home_directory=home_directory,
            action_claim=action_claim,
        )
    cleanup_observations = tuple(captured)
    report = action_authority._release_install_report(action_claim)
    _physical_require(
        report["release_host_check"] is release_host_check
        and report["installation"] is installation
        and report["package"] == marketplace_build.get("package"),
        "physical_report_binding",
    )
    cache_inventory_sha256, mcp_observation_sha256 = _install_observation(installation)
    cleanup_sha256 = _cleanup_sha256(cleanup_observations)
    observation = _physical_observation(
        claim=action_claim,
        report=report,
        release_host_check=release_host_check,
        marketplace_build=marketplace_build,
        installation=installation,
        cache_inventory_sha256=cache_inventory_sha256,
        mcp_observation_sha256=mcp_observation_sha256,
        cleanup_sha256=cleanup_sha256,
    )
    return _issue_physical_result(
        claim=action_claim,
        report=report,
        context=physical_context,
        physical_observation=observation,
        release_host_check=release_host_check,
        marketplace_build=marketplace_build,
        installation=installation,
        cleanup_observations=cleanup_observations,
    )


def release_and_install_physical(
    source_root: os.PathLike[str] | str,
    release_root: os.PathLike[str] | str,
    *,
    health_evidence: Mapping[str, Any],
    codex_executable: os.PathLike[str] | str,
    codex_home: os.PathLike[str] | str | None = None,
    home_directory: os.PathLike[str] | str | None = None,
    action_claim: action_authority.ReleaseInstallClaim | None = None,
    physical_context: rv.FrozenValue | None = None,
) -> ReleasePhysicalResult:
    """Provider boundary for a pre-claimed release; never records success."""

    # A valid claim proves only that the source-owned action authority spent a
    # release slot.  It is deliberately insufficient to call the physical
    # provider directly.  The exact immediate caller and its globals bind this
    # function to the reviewed ``execute_release`` code path, and the current
    # reviewed guard binds that path to the pinned source set.  Neither proof
    # comes from caller-supplied arguments, booleans, or tokens.
    caller = None
    provider_authorized = False
    try:
        from lifecycle_conformance import release_execution

        caller = sys._getframe(1)
        accepted_guard = release_execution._ACCEPTED_RELEASE_GUARD_SHA256
        current_guard = release_execution._release_guard_sha256()
        guard_current = (
            type(accepted_guard) is str
            and type(current_guard) is str
            and accepted_guard == current_guard
        )
        fixed_execute = (
            _fixed_source_release_execute(release_execution)
            if guard_current
            else None
        )
        provider_authorized = (
            fixed_execute is not None
            and release_execution.execute_release is fixed_execute
            and caller.f_code is fixed_execute.__code__
            and caller.f_globals is release_execution.__dict__
            and release_execution._release_guard_sha256() == accepted_guard
        )
    except BaseException:
        # Failure to establish either source-owned proof is authorization
        # failure.  In particular, do not fall through to the first host,
        # build, or install effect.
        provider_authorized = False
    finally:
        del caller

    try:
        _physical_require(provider_authorized, "physical_provider_authority")
        local_marketplace.sanitize_health_evidence(health_evidence)
        _physical_require(type(action_claim) is action_authority.ReleaseInstallClaim, "physical_claim_type")
        _physical_require(type(physical_context) is rv.FrozenValue, "physical_context_type")
        return _run_claimed_release(
            source_root,
            release_root,
            health_evidence=health_evidence,
            codex_executable=codex_executable,
            codex_home=codex_home,
            home_directory=home_directory,
            action_claim=action_claim,
            physical_context=physical_context,
        )
    except LifecycleContractError as exc:
        raise ReleaseMarketplaceError(str(exc)) from exc


def validate_release_physical_result(result) -> dict[str, object]:
    """Recompute every physical fact from the retained source-issued original."""

    _require_issued_physical_result(result)
    claim = result.claim
    record = action_authority._operation_record(claim)
    _physical_require(
        record["state"] == "COMPLETE"
        and result.release_host_check is record["host_output"]
        and result.marketplace_build is record["build_output"]
        and result.installation is record["install_output"]
        and result.report is record["report"],
        "physical_operation_identity",
    )
    report = action_authority._release_install_report(claim)
    _physical_require(report is result.report, "physical_report_identity")
    context = _context_plain(result.context, claim)
    candidate = _resolved_directory(claim.inputs.candidate_root, "candidate_root")
    source_inventory_sha256 = _candidate_source_inventory_sha256(candidate)
    runtime_package_sha256 = _candidate_runtime_package_sha256(candidate)
    candidate_transition_sha256 = _candidate_transition_sha256(claim)
    _physical_require(
        context["source_inventory_sha256"] == source_inventory_sha256
        and context["runtime_package_sha256"] == runtime_package_sha256
        and context["candidate_transition_sha256"] == candidate_transition_sha256,
        "physical_candidate_binding",
    )
    _physical_require(
        type(result.release_host_check) is dict
        and result.release_host_check.get("schema") == RELEASE_HOST_CHECK_SCHEMA
        and result.release_host_check.get("status") == "PASS"
        and type(result.marketplace_build) is dict
        and result.marketplace_build.get("schema") == SCHEMA
        and result.marketplace_build.get("status") == "PASS"
        and type(result.installation) is dict
        and result.installation.get("schema") == INSTALL_SCHEMA
        and result.installation.get("status") == "PASS"
        and result.marketplace_build.get("package") == result.installation.get("package")
        and result.marketplace_build.get("package", {}).get("package_digest")
        == runtime_package_sha256,
        "physical_package_parity",
    )
    cache_inventory_sha256, mcp_observation_sha256 = _install_observation(result.installation)
    cleanup_sha256 = _cleanup_sha256(result.cleanup_observations)
    expected_observation = _physical_observation(
        claim=claim,
        report=report,
        release_host_check=result.release_host_check,
        marketplace_build=result.marketplace_build,
        installation=result.installation,
        cache_inventory_sha256=cache_inventory_sha256,
        mcp_observation_sha256=mcp_observation_sha256,
        cleanup_sha256=cleanup_sha256,
    )
    _physical_require(
        result.physical_observation == expected_observation,
        "physical_observation_binding",
    )
    return {
        "valid": True,
        "facts": ["release_host_consumed", "install_parity_mcp_consumed"],
        "report_sha256": _content_sha256(report),
        "source_inventory_sha256": source_inventory_sha256,
        "runtime_package_sha256": runtime_package_sha256,
        "candidate_transition_sha256": candidate_transition_sha256,
        "release_host_sha256": _content_sha256(result.release_host_check),
        "build_sha256": _content_sha256(result.marketplace_build),
        "install_sha256": _content_sha256(result.installation),
        "cache_inventory_sha256": cache_inventory_sha256,
        "mcp_observation_sha256": mcp_observation_sha256,
        "cleanup_sha256": cleanup_sha256,
    }


def release_and_install(
    source_root: os.PathLike[str] | str,
    release_root: os.PathLike[str] | str,
    *,
    health_evidence: Mapping[str, Any],
    codex_executable: os.PathLike[str] | str,
    codex_home: os.PathLike[str] | str | None = None,
    home_directory: os.PathLike[str] | str | None = None,
    action_inputs: action_authority.ReleaseActionInputs | None = None,
) -> dict[str, Any]:
    """Compatibility projection over the reader-owned physical custody path."""

    try:
        local_marketplace.sanitize_health_evidence(health_evidence)
    except local_marketplace.LocalMarketplaceError as exc:
        raise ReleaseMarketplaceError(str(exc)) from exc
    # Keep this import lazy: release_execution pins this module's physical
    # entrypoint, while this compatibility projection delegates the final
    # outcome to that reader.
    from lifecycle_conformance import release_execution

    resolved_home = Path.home() if home_directory is None else Path(home_directory)
    resolved_codex_home = (
        _resolved_codex_home(
            os.environ,
            None,
        )
        if codex_home is None
        else Path(codex_home)
    )
    try:
        execution = release_execution.execute_release(
            action_inputs,
            {
                "release_root": release_root,
                "codex_executable": codex_executable,
                "codex_home": resolved_codex_home,
                "home_directory": resolved_home,
            },
        )
        diagnostic = release_execution.release_report(execution).to_plain()
        if diagnostic["physical_execution_validated"] is not True:
            if execution.original_failure is not None:
                raise execution.original_failure
            raise ReleaseMarketplaceError("release:physical_validation_failed")
        report, receipt = release_execution.finalize_release(execution)
        return {**report, "release_install_consumption": receipt.to_plain()}
    except LifecycleContractError as exc:
        # This compatibility API predates the custody reader.  Preserve its
        # public error contract while retaining the source-owned reason for
        # callers and the CLI.
        raise ReleaseMarketplaceError(exc.reason) from exc


def _blocking_issues(error: BaseException) -> list[str]:
    """Return one closed, specific CLI issue without classifying it as JSON."""

    if isinstance(error, json.JSONDecodeError):
        return ["health_json:malformed"]
    issues = getattr(error, "issues", None)
    if (
        type(issues) in (list, tuple)
        and issues
        and all(type(issue) is str and issue for issue in issues)
    ):
        return list(issues)
    reason = getattr(error, "reason", None)
    if type(reason) is str and reason:
        return [reason]
    return ["release_marketplace:failed"]


def _main(
    argv: Sequence[str] | None = None,
    *,
    action_inputs: action_authority.ReleaseActionInputs | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument(
        "release",
        type=Path,
        nargs="?",
        default=None,
        help="create-only marketplace root (defaults to the versioned local release store)",
    )
    parser.add_argument("--health-json", required=True)
    parser.add_argument("--codex-executable", type=Path, required=True)
    parser.add_argument("--codex-home", type=Path, default=None)
    parser.add_argument("--home-directory", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        health = json.loads(args.health_json)
        source = _path(args.source, "source_root")
        release = args.release
        if release is None:
            version = _plugin_version(source)
            release = Path.home() / ".local" / "share" / "orch-dork" / "marketplaces" / version
        report = release_and_install(
            source,
            release,
            health_evidence=health,
            codex_executable=args.codex_executable,
            codex_home=args.codex_home,
            home_directory=args.home_directory,
            action_inputs=action_inputs,
        )
    except (
        json.JSONDecodeError,
        LifecycleContractError,
        ReleaseMarketplaceError,
        local_marketplace.LocalMarketplaceError,
        runtime_package.RuntimePackageError,
    ) as exc:
        issues = _blocking_issues(exc)
        print(json.dumps({"status": "BLOCKED", "issues": issues}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
