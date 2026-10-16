#!/usr/bin/env python3
"""Provider-free containment for one disposable adapter process group.

Issue 49 deliberately keeps this seam small and boring.  ``run_contained``
starts one child with ``start_new_session=True`` (therefore one owned process
group), reads both output streams without blocking, samples Linux ``/proc``
telemetry, and kills the complete group when a bound is crossed.  No shell,
network, provider, credential store, or adjacent Orch Dork module is used.

The module is also useful on systems without ``/proc``: launch and output
handling still work, but an invocation that needs missing resource telemetry is
reported ``UNKNOWN`` and is never treated as a pass.  The tests use disposable
Python fixtures and inject only ordinary argv/config values.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import threading

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from typing import Any, Mapping, Sequence


# Keep process limits bound to the one Issue 49 profile.  The import is
# provider-free and only reaches the sibling source file in this plugin.
try:
    from orch_dork_hostile_input import (  # type: ignore
        PROFILE as HOSTILE_INPUT_PROFILE,
        HostileInputError,
        parse_bounded_json,
    )
except ImportError:  # pragma: no cover - standalone source execution
    HOSTILE_INPUT_PROFILE = None
    HostileInputError = ValueError  # type: ignore[misc,assignment]
    parse_bounded_json = None  # type: ignore[assignment]


PROFILE = HOSTILE_INPUT_PROFILE


class DispatchScope:
    """The lifetime of one dispatch, shared only with explicitly managed I/O."""

    def __init__(self, deadline: float):
        self.deadline = deadline
        self.cancelled = threading.Event()
        self.managed = False

    def stopped(self) -> bool:
        return self.cancelled.is_set() or time.monotonic() >= self.deadline


_DISPATCH_SCOPE: ContextVar[DispatchScope | None] = ContextVar("orch_dispatch_scope", default=None)


def current_dispatch_scope() -> DispatchScope | None:
    return _DISPATCH_SCOPE.get()


@contextmanager
def dispatch_scope(scope: DispatchScope):
    token = _DISPATCH_SCOPE.set(scope)
    try:
        yield
    finally:
        _DISPATCH_SCOPE.reset(token)
PROFILE_VERSION = PROFILE.schema if PROFILE is not None else "orch-dork/hostile-input-profile/v1"
DEFENSIVE_PROFILE_VERSION = PROFILE_VERSION
PRNG_SEED = PROFILE.fuzz_seed if PROFILE is not None else 0x4F524348

# Canonical Issue 49 adapter-process limits.  A caller may lower a limit but
# cannot silently raise one through ``ContainmentLimits`` or config.
MAX_DESCENDANTS = PROFILE.adapter_descendants if PROFILE is not None else 8
MAX_RSS_BYTES = PROFILE.adapter_rss_bytes if PROFILE is not None else 256 * 1024 * 1024
MAX_CPU_SECONDS = PROFILE.adapter_cpu_seconds if PROFILE is not None else 1.0
MAX_WALL_SECONDS = PROFILE.adapter_wall_seconds if PROFILE is not None else 10.0
MAX_STDOUT_BYTES = PROFILE.adapter_stream_bytes if PROFILE is not None else 65_536
MAX_STDERR_BYTES = PROFILE.adapter_stream_bytes if PROFILE is not None else 65_536
MAX_CLEANUP_SECONDS = 2.0
MAX_INPUT_BYTES = PROFILE.canonical_json_bytes if PROFILE is not None else 256 * 1024
MAX_ARG_BYTES = 65_536
MAX_ARGV_BYTES = 256 * 1024
MAX_ARG_COUNT = 256
MAX_CONFIG_KEYS = 32

DEFENSIVE_PROFILE = {
    "schema": PROFILE_VERSION,
    "version": PROFILE_VERSION,
    "max_descendants": MAX_DESCENDANTS,
    "rss_bytes": MAX_RSS_BYTES,
    "cpu_seconds": MAX_CPU_SECONDS,
    "wall_seconds": MAX_WALL_SECONDS,
    "stdout_bytes": MAX_STDOUT_BYTES,
    "stderr_bytes": MAX_STDERR_BYTES,
    "cleanup_seconds": MAX_CLEANUP_SECONDS,
}

# Stable reason codes.  They are intentionally independent of platform error
# strings and never include an argv, path, traceback, or environment value.
REASON_ARGV_INVALID = "ARGV_INVALID"
REASON_ARGV_LIMIT_EXCEEDED = "ARGV_LIMIT_EXCEEDED"
REASON_CONFIG_INVALID = "CONFIG_INVALID"
REASON_LIMIT_WIDENING = "LIMIT_WIDENING"
REASON_INPUT_LIMIT_EXCEEDED = "INPUT_LIMIT_EXCEEDED"
REASON_PROCESS_LAUNCH_FAILED = "PROCESS_LAUNCH_FAILED"
REASON_GROUP_TELEMETRY_UNAVAILABLE = "GROUP_TELEMETRY_UNAVAILABLE"
REASON_DESCENDANT_LIMIT_EXCEEDED = "DESCENDANT_LIMIT_EXCEEDED"
REASON_RSS_LIMIT_EXCEEDED = "RSS_LIMIT_EXCEEDED"
REASON_CPU_LIMIT_EXCEEDED = "CPU_LIMIT_EXCEEDED"
REASON_HARD_WALL_TIMEOUT = "HARD_WALL_TIMEOUT"
REASON_STDOUT_LIMIT_EXCEEDED = "STDOUT_LIMIT_EXCEEDED"
REASON_STDERR_LIMIT_EXCEEDED = "STDERR_LIMIT_EXCEEDED"
REASON_PROCESS_SIGNALED = "PROCESS_SIGNALED"
REASON_PROCESS_EXIT_NONZERO = "PROCESS_EXIT_NONZERO"
REASON_DESCENDANT_LEAK = "DESCENDANT_LEAK"
REASON_MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
REASON_INPUT_WRITE_FAILED = "INPUT_WRITE_FAILED"
REASON_CLEANUP_UNKNOWN = "CLEANUP_UNKNOWN"
REASON_CLEANUP_TIMEOUT = "CLEANUP_TIMEOUT"

KNOWN_REASON_CODES = frozenset(
    {
        REASON_ARGV_INVALID,
        REASON_ARGV_LIMIT_EXCEEDED,
        REASON_CONFIG_INVALID,
        REASON_LIMIT_WIDENING,
        REASON_INPUT_LIMIT_EXCEEDED,
        REASON_PROCESS_LAUNCH_FAILED,
        REASON_GROUP_TELEMETRY_UNAVAILABLE,
        REASON_DESCENDANT_LIMIT_EXCEEDED,
        REASON_RSS_LIMIT_EXCEEDED,
        REASON_CPU_LIMIT_EXCEEDED,
        REASON_HARD_WALL_TIMEOUT,
        REASON_STDOUT_LIMIT_EXCEEDED,
        REASON_STDERR_LIMIT_EXCEEDED,
        REASON_PROCESS_SIGNALED,
        REASON_PROCESS_EXIT_NONZERO,
        REASON_DESCENDANT_LEAK,
        REASON_MALFORMED_OUTPUT,
        REASON_INPUT_WRITE_FAILED,
        REASON_CLEANUP_UNKNOWN,
        REASON_CLEANUP_TIMEOUT,
    }
)

_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9_.@+-]+")
_CONFIG_NAMES = frozenset(
    {
        "max_descendants",
        "rss_bytes",
        "cpu_seconds",
        "wall_seconds",
        "stdout_bytes",
        "stderr_bytes",
        "cleanup_seconds",
        "expect_json",
    }
)


@dataclass(frozen=True)
class ContainmentLimits:
    """Per-invocation limits; values greater than the canonical profile fail."""

    max_descendants: int = MAX_DESCENDANTS
    rss_bytes: int = MAX_RSS_BYTES
    cpu_seconds: float = MAX_CPU_SECONDS
    wall_seconds: float = MAX_WALL_SECONDS
    stdout_bytes: int = MAX_STDOUT_BYTES
    stderr_bytes: int = MAX_STDERR_BYTES
    cleanup_seconds: float = MAX_CLEANUP_SECONDS

    def validate(self) -> str | None:
        """Return a stable failure reason, if this profile is invalid."""

        integer_fields = (
            ("max_descendants", self.max_descendants, MAX_DESCENDANTS),
            ("rss_bytes", self.rss_bytes, MAX_RSS_BYTES),
            ("stdout_bytes", self.stdout_bytes, MAX_STDOUT_BYTES),
            ("stderr_bytes", self.stderr_bytes, MAX_STDERR_BYTES),
        )
        for _name, value, maximum in integer_fields:
            if type(value) is not int or value < 0:
                return REASON_CONFIG_INVALID
            if value > maximum:
                return REASON_LIMIT_WIDENING
        float_fields = (
            ("cpu_seconds", self.cpu_seconds, MAX_CPU_SECONDS),
            ("wall_seconds", self.wall_seconds, MAX_WALL_SECONDS),
            ("cleanup_seconds", self.cleanup_seconds, MAX_CLEANUP_SECONDS),
        )
        for _name, value, maximum in float_fields:
            if type(value) not in (int, float) or not math.isfinite(float(value)) or float(value) <= 0:
                return REASON_CONFIG_INVALID
            if float(value) > maximum:
                return REASON_LIMIT_WIDENING
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_descendants": self.max_descendants,
            "rss_bytes": self.rss_bytes,
            "cpu_seconds": float(self.cpu_seconds),
            "wall_seconds": float(self.wall_seconds),
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "cleanup_seconds": float(self.cleanup_seconds),
        }


@dataclass(frozen=True)
class _ProcessStat:
    pid: int
    ppid: int
    pgid: int
    rss_bytes: int
    cpu_seconds: float
    state: str


class ContainmentError(ValueError):
    """Validation error carrying a stable Issue 49 reason code."""

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        super().__init__(message or reason)


def _safe_token(value: Any, default: str = "unknown", limit: int = 128) -> str:
    text = str(value) if isinstance(value, (str, int)) else default
    text = _SAFE_TOKEN.sub("_", text).strip("_")[:limit]
    return text or default


def _coerce_input(data: bytes | bytearray | memoryview | str | None) -> bytes:
    if data is None:
        return b""
    if isinstance(data, str):
        try:
            return data.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ContainmentError(REASON_CONFIG_INVALID) from exc
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise ContainmentError(REASON_CONFIG_INVALID, "input must be bytes or text")


def _limits_from_config(
    config: Mapping[str, Any] | None, limits: ContainmentLimits | None
) -> tuple[ContainmentLimits, bool]:
    """Parse a small closed config and return ``(limits, expect_json)``."""

    if limits is not None and not isinstance(limits, ContainmentLimits):
        raise ContainmentError(REASON_CONFIG_INVALID, "limits must be ContainmentLimits")
    effective = limits or ContainmentLimits()
    if config is None:
        config = {}
    if not isinstance(config, Mapping) or len(config) > MAX_CONFIG_KEYS:
        raise ContainmentError(REASON_CONFIG_INVALID)
    unknown = set(config) - _CONFIG_NAMES
    if unknown:
        raise ContainmentError(REASON_CONFIG_INVALID)
    expect_json = bool(config.get("expect_json", False))
    if "expect_json" in config and type(config["expect_json"]) is not bool:
        raise ContainmentError(REASON_CONFIG_INVALID)
    values = effective.as_dict()
    for name in _CONFIG_NAMES - {"expect_json"}:
        if name in config:
            value = config[name]
            if type(value) not in (int, float) or isinstance(value, bool):
                raise ContainmentError(REASON_CONFIG_INVALID)
            values[name] = value
    effective = ContainmentLimits(**values)
    reason = effective.validate()
    if reason:
        raise ContainmentError(reason)
    return effective, expect_json


def validate_invocation(
    argv: Sequence[str],
    *,
    input_bytes: bytes | bytearray | memoryview | str | None = None,
    config: Mapping[str, Any] | None = None,
    limits: ContainmentLimits | None = None,
) -> dict[str, Any]:
    """Validate argv/config/input before allocating or launching a process.

    The returned report contains no caller-provided body or path.  It is safe
    to use as a denial receipt in a caller's logs.
    """

    try:
        if not isinstance(argv, (list, tuple)) or not argv or len(argv) > MAX_ARG_COUNT:
            raise ContainmentError(REASON_ARGV_INVALID)
        total = 0
        for index, argument in enumerate(argv):
            if not isinstance(argument, str) or not argument or "\x00" in argument:
                raise ContainmentError(REASON_ARGV_INVALID)
            if index == 0 and any(part == ".." for part in Path(argument).parts):
                raise ContainmentError(REASON_ARGV_INVALID)
            try:
                raw = argument.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ContainmentError(REASON_ARGV_INVALID) from exc
            if len(raw) > MAX_ARG_BYTES:
                raise ContainmentError(REASON_ARGV_LIMIT_EXCEEDED)
            total += len(raw) + 1
            if index == 0 and not argument.strip():
                raise ContainmentError(REASON_ARGV_INVALID)
        if total > MAX_ARGV_BYTES:
            raise ContainmentError(REASON_ARGV_LIMIT_EXCEEDED)
        data = _coerce_input(input_bytes)
        if len(data) > MAX_INPUT_BYTES:
            raise ContainmentError(REASON_INPUT_LIMIT_EXCEEDED)
        effective, expect_json = _limits_from_config(config, limits)
        return {
            "status": "PASS",
            "reason": None,
            "argv_count": len(argv),
            "argv_bytes": total,
            "input_bytes": len(data),
            "limits": effective.as_dict(),
            "expect_json": expect_json,
        }
    except (ContainmentError, UnicodeError) as exc:
        reason = exc.reason if isinstance(exc, ContainmentError) else REASON_CONFIG_INVALID
        return {
            "status": "FAIL",
            "reason": reason,
            "argv_count": len(argv) if isinstance(argv, (list, tuple)) else 0,
            "argv_bytes": None,
            "input_bytes": None,
        }


def _proc_stat(pid: int) -> _ProcessStat | None:
    """Read one process's bounded Linux proc record, if available."""

    stat_path = f"/proc/{pid}/stat"
    status_path = f"/proc/{pid}/status"
    try:
        line = Path(stat_path).read_text(encoding="utf-8", errors="replace")
        close = line.rfind(")")
        if close < 0:
            return None
        tail = line[close + 2 :].split()
        if len(tail) < 13:
            return None
        state = tail[0]
        ppid = int(tail[1])
        pgid = int(tail[2])
        ticks = int(tail[11]) + int(tail[12])
        clk = os.sysconf("SC_CLK_TCK")
        cpu = ticks / float(clk)
        rss = 0
        for raw in Path(status_path).read_text(encoding="utf-8", errors="replace").splitlines():
            if raw.startswith("VmRSS:"):
                fields = raw.split()
                if len(fields) >= 2:
                    rss = max(0, int(fields[1]) * 1024)
                break
        return _ProcessStat(pid, ppid, pgid, rss, cpu, state)
    except (FileNotFoundError, PermissionError, OSError, ValueError, IndexError):
        return None


def _group_snapshot(pgid: int) -> list[_ProcessStat] | None:
    """Return all observed members of ``pgid``; ``None`` means telemetry unknown."""

    proc = Path("/proc")
    if not proc.is_dir():
        return _ps_group_snapshot(pgid)
    records: list[_ProcessStat] = []
    saw_process = False
    try:
        entries = list(proc.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        saw_process = True
        record = _proc_stat(int(entry.name))
        if record is not None and record.pgid == pgid:
            records.append(record)
    if not saw_process:
        return _ps_group_snapshot(pgid)
    return records


def _parse_ps_cpu(value: str) -> float:
    """Parse the locale-independent ``ps time`` field into seconds."""

    value = value.strip()
    if not value:
        return 0.0
    days = 0
    if "-" in value:
        day_text, value = value.split("-", 1)
        days = int(day_text)
    pieces = value.split(":")
    if len(pieces) == 3:
        hours, minutes, seconds = pieces
    elif len(pieces) == 2:
        hours, minutes, seconds = "0", pieces[0], pieces[1]
    else:
        hours, minutes, seconds = "0", "0", pieces[0]
    return days * 86400 + int(hours) * 3600 + int(minutes) * 60 + float(seconds)


def _ps_group_snapshot(pgid: int) -> list[_ProcessStat] | None:
    """Use the platform ``ps`` utility when ``/proc`` is unavailable.

    ``ps`` is an observation helper launched outside the owned adapter group;
    it receives a fixed environment and no caller data.  A timeout or malformed
    row is unknown, never an empty/healthy observation.
    """

    try:
        completed = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,pgid=,rss=,time=,stat="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
            env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"},
            timeout=0.25,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    try:
        text = completed.stdout.decode("ascii")
    except UnicodeDecodeError:
        return None
    records: list[_ProcessStat] = []
    saw_rows = False
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        saw_rows = True
        if len(fields) < 6:
            return None
        try:
            pid, ppid, row_pgid = (int(fields[0]), int(fields[1]), int(fields[2]))
            rss = max(0, int(fields[3])) * 1024
            cpu = _parse_ps_cpu(fields[4])
            state = fields[5]
        except (TypeError, ValueError, IndexError):
            return None
        if row_pgid == pgid:
            records.append(_ProcessStat(pid, ppid, row_pgid, rss, cpu, state))
    return records if saw_rows else None


def _kill_group(pgid: int) -> bool:
    """Terminate the owned process group, escalating once, without shell use."""

    sent = False
    try:
        os.killpg(pgid, signal.SIGTERM)
        sent = True
    except (ProcessLookupError, PermissionError, OSError):
        pass
    # A short grace period lets cooperative fixtures flush and exit.  The hard
    # cleanup deadline is enforced by the caller, not this grace sleep.
    deadline = time.monotonic() + 0.10
    while time.monotonic() < deadline:
        if _group_snapshot(pgid) == []:
            return sent
        time.sleep(0.005)
    try:
        os.killpg(pgid, signal.SIGKILL)
        sent = True
    except (ProcessLookupError, PermissionError, OSError):
        pass
    return sent


def _parse_json_output(data: bytes) -> tuple[Any | None, str | None]:
    if parse_bounded_json is not None:
        try:
            return parse_bounded_json(data, profile=PROFILE), None
        except Exception:
            # Keep the adapter boundary's stable reason independent of parser
            # exception text or implementation details.
            return None, REASON_MALFORMED_OUTPUT
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, REASON_MALFORMED_OUTPUT
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)

    try:
        decoder = json.JSONDecoder(
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite number")),
        )
        value, end = decoder.raw_decode(text)
        if text[end:].strip():
            return None, REASON_MALFORMED_OUTPUT
        return value, None
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, REASON_MALFORMED_OUTPUT


def sanitize_crash_evidence(
    *,
    surface: Any,
    case_id: Any,
    seed: Any,
    input_data: bytes | bytearray | memoryview | str | None,
    bound_name: Any,
    reason_code: Any,
    exit_signal_class: Any,
    elapsed_seconds: Any,
    output_bytes: Any,
    process_group_count: Any,
    cleanup_status: Any,
) -> dict[str, Any]:
    """Build the exact allow-listed, hash-bound crash-evidence shape.

    No input body, path, traceback, prompt, or environment value is retained.
    ``input_sha256`` is the only representation of input content.
    """

    try:
        data = _coerce_input(input_data)
    except ContainmentError:
        data = b""
    reason = _safe_token(reason_code)
    if reason not in KNOWN_REASON_CODES:
        reason = REASON_CLEANUP_UNKNOWN if reason.upper().startswith("CLEANUP") else "UNKNOWN_REASON"
    cleanup = _safe_token(cleanup_status)
    if cleanup not in {"complete", "uncertain", "unknown", "not_started"}:
        cleanup = "unknown"
    try:
        elapsed = float(elapsed_seconds)
        elapsed = elapsed if math.isfinite(elapsed) and elapsed >= 0 else 0.0
    except (TypeError, ValueError):
        elapsed = 0.0
    try:
        output_count = max(0, int(output_bytes))
    except (TypeError, ValueError):
        output_count = 0
    try:
        group_count = max(0, int(process_group_count))
    except (TypeError, ValueError):
        group_count = 0
    return {
        "surface": _safe_token(surface),
        "case_id": _safe_token(case_id),
        "seed": _safe_token(seed),
        "input_byte_count": len(data),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "bound_name": _safe_token(bound_name),
        "reason_code": reason,
        "exit_signal_class": _safe_token(exit_signal_class),
        "elapsed_seconds": round(elapsed, 6),
        "output_byte_count": output_count,
        "process_group_count": group_count,
        "cleanup_status": cleanup,
    }


def append_sanitized_evidence(path: str | os.PathLike[str], evidence: Mapping[str, Any]) -> None:
    """Append one canonical JSON evidence record; never overwrite prior records."""

    allowed = {
        "surface",
        "case_id",
        "seed",
        "input_byte_count",
        "input_sha256",
        "bound_name",
        "reason_code",
        "exit_signal_class",
        "elapsed_seconds",
        "output_byte_count",
        "process_group_count",
        "cleanup_status",
    }
    if set(evidence) != allowed:
        raise ValueError("evidence shape is not sanitized")
    for key in ("surface", "case_id", "seed", "bound_name", "reason_code", "exit_signal_class", "cleanup_status"):
        value = evidence.get(key)
        if not isinstance(value, str) or _safe_token(value) != value:
            raise ValueError("evidence contains an unsafe token")
    if not isinstance(evidence.get("input_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", evidence["input_sha256"]):
        raise ValueError("evidence input hash is invalid")
    for key in ("input_byte_count", "output_byte_count", "process_group_count"):
        if type(evidence.get(key)) is not int or evidence[key] < 0:
            raise ValueError("evidence count is invalid")
    if type(evidence.get("elapsed_seconds")) not in (int, float) or not math.isfinite(float(evidence["elapsed_seconds"])) or evidence["elapsed_seconds"] < 0:
        raise ValueError("evidence elapsed time is invalid")
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(dict(evidence), sort_keys=True, separators=(",", ":")) + "\n")


def _bound_name(reason: str | None) -> str:
    return {
        REASON_ARGV_LIMIT_EXCEEDED: "argv_bytes",
        REASON_INPUT_LIMIT_EXCEEDED: "input_bytes",
        REASON_DESCENDANT_LIMIT_EXCEEDED: "max_descendants",
        REASON_RSS_LIMIT_EXCEEDED: "rss_bytes",
        REASON_CPU_LIMIT_EXCEEDED: "cpu_seconds",
        REASON_HARD_WALL_TIMEOUT: "wall_seconds",
        REASON_STDOUT_LIMIT_EXCEEDED: "stdout_bytes",
        REASON_STDERR_LIMIT_EXCEEDED: "stderr_bytes",
        REASON_CLEANUP_UNKNOWN: "cleanup_seconds",
        REASON_CLEANUP_TIMEOUT: "cleanup_seconds",
        REASON_MALFORMED_OUTPUT: "output_format",
    }.get(reason or "", "process_group")


def _new_result(validation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": validation.get("status", "FAIL"),
        "reason": validation.get("reason"),
        "underlying_reason": None,
        "exit_code": None,
        "signal": None,
        "elapsed_seconds": 0.0,
        "stdout": b"",
        "stderr": b"",
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "output_bytes": 0,
        "process_group_id": None,
        "process_group_count": 0,
        "descendant_count": 0,
        "peak_descendant_count": 0,
        "peak_rss_bytes": 0,
        "peak_cpu_seconds": 0.0,
        "cleanup_status": "not_started",
        "cleanup_observed_within_seconds": None,
        "parsed_output": None,
        "crash_evidence": None,
    }


def run_contained(
    argv: Sequence[str],
    *,
    input_bytes: bytes | bytearray | memoryview | str | None = None,
    config: Mapping[str, Any] | None = None,
    limits: ContainmentLimits | None = None,
    expect_json: bool | None = None,
    case_id: Any = "runtime",
    seed: Any = PRNG_SEED,
    surface: Any = "adapter-process",
    evidence_path: str | os.PathLike[str] | None = None,
    scope: DispatchScope | None = None,
) -> dict[str, Any]:
    """Run exactly one argv in one owned process group and return a bounded result."""

    validation = validate_invocation(argv, input_bytes=input_bytes, config=config, limits=limits)
    result = _new_result(validation)
    if validation["status"] != "PASS":
        return result
    data = _coerce_input(input_bytes)
    effective, configured_json = _limits_from_config(config, limits)
    if expect_json is not None and type(expect_json) is not bool:
        result["status"] = "FAIL"
        result["reason"] = REASON_CONFIG_INVALID
        return result
    parse_json = configured_json if expect_json is None else expect_json
    if scope is not None and scope.stopped():
        result["status"] = "FAIL"
        result["reason"] = REASON_HARD_WALL_TIMEOUT
        return result
    pgid: int | None = None
    started = time.monotonic()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    output_reason: str | None = None
    primary_reason: str | None = None
    telemetry_unknown = False
    peak_count = 0
    peak_rss = 0
    peak_cpu = 0.0
    proc: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    stdin_view = memoryview(data)
    stdin_offset = 0
    stdin_registered = False
    stream_fds: set[int] = set()

    def drain(fd: int, target: bytearray, limit: int, stream_reason: str) -> bool:
        nonlocal output_reason
        try:
            chunk = os.read(fd, min(16_384, limit - len(target) + 1))
        except BlockingIOError:
            return True
        except OSError:
            chunk = b""
        if not chunk:
            try:
                selector.unregister(fd)
            except Exception:
                pass
            stream_fds.discard(fd)
            return False
        remaining = limit - len(target)
        if len(chunk) > remaining:
            target.extend(chunk[:remaining])
            output_reason = stream_reason
            return True
        target.extend(chunk)
        return True

    try:
        # ``shell=False`` and ``close_fds`` are deliberate hard boundaries;
        # no caller supplied environment, cwd, descriptor, or shell string is
        # accepted by this API.
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"},
        )
        pgid = proc.pid
        result["process_group_id"] = pgid
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        for stream in (proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, stream)
            stream_fds.add(stream.fileno())
        os.set_blocking(proc.stdin.fileno(), False)
        if stdin_view:
            selector.register(proc.stdin, selectors.EVENT_WRITE, proc.stdin)
            stdin_registered = True
        else:
            proc.stdin.close()
    except (OSError, ValueError):
        result["status"] = "FAIL"
        result["reason"] = REASON_PROCESS_LAUNCH_FAILED
        result["elapsed_seconds"] = round(time.monotonic() - started, 6)
        return result

    def sample() -> bool:
        nonlocal telemetry_unknown, peak_count, peak_rss, peak_cpu
        assert pgid is not None
        snapshot = _group_snapshot(pgid)
        if snapshot is None:
            telemetry_unknown = True
            return False
        count = max(0, len(snapshot) - 1)
        rss = sum(item.rss_bytes for item in snapshot)
        cpu = sum(item.cpu_seconds for item in snapshot)
        peak_count = max(peak_count, count)
        peak_rss = max(peak_rss, rss)
        peak_cpu = max(peak_cpu, cpu)
        result["process_group_count"] = len(snapshot)
        result["descendant_count"] = count
        result["peak_descendant_count"] = peak_count
        result["peak_rss_bytes"] = peak_rss
        result["peak_cpu_seconds"] = round(peak_cpu, 6)
        if count > effective.max_descendants:
            return _set_reason(REASON_DESCENDANT_LIMIT_EXCEEDED)
        if rss > effective.rss_bytes:
            return _set_reason(REASON_RSS_LIMIT_EXCEEDED)
        if cpu > effective.cpu_seconds:
            return _set_reason(REASON_CPU_LIMIT_EXCEEDED)
        return True

    def _set_reason(reason: str) -> bool:
        nonlocal primary_reason
        if primary_reason is None:
            primary_reason = reason
        return False

    def collect(timeout: float) -> None:
        nonlocal stdin_offset, stdin_registered
        end = time.monotonic() + max(0.0, timeout)
        while selector.get_map() and time.monotonic() < end:
            events = selector.select(min(0.02, max(0.0, end - time.monotonic())))
            for key, mask in events:
                fd = key.fd
                if stdin_registered and key.fileobj is proc.stdin:
                    try:
                        if stdin_offset < len(stdin_view):
                            written = os.write(fd, stdin_view[stdin_offset : stdin_offset + 16_384])
                            stdin_offset += written
                        if stdin_offset >= len(stdin_view):
                            selector.unregister(fd)
                            proc.stdin.close()
                            stdin_registered = False
                    except (BrokenPipeError, OSError):
                        try:
                            selector.unregister(fd)
                        except Exception:
                            pass
                        try:
                            proc.stdin.close()
                        except Exception:
                            pass
                        stdin_registered = False
                elif key.fileobj is proc.stdout:
                    drain(fd, stdout_buffer, effective.stdout_bytes, REASON_STDOUT_LIMIT_EXCEEDED)
                elif key.fileobj is proc.stderr:
                    drain(fd, stderr_buffer, effective.stderr_bytes, REASON_STDERR_LIMIT_EXCEEDED)

    try:
        while True:
            elapsed = time.monotonic() - started
            result["elapsed_seconds"] = round(elapsed, 6)
            if output_reason and primary_reason is None:
                primary_reason = output_reason
            if primary_reason is None:
                sample_ok = sample()
                if not sample_ok and telemetry_unknown:
                    primary_reason = REASON_GROUP_TELEMETRY_UNAVAILABLE
                elif elapsed >= effective.wall_seconds or (scope is not None and scope.stopped()):
                    primary_reason = REASON_HARD_WALL_TIMEOUT
            collect(min(0.02, max(0.0, effective.wall_seconds - elapsed)))
            if output_reason and primary_reason is None:
                primary_reason = output_reason
            if proc.poll() is not None:
                # Drain everything the exited process left in its pipes before
                # making the final output/JSON decision.
                collect(0.05)
                break
            if primary_reason is not None:
                break
            if elapsed >= effective.wall_seconds:
                primary_reason = REASON_HARD_WALL_TIMEOUT
                break
    finally:
        if primary_reason is not None and pgid is not None:
            _kill_group(pgid)
        # Ensure the leader is reaped.  A timeout here is an unknown cleanup,
        # not a pass based on the parent's exit alone.
        if proc.poll() is None:
            try:
                proc.wait(timeout=effective.cleanup_seconds)
            except subprocess.TimeoutExpired:
                pass
        collect(effective.cleanup_seconds)
        try:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=0.2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            selector.close()
        except Exception:
            pass
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass

    result["stdout"] = bytes(stdout_buffer)
    result["stderr"] = bytes(stderr_buffer)
    result["stdout_bytes"] = len(stdout_buffer)
    result["stderr_bytes"] = len(stderr_buffer)
    result["output_bytes"] = len(stdout_buffer) + len(stderr_buffer)
    result["exit_code"] = proc.returncode
    result["signal"] = -proc.returncode if proc.returncode is not None and proc.returncode < 0 else None
    result["elapsed_seconds"] = round(time.monotonic() - started, 6)

    # Verify the entire owned group, not merely the leader's exit.  Missing
    # telemetry is explicitly unknown and blocks qualification.
    cleanup_started = time.monotonic()
    cleanup_snapshot: list[_ProcessStat] | None = None
    cleanup_deadline = cleanup_started + effective.cleanup_seconds
    while pgid is not None and time.monotonic() < cleanup_deadline:
        cleanup_snapshot = _group_snapshot(pgid)
        if cleanup_snapshot is None:
            break
        result["process_group_count"] = len(cleanup_snapshot)
        result["descendant_count"] = max(0, len(cleanup_snapshot) - 1)
        if not cleanup_snapshot:
            break
        if primary_reason is None:
            primary_reason = REASON_DESCENDANT_LEAK
            _kill_group(pgid)
        time.sleep(0.01)
    cleanup_elapsed = time.monotonic() - cleanup_started
    result["cleanup_observed_within_seconds"] = round(cleanup_elapsed, 6)
    if pgid is None:
        result["cleanup_status"] = "not_started"
    elif cleanup_snapshot is None:
        result["cleanup_status"] = "unknown"
    elif cleanup_snapshot:
        result["cleanup_status"] = "uncertain"
    else:
        result["cleanup_status"] = "complete"

    if result["cleanup_status"] != "complete":
        result["underlying_reason"] = primary_reason
        result["status"] = "UNKNOWN"
        result["reason"] = REASON_CLEANUP_UNKNOWN if result["cleanup_status"] == "unknown" else REASON_CLEANUP_TIMEOUT
    elif primary_reason is not None:
        result["status"] = "FAIL"
        result["reason"] = primary_reason
    elif proc.returncode is not None and proc.returncode < 0:
        result["status"] = "FAIL"
        result["reason"] = REASON_PROCESS_SIGNALED
    elif proc.returncode not in (0, None):
        result["status"] = "FAIL"
        result["reason"] = REASON_PROCESS_EXIT_NONZERO
    elif parse_json:
        parsed, parse_reason = _parse_json_output(bytes(stdout_buffer))
        if parse_reason:
            result["status"] = "FAIL"
            result["reason"] = parse_reason
            result["underlying_reason"] = parse_reason
        else:
            result["parsed_output"] = parsed
            result["status"] = "PASS"
    else:
        result["status"] = "PASS"

    if result["status"] != "PASS":
        exit_class = "none"
        if result["signal"] is not None:
            exit_class = f"signal_{result['signal']}"
        elif result["exit_code"] is not None:
            exit_class = "exit_nonzero" if result["exit_code"] else "exit_zero"
        evidence = sanitize_crash_evidence(
            surface=surface,
            case_id=case_id,
            seed=seed,
            input_data=data,
            bound_name=_bound_name(result["reason"]),
            reason_code=(result["reason"] or REASON_CLEANUP_UNKNOWN),
            exit_signal_class=exit_class,
            elapsed_seconds=result["elapsed_seconds"],
            output_bytes=result["output_bytes"],
            process_group_count=result["process_group_count"],
            cleanup_status=result["cleanup_status"],
        )
        result["crash_evidence"] = evidence
        if evidence_path is not None:
            append_sanitized_evidence(evidence_path, evidence)
    return result


# Friendly aliases used by callers that describe the operation as an adapter
# runner rather than a process runner.
PROCESS_LIMITS = DEFENSIVE_PROFILE
ProcessLimits = ContainmentLimits
contain_process = run_contained
run_process = run_contained
run_contained_process = run_contained
contain_adapter_process = run_contained
validate_process_request = validate_invocation
validate_process_argv = validate_invocation
build_crash_evidence = sanitize_crash_evidence
sanitize_evidence = sanitize_crash_evidence


__all__ = [
    "ContainmentError",
    "ContainmentLimits",
    "PROFILE",
    "DEFENSIVE_PROFILE",
    "DEFENSIVE_PROFILE_VERSION",
    "MAX_ARG_BYTES",
    "MAX_ARGV_BYTES",
    "MAX_ARG_COUNT",
    "MAX_CLEANUP_SECONDS",
    "MAX_CPU_SECONDS",
    "MAX_DESCENDANTS",
    "MAX_INPUT_BYTES",
    "MAX_RSS_BYTES",
    "MAX_STDERR_BYTES",
    "MAX_STDOUT_BYTES",
    "MAX_WALL_SECONDS",
    "PROCESS_LIMITS",
    "ProcessLimits",
    "PRNG_SEED",
    "append_sanitized_evidence",
    "build_crash_evidence",
    "contain_process",
    "run_contained",
    "run_contained_process",
    "run_process",
    "sanitize_crash_evidence",
    "sanitize_evidence",
    "validate_invocation",
    "validate_process_argv",
    "validate_process_request",
]
