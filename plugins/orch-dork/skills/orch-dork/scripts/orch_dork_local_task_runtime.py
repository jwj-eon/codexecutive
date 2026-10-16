#!/usr/bin/env python3
"""Observe the exact Local app-server process that owns the current task.

The owner socket is injected before the task and its MCP children start.  This
module never guesses a desktop/global socket and never falls back to rollout
inference when the selected app server does not own the current task.
"""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import time
from typing import Any, Mapping, MutableMapping, NamedTuple
import weakref


SCHEMA = "orch-dork/current-local-task-runtime/v1"
HOOK_TRUST_SCHEMA = "orch-dork/current-local-task-hook-trust/v2"
HOOK_INVENTORY_SCHEMA = "orch-dork/current-local-task-hook-inventory/v1"
MCP_CALL_SCHEMA = "orch-dork/current-local-task-mcp-observation/v1"
ATTEMPT_SOURCES_SCHEMA = "orch-dork/completed-attempt-sources/v1"
CHECKPOINT_SOURCES_SCHEMA = "orch-dork/worker-checkpoint-sources/v1"
WORKER_FINAL_SOURCES_SCHEMA = "orch-dork/worker-final-sources/v1"
_CHECKPOINT_ARRIVAL_SOURCES_SCHEMA = "orch-dork/worker-checkpoint-arrivals/v1"
WORKER_FINAL_ARRIVAL_SOURCES_SCHEMA = "orch-dork/worker-final-arrivals/v1"
OWNER_SOCKET_ENV = "ORCH_DORK_APP_SERVER_SOCKET"
MAX_FRAME_BYTES = 16 * 1024 * 1024
MAX_CMDLINE_BYTES = 65_536
MAX_MESSAGES_PER_REQUEST = 256
RPC_TIMEOUT_SECONDS = 5.0
RETAINED_TRANSPORT_TIMEOUT_SECONDS = 30.0
_HOOK_TRUST_BYPASS_FLAG = b"--dangerously-bypass-hook-trust"
_APP_SERVER_SUBCOMMAND = b"app-server"
_PLUGIN_ID = "orch-dork@orch-dork-local"
_HOOK_SOURCE = "hooks/hooks.json"
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_HASH = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_REQUIRED_HOOKS = (
    ("postToolUse", "post_tool_use", ".*"),
    ("preToolUse", "pre_tool_use", ".*"),
    ("sessionStart", "session_start", "startup|resume|clear|compact"),
    ("stop", "stop", None),
    ("subagentStop", "subagent_stop", ".*"),
)
_HOOK_ROW_FIELDS = frozenset(
    {"event_name", "key", "matcher", "enabled", "trust_status", "current_hash"}
)
_HOOK_INVENTORY_FIELDS = frozenset(
    {
        "schema",
        "status",
        "disposition",
        "plugin_id",
        "source_path",
        "owner_identity_sha256",
        "app_server_argv_sha256",
        "hooks",
        "issues",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "credential_reads",
        "network_calls",
        "task_creations",
        "native_calls",
        "report_sha256",
    }
)
_RETAINED_OWNER_TRANSPORT_MINT = object()
_RETAINED_OWNER_TRANSPORTS: weakref.WeakSet[Any] = weakref.WeakSet()


class LocalTaskRuntimeError(ValueError):
    """Sanitized fail-closed owner-observation error."""


def _plugin_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _hook_source_path() -> Path:
    return _plugin_root() / _HOOK_SOURCE


def _hook_key(key_name: str) -> str:
    return f"{_PLUGIN_ID}:{_HOOK_SOURCE}:{key_name}:0:0"


def build_qualification_hook_state_override() -> str:
    """Return the complete invocation-local hook enablement overlay.

    The caller passes this value to one Codex ``-c`` argument.  It neither
    edits persistent configuration nor carries trust hashes.
    """

    entries = ",".join(
        f'"{_hook_key(key_name)}"={{enabled=true}}'
        for _, key_name, _ in _REQUIRED_HOOKS
    )
    return "hooks.state={" + entries + "}"


class OwnerHookInventoryArtifact:
    """Strict access to one sealed, owner-observed plugin hook inventory."""

    __slots__ = (
        "report",
        "report_sha256",
        "owner_identity_sha256",
        "app_server_argv_sha256",
        "hooks",
    )

    report: dict[str, Any]
    report_sha256: str
    owner_identity_sha256: str
    app_server_argv_sha256: str
    hooks: tuple[dict[str, Any], ...]

    def __init__(
        self,
        *,
        report: dict[str, Any],
        report_sha256: str,
        owner_identity_sha256: str,
        app_server_argv_sha256: str,
        hooks: tuple[dict[str, Any], ...],
    ) -> None:
        object.__setattr__(self, "report", report)
        object.__setattr__(self, "report_sha256", report_sha256)
        object.__setattr__(
            self, "owner_identity_sha256", owner_identity_sha256
        )
        object.__setattr__(
            self, "app_server_argv_sha256", app_server_argv_sha256
        )
        object.__setattr__(self, "hooks", hooks)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("OwnerHookInventoryArtifact is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("OwnerHookInventoryArtifact is immutable")

    @classmethod
    def from_report(cls, report: Any) -> "OwnerHookInventoryArtifact":
        if not isinstance(report, Mapping) or set(report) != _HOOK_INVENTORY_FIELDS:
            raise LocalTaskRuntimeError("hook_inventory:report_shape_invalid")
        value = deepcopy(dict(report))
        hooks = value.get("hooks")
        try:
            expected_path = str(_hook_source_path().resolve(strict=True))
        except OSError as error:
            raise LocalTaskRuntimeError(
                "hook_inventory:source_unavailable"
            ) from error
        expected_rows = {
            event_name: (_hook_key(key_name), matcher)
            for event_name, key_name, matcher in _REQUIRED_HOOKS
        }
        valid_hooks = isinstance(hooks, list) and len(hooks) == len(expected_rows)
        if valid_hooks:
            for row, (event_name, (key, matcher)) in zip(
                hooks, sorted(expected_rows.items())
            ):
                if (
                    not isinstance(row, Mapping)
                    or set(row) != _HOOK_ROW_FIELDS
                    or row.get("event_name") != event_name
                    or row.get("key") != key
                    or row.get("matcher") != matcher
                    or row.get("enabled") is not True
                    or row.get("trust_status")
                    not in {"trusted", "untrusted", "modified"}
                    or _HASH.fullmatch(str(row.get("current_hash", ""))) is None
                ):
                    valid_hooks = False
                    break
        core = {key: item for key, item in value.items() if key != "report_sha256"}
        if (
            value.get("schema") != HOOK_INVENTORY_SCHEMA
            or value.get("status") != "PASS"
            or value.get("disposition") != "OWNER_HOOK_INVENTORY_VERIFIED"
            or value.get("plugin_id") != _PLUGIN_ID
            or value.get("source_path") != expected_path
            or _SHA256.fullmatch(
                str(value.get("owner_identity_sha256", ""))
            )
            is None
            or _SHA256.fullmatch(
                str(value.get("app_server_argv_sha256", ""))
            )
            is None
            or not valid_hooks
            or value.get("issues") != []
            or value.get("provider_free") is not True
            or any(
                value.get(name) != 0
                for name in (
                    "model_calls",
                    "hosted_calls",
                    "credential_reads",
                    "network_calls",
                    "task_creations",
                    "native_calls",
                )
            )
            or _SHA256.fullmatch(str(value.get("report_sha256", ""))) is None
            or value.get("report_sha256") != _sha256(core)
        ):
            raise LocalTaskRuntimeError("hook_inventory:report_invalid")
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            owner_identity_sha256=str(value["owner_identity_sha256"]),
            app_server_argv_sha256=str(value["app_server_argv_sha256"]),
            hooks=tuple(dict(row) for row in hooks),
        )


def _retained_hook_inventory_report(report: Any) -> dict[str, Any]:
    """Validate hook transport after its observed projected root is gone."""
    if not isinstance(report, Mapping) or set(report) != _HOOK_INVENTORY_FIELDS:
        raise LocalTaskRuntimeError("hook_inventory:report_shape_invalid")
    value = deepcopy(dict(report))
    source_path = value.get("source_path")
    suffix = Path(_HOOK_SOURCE).parts
    if (not isinstance(source_path, str) or not source_path
            or len(source_path) > 4096 or "\x00" in source_path):
        raise LocalTaskRuntimeError("hook_inventory:report_invalid")
    source = Path(source_path)
    if (not source.is_absolute() or ".." in source.parts
            or tuple(source.parts[-len(suffix):]) != suffix):
        raise LocalTaskRuntimeError("hook_inventory:report_invalid")
    core = {key: item for key, item in value.items()
            if key != "report_sha256"}
    if value.get("report_sha256") != _sha256(core):
        raise LocalTaskRuntimeError("hook_inventory:report_invalid")
    normalized = deepcopy(value)
    normalized["source_path"] = str(_hook_source_path().resolve(strict=True))
    normalized["report_sha256"] = _sha256({
        key: item for key, item in normalized.items()
        if key != "report_sha256"
    })
    OwnerHookInventoryArtifact.from_report(normalized)
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _report(**values: Any) -> dict[str, Any]:
    report = {
        "schema": SCHEMA,
        **values,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "credential_reads": 0,
        "network_calls": 0,
        "task_creations": 0,
        "native_calls": 0,
    }
    report["report_sha256"] = _sha256(report)
    return report


def _failure(issue: str, *, disposition: str = "TASK_OWNER_UNAVAILABLE") -> dict[str, Any]:
    return _report(
        status="FAIL",
        disposition=disposition,
        task_owner_verified=False,
        task_loaded=False,
        task_status=None,
        descendant_count=None,
        owner_identity_sha256=None,
        issues=[issue],
    )


def _inspect_peer_invocation(
    peer: Mapping[str, Any],
    *,
    proc_root: Path = Path("/proc"),
) -> dict[str, Any]:
    """Sanitize one connected Linux peer; pid drift can only refuse.

    The peer socket remains open while `/proc` is read, and uid/type checks
    are repeated on the process and cmdline descriptors. A vanished or reused
    pid therefore produces no affirmative attestation.
    """

    pid = peer.get("pid")
    uid = peer.get("uid")
    current_uid = os.getuid() if hasattr(os, "getuid") else uid
    issue: str | None = None
    raw = b""
    if (
        type(pid) is not int
        or pid < 1
        or type(uid) is not int
        or uid != current_uid
        or not proc_root.is_absolute()
        or proc_root.is_symlink()
    ):
        issue = "hook_trust:peer_identity_unavailable"
    else:
        process_root = proc_root / str(pid)
        cmdline = process_root / "cmdline"
        descriptor: int | None = None
        try:
            process_info = process_root.lstat()
            if (
                process_root.is_symlink()
                or not stat.S_ISDIR(process_info.st_mode)
                or process_info.st_uid != uid
            ):
                raise ValueError("unsafe process root")
            descriptor = os.open(
                cmdline,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
                raise ValueError("unsafe cmdline")
            while len(raw) <= MAX_CMDLINE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(8192, MAX_CMDLINE_BYTES + 1 - len(raw)),
                )
                if not chunk:
                    break
                raw += chunk
            if not raw or len(raw) > MAX_CMDLINE_BYTES or not raw.endswith(b"\0"):
                raise ValueError("invalid cmdline")
        except (OSError, ValueError):
            issue = "hook_trust:owner_invocation_unavailable"
        finally:
            if descriptor is not None:
                os.close(descriptor)

    argv_sha256 = hashlib.sha256(raw).hexdigest() if raw else None
    if issue is None:
        argv = raw[:-1].split(b"\0")
        bypass_positions = [
            index
            for index, value in enumerate(argv)
            if value == _HOOK_TRUST_BYPASS_FLAG
        ]
        app_server_positions = [
            index
            for index, value in enumerate(argv)
            if value == _APP_SERVER_SUBCOMMAND
        ]
        if len(bypass_positions) > 1:
            issue = "hook_trust:bypass_flag_ambiguous"
        elif not bypass_positions:
            issue = "hook_trust:bypass_flag_missing"
        elif len(app_server_positions) != 1:
            issue = "hook_trust:app_server_subcommand_invalid"
        elif bypass_positions[0] > app_server_positions[0]:
            issue = "hook_trust:bypass_flag_position_invalid"
    return {
        "status": "PASS" if issue is None else "FAIL",
        "mode": "one_invocation_bypass" if issue is None else None,
        "app_server_argv_sha256": argv_sha256,
        "issues": [] if issue is None else [issue],
    }


def _owner_socket_path(env: Mapping[str, str]) -> Path:
    raw = env.get(OWNER_SOCKET_ENV)
    if not isinstance(raw, str) or not raw or len(raw) > 4096 or "\x00" in raw:
        raise LocalTaskRuntimeError("task_owner:socket_unavailable")
    path = Path(raw)
    if not path.is_absolute():
        raise LocalTaskRuntimeError("task_owner:socket_unsafe")
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise LocalTaskRuntimeError("task_owner:socket_unavailable") from exc
    current_uid = os.geteuid() if hasattr(os, "geteuid") else parent.st_uid
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != current_uid
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise LocalTaskRuntimeError("task_owner:socket_unsafe")
    qualification_owner_socket_binding(path)
    return path


def qualification_owner_codex_socket_path(path: str | Path) -> Path:
    """Return Codex's deterministic protected socket for one advertised path."""

    selected = Path(path)
    try:
        if not selected.is_absolute() or "\n" in str(selected):
            raise ValueError("invalid advertised path")
        canonical_parent = selected.parent.resolve(strict=True)
        canonical_temporary_root = (Path(os.sep) / "tmp").resolve(strict=True)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else 0
        daemon_root = canonical_temporary_root / f"codex-daemon-{current_uid}"
        root_info = daemon_root.lstat()
        if (
            daemon_root.is_symlink()
            or not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != current_uid
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise ValueError("unsafe Codex socket directory")
        canonical_path = canonical_parent / selected.name
        digest = hashlib.sha256(os.fsencode(str(canonical_path))).hexdigest()
        return daemon_root / digest
    except (OSError, TypeError, ValueError) as error:
        raise LocalTaskRuntimeError("task_owner:socket_unsafe") from error


class QualificationOwnerSocketBinding(NamedTuple):
    """One immutable advertised/physical Unix-socket identity."""

    advertised_path: Path
    advertised_epoch: tuple[int, int, int, int]
    physical_path: Path
    physical_epoch: tuple[int, int, int, int]

    @property
    def rendezvous(self) -> bool:
        return self.advertised_path != self.physical_path


def qualification_owner_socket_binding(
    path: str | Path,
) -> QualificationOwnerSocketBinding:
    """Resolve a direct socket or Codex's exact protected rendezvous alias."""

    selected = Path(path)
    try:
        info = selected.lstat()
    except OSError as error:
        raise LocalTaskRuntimeError("task_owner:socket_unavailable") from error
    current_uid = os.geteuid() if hasattr(os, "geteuid") else info.st_uid
    advertised_epoch = (
        info.st_dev,
        info.st_ino,
        info.st_ctime_ns,
        info.st_uid,
    )
    physical_path = selected
    physical_info = info
    if stat.S_ISLNK(info.st_mode):
        expected = qualification_owner_codex_socket_path(selected)
        try:
            target = Path(os.readlink(selected))
        except OSError as error:
            raise LocalTaskRuntimeError("task_owner:socket_unavailable") from error
        if (
            info.st_uid != current_uid
            or not target.is_absolute()
            or target != expected
        ):
            raise LocalTaskRuntimeError("task_owner:socket_unsafe")
        try:
            physical_info = expected.lstat()
        except OSError as error:
            raise LocalTaskRuntimeError("task_owner:socket_unavailable") from error
        if (
            not stat.S_ISSOCK(physical_info.st_mode)
            or physical_info.st_uid != current_uid
            or stat.S_IMODE(physical_info.st_mode) != 0o600
        ):
            raise LocalTaskRuntimeError("task_owner:socket_unsafe")
        physical_path = expected
    elif not stat.S_ISSOCK(info.st_mode) or info.st_uid != current_uid:
        raise LocalTaskRuntimeError("task_owner:socket_unsafe")
    physical_epoch = (
        physical_info.st_dev,
        physical_info.st_ino,
        physical_info.st_ctime_ns,
        physical_info.st_uid,
    )
    return QualificationOwnerSocketBinding(
        advertised_path=selected,
        advertised_epoch=advertised_epoch,
        physical_path=physical_path,
        physical_epoch=physical_epoch,
    )


def _socket_epoch(path: Path) -> tuple[int, int, int, int]:
    return qualification_owner_socket_binding(path).physical_epoch


def _qualification_workspace_path(value: str | Path) -> Path:
    """Resolve one owner-bound workspace without accepting aliases."""

    try:
        path = Path(value)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("workspace is not an owned directory")
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except (OSError, TypeError, ValueError) as error:
        raise LocalTaskRuntimeError(
            "qualification_owner:workspace_unsafe"
        ) from error
    current_uid = os.getuid() if hasattr(os, "getuid") else info.st_uid
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != current_uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise LocalTaskRuntimeError("qualification_owner:workspace_unsafe")
    return resolved


def _peer_cwd(peer: Mapping[str, int | None]) -> Path:
    """Read one Linux peer cwd while its connected Unix credential is live."""

    pid = peer.get("pid")
    uid = peer.get("uid")
    current_uid = os.getuid() if hasattr(os, "getuid") else uid
    if (
        type(pid) is not int
        or pid < 1
        or type(uid) is not int
        or uid != current_uid
    ):
        raise LocalTaskRuntimeError("qualification_owner:peer_identity_unavailable")
    process_root = Path("/proc") / str(pid)
    try:
        root_info = process_root.lstat()
        if (
            process_root.is_symlink()
            or not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != uid
        ):
            raise ValueError("unsafe process root")
        raw_cwd = os.readlink(process_root / "cwd")
        cwd = Path(raw_cwd)
        if not cwd.is_absolute() or raw_cwd.endswith(" (deleted)"):
            raise ValueError("unsafe cwd")
        resolved = cwd.resolve(strict=True)
        info = resolved.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
            raise ValueError("unsafe cwd")
        return resolved
    except (OSError, ValueError) as error:
        raise LocalTaskRuntimeError(
            "qualification_owner:peer_cwd_unavailable"
        ) from error


class _OwnerClient:
    """Small bounded WebSocket JSON-RPC client over one owned Unix socket."""

    def __init__(
        self,
        path: Path,
        *,
        deadline: float,
        socket_binding: QualificationOwnerSocketBinding | None = None,
    ) -> None:
        self.deadline = deadline
        resolved_binding = qualification_owner_socket_binding(path)
        if (
            socket_binding is not None
            and (
                socket_binding.advertised_path != path
                or resolved_binding != socket_binding
            )
        ):
            raise LocalTaskRuntimeError("task_owner:socket_changed")
        selected_binding = socket_binding or resolved_binding
        before = selected_binding.physical_epoch
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self._remaining())
        try:
            connection.connect(str(selected_binding.physical_path))
            self._verify_peer_owner(connection, before[3])
            if qualification_owner_socket_binding(path) != selected_binding:
                raise LocalTaskRuntimeError("task_owner:socket_changed")
            self.socket = connection
            self.socket_binding = selected_binding
            self.next_id = 1
            self._handshake()
            peer = self._peer_identity(connection)
            self.owner_invocation = _inspect_peer_invocation(peer)
            self.owner_identity_sha256 = _sha256(
                {
                    "schema": "orch-dork/local-task-owner-identity/v1",
                    "socket": {
                        "device": before[0],
                        "inode": before[1],
                        "ctime_ns": before[2],
                        "uid": before[3],
                    },
                    "peer": peer,
                }
            )
        except Exception:
            connection.close()
            raise

    def _remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise LocalTaskRuntimeError("task_owner:request_timeout")
        return remaining

    @staticmethod
    def _peer_identity(connection: socket.socket) -> dict[str, int | None]:
        if hasattr(socket, "SO_PEERCRED"):
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            pid, uid, gid = struct.unpack("3i", raw)
            return {"pid": pid, "uid": uid, "gid": gid}
        getter = getattr(connection, "getpeereid", None)
        if callable(getter):
            uid, gid = getter()
            return {"pid": None, "uid": int(uid), "gid": int(gid)}
        raise LocalTaskRuntimeError("task_owner:peer_identity_unavailable")

    @classmethod
    def _verify_peer_owner(cls, connection: socket.socket, socket_uid: int) -> None:
        peer = cls._peer_identity(connection)
        current_uid = os.geteuid() if hasattr(os, "geteuid") else socket_uid
        if peer["uid"] != socket_uid or peer["uid"] != current_uid:
            raise LocalTaskRuntimeError("task_owner:peer_owner_mismatch")

    def _recv_exact(self, count: int) -> bytes:
        value = bytearray()
        while len(value) < count:
            self.socket.settimeout(self._remaining())
            try:
                chunk = self.socket.recv(count - len(value))
            except TimeoutError as exc:
                raise LocalTaskRuntimeError("task_owner:request_timeout") from exc
            if not chunk:
                raise LocalTaskRuntimeError("task_owner:transport_closed")
            value.extend(chunk)
        return bytes(value)

    def _handshake(self) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        self.socket.sendall(request)
        response = bytearray()
        marker = b"\r\n\r\n"
        while marker not in response and len(response) < 16_384:
            response.extend(self._recv_exact(1))
        if marker not in response:
            raise LocalTaskRuntimeError("task_owner:websocket_handshake_invalid")
        try:
            lines = bytes(response).decode("iso-8859-1").split("\r\n")
        except UnicodeDecodeError as exc:  # pragma: no cover - iso-8859-1 is total.
            raise LocalTaskRuntimeError("task_owner:websocket_handshake_invalid") from exc
        if not lines or " 101 " not in lines[0]:
            raise LocalTaskRuntimeError("task_owner:websocket_handshake_refused")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        expected = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        ).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            raise LocalTaskRuntimeError("task_owner:websocket_identity_invalid")

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if len(payload) > MAX_FRAME_BYTES:
            raise LocalTaskRuntimeError("task_owner:request_too_large")
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        mask = os.urandom(4)
        header.extend(mask)
        body = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(bytes(header) + body)

    def _read_frame(self) -> tuple[int, bytes, bool]:
        first, second = self._recv_exact(2)
        final = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        if length > MAX_FRAME_BYTES:
            raise LocalTaskRuntimeError("task_owner:response_too_large")
        mask = self._recv_exact(4) if masked else b""
        payload = self._recv_exact(length)
        if masked:
            payload = bytes(
                byte ^ mask[index % 4] for index, byte in enumerate(payload)
            )
        return opcode, payload, final

    def _message(self) -> dict[str, Any]:
        fragments = bytearray()
        fragment_opcode: int | None = None
        for _ in range(MAX_MESSAGES_PER_REQUEST):
            opcode, payload, final = self._read_frame()
            if opcode == 0x8:
                raise LocalTaskRuntimeError("task_owner:transport_closed")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode in {0x1, 0x2}:
                fragments = bytearray(payload)
                fragment_opcode = opcode
            elif opcode == 0x0 and fragment_opcode is not None:
                fragments.extend(payload)
            else:
                raise LocalTaskRuntimeError("task_owner:websocket_frame_invalid")
            if len(fragments) > MAX_FRAME_BYTES:
                raise LocalTaskRuntimeError("task_owner:response_too_large")
            if not final:
                continue
            if fragment_opcode != 0x1:
                raise LocalTaskRuntimeError("task_owner:websocket_frame_invalid")
            try:
                value = json.loads(bytes(fragments).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise LocalTaskRuntimeError("task_owner:response_invalid") from exc
            if not isinstance(value, dict):
                raise LocalTaskRuntimeError("task_owner:response_invalid")
            return value
        raise LocalTaskRuntimeError("task_owner:response_limit_exceeded")

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"method": method}
        if params is not None:
            message["params"] = dict(params)
        self._send_frame(0x1, _canonical_bytes(message))

    def request(self, method: str, params: Mapping[str, Any]) -> Any:
        request_id = self.next_id
        self.next_id += 1
        self._send_frame(
            0x1,
            _canonical_bytes(
                {"id": request_id, "method": method, "params": dict(params)}
            ),
        )
        for _ in range(MAX_MESSAGES_PER_REQUEST):
            self._remaining()
            message = self._message()
            if message.get("id") != request_id:
                continue
            if "error" in message:
                error = message.get("error")
                error_message = (
                    error.get("message") if isinstance(error, Mapping) else None
                )
                if method == "thread/read" and isinstance(error_message, str) and (
                    "thread not found" in error_message.lower()
                    or "no rollout found" in error_message.lower()
                ):
                    raise LocalTaskRuntimeError("task_owner:thread_not_owned")
                raise LocalTaskRuntimeError("task_owner:rpc_refused")
            return message.get("result")
        raise LocalTaskRuntimeError("task_owner:response_limit_exceeded")

    def close(self) -> None:
        try:
            self._send_frame(0x8, struct.pack("!H", 1000))
        except (OSError, LocalTaskRuntimeError):
            pass
        self.socket.close()

    def _abandon(self) -> None:
        """Close locally without writing to a possibly inherited peer."""

        try:
            self.socket.close()
        except OSError:
            pass

    def __enter__(self) -> "_OwnerClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def _qualification_owner_binding(
    client: _OwnerClient,
    *,
    socket_epoch: tuple[int, int, int, int],
    workspace: Path,
    expected_argv_sha256: str,
) -> tuple[dict[str, int | None], dict[str, Any], str]:
    """Bind one connected owner to its sealed argv, cwd, and socket epoch."""

    peer = client._peer_identity(client.socket)
    client._verify_peer_owner(client.socket, socket_epoch[3])
    invocation = _inspect_peer_invocation(peer)
    if (
        invocation.get("status") != "PASS"
        or invocation.get("mode") != "one_invocation_bypass"
        or invocation.get("app_server_argv_sha256") != expected_argv_sha256
        or invocation.get("issues") != []
    ):
        raise LocalTaskRuntimeError(
            "qualification_owner:peer_invocation_mismatch"
        )
    if _peer_cwd(peer) != workspace:
        raise LocalTaskRuntimeError("qualification_owner:peer_cwd_mismatch")
    identity = _sha256(
        {
            "schema": "orch-dork/local-task-owner-identity/v1",
            "socket": {
                "device": socket_epoch[0],
                "inode": socket_epoch[1],
                "ctime_ns": socket_epoch[2],
                "uid": socket_epoch[3],
            },
            "peer": peer,
        }
    )
    return peer, invocation, identity


class _RetainedQualificationOwnerTransport:
    """One PID-bound owner connection for a qualification owner session.

    The constructor is deliberately private.  The transport exposes only the
    three operations consumed by ``_RetainedOwnerRpc`` and immutable
    attestation properties.  Every operation rechecks the original Unix-peer,
        socket binding, app-server invocation, and workspace; no reconnect path
    exists.  A forked child loses the inherited connection before it can send
    a frame.
    """

    __slots__ = (
        "_client",
        "_socket_binding",
        "_workspace",
        "_expected_argv_sha256",
        "_owner_pid",
        "_owner_peer",
        "_owner_invocation",
        "_owner_identity_sha256",
        "_closed",
        "_closed_reason",
        "__weakref__",
    )

    def __init__(
        self,
        *,
        client: _OwnerClient,
        socket_binding: QualificationOwnerSocketBinding,
        workspace: Path,
        expected_argv_sha256: str,
        owner_peer: dict[str, int | None],
        owner_invocation: dict[str, Any],
        owner_identity_sha256: str,
        _key: object,
    ) -> None:
        if _key is not _RETAINED_OWNER_TRANSPORT_MINT:
            raise TypeError("retained qualification transport is factory-owned")
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_socket_binding", socket_binding)
        object.__setattr__(self, "_workspace", workspace)
        object.__setattr__(self, "_expected_argv_sha256", expected_argv_sha256)
        object.__setattr__(self, "_owner_pid", os.getpid())
        object.__setattr__(self, "_owner_peer", deepcopy(owner_peer))
        object.__setattr__(self, "_owner_invocation", deepcopy(owner_invocation))
        object.__setattr__(
            self, "_owner_identity_sha256", owner_identity_sha256
        )
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_closed_reason", None)
        _RETAINED_OWNER_TRANSPORTS.add(self)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("retained qualification transport is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("retained qualification transport is immutable")

    def _clear_authority(self, reason: str) -> None:
        if not self._closed:
            try:
                self._client._abandon()
            finally:
                object.__setattr__(self, "_closed", True)
                object.__setattr__(self, "_closed_reason", reason)
                _RETAINED_OWNER_TRANSPORTS.discard(self)

    def _refuse(self, reason: str) -> None:
        self._clear_authority(reason)
        raise LocalTaskRuntimeError("qualification_owner:" + reason)

    def _ensure_owner_process(self) -> None:
        if self._closed:
            raise LocalTaskRuntimeError(
                "qualification_owner:" + str(
                    self._closed_reason or "transport_closed"
                )
            )
        if os.getpid() != self._owner_pid:
            self._refuse("transport_forked")

    def _validate_live_binding(self) -> None:
        self._ensure_owner_process()
        try:
            current_binding = qualification_owner_socket_binding(
                self._socket_binding.advertised_path
            )
        except LocalTaskRuntimeError:
            self._refuse("socket_changed")
        if current_binding != self._socket_binding:
            self._refuse("socket_changed")
        try:
            peer, invocation, identity = _qualification_owner_binding(
                self._client,
                socket_epoch=self._socket_binding.physical_epoch,
                workspace=self._workspace,
                expected_argv_sha256=self._expected_argv_sha256,
            )
            if (
                peer != self._owner_peer
                or invocation != self._owner_invocation
                or identity != self._owner_identity_sha256
            ):
                self._refuse("peer_changed")
        except LocalTaskRuntimeError:
            if not self._closed:
                self._clear_authority("binding_invalid")
            raise

    @property
    def owner_identity_sha256(self) -> str:
        self._ensure_owner_process()
        return self._owner_identity_sha256

    @property
    def owner_invocation(self) -> dict[str, Any]:
        self._ensure_owner_process()
        return deepcopy(self._owner_invocation)

    @property
    def owner_peer(self) -> dict[str, int | None]:
        self._ensure_owner_process()
        return deepcopy(self._owner_peer)

    @property
    def owner_pid(self) -> int:
        self._ensure_owner_process()
        peer_pid = self._owner_peer.get("pid")
        if type(peer_pid) is not int or peer_pid < 1:
            self._refuse("peer_identity_unavailable")
        return peer_pid

    @property
    def app_server_argv_sha256(self) -> str:
        self._ensure_owner_process()
        return self._expected_argv_sha256

    @property
    def cwd(self) -> Path:
        self._ensure_owner_process()
        return self._workspace

    def send(self, message: Mapping[str, Any]) -> None:
        """Send one bounded JSON-RPC message on the sole retained socket."""

        if not isinstance(message, Mapping):
            raise LocalTaskRuntimeError("qualification_owner:message_invalid")
        try:
            payload = _canonical_bytes(dict(message))
        except (TypeError, ValueError, OverflowError, RecursionError) as error:
            raise LocalTaskRuntimeError(
                "qualification_owner:message_invalid"
            ) from error
        if len(payload) > MAX_FRAME_BYTES:
            raise LocalTaskRuntimeError("qualification_owner:message_too_large")
        self._validate_live_binding()
        try:
            self._client.deadline = time.monotonic() + RPC_TIMEOUT_SECONDS
            self._client.socket.settimeout(self._client._remaining())
            self._client._send_frame(0x1, payload)
        except (OSError, LocalTaskRuntimeError) as error:
            self._clear_authority("transport_write_failed")
            raise LocalTaskRuntimeError(
                "qualification_owner:transport_write_failed"
            ) from error
        self._validate_live_binding()

    def receive(self, deadline: float) -> dict[str, Any]:
        """Read one bounded response, preserving an idle timeout as retryable."""

        if (
            type(deadline) not in (int, float)
            or isinstance(deadline, bool)
            or not math.isfinite(float(deadline))
        ):
            raise LocalTaskRuntimeError("qualification_owner:deadline_invalid")
        self._validate_live_binding()
        now = time.monotonic()
        remaining = float(deadline) - now
        if remaining <= 0:
            raise TimeoutError("qualification_owner:receive_timeout")
        if remaining > RETAINED_TRANSPORT_TIMEOUT_SECONDS:
            raise LocalTaskRuntimeError("qualification_owner:deadline_invalid")
        try:
            ready, _write, _errors = select.select(
                [self._client.socket], [], [], remaining
            )
        except (OSError, ValueError) as error:
            self._clear_authority("transport_read_failed")
            raise LocalTaskRuntimeError(
                "qualification_owner:transport_read_failed"
            ) from error
        if not ready:
            raise TimeoutError("qualification_owner:receive_timeout")
        try:
            self._client.deadline = float(deadline)
            value = self._client._message()
        except LocalTaskRuntimeError as error:
            if str(error) == "task_owner:request_timeout":
                raise TimeoutError(
                    "qualification_owner:receive_timeout"
                ) from error
            self._clear_authority("transport_read_failed")
            raise LocalTaskRuntimeError(
                "qualification_owner:transport_read_failed"
            ) from error
        except OSError as error:
            self._clear_authority("transport_read_failed")
            raise LocalTaskRuntimeError(
                "qualification_owner:transport_read_failed"
            ) from error
        self._validate_live_binding()
        return value

    def close(self) -> None:
        """Release the retained descriptor without writing after a fork."""

        if os.getpid() != self._owner_pid:
            self._clear_authority("transport_forked")
            return
        self._clear_authority("transport_closed")


def _clear_retained_owner_transports_after_fork() -> None:
    for transport in tuple(_RETAINED_OWNER_TRANSPORTS):
        transport._clear_authority("transport_forked")


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_clear_retained_owner_transports_after_fork)


def open_retained_qualification_owner_transport(
    socket_path: str | Path,
    cwd: str | Path,
    expected_argv_sha256: str,
) -> _RetainedQualificationOwnerTransport:
    """Open one non-reconnectable qualification-owner WebSocket transport.

    The owner peer must remain the current user, use the supplied workspace,
    and expose the exact sealed app-server argv digest.  The returned object is
    valid only in this process and only while this socket inode and Unix peer
    retain their original binding.
    """

    if _SHA256.fullmatch(str(expected_argv_sha256)) is None:
        raise LocalTaskRuntimeError("qualification_owner:argv_sha256_invalid")
    workspace = _qualification_workspace_path(cwd)
    client: _OwnerClient | None = None
    try:
        path = _owner_socket_path({OWNER_SOCKET_ENV: str(socket_path)})
        binding = qualification_owner_socket_binding(path)
        client = _OwnerClient(
            path,
            deadline=time.monotonic() + RPC_TIMEOUT_SECONDS,
            socket_binding=binding,
        )
        peer, invocation, identity = _qualification_owner_binding(
            client,
            socket_epoch=binding.physical_epoch,
            workspace=workspace,
            expected_argv_sha256=expected_argv_sha256,
        )
        if (
            qualification_owner_socket_binding(path) != binding
            or client.owner_identity_sha256 != identity
            or client.owner_invocation != invocation
            or client.socket_binding != binding
        ):
            raise LocalTaskRuntimeError("qualification_owner:socket_changed")
        return _RetainedQualificationOwnerTransport(
            client=client,
            socket_binding=binding,
            workspace=workspace,
            expected_argv_sha256=expected_argv_sha256,
            owner_peer=peer,
            owner_invocation=invocation,
            owner_identity_sha256=identity,
            _key=_RETAINED_OWNER_TRANSPORT_MINT,
        )
    except LocalTaskRuntimeError as error:
        if client is not None:
            client._abandon()
        message = str(error)
        if message.startswith("qualification_owner:"):
            raise
        raise LocalTaskRuntimeError(
            "qualification_owner:transport_unavailable"
        ) from error
    except (OSError, TypeError, ValueError, OverflowError, RecursionError) as error:
        if client is not None:
            client._abandon()
        raise LocalTaskRuntimeError(
            "qualification_owner:transport_unavailable"
        ) from error


def _hook_inventory_report(
    raw: Any,
    *,
    expected_cwd: Any,
    owner_identity_sha256: Any,
    app_server_argv_sha256: Any,
) -> dict[str, Any]:
    issues: list[str] = []
    rows: list[Mapping[str, Any]] = []
    data = raw.get("data") if isinstance(raw, Mapping) else None
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], Mapping):
        issues.append("hook_inventory:response_invalid")
        entry: Mapping[str, Any] = {}
    else:
        entry = data[0]
    if not isinstance(expected_cwd, str) or entry.get("cwd") != expected_cwd:
        issues.append("hook_inventory:cwd_mismatch")
    if entry.get("errors") != []:
        issues.append("hook_inventory:errors_present")
    if entry.get("warnings") != []:
        issues.append("hook_inventory:warnings_present")
    raw_hooks = entry.get("hooks")
    if isinstance(raw_hooks, list) and all(
        isinstance(item, Mapping) for item in raw_hooks
    ):
        rows = [item for item in raw_hooks if item.get("pluginId") == _PLUGIN_ID]
    else:
        issues.append("hook_inventory:hooks_invalid")

    try:
        expected_source: str | None = str(
            _hook_source_path().resolve(strict=True)
        )
    except OSError:
        expected_source = None
        issues.append("hook_inventory:source_unavailable")
    if _SHA256.fullmatch(str(owner_identity_sha256 or "")) is None:
        owner_identity_sha256 = None
        issues.append("hook_inventory:owner_identity_invalid")
    if _SHA256.fullmatch(str(app_server_argv_sha256 or "")) is None:
        app_server_argv_sha256 = None
        issues.append("hook_inventory:owner_invocation_invalid")
    normalized: list[dict[str, Any]] = []
    for event_name, key_name, matcher in _REQUIRED_HOOKS:
        matches = [row for row in rows if row.get("eventName") == event_name]
        if not matches:
            issues.append(f"hook_inventory:missing:{event_name}")
            continue
        if len(matches) != 1:
            issues.append(f"hook_inventory:duplicate:{event_name}")
            continue
        row = matches[0]
        normalized_row = {
            "event_name": event_name,
            "key": row.get("key"),
            "matcher": row.get("matcher"),
            "enabled": row.get("enabled"),
            "trust_status": row.get("trustStatus"),
            "current_hash": row.get("currentHash"),
        }
        normalized.append(normalized_row)
        if row.get("key") != _hook_key(key_name):
            issues.append(f"hook_inventory:key_invalid:{event_name}")
        if row.get("source") != "plugin":
            issues.append(f"hook_inventory:source_invalid:{event_name}")
        if (
            expected_source is not None
            and row.get("sourcePath") != expected_source
        ):
            issues.append(f"hook_inventory:source_path_invalid:{event_name}")
        if row.get("matcher") != matcher:
            issues.append(f"hook_inventory:matcher_invalid:{event_name}")
        if row.get("enabled") is not True:
            issues.append(f"hook_inventory:disabled:{event_name}")
        if row.get("trustStatus") not in {"trusted", "untrusted", "modified"}:
            issues.append(f"hook_inventory:trust_status_invalid:{event_name}")
        if _HASH.fullmatch(str(row.get("currentHash", ""))) is None:
            issues.append(f"hook_inventory:current_hash_invalid:{event_name}")
    known_events = {event_name for event_name, _, _ in _REQUIRED_HOOKS}
    if any(row.get("eventName") not in known_events for row in rows):
        issues.append("hook_inventory:unexpected_hook")
    issues = sorted(set(issues))
    core = {
        "schema": HOOK_INVENTORY_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "disposition": (
            "OWNER_HOOK_INVENTORY_VERIFIED"
            if not issues
            else "OWNER_HOOK_INVENTORY_BLOCKED"
        ),
        "plugin_id": _PLUGIN_ID,
        "source_path": expected_source,
        "owner_identity_sha256": owner_identity_sha256,
        "app_server_argv_sha256": app_server_argv_sha256,
        "hooks": sorted(normalized, key=lambda item: str(item["event_name"])),
        "issues": issues,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "credential_reads": 0,
        "network_calls": 0,
        "task_creations": 0,
        "native_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}


def _hook_inventory_failure(issue: str) -> dict[str, Any]:
    try:
        source_path: str | None = str(
            _hook_source_path().resolve(strict=True)
        )
    except OSError:
        source_path = None
    core = {
        "schema": HOOK_INVENTORY_SCHEMA,
        "status": "FAIL",
        "disposition": "OWNER_HOOK_INVENTORY_BLOCKED",
        "plugin_id": _PLUGIN_ID,
        "source_path": source_path,
        "owner_identity_sha256": None,
        "app_server_argv_sha256": None,
        "hooks": [],
        "issues": [issue],
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "credential_reads": 0,
        "network_calls": 0,
        "task_creations": 0,
        "native_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}


def observe_qualification_host_hooks(
    *,
    socket_path: str | Path,
    cwd: str | Path,
) -> dict[str, Any]:
    """Observe exact enabled hooks before creating a qualification task."""

    workspace = Path(cwd)
    try:
        if not workspace.is_absolute() or workspace.is_symlink():
            raise LocalTaskRuntimeError("hook_inventory:cwd_unsafe")
        selected_cwd = str(workspace.resolve(strict=True))
        path = _owner_socket_path({OWNER_SOCKET_ENV: str(socket_path)})
        with _OwnerClient(
            path, deadline=time.monotonic() + RPC_TIMEOUT_SECONDS
        ) as client:
            client.request(
                "initialize",
                {
                    "clientInfo": {
                        "name": "orch-dork-qualification-host",
                        "title": "Orch Dork Qualification Host",
                        "version": "1",
                    },
                    "capabilities": {"experimentalApi": True},
                },
            )
            client.notify("initialized", {})
            raw = client.request("hooks/list", {"cwds": [selected_cwd]})
            owner_identity_sha256 = client.owner_identity_sha256
            invocation = dict(client.owner_invocation)
        return _hook_inventory_report(
            raw,
            expected_cwd=selected_cwd,
            owner_identity_sha256=owner_identity_sha256,
            app_server_argv_sha256=invocation.get(
                "app_server_argv_sha256"
            ),
        )
    except LocalTaskRuntimeError as error:
        issue = str(error)
        if not issue.startswith("hook_inventory:"):
            issue = "hook_inventory:owner_unavailable"
        return _hook_inventory_failure(issue)
    except (OSError, TimeoutError, ValueError):
        return _hook_inventory_failure("hook_inventory:owner_unavailable")


def _query_owner(
    path: Path,
    task_id: str,
    *,
    require_hook_inventory: bool = False,
    include_turns: bool = False,
) -> dict[str, Any]:
    try:
        with _OwnerClient(
            path, deadline=time.monotonic() + RPC_TIMEOUT_SECONDS
        ) as client:
            client.request(
                "initialize",
                {
                    "clientInfo": {
                        "name": "orch-dork-local-task-runtime",
                        "title": "Orch Dork Local Task Runtime",
                        "version": "1",
                    },
                    "capabilities": {"experimentalApi": True},
                },
            )
            client.notify("initialized", {})
            read = client.request(
                "thread/read", {"threadId": task_id, "includeTurns": include_turns}
            )
            loaded = client.request("thread/loaded/list", {})
            descendants = client.request(
                "thread/list", {"limit": 100, "parentThreadId": task_id}
            )
            thread = read.get("thread") if isinstance(read, Mapping) else None
            result = {
                "thread": thread,
                "loaded": loaded,
                "descendants": descendants,
                "owner_identity_sha256": client.owner_identity_sha256,
                "owner_invocation": dict(client.owner_invocation),
            }
            if include_turns:
                # Retain only the digest outside this observation. The complete
                # response may also contain private conversational material.
                result["thread_read_sha256"] = _sha256(read)
            if require_hook_inventory:
                cwd = thread.get("cwd") if isinstance(thread, Mapping) else None
                result["hook_inventory"] = (
                    client.request("hooks/list", {"cwds": [cwd]})
                    if isinstance(cwd, str) and cwd
                    else None
                )
            return result
    except LocalTaskRuntimeError:
        raise
    except (OSError, TimeoutError, ValueError) as exc:
        raise LocalTaskRuntimeError("task_owner:transport_unavailable") from exc


def _task_status(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping) and isinstance(value.get("type"), str):
        return value["type"]
    return None


def _runtime_report_from_observed(
    selected_task: str,
    observed: Mapping[str, Any],
    *,
    allowed_statuses: frozenset[str] = frozenset({"active"}),
) -> dict[str, Any]:
    issues: list[str] = []
    thread = observed.get("thread")
    loaded = observed.get("loaded")
    descendants = observed.get("descendants")
    owner_identity = observed.get("owner_identity_sha256")
    task_owner_verified = bool(
        isinstance(thread, Mapping) and thread.get("id") == selected_task
    )
    if not task_owner_verified:
        issues.append("task_owner:thread_not_owned")
    status = _task_status(thread.get("status") if isinstance(thread, Mapping) else None)
    if status not in allowed_statuses:
        issues.append("task_runtime:not_active")
    loaded_ids = loaded.get("data") if isinstance(loaded, Mapping) else None
    task_loaded = bool(
        isinstance(loaded_ids, list)
        and all(isinstance(item, str) for item in loaded_ids)
        and selected_task in loaded_ids
    )
    if not task_loaded:
        issues.append("task_runtime:not_loaded")
    rows = descendants.get("data") if isinstance(descendants, Mapping) else None
    if not isinstance(rows, list) or not all(isinstance(item, Mapping) for item in rows):
        rows = []
        issues.append("task_runtime:descendant_inventory_invalid")
    if isinstance(descendants, Mapping) and descendants.get("nextCursor") is not None:
        issues.append("task_runtime:descendant_inventory_incomplete")
    if rows:
        issues.append("task_runtime:descendants_present")
    if not (
        isinstance(owner_identity, str)
        and len(owner_identity) == 64
        and all(character in "0123456789abcdef" for character in owner_identity)
    ):
        owner_identity = None
        issues.append("task_owner:identity_invalid")

    return _report(
        status="PASS" if not issues else "FAIL",
        disposition=(
            "CURRENT_TASK_RUNTIME_VERIFIED"
            if not issues
            else "CURRENT_TASK_RUNTIME_BLOCKED"
        ),
        task_owner_verified=task_owner_verified,
        task_loaded=task_loaded,
        task_status=status,
        descendant_count=len(rows),
        owner_identity_sha256=owner_identity,
        issues=sorted(set(issues)),
    )


def _observe(
    *,
    task_id: str | None,
    require_task_id: bool,
    include_hook_inventory: bool = False,
    allowed_statuses: frozenset[str] = frozenset({"active"}),
    env: MutableMapping[str, str] | Mapping[str, str] | None,
) -> tuple[str | None, Mapping[str, Any] | None, dict[str, Any]]:
    selected_env = os.environ if env is None else env
    selected_task = task_id
    if selected_task is None and not require_task_id:
        selected_task = selected_env.get("CODEX_THREAD_ID") or selected_env.get(
            "CODEX_SESSION_ID"
        )
    if not isinstance(selected_task, str) or not selected_task or len(selected_task) > 128:
        report = _failure(
            "task_owner:mcp_task_id_missing"
            if require_task_id
            else "task_owner:task_id_unavailable"
        )
        return None, None, report
    try:
        path = _owner_socket_path(selected_env)
        if include_hook_inventory:
            observed = _query_owner(
                path,
                selected_task,
                require_hook_inventory=True,
            )
        else:
            observed = _query_owner(path, selected_task)
    except LocalTaskRuntimeError as exc:
        issue = str(exc)
        if not issue.startswith("task_owner:"):
            issue = "task_owner:observation_failed"
        return selected_task, None, _failure(issue)
    if not isinstance(observed, Mapping):
        return selected_task, None, _failure("task_owner:observation_failed")
    return (
        selected_task,
        observed,
        _runtime_report_from_observed(
            selected_task,
            observed,
            allowed_statuses=allowed_statuses,
        ),
    )


def observe_current_local_task_runtime(
    *,
    task_id: str | None = None,
    require_task_id: bool = False,
    env: MutableMapping[str, str] | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify current-task ownership and zero descendants without fallback."""

    return _observe(
        task_id=task_id,
        require_task_id=require_task_id,
        env=env,
    )[2]


def observe_local_task_pre_turn_runtime(
    *,
    task_id: str,
    env: MutableMapping[str, str] | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify an owner-bound loaded task is idle before its first turn."""

    return _observe(
        task_id=task_id,
        require_task_id=True,
        allowed_statuses=frozenset({"idle"}),
        env=env,
    )[2]


def _mcp_expectation(value: Any) -> dict[str, Any]:
    from lifecycle_conformance.host_adapter import decode_response

    fields = {"task_id", "turn_id", "tool_call_id", "owner_identity_sha256", "app_server_argv_sha256",
              "hook_inventory_report_sha256",
              "server", "tool", "arguments", "structured_result"}
    try:
        value = decode_response(value)
        if (set(value) != fields
                or any(type(value[key]) is not str or not value[key].strip()
                       for key in fields - {"arguments", "structured_result"})
                or any(_SHA256.fullmatch(value[key]) is None
                       for key in ("owner_identity_sha256", "app_server_argv_sha256", "hook_inventory_report_sha256"))
                or len(value["task_id"]) > 128
                or type(value["arguments"]) is not dict or type(value["structured_result"]) is not dict):
            raise ValueError("invalid expectation")
        return value
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        raise LocalTaskRuntimeError("mcp_observation:expectation_invalid") from error


def _completed_mcp_observation(expected: dict[str, Any], observed: Any) -> dict[str, Any] | None:
    from lifecycle_conformance.host_adapter import canonical_bytes, completed_mcp_tool_call

    try:
        thread = observed["thread"]
        invocation = observed["owner_invocation"]
        if (type(thread) is not dict or thread.get("id") != expected["task_id"]
                or thread.get("sessionId") != expected["task_id"] or "parentThreadId" not in thread
                or thread["parentThreadId"] is not None
                or _task_status(thread.get("status")) != "active"
                or type(observed["loaded"]) is not dict or type(observed["loaded"].get("data")) is not list
                or any(type(item) is not str for item in observed["loaded"]["data"])
                or expected["task_id"] not in observed["loaded"]["data"]
                or observed["owner_identity_sha256"] != expected["owner_identity_sha256"]
                or type(invocation) is not dict or invocation.get("status") != "PASS"
                or invocation.get("mode") != "one_invocation_bypass" or invocation.get("issues") != []
                or invocation.get("app_server_argv_sha256") != expected["app_server_argv_sha256"]):
            raise LocalTaskRuntimeError("mcp_observation:owner_mismatch")
        if thread.get("modelProvider") != "openai":
            raise LocalTaskRuntimeError("mcp_observation:route_mismatch")
        hooks = _hook_inventory_report(
            observed.get("hook_inventory"), expected_cwd=thread.get("cwd"),
            owner_identity_sha256=observed["owner_identity_sha256"],
            app_server_argv_sha256=invocation["app_server_argv_sha256"])
        if hooks["status"] != "PASS" or hooks["report_sha256"] != expected["hook_inventory_report_sha256"]:
            raise LocalTaskRuntimeError("mcp_observation:hooks_unavailable")
        turns = thread.get("turns")
        if (type(turns) is not list or not turns or any(type(turn) is not dict for turn in turns)
                or any(type(turn.get("id")) is not str or not turn["id"] for turn in turns)
                or len({turn["id"] for turn in turns}) != len(turns)
                or any(turn.get("itemsView") != "full" for turn in turns)
                or any(type(turn.get("items")) is not list for turn in turns)
                or any(type(item) is not dict for turn in turns for item in turn["items"])
                or any(type(item.get("id")) is not str or not item["id"]
                       for turn in turns for item in turn["items"] if item.get("type") == "mcpToolCall")):
            raise LocalTaskRuntimeError("mcp_observation:turn_inventory_invalid")
        candidates = [(turn, item) for turn in turns for item in turn["items"]
                      if item.get("type") == "mcpToolCall" and item.get("id") == expected["tool_call_id"]]
        if not candidates:
            return None
        if len(candidates) != 1:
            raise LocalTaskRuntimeError("mcp_observation:call_ambiguous")
        turn, raw = candidates[0]
        if (turn["id"] != expected["turn_id"]
                or turn.get("status") not in {"inProgress", "completed", "interrupted", "failed"}):
            raise LocalTaskRuntimeError("mcp_observation:turn_mismatch")
        call = completed_mcp_tool_call(raw)
        if (call["pluginId"] != _PLUGIN_ID or call["server"] != expected["server"] or call["tool"] != expected["tool"]
                or canonical_bytes(call["arguments"]) != canonical_bytes(expected["arguments"])
                or canonical_bytes(call["result"]["structuredContent"]) != canonical_bytes(expected["structured_result"])):
            raise LocalTaskRuntimeError("mcp_observation:result_mismatch")
        if type(observed.get("thread_read_sha256")) is not str or _SHA256.fullmatch(observed["thread_read_sha256"]) is None:
            raise LocalTaskRuntimeError("mcp_observation:source_digest_invalid")
        return {
            "task_id": thread["id"], "turn_id": turn["id"], "model_provider": thread["modelProvider"],
            "owner_identity_sha256": observed["owner_identity_sha256"],
            "app_server_argv_sha256": invocation["app_server_argv_sha256"],
            "hook_inventory_report": hooks, "call": call, "thread_read_sha256": observed["thread_read_sha256"],
        }
    except LocalTaskRuntimeError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        raise LocalTaskRuntimeError("mcp_observation:source_invalid") from error


def observe_current_local_task_mcp_call(
    expectation: Any, *, env: MutableMapping[str, str] | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Read one completed call from the pinned owner while its root is active.

    Select the exact native call and turn IDs. Model and effort provenance must
    come from native call metadata in the reconciled host acknowledgement;
    current thread configuration cannot attest a historical turn. Missing calls remain pending. This
    observer never parses conversational prose, changes authority, or launches
    a model. Its public seal is transport integrity, not a signing authority.
    """
    expected = _mcp_expectation(expectation)
    observation = None
    try:
        path = _owner_socket_path(os.environ if env is None else env)
        observed = _query_owner(path, expected["task_id"], require_hook_inventory=True, include_turns=True)
        observation = _completed_mcp_observation(expected, observed)
        status = "OBSERVED" if observation is not None else "PENDING"
        issues = [] if observation is not None else ["mcp_observation:awaiting_completed_call"]
    except (LocalTaskRuntimeError, OSError, ValueError) as error:
        status = "REFUSED"
        code = str(error)
        issues = [code if code.startswith("mcp_observation:") else "mcp_observation:owner_unavailable"]
    core = {
        "schema": MCP_CALL_SCHEMA, "status": status, "issues": issues, "expectation": expected,
        "observation": observation, "provider_free": True, "model_calls": 0, "hosted_calls": 0,
        "credential_reads": 0, "network_calls": 0, "task_creations": 0, "native_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}


def validate_current_local_task_mcp_observation(report: Any) -> dict[str, Any]:
    """Validate a whole observation's transport; do not attest caller custody.

    Semantic authority must call the owner observer itself. This validator is
    for replaying retained reports without a second, different owner read.
    """
    from lifecycle_conformance.host_adapter import canonical_bytes, completed_mcp_tool_call, decode_response

    counters = {"model_calls", "hosted_calls", "credential_reads", "network_calls", "task_creations", "native_calls"}
    fields = {"schema", "status", "issues", "expectation", "observation", "provider_free", "report_sha256", *counters}
    refusals = {
        "mcp_observation:owner_mismatch", "mcp_observation:route_mismatch", "mcp_observation:hooks_unavailable",
        "mcp_observation:turn_inventory_invalid", "mcp_observation:call_ambiguous", "mcp_observation:turn_mismatch",
        "mcp_observation:result_mismatch", "mcp_observation:source_digest_invalid", "mcp_observation:source_invalid",
        "mcp_observation:owner_unavailable",
    }
    try:
        value = decode_response(report)
        if (set(value) != fields or value["schema"] != MCP_CALL_SCHEMA or value["provider_free"] is not True
                or any(type(value[key]) is not int or value[key] != 0 for key in counters)
                or value["report_sha256"] != _sha256({k: v for k, v in value.items() if k != "report_sha256"})):
            raise ValueError("invalid observation report")
        expected = _mcp_expectation(value["expectation"])
        observation = value["observation"]
        if value["status"] == "OBSERVED":
            if (value["issues"] != [] or type(observation) is not dict or set(observation) != {
                    "task_id", "turn_id", "model_provider", "owner_identity_sha256", "app_server_argv_sha256",
                    "hook_inventory_report", "call", "thread_read_sha256"}
                    or observation["model_provider"] != "openai"
                    or any(observation[key] != expected[key] for key in (
                        "task_id", "turn_id", "owner_identity_sha256", "app_server_argv_sha256"))
                    or type(observation["thread_read_sha256"]) is not str
                    or _SHA256.fullmatch(observation["thread_read_sha256"]) is None):
                raise ValueError("invalid observed facts")
            hooks = OwnerHookInventoryArtifact.from_report(
                observation["hook_inventory_report"])
            if (hooks.report_sha256 != expected["hook_inventory_report_sha256"]
                    or hooks.owner_identity_sha256 != expected["owner_identity_sha256"]
                    or hooks.app_server_argv_sha256 != expected["app_server_argv_sha256"]
                    or any(type(hooks.report[key]) is not int
                           or hooks.report[key] != 0 for key in counters)):
                raise ValueError("invalid observed hooks")
            call = completed_mcp_tool_call(observation["call"])
            if (call["id"] != expected["tool_call_id"] or call["server"] != expected["server"]
                    or call["tool"] != expected["tool"] or call["pluginId"] != _PLUGIN_ID
                    or canonical_bytes(call["arguments"]) != canonical_bytes(expected["arguments"])
                    or canonical_bytes(call["result"]["structuredContent"]) != canonical_bytes(expected["structured_result"])):
                raise ValueError("invalid observed call")
        elif value["status"] == "PENDING":
            if observation is not None or value["issues"] != ["mcp_observation:awaiting_completed_call"]:
                raise ValueError("invalid pending observation")
        elif value["status"] == "REFUSED":
            if (observation is not None or type(value["issues"]) is not list or len(value["issues"]) != 1
                    or type(value["issues"][0]) is not str or value["issues"][0] not in refusals):
                raise ValueError("invalid refused observation")
        else:
            raise ValueError("invalid observation status")
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        return {"valid": False, "issues": ["mcp_observation:report_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport", "report_sha256": value["report_sha256"]}


def _attempt_source_expectation(value: Any) -> dict[str, Any]:
    fields = {"root_task_id", "worker_ids", "owner_identity_sha256", "app_server_argv_sha256", "hook_inventory_report_sha256"}
    if (type(value) is not dict or set(value) != fields or type(value["worker_ids"]) is not dict
            or set(value["worker_ids"]) != {"spec", "standards"}
            or any(type(value[key]) is not str or _SHA256.fullmatch(value[key]) is None
                   for key in fields - {"root_task_id", "worker_ids"})):
        raise LocalTaskRuntimeError("attempt_sources:expectation_invalid")
    ids = [value["root_task_id"], *value["worker_ids"].values()]
    if any(type(item) is not str or not 0 < len(item) <= 128 for item in ids) or len(set(ids)) != 3:
        raise LocalTaskRuntimeError("attempt_sources:expectation_invalid")
    return deepcopy(value)


def _attempt_source_membership(expected: dict[str, Any], sources: Any) -> None:
    from lifecycle_conformance.host_adapter import validate_native_v1_thread_source

    if type(sources) is not dict or set(sources) != {"root", "spec", "standards"}:
        raise LocalTaskRuntimeError("attempt_sources:inventory_invalid")
    for role, task in {"root": expected["root_task_id"], **expected["worker_ids"]}.items():
        source = sources[role]
        if type(source) is not dict:
            raise LocalTaskRuntimeError("attempt_sources:inventory_invalid")
        digest = source.get("thread_read_sha256")
        projection = {key: item for key, item in source.items() if key != "thread_read_sha256"}
        if (type(digest) is not str or _SHA256.fullmatch(digest) is None
                or not validate_native_v1_thread_source(projection)["valid"]
                or source["task_id"] != task
                or source["parent_thread_id"] != (None if role == "root" else expected["root_task_id"])):
            raise LocalTaskRuntimeError("attempt_sources:inventory_invalid")
    if len({source["path"] for source in sources.values()}) != 3:
        raise LocalTaskRuntimeError("attempt_sources:inventory_invalid")


def _attempt_owner_identity(expected: dict[str, Any], client: _OwnerClient) -> None:
    invocation = client.owner_invocation
    if (client.owner_identity_sha256 != expected["owner_identity_sha256"]
            or type(invocation) is not dict or invocation.get("status") != "PASS"
            or invocation.get("mode") != "one_invocation_bypass" or invocation.get("issues") != []
            or invocation.get("app_server_argv_sha256") != expected["app_server_argv_sha256"]):
        raise LocalTaskRuntimeError("attempt_sources:owner_mismatch")


def _checkpoint_source_expectation(value: Any) -> dict[str, Any]:
    if (type(value) is not dict or set(value) != {"owner", "root_turn_id", "worker_turn_ids"}
            or type(value["worker_turn_ids"]) is not dict or set(value["worker_turn_ids"]) != {"spec", "standards"}):
        raise LocalTaskRuntimeError("attempt_sources:expectation_invalid")
    _attempt_source_expectation(value["owner"])
    turns = [value["root_turn_id"], *value["worker_turn_ids"].values()]
    if any(type(turn) is not str or not 0 < len(turn) <= 128 for turn in turns) or len(set(turns)) != 3:
        raise LocalTaskRuntimeError("attempt_sources:expectation_invalid")
    return deepcopy(value)


def _attempt_source_readiness(sources: dict[str, Any], checkpoint: dict[str, Any] | None,
                              *, worker_turn_count: int = 2) -> None:
    if type(worker_turn_count) is not int or worker_turn_count not in (2, 3):
        raise LocalTaskRuntimeError("attempt_sources:inventory_invalid")
    if checkpoint is None:
        if (sources["root"]["status"] != "idle" or any(source["status"] == "active"
                or any(turn["status"] == "inProgress" for turn in source["turns"]) for source in sources.values())):
            raise LocalTaskRuntimeError("attempt_sources:awaiting_completed_turns")
        return
    root = sources["root"]
    if (root["status"] != "active" or root["turns"][-1] != {"id": checkpoint["root_turn_id"], "status": "inProgress"}
            or any(turn["status"] != "completed" for turn in root["turns"][:-1])):
        raise LocalTaskRuntimeError("attempt_sources:checkpoint_turn_mismatch")
    pending = False
    for lane in ("spec", "standards"):
        source = sources[lane]
        turns = source["turns"]
        if (len(turns) > worker_turn_count or any(turn["status"] in {"failed", "interrupted"} for turn in turns)
                or len(turns) == worker_turn_count and turns[-1]["id"] != checkpoint["worker_turn_ids"][lane]
                or len(turns) < worker_turn_count and any(turn["id"] == checkpoint["worker_turn_ids"][lane] for turn in turns)):
            raise LocalTaskRuntimeError("attempt_sources:checkpoint_turn_mismatch")
        pending |= len(turns) != worker_turn_count or source["status"] == "active" or any(turn["status"] == "inProgress" for turn in turns)
    if pending:
        raise LocalTaskRuntimeError("attempt_sources:awaiting_completed_turns")


def _checkpoint_arrival_sets(
    sources: dict[str, Any], checkpoint: dict[str, Any], *, worker_turn_count: int = 2,
) -> tuple[list[str], list[str]]:
    if type(worker_turn_count) is not int or worker_turn_count not in (2, 3):
        raise LocalTaskRuntimeError("attempt_sources:inventory_invalid")
    root = sources["root"]
    if (root["status"] != "active"
            or root["turns"][-1] != {"id": checkpoint["root_turn_id"], "status": "inProgress"}
            or any(turn["status"] != "completed" for turn in root["turns"][:-1])):
        raise LocalTaskRuntimeError("attempt_sources:checkpoint_turn_mismatch")
    completed, pending = [], []
    for lane in ("spec", "standards"):
        source = sources[lane]
        turns = source["turns"]
        selected_turn = checkpoint["worker_turn_ids"][lane]
        if (len(turns) > worker_turn_count
                or any(turn["status"] in {"failed", "interrupted"} for turn in turns)
                or len(turns) == worker_turn_count
                and turns[-1]["id"] != selected_turn
                or len(turns) < worker_turn_count
                and any(turn["id"] == selected_turn for turn in turns)):
            raise LocalTaskRuntimeError("attempt_sources:checkpoint_turn_mismatch")
        if (len(turns) == worker_turn_count
                and turns[-1]["status"] == "completed"):
            if source["status"] == "active" or any(turn["status"] != "completed" for turn in turns):
                raise LocalTaskRuntimeError("attempt_sources:checkpoint_turn_mismatch")
            completed.append(lane)
        else:
            if (len(turns) < worker_turn_count
                    and any(turn["status"] != "completed" for turn in turns)
                    or len(turns) == worker_turn_count
                    and (any(turn["status"] != "completed" for turn in turns[:-1])
                         or turns[-1]["status"] != "inProgress"
                         or source["status"] != "active")):
                raise LocalTaskRuntimeError("attempt_sources:checkpoint_turn_mismatch")
            pending.append(lane)
    return completed, pending


def _attempt_source_inventory_snapshot(expected: dict[str, Any], client: _OwnerClient) -> dict[str, Any]:
    from lifecycle_conformance.host_adapter import native_v1_thread_source

    _attempt_owner_identity(expected, client)
    sources = {}
    for role, task in {"root": expected["root_task_id"], **expected["worker_ids"]}.items():
        read = client.request("thread/read", {"threadId": task, "includeTurns": True})
        sources[role] = {**native_v1_thread_source(read), "thread_read_sha256": _sha256(read)}
    _attempt_source_membership(expected, sources)
    loaded = client.request("thread/loaded/list", {})
    if (type(loaded) is not dict or type(loaded.get("data")) is not list
            or len(loaded["data"]) > 256 or loaded.get("nextCursor") is not None
            or any(type(task) is not str for task in loaded["data"])
            or len(set(loaded["data"])) != len(loaded["data"])
            or expected["root_task_id"] not in loaded["data"]):
        raise LocalTaskRuntimeError("attempt_sources:owner_mismatch")
    for source in sources.values():
        if (source["task_id"] in loaded["data"]) != (source["status"] != "notLoaded"):
            raise LocalTaskRuntimeError("attempt_sources:inventory_invalid")
    hooks = _hook_inventory_report(
        client.request("hooks/list", {"cwds": [sources["root"]["cwd"]]}),
        expected_cwd=sources["root"]["cwd"], owner_identity_sha256=expected["owner_identity_sha256"],
        app_server_argv_sha256=expected["app_server_argv_sha256"])
    if hooks["status"] != "PASS" or hooks["report_sha256"] != expected["hook_inventory_report_sha256"]:
        raise LocalTaskRuntimeError("attempt_sources:hooks_unavailable")
    return {"sources": sources, "hook_inventory_report": hooks, "read_passes": 2}


def _attempt_source_snapshot(expected: dict[str, Any], client: _OwnerClient,
                             checkpoint: dict[str, Any] | None = None, *, worker_turn_count: int = 2) -> dict[str, Any]:
    observation = _attempt_source_inventory_snapshot(expected, client)
    sources = observation["sources"]
    _attempt_source_readiness(sources, checkpoint, worker_turn_count=worker_turn_count)
    return observation


def _checkpoint_arrival_source_snapshot(
    expected: dict[str, Any], client: _OwnerClient, checkpoint: dict[str, Any],
    *, worker_turn_count: int = 2,
) -> dict[str, Any]:
    observation = _attempt_source_inventory_snapshot(expected, client)
    completed, pending = _checkpoint_arrival_sets(
        observation["sources"], checkpoint,
        worker_turn_count=worker_turn_count,
    )
    return {**observation, "completed_lane_ids": completed, "pending_lane_ids": pending}


def observe_completed_attempt_sources(
    expectation: Any, *, env: MutableMapping[str, str] | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Discover the exact root/two-lane source paths from one pinned owner.

    This host-side observation runs after the root becomes idle. Two identical
    bounded reads attest source discovery at that point, not rollout custody,
    historical model routing, descendant cleanup or final qualification. Only
    the fixed injected owner socket is consulted. No tasks or turns are created.
    """
    return _observe_attempt_sources(_attempt_source_expectation(expectation), env=env)


def observe_worker_checkpoint_sources(
    expectation: Any, *, env: MutableMapping[str, str] | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Discover two yielded checkpoint sources while the exact root turn is active.

    Continuation IDs must come from the controller's retained native results.
    This observation authenticates source selection only; a separate owned read
    must validate the actual raw checkpoints and usage before admission.
    """
    selected = _checkpoint_source_expectation(expectation)
    return _observe_attempt_sources(selected["owner"], checkpoint=selected, env=env)


def observe_worker_checkpoint_arrival_sources(
    expectation: Any, *, env: MutableMapping[str, str] | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Observe a stable zero, one or two-lane checkpoint source frontier.

    The caller supplies both controller-retained continuation IDs together;
    it cannot select or suppress a lane. This authenticates owner-bound source
    selection only. Raw checkpoint custody, worker execution and every
    controller, grant, progress, continuation or terminal authority remain
    outside this report.
    """
    selected = _checkpoint_source_expectation(expectation)
    return _observe_attempt_sources(
        selected["owner"], checkpoint=selected, checkpoint_arrivals=True, env=env)


def observe_worker_final_sources(
    expectation: Any, *, env: MutableMapping[str, str] | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Discover yielded third turns while the selected coordinator turn is active.

    Final continuation IDs must come from retained controller results. This
    proves source selection only; readers must still check checkpoint custody,
    typed handoffs and usage. It grants no cleanup, release or qualification.
    """
    selected = _checkpoint_source_expectation(expectation)
    return _observe_attempt_sources(selected["owner"], checkpoint=selected, worker_turn_count=3, env=env)


def observe_worker_final_arrival_sources(
    expectation: Any, *, env: MutableMapping[str, str] | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Observe a stable zero, one or two-lane third-turn source frontier.

    Both controller-retained final continuation IDs remain mandatory. The
    caller cannot select a lane, and the report grants no raw custody or
    controller authority.
    """
    selected = _checkpoint_source_expectation(expectation)
    return _observe_attempt_sources(
        selected["owner"], checkpoint=selected, worker_turn_count=3,
        checkpoint_arrivals=True, env=env,
    )


def _attempt_sources_schema(checkpoint: bool, worker_turn_count: int) -> str:
    if (type(checkpoint) is not bool or type(worker_turn_count) is not int
            or worker_turn_count not in (2, 3) or not checkpoint and worker_turn_count != 2):
        raise LocalTaskRuntimeError("attempt_sources:inventory_invalid")
    return (WORKER_FINAL_SOURCES_SCHEMA if worker_turn_count == 3 else CHECKPOINT_SOURCES_SCHEMA) if checkpoint else ATTEMPT_SOURCES_SCHEMA


def _observe_attempt_sources(expected: dict[str, Any], *, checkpoint: dict[str, Any] | None = None,
                             worker_turn_count: int = 2, checkpoint_arrivals: bool = False,
                             env: MutableMapping[str, str] | Mapping[str, str] | None = None) -> dict[str, Any]:
    from lifecycle_conformance.host_adapter import decode_bounded_response

    if checkpoint_arrivals and (
            checkpoint is None or worker_turn_count not in (2, 3)):
        raise LocalTaskRuntimeError("attempt_sources:inventory_invalid")
    schema = ((WORKER_FINAL_ARRIVAL_SOURCES_SCHEMA
               if worker_turn_count == 3
               else _CHECKPOINT_ARRIVAL_SOURCES_SCHEMA)
              if checkpoint_arrivals
              else _attempt_sources_schema(checkpoint is not None, worker_turn_count))
    observation = None
    try:
        path = _owner_socket_path(os.environ if env is None else env)
        epoch = _socket_epoch(path)
        with _OwnerClient(path, deadline=time.monotonic() + RPC_TIMEOUT_SECONDS) as client:
            _attempt_owner_identity(expected, client)
            client.request("initialize", {"clientInfo": {"name": "orch-dork-attempt-sources", "version": "1"},
                                          "capabilities": {"experimentalApi": True}})
            client.notify("initialized", {})
            if checkpoint_arrivals:
                first = _checkpoint_arrival_source_snapshot(
                    expected, client, checkpoint,
                    worker_turn_count=worker_turn_count,
                )
                second = _checkpoint_arrival_source_snapshot(
                    expected, client, checkpoint,
                    worker_turn_count=worker_turn_count,
                )
            else:
                first = _attempt_source_snapshot(expected, client, checkpoint, worker_turn_count=worker_turn_count)
                second = _attempt_source_snapshot(expected, client, checkpoint, worker_turn_count=worker_turn_count)
            if first != second:
                raise LocalTaskRuntimeError("attempt_sources:snapshot_changed")
            live_invocation = _inspect_peer_invocation(client._peer_identity(client.socket))
            if live_invocation != client.owner_invocation or epoch != _socket_epoch(path):
                raise LocalTaskRuntimeError("attempt_sources:owner_changed")
            _attempt_owner_identity(expected, client)
            observation = first
            if checkpoint_arrivals and observation["completed_lane_ids"] == []:
                raise LocalTaskRuntimeError("attempt_sources:awaiting_completed_turns")
        status, issues = "OBSERVED", []
    except (LocalTaskRuntimeError, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        observation = None
        code = str(error)
        if not code.startswith("attempt_sources:"):
            code = "attempt_sources:source_unavailable"
        status = "PENDING" if code == "attempt_sources:awaiting_completed_turns" else "REFUSED"
        issues = [code]
    core = {"schema": schema,
            "status": status, "issues": issues, "expectation": checkpoint if checkpoint is not None else expected,
            "observation": observation, "provider_free": True, "model_calls": 0, "hosted_calls": 0,
            "credential_reads": 0, "network_calls": 0, "task_creations": 0, "native_calls": 0}
    if checkpoint_arrivals:
        core.update(
            scope="owner_authenticated_source_selection",
            retained_owner_authentication=False,
            chronology_attested=False,
            capture_authenticated=False,
            host_execution_custody=False,
            controller_continuation_authorized=False,
            raw_checkpoint_custody=False,
            controller_authority=False,
            grant_authority=False,
            progress_authority=False,
            continuation_permitted=False,
            terminal_claim_permitted=False,
            execution_attested=False,
            complete_campaign=False,
            release_authorized=False,
            qualification_authorized=False,
        )
    try:
        # Individually bounded sources can still exceed the combined report
        # limit. Keep producer/validator closure without raising that limit.
        decode_bounded_response({**core, "report_sha256": "0" * 64})
    except (ValueError, TypeError, RecursionError):
        core.update(status="REFUSED", issues=["attempt_sources:report_bounds"], observation=None)
    return {**core, "report_sha256": _sha256(core)}


def validate_completed_attempt_sources(report: Any) -> dict[str, Any]:
    """Validate retained transport only; final authority invokes its producer."""
    return _validate_attempt_sources(report, checkpoint=False)


def validate_worker_checkpoint_sources(report: Any) -> dict[str, Any]:
    """Validate checkpoint source transport without authenticating live custody."""
    return _validate_attempt_sources(report, checkpoint=True)


def validate_worker_checkpoint_arrival_sources(report: Any) -> dict[str, Any]:
    """Validate retained arrival transport without authenticating live custody."""
    return _validate_attempt_sources(report, checkpoint=True, checkpoint_arrivals=True)


def validate_worker_final_sources(report: Any) -> dict[str, Any]:
    """Validate third-turn source transport without granting current custody."""
    return _validate_attempt_sources(report, checkpoint=True, worker_turn_count=3)


def validate_worker_final_arrival_sources(report: Any) -> dict[str, Any]:
    """Validate retained third-turn frontier transport without live custody."""
    return _validate_attempt_sources(
        report, checkpoint=True, worker_turn_count=3,
        checkpoint_arrivals=True,
    )


def _validate_attempt_sources(report: Any, *, checkpoint: bool, worker_turn_count: int = 2,
                              checkpoint_arrivals: bool = False) -> dict[str, Any]:
    from lifecycle_conformance.host_adapter import decode_bounded_response

    counters = {"model_calls", "hosted_calls", "credential_reads", "network_calls", "task_creations", "native_calls"}
    arrival_fields = {"scope", "retained_owner_authentication", "chronology_attested",
                      "capture_authenticated", "host_execution_custody",
                      "controller_continuation_authorized", "raw_checkpoint_custody",
                      "controller_authority", "grant_authority", "progress_authority",
                      "continuation_permitted", "terminal_claim_permitted", "execution_attested",
                      "complete_campaign", "release_authorized", "qualification_authorized"}
    try:
        value = decode_bounded_response(report)
        if checkpoint_arrivals and (
                not checkpoint or worker_turn_count not in (2, 3)):
            raise ValueError("invalid arrival mode")
        fields = {"schema", "status", "issues", "expectation", "observation", "provider_free", "report_sha256", *counters}
        if checkpoint_arrivals:
            fields |= arrival_fields
        if (set(value) != fields
                or value["schema"] != ((WORKER_FINAL_ARRIVAL_SOURCES_SCHEMA
                                         if worker_turn_count == 3
                                         else _CHECKPOINT_ARRIVAL_SOURCES_SCHEMA)
                                        if checkpoint_arrivals
                                       else _attempt_sources_schema(checkpoint, worker_turn_count))
                or value["provider_free"] is not True
                or any(type(value[key]) is not int or value[key] != 0 for key in counters)
                or value["report_sha256"] != _sha256({k: v for k, v in value.items() if k != "report_sha256"})):
            raise ValueError("invalid report")
        if checkpoint_arrivals and (
                value["scope"] != "owner_authenticated_source_selection"
                or any(value[key] is not False for key in arrival_fields - {"scope"})):
            raise ValueError("invalid authority boundary")
        selected = _checkpoint_source_expectation(value["expectation"]) if checkpoint else None
        expected = selected["owner"] if selected is not None else _attempt_source_expectation(value["expectation"])
        observation = value["observation"]
        if value["status"] == "OBSERVED":
            if (value["issues"] != [] or type(observation) is not dict
                    or set(observation) != ({"sources", "hook_inventory_report", "read_passes",
                                             "completed_lane_ids", "pending_lane_ids"}
                                            if checkpoint_arrivals else
                                            {"sources", "hook_inventory_report", "read_passes"})
                    or type(observation["read_passes"]) is not int or observation["read_passes"] != 2):
                raise ValueError("invalid observed source inventory")
            _attempt_source_membership(expected, observation["sources"])
            sources = observation["sources"]
            if checkpoint_arrivals:
                completed, pending = _checkpoint_arrival_sets(
                    sources, selected, worker_turn_count=worker_turn_count)
                if (completed == [] or observation["completed_lane_ids"] != completed
                        or observation["pending_lane_ids"] != pending):
                    raise ValueError("invalid arrival sets")
            else:
                _attempt_source_readiness(sources, selected, worker_turn_count=worker_turn_count)
            hooks = _retained_hook_inventory_report(
                observation["hook_inventory_report"])
            if (hooks["report_sha256"] != expected["hook_inventory_report_sha256"]
                    or hooks["owner_identity_sha256"] != expected["owner_identity_sha256"]
                    or hooks["app_server_argv_sha256"] != expected["app_server_argv_sha256"]
                    or any(type(hooks[key]) is not int or hooks[key] != 0
                           for key in counters)):
                raise ValueError("invalid hooks")
        elif value["status"] == "PENDING":
            if observation is not None or value["issues"] != ["attempt_sources:awaiting_completed_turns"]:
                raise ValueError("invalid pending observation")
        elif value["status"] == "REFUSED":
            if (observation is not None or type(value["issues"]) is not list or len(value["issues"]) != 1
                    or value["issues"][0] not in (
                        "attempt_sources:inventory_invalid", "attempt_sources:owner_mismatch",
                        "attempt_sources:hooks_unavailable", "attempt_sources:snapshot_changed",
                        "attempt_sources:owner_changed", "attempt_sources:source_unavailable", "attempt_sources:report_bounds",
                        *(["attempt_sources:checkpoint_turn_mismatch"] if checkpoint else []))):
                raise ValueError("invalid refusal")
        else:
            raise ValueError("invalid status")
    except (KeyError, ValueError, TypeError, RecursionError, OverflowError):
        return {"valid": False, "issues": ["attempt_sources:report_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport", "report_sha256": value["report_sha256"]}


def observe_current_local_task_hook_trust(
    *,
    task_id: str | None = None,
    env: MutableMapping[str, str] | Mapping[str, str] | None = None,
    allow_pre_turn_idle: bool = False,
) -> dict[str, Any]:
    """Attest one exact owner-bound app-server hook-trust bypass."""

    selected_task, observed, runtime_report = _observe(
        task_id=task_id,
        require_task_id=True,
        include_hook_inventory=True,
        allowed_statuses=(
            frozenset({"active", "idle"})
            if allow_pre_turn_idle
            else frozenset({"active"})
        ),
        env=env,
    )
    invocation = (
        observed.get("owner_invocation")
        if isinstance(observed, Mapping)
        and isinstance(observed.get("owner_invocation"), Mapping)
        else {}
    )
    invocation_issues = invocation.get("issues")
    issues = list(runtime_report.get("issues", []))
    thread = observed.get("thread") if isinstance(observed, Mapping) else None
    hook_inventory_report = _hook_inventory_report(
        observed.get("hook_inventory") if isinstance(observed, Mapping) else None,
        expected_cwd=(thread.get("cwd") if isinstance(thread, Mapping) else None),
        owner_identity_sha256=observed.get("owner_identity_sha256")
        if isinstance(observed, Mapping)
        else None,
        app_server_argv_sha256=invocation.get(
            "app_server_argv_sha256"
        ),
    )
    issues.extend(hook_inventory_report["issues"])
    if invocation.get("status") != "PASS":
        if isinstance(invocation_issues, list) and all(
            isinstance(item, str) and item.startswith("hook_trust:")
            for item in invocation_issues
        ):
            issues.extend(invocation_issues)
        else:
            issues.append("hook_trust:owner_invocation_unavailable")
    mode = invocation.get("mode")
    argv_sha256 = invocation.get("app_server_argv_sha256")
    if mode != "one_invocation_bypass":
        mode = None
    if not (
        isinstance(argv_sha256, str)
        and len(argv_sha256) == 64
        and all(character in "0123456789abcdef" for character in argv_sha256)
    ):
        argv_sha256 = None
        issues.append("hook_trust:argv_identity_invalid")
    issues = sorted(set(issues))
    owner_identity = runtime_report.get("owner_identity_sha256")
    invocation_id = None
    if not issues and isinstance(selected_task, str):
        invocation_id = "hook-invocation-" + _sha256(
            {
                "schema": "orch-dork/hook-trust-invocation-identity/v1",
                "task_id": selected_task,
                "owner_identity_sha256": owner_identity,
                "app_server_argv_sha256": argv_sha256,
                "hook_inventory_report_sha256": hook_inventory_report[
                    "report_sha256"
                ],
            }
        )[:32]
    core = {
        "schema": HOOK_TRUST_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "disposition": (
            "ONE_INVOCATION_BYPASS_ATTESTED"
            if not issues
            else "HOOK_TRUST_UNAVAILABLE"
        ),
        "task_id": selected_task,
        "task_runtime_report": runtime_report,
        "hook_inventory_report": hook_inventory_report,
        "mode": mode if not issues else None,
        "invocation_id": invocation_id,
        "app_server_argv_sha256": argv_sha256,
        "issues": issues,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "credential_reads": 0,
        "network_calls": 0,
        "task_creations": 0,
        "native_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}


__all__ = [
    "ATTEMPT_SOURCES_SCHEMA",
    "CHECKPOINT_SOURCES_SCHEMA",
    "WORKER_FINAL_SOURCES_SCHEMA",
    "WORKER_FINAL_ARRIVAL_SOURCES_SCHEMA",
    "MCP_CALL_SCHEMA",
    "HOOK_INVENTORY_SCHEMA",
    "HOOK_TRUST_SCHEMA",
    "LocalTaskRuntimeError",
    "OwnerHookInventoryArtifact",
    "OWNER_SOCKET_ENV",
    "QualificationOwnerSocketBinding",
    "RETAINED_TRANSPORT_TIMEOUT_SECONDS",
    "SCHEMA",
    "build_qualification_hook_state_override",
    "open_retained_qualification_owner_transport",
    "qualification_owner_codex_socket_path",
    "qualification_owner_socket_binding",
    "observe_qualification_host_hooks",
    "observe_current_local_task_hook_trust",
    "observe_current_local_task_runtime",
    "observe_current_local_task_mcp_call",
    "validate_current_local_task_mcp_observation",
    "observe_completed_attempt_sources",
    "validate_completed_attempt_sources",
    "observe_worker_checkpoint_sources",
    "validate_worker_checkpoint_sources",
    "observe_worker_checkpoint_arrival_sources",
    "validate_worker_checkpoint_arrival_sources",
    "observe_worker_final_sources",
    "validate_worker_final_sources",
    "observe_worker_final_arrival_sources",
    "validate_worker_final_arrival_sources",
    "observe_local_task_pre_turn_runtime",
]
