#!/usr/bin/env python3
"""One WebSocket JSON-RPC connection to a Codex app server over a Unix socket.

Issue 193's governed-run watcher speaks to Codex's shared app-server daemon or
to the governed runner through this client.  It keeps every notification and
server request that arrives while a request waits for its answer, in order,
so an observer never loses a turn event, and it resolves Codex's advertised
daemon path to its physical socket through the owner-socket binding the
qualification owner already uses.
"""

from __future__ import annotations

import base64
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import time
from typing import Any, Mapping


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import orch_dork_local_task_runtime as local_task_runtime  # noqa: E402


MAX_FRAME_BYTES = 16 * 1024 * 1024
_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class AppServerRequestError(RuntimeError):
    """The app server answered one request with a JSON-RPC error."""

    def __init__(self, method: str, detail: str) -> None:
        super().__init__(method + ": " + detail)
        self.method = method
        self.detail = detail


def resolve_socket(path: Path) -> Path:
    """The physical socket behind a direct path or Codex's rendezvous alias."""

    try:
        return local_task_runtime.qualification_owner_socket_binding(path).physical_path
    except local_task_runtime.LocalTaskRuntimeError as error:
        raise ConnectionError("app_server:socket_unavailable:" + str(error)) from error


class AppServerConnection:
    """One WebSocket JSON-RPC connection over a Unix socket."""

    def __init__(self, path: Path, *, timeout: float = 30.0) -> None:
        self.path = Path(path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.buffer = bytearray()
        self.fragments = bytearray()
        self.pending: deque[dict[str, Any]] = deque()
        self.next_id = 1
        self.closed = False
        try:
            self.sock.connect(str(self.path))
            self._handshake()
        except Exception:
            self.sock.close()
            self.closed = True
            raise

    def _handshake(self) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        self.sock.sendall(
            (
                "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode("ascii")
        )
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk or len(response) > 16_384:
                raise ConnectionError("app_server:handshake_failed")
            response.extend(chunk)
        head, _, rest = bytes(response).partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        expected = base64.b64encode(
            hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()
        ).decode("ascii")
        headers = {
            name.strip().lower(): value.strip()
            for name, _, value in (line.partition(":") for line in lines[1:])
        }
        if " 101 " not in lines[0] or headers.get("sec-websocket-accept") != expected:
            raise ConnectionError("app_server:handshake_refused")
        self.buffer.extend(rest)

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if len(payload) > MAX_FRAME_BYTES:
            raise ConnectionError("app_server:frame_too_large")
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
        self.sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def send(self, value: Mapping[str, Any]) -> None:
        self._send_frame(0x1, json.dumps(value, separators=(",", ":")).encode("utf-8"))

    def _frame(self) -> tuple[int, bytes, bool] | None:
        data = self.buffer
        if len(data) < 2:
            return None
        length, offset = data[1] & 0x7F, 2
        if length == 126:
            if len(data) < 4:
                return None
            length, offset = struct.unpack("!H", bytes(data[2:4]))[0], 4
        elif length == 127:
            if len(data) < 10:
                return None
            length, offset = struct.unpack("!Q", bytes(data[2:10]))[0], 10
        masked = bool(data[1] & 0x80)
        if masked:
            offset += 4
        if length > MAX_FRAME_BYTES:
            raise ConnectionError("app_server:frame_too_large")
        if len(data) < offset + length:
            return None
        payload = bytes(data[offset:offset + length])
        if masked:
            mask = bytes(data[offset - 4:offset])
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        opcode, final = data[0] & 0x0F, bool(data[0] & 0x80)
        del data[:offset + length]
        return opcode, payload, final

    def _receive(self, timeout: float) -> dict[str, Any] | None:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            frame = self._frame()
            if frame is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                ready, _, _ = select.select([self.sock], [], [], remaining)
                if not ready:
                    return None
                chunk = self.sock.recv(65_536)
                if not chunk:
                    raise ConnectionError("app_server:connection_closed")
                self.buffer.extend(chunk)
                continue
            opcode, payload, final = frame
            if opcode == 0x8:
                raise ConnectionError("app_server:connection_closed")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            self.fragments.extend(payload)
            if len(self.fragments) > MAX_FRAME_BYTES:
                raise ConnectionError("app_server:frame_too_large")
            if not final:
                continue
            raw, self.fragments = bytes(self.fragments), bytearray()
            value = json.loads(raw.decode("utf-8"))
            if isinstance(value, dict):
                return value

    def request(self, method: str, params: Mapping[str, Any], *, timeout: float = 60.0) -> Any:
        """Send one request and return its result; queue everything else."""

        identifier = self.next_id
        self.next_id += 1
        self.send({"id": identifier, "method": method, "params": dict(params)})
        deadline = time.monotonic() + timeout
        while True:
            message = self._receive(deadline - time.monotonic())
            if message is None:
                raise TimeoutError("app_server:" + method + "_timeout")
            if message.get("id") == identifier and "method" not in message:
                if "error" in message:
                    error = message.get("error")
                    detail = error.get("message") if isinstance(error, Mapping) else error
                    raise AppServerRequestError(method, str(detail)[:400])
                return message.get("result")
            self.pending.append(message)

    def next_message(self, timeout: float) -> dict[str, Any] | None:
        """The next queued or arriving notification or server request."""

        if self.pending:
            return self.pending.popleft()
        return self._receive(timeout)

    def respond_error(self, identifier: Any, message: str) -> None:
        self.send({"id": identifier, "error": {"code": -32601, "message": message}})

    def initialize(self, client_name: str) -> dict[str, Any]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"experimentalApi": True},
                "clientInfo": {"name": client_name, "version": "1"},
            },
        )
        self.send({"method": "initialized", "params": {}})
        return result if isinstance(result, dict) else {}

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self._send_frame(0x8, struct.pack("!H", 1000))
        except OSError:
            pass
        self.sock.close()


__all__ = [
    "AppServerConnection",
    "AppServerRequestError",
    "MAX_FRAME_BYTES",
    "resolve_socket",
]
