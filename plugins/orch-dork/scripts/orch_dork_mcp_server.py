#!/usr/bin/env python3
"""Provider-free bounded MCP framing and dispatch.

The real Orch Dork policy service may embed this module or use its helpers as
a transport seam.  It intentionally has no provider, task-creation, or
authority integration: callers provide a finite method-to-handler mapping and
the dispatcher applies the Issue 49 limits before invoking a handler.
"""

from __future__ import annotations

from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
import hashlib
import json
import queue
import threading
import time
from pathlib import Path
import sys
from typing import Any, Callable, Iterable, Mapping, Sequence


_SCRIPT_DIR = Path(__file__).resolve().parents[1] / "skills" / "orch-dork" / "scripts"
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from orch_dork_hostile_input import (  # noqa: E402
    DenialReason,
    DefensiveProfile,
    HostileInputError,
    PROFILE,
    canonicalize_bounded_json,
    parse_bounded_json,
    validate_mcp_request,
)
from orch_dork_process_containment import DispatchScope, dispatch_scope, MAX_CLEANUP_SECONDS


MCP_PROTOCOL = "orch-dork/mcp/v1"
MCP_FRAME_SCHEMA = "orch-dork/mcp-frame/v1"
MCP_ERROR_SCHEMA = "orch-dork/mcp-error/v1"

MCP_ERROR_CODES = {
    DenialReason.INPUT_TOO_LARGE.value: -32001,
    DenialReason.FRAME_TOO_LARGE.value: -32002,
    DenialReason.MALFORMED_FRAME.value: -32003,
    DenialReason.UNKNOWN_METHOD.value: -32004,
    DenialReason.QUEUE_FULL.value: -32005,
    DenialReason.IN_FLIGHT_FULL.value: -32006,
    DenialReason.PARSE_TIMEOUT.value: -32007,
    DenialReason.DISPATCH_TIMEOUT.value: -32008,
    DenialReason.DUPLICATE_DELIVERY.value: -32009,
    DenialReason.OUTPUT_TOO_LARGE.value: -32010,
}


def _denial(reason: str | DenialReason, *, request_id: Any = None, observed: Any = None, bound: Any = None, detail: str | None = None) -> dict[str, Any]:
    code = reason.value if isinstance(reason, DenialReason) else str(reason)
    result: dict[str, Any] = {
        "schema": MCP_ERROR_SCHEMA,
        "protocol": MCP_PROTOCOL,
        "status": "DENIED",
        "reason": code,
        "request_id": request_id,
        "error": {"code": MCP_ERROR_CODES.get(code, -32099), "reason": code},
    }
    if observed is not None:
        result["observed"] = observed
    if bound is not None:
        result["bound"] = bound
    if detail is not None:
        # Detail is a fixed diagnostic token, never a parser exception or
        # caller-provided input body.
        result["detail"] = detail
    return result


def _raw_bytes(frame: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(frame, str):
        return frame.encode("utf-8", "strict")
    if isinstance(frame, (bytes, bytearray, memoryview)):
        return bytes(frame)
    raise HostileInputError(DenialReason.INPUT_TYPE)


def _extract_content_length(frame: bytes, profile: DefensiveProfile) -> bytes:
    """Decode optional ``Content-Length`` framing without unbounded reads."""

    if not frame.startswith(b"Content-Length:"):
        return frame
    if len(frame) > profile.max_frame_bytes:
        raise HostileInputError(DenialReason.FRAME_TOO_LARGE, observed=len(frame), bound=profile.max_frame_bytes)
    marker = b"\r\n\r\n"
    split = frame.find(marker)
    if split < 0:
        raise HostileInputError(DenialReason.MALFORMED_FRAME)
    header = frame[:split]
    payload = frame[split + len(marker) :]
    lines = header.split(b"\r\n")
    if len(lines) != 1 or not lines[0].startswith(b"Content-Length:"):
        raise HostileInputError(DenialReason.MALFORMED_FRAME)
    raw_length = lines[0][len(b"Content-Length:") :].strip()
    if not raw_length or not raw_length.isdigit():
        raise HostileInputError(DenialReason.MALFORMED_FRAME)
    declared = int(raw_length, 10)
    if declared > profile.max_frame_bytes:
        raise HostileInputError(DenialReason.FRAME_TOO_LARGE, observed=declared, bound=profile.max_frame_bytes)
    if len(payload) != declared:
        raise HostileInputError(DenialReason.MALFORMED_FRAME)
    return payload


def parse_mcp_frame(frame: bytes | bytearray | memoryview | str, *, profile: DefensiveProfile = PROFILE) -> dict[str, Any] | list[dict[str, Any]]:
    """Parse a direct JSON or Content-Length framed MCP request/batch."""

    raw = _raw_bytes(frame)
    if len(raw) > profile.max_frame_bytes:
        raise HostileInputError(DenialReason.FRAME_TOO_LARGE, observed=len(raw), bound=profile.max_frame_bytes)
    payload = _extract_content_length(raw, profile)
    value = parse_bounded_json(payload, profile=profile, batch=True)
    if isinstance(value, list):
        if not value or len(value) > profile.max_operations:
            reason = DenialReason.OPERATIONS_EXCEEDED if len(value) > profile.max_operations else DenialReason.MALFORMED_FRAME
            raise HostileInputError(reason, observed=len(value), bound=profile.max_operations if len(value) > profile.max_operations else None)
        requests: list[dict[str, Any]] = []
        for item in value:
            report = validate_mcp_request(item, profile=profile)
            if report.get("status") != "PASS":
                raise HostileInputError(str(report.get("reason", DenialReason.MALFORMED_FRAME.value)))
            requests.append(report["request"])
        return requests
    report = validate_mcp_request(value, profile=profile)
    if report.get("status") != "PASS":
        raise HostileInputError(str(report.get("reason", DenialReason.MALFORMED_FRAME.value)))
    return report["request"]


def validate_mcp_frame(frame: bytes | bytearray | memoryview | str, *, profile: DefensiveProfile = PROFILE) -> dict[str, Any]:
    started = time.monotonic()
    try:
        value = parse_mcp_frame(frame, profile=profile)
        requests = value if isinstance(value, list) else [value]
        return {
            "schema": MCP_FRAME_SCHEMA,
            "status": "PASS",
            "valid": True,
            "operations": len(requests),
            "request_ids": [request.get("id") for request in requests],
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
    except HostileInputError as exc:
        return {
            "schema": MCP_FRAME_SCHEMA,
            "status": "DENIED",
            "valid": False,
            "reason": exc.reason,
            "observed": exc.observed,
            "bound": exc.bound,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }


def encode_mcp_frame(request: Mapping[str, Any] | Sequence[Mapping[str, Any]], *, profile: DefensiveProfile = PROFILE, content_length: bool = False) -> bytes:
    payload = canonicalize_bounded_json(json.dumps(request, ensure_ascii=False, separators=(",", ":")), profile=profile, batch=isinstance(request, Sequence) and not isinstance(request, Mapping))
    if len(payload) > profile.max_frame_bytes:
        raise HostileInputError(DenialReason.FRAME_TOO_LARGE, observed=len(payload), bound=profile.max_frame_bytes)
    if not content_length:
        return payload
    framed = b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n" + payload
    if len(framed) > profile.max_frame_bytes:
        raise HostileInputError(DenialReason.FRAME_TOO_LARGE, observed=len(framed), bound=profile.max_frame_bytes)
    return framed


@dataclass
class DispatchTicket:
    """A bounded asynchronous dispatch receipt."""

    accepted: bool
    reason: str | None = None
    request_id: Any = None
    future: Future[Any] | None = None
    operations: int = 0

    @property
    def status(self) -> str:
        return "ACCEPTED" if self.accepted else "DENIED"

    def as_dict(self, *, include_future: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema": "orch-dork/mcp-dispatch-ticket/v1",
            "status": self.status,
            "accepted": self.accepted,
            "reason": self.reason,
            "request_id": self.request_id,
            "operations": self.operations,
        }
        if include_future:
            result["future"] = self.future
        return result

    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_dict().get(key, default)


class BoundedDispatcher:
    """Fixed-worker MCP dispatcher with queue and duplicate-delivery bounds."""

    def __init__(
        self,
        handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
        *,
        profile: DefensiveProfile = PROFILE,
        queue_limit: int | None = None,
        in_flight_limit: int | None = None,
        executor: ThreadPoolExecutor | None = None,
    ) -> None:
        self.profile = profile
        self.queue_limit = min(profile.max_queue, profile.max_queue if queue_limit is None else max(0, int(queue_limit)))
        self.in_flight_limit = min(profile.max_in_flight, profile.max_in_flight if in_flight_limit is None else max(0, int(in_flight_limit)))
        self._handlers: dict[str, Callable[[Mapping[str, Any]], Any]] = dict(handlers or {})
        self._executor = executor or ThreadPoolExecutor(max_workers=max(1, self.in_flight_limit), thread_name_prefix="orch-mcp")
        self._owns_executor = executor is None
        self._lock = threading.RLock()
        self._pending = 0
        self._in_flight = 0
        self._completed: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._in_progress: dict[str, Future[Any]] = {}
        self._scopes: dict[Future[Any], DispatchScope] = {}
        self._closed = False

    @property
    def queue_depth(self) -> int:
        with self._lock:
            return self._pending

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    @property
    def handlers(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))

    def register(self, method: str, handler: Callable[[Mapping[str, Any]], Any]) -> None:
        if not isinstance(method, str) or not method or not callable(handler):
            raise ValueError("invalid_handler")
        with self._lock:
            if self._closed:
                raise RuntimeError("dispatcher_closed")
            self._handlers[method] = handler

    def _key(self, request: Mapping[str, Any]) -> str | None:
        if "id" not in request or request.get("id") is None:
            return None
        try:
            payload = canonicalize_bounded_json(
                json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False),
                profile=self.profile,
            )
            return hashlib.sha256(payload).hexdigest()
        except (HostileInputError, TypeError, ValueError):
            return None

    def _bounded_response(self, response: Any, *, request_id: Any) -> Any:
        if response is None:
            return None
        try:
            canonical = canonicalize_bounded_json(
                json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False),
                profile=self.profile,
                batch=isinstance(response, list),
            )
        except (HostileInputError, TypeError, ValueError):
            return _denial(DenialReason.OUTPUT_TOO_LARGE, request_id=request_id, bound=self.profile.canonical_json_bytes)
        if len(canonical) > self.profile.canonical_json_bytes:
            return _denial(DenialReason.OUTPUT_TOO_LARGE, request_id=request_id, observed=len(canonical), bound=self.profile.canonical_json_bytes)
        return json.loads(canonical)

    def _execute_one(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        method = request.get("method")
        handler = self._handlers.get(str(method))
        if handler is None:
            return _denial(DenialReason.UNKNOWN_METHOD, request_id=request.get("id"))
        try:
            result = handler(dict(request))
        except HostileInputError as exc:
            return _denial(exc.reason, request_id=request.get("id"), observed=exc.observed, bound=exc.bound)
        except Exception:
            # Deliberately do not expose traceback, arguments, environment, or
            # handler exception text across the MCP boundary.
            return _denial(DenialReason.HANDLER_ERROR, request_id=request.get("id"))
        if result is None:
            return None
        if (
            isinstance(result, Mapping)
            and result.get("jsonrpc") == "2.0"
            and result.get("id") == request.get("id")
            and ("result" in result or "error" in result)
        ):
            response = dict(result)
        else:
            response = {
                "schema": "orch-dork/mcp-response/v1",
                "protocol": MCP_PROTOCOL,
                "status": "PASS",
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": result,
            }
        return self._bounded_response(response, request_id=request.get("id"))

    def _execute(self, requests: list[Mapping[str, Any]], cache_keys: list[str | None]) -> dict[str, Any] | list[dict[str, Any]]:
        with self._lock:
            self._pending -= 1
            self._in_flight += 1
        try:
            results = [self._execute_one(request) for request in requests]
            visible = [result for result in results if result is not None]
            output: Any = (visible[0] if len(visible) == 1 else visible) if visible else None
            output = self._bounded_response(output, request_id=requests[0].get("id"))
            with self._lock:
                for key, result in zip(cache_keys, results):
                    if key is not None and result is not None:
                        self._completed[key] = result
                        self._completed.move_to_end(key)
                        while len(self._completed) > self.profile.max_queue:
                            self._completed.popitem(last=False)
            return output
        finally:
            with self._lock:
                for key in cache_keys:
                    if key is not None:
                        self._in_progress.pop(key, None)
                self._in_flight -= 1

    def _execute_scoped(self, requests, keys, scope):
        with dispatch_scope(scope):
            return self._execute(requests, keys)

    def _finished(self, future):
        with self._lock:
            self._scopes.pop(future, None)
            if future.cancelled():
                self._pending -= 1
                for key in [key for key, value in self._in_progress.items() if value is future]:
                    self._in_progress.pop(key, None)

    def submit(self, frame: bytes | bytearray | memoryview | str, *, timeout: float | None = None) -> DispatchTicket:
        started = time.monotonic()
        try:
            value = parse_mcp_frame(frame, profile=self.profile)
        except HostileInputError as exc:
            reason = DenialReason.FRAME_TOO_LARGE if exc.reason == DenialReason.INPUT_TOO_LARGE.value else exc.reason
            return DispatchTicket(False, reason=reason)
        elapsed = time.monotonic() - started
        if elapsed > self.profile.parse_wall_seconds:
            return DispatchTicket(False, reason=DenialReason.PARSE_TIMEOUT.value)
        requests = value if isinstance(value, list) else [value]
        methods = [str(request.get("method")) for request in requests]
        with self._lock:
            if self._closed:
                return DispatchTicket(False, reason=DenialReason.CANCELLED.value)
            unknown = next((method for method in methods if method not in self._handlers), None)
            if unknown is not None:
                return DispatchTicket(False, reason=DenialReason.UNKNOWN_METHOD.value)
            if self._pending >= self.queue_limit:
                reason = DenialReason.QUEUE_FULL.value if self.queue_limit else DenialReason.IN_FLIGHT_FULL.value
                return DispatchTicket(False, reason=reason)
            keys = [self._key(request) for request in requests]
            # Idempotent repeated delivery returns a bounded cached result and
            # does not enqueue a second invocation.
            cached = [self._completed.get(key) if key is not None else None for key in keys]
            if all(result is not None for result in cached):
                future: Future[Any] = Future()
                future.set_result(cached[0] if len(cached) == 1 else cached)
                return DispatchTicket(True, reason=DenialReason.DUPLICATE_DELIVERY.value, request_id=requests[0].get("id"), future=future, operations=len(requests))
            if len(keys) == 1 and keys[0] is not None and keys[0] in self._in_progress:
                return DispatchTicket(
                    True,
                    reason=DenialReason.DUPLICATE_DELIVERY.value,
                    request_id=requests[0].get("id"),
                    future=self._in_progress[keys[0]],
                    operations=1,
                )
            self._pending += 1
            try:
                limit = self.profile.dispatch_wall_seconds if timeout is None else min(float(timeout), self.profile.dispatch_wall_seconds)
                scope = DispatchScope(time.monotonic() + max(0.0, limit))
                future = self._executor.submit(self._execute_scoped, requests, keys, scope)
                self._scopes[future] = scope
                for key in keys:
                    if key is not None:
                        self._in_progress[key] = future
                future.add_done_callback(self._finished)
            except Exception:
                self._pending -= 1
                return DispatchTicket(False, reason=DenialReason.QUEUE_FULL.value)
        return DispatchTicket(True, request_id=requests[0].get("id"), future=future, operations=len(requests))

    def dispatch(self, frame: bytes | bytearray | memoryview | str, *, timeout: float | None = None) -> dict[str, Any] | list[dict[str, Any]] | None:
        ticket = self.submit(frame, timeout=timeout)
        return self.wait(ticket, timeout=timeout)

    def wait(self, ticket: DispatchTicket, *, timeout: float | None = None):
        """Wait within the dispatch wall, including owned-process cleanup."""
        if not ticket.accepted:
            return _denial(ticket.reason or DenialReason.UNKNOWN.value, request_id=ticket.request_id)
        assert ticket.future is not None
        limit = self.profile.dispatch_wall_seconds if timeout is None else min(float(timeout), self.profile.dispatch_wall_seconds)
        try:
            return ticket.future.result(timeout=limit)
        except FutureTimeout:
            self.cancel(ticket)
            return _denial(DenialReason.DISPATCH_TIMEOUT, request_id=ticket.request_id)
        except Exception:
            return _denial(DenialReason.HANDLER_ERROR, request_id=ticket.request_id)

    handle = dispatch
    dispatch_async = submit

    def cancel(self, ticket: DispatchTicket | Future[Any]) -> bool:
        future = ticket.future if isinstance(ticket, DispatchTicket) else ticket
        if future is None:
            return False
        with self._lock:
            scope = self._scopes.get(future)
        if scope is not None:
            scope.cancelled.set()
        cancelled = future.cancel()
        if scope is not None and scope.managed and not cancelled:
            try:
                future.result(timeout=2 * MAX_CLEANUP_SECONDS + 0.5)
            except FutureTimeout:
                return False
            except Exception:
                pass
            return future.done()
        return bool(cancelled)

    def close(self, *, wait: bool = True) -> None:
        with self._lock:
            self._closed = True
            scopes = list(self._scopes.values())
        for scope in scopes:
            scope.cancelled.set()
        if self._owns_executor:
            self._executor.shutdown(wait=wait, cancel_futures=True)

    shutdown = close


def serve_stdio(
    handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]],
    *,
    input_stream: Any = None,
    output_stream: Any = None,
    profile: DefensiveProfile = PROFILE,
) -> int:
    """Serve newline-framed MCP through the bounded parser and dispatcher.

    Only JSON-RPC goes back on the wire.  A request with an id always gets a
    response for that id (a denial becomes a JSON-RPC error carrying the
    denial as data); anything else -- notifications, responses, error
    objects, unparseable lines -- gets no reply.  Rehearsal runs 17 and 19
    wrote a bare denial object after the dispatch wall, so Codex never saw
    the call's response, and replies to non-requests let the server and its
    client exchange error frames without end.
    """

    source = input_stream or sys.stdin.buffer
    target = output_stream or sys.stdout.buffer
    # Keep policy effects serial while the reading thread remains available
    # for cancellation. Both queued frames and outstanding replies are bounded.
    dispatcher = BoundedDispatcher(handlers, profile=profile, in_flight_limit=1)
    replies = queue.Queue(maxsize=profile.max_queue + 1)
    slots = threading.BoundedSemaphore(profile.max_queue + 1)
    wire_lock = threading.RLock()
    active = {}
    writer_errors = []

    def emit(response, request_id):
        response = _wire_response(response, request_id)
        if response is None:
            return
        encoded = json.dumps(response, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded) > profile.canonical_json_bytes:
            response = _wire_response(_denial(DenialReason.OUTPUT_TOO_LARGE,
                                      observed=len(encoded), bound=profile.canonical_json_bytes), request_id)
            if response is None:
                return
            encoded = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8")
        target.write(encoded + b"\n")
        target.flush()

    def write_replies():
        while True:
            item = replies.get()
            if item is None:
                return
            try:
                ticket = item["ticket"]
                response = dispatcher.wait(ticket, timeout=max(0, item["deadline"] - time.monotonic()))
                with wire_lock:
                    if item["cancelled"]:
                        response = _denial(DenialReason.CANCELLED, request_id=item["id"])
                    if not writer_errors:
                        emit(response, item["id"])
            except Exception as error:
                # Drain the bounded queue and stop owned work even if the
                # output pipe fails; the serving caller receives the error.
                if not writer_errors:
                    writer_errors.append(error)
                dispatcher.cancel(item["ticket"])
            finally:
                with wire_lock:
                    if item["id"] in active:
                        active[item["id"]].remove(item)
                        if not active[item["id"]]:
                            del active[item["id"]]
                slots.release()

    writer = threading.Thread(target=write_replies, name="orch-mcp-replies")
    writer.start()
    try:
        while True:
            raw = source.readline(profile.max_frame_bytes + 1)
            if not raw:
                break
            if writer_errors:
                raise writer_errors[0]
            request_id = _wire_request_id(raw, profile)
            try:
                message = parse_mcp_frame(raw, profile=profile)
            except HostileInputError:
                message = None
            if isinstance(message, dict) and message.get("method") == "notifications/cancelled" and "id" not in message:
                params = message.get("params")
                cancel_id = params.get("requestId") if isinstance(params, Mapping) else None
                if isinstance(cancel_id, (str, int)) and not isinstance(cancel_id, bool):
                    with wire_lock:
                        cancelled = list(active.get(cancel_id, ()))
                        for item in cancelled:
                            item["cancelled"] = True
                    for item in cancelled:
                        dispatcher.cancel(item["ticket"])
                continue
            if not slots.acquire(blocking=False):
                with wire_lock:
                    emit(_denial(DenialReason.QUEUE_FULL, request_id=request_id), request_id)
                continue
            with wire_lock:
                ticket = dispatcher.submit(raw)
                item = {"id": request_id, "ticket": ticket, "cancelled": False,
                        "deadline": time.monotonic() + profile.dispatch_wall_seconds}
                if request_id is not None:
                    active.setdefault(request_id, []).append(item)
                replies.put_nowait(item)
    finally:
        replies.put(None)
        writer.join()
        dispatcher.close()
    if writer_errors:
        raise writer_errors[0]
    return 0


def _wire_request_id(raw: bytes, profile: DefensiveProfile) -> Any:
    """The id of a JSON-RPC request line, or None for anything that is not one."""
    try:
        message = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if (
        not isinstance(message, dict)
        or not isinstance(message.get("method"), str)
        or "id" not in message
    ):
        return None
    request_id = message["id"]
    if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
        return None
    return request_id


def _wire_response(response: Any, request_id: Any) -> Any:
    """Map a dispatcher result onto the JSON-RPC wire, or None for no reply."""
    if response is None:
        return None
    if isinstance(response, dict) and response.get("schema") == MCP_ERROR_SCHEMA:
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": int(response.get("error", {}).get("code", -32099)),
                "message": str(response.get("reason")),
                "data": response,
            },
        }
    return response if request_id is not None else None


# Common short name used by embedding code.
MCPDispatcher = BoundedDispatcher
Dispatcher = BoundedDispatcher


__all__ = [
    "MCP_PROTOCOL",
    "MCP_FRAME_SCHEMA",
    "MCP_ERROR_SCHEMA",
    "MCP_ERROR_CODES",
    "parse_mcp_frame",
    "validate_mcp_frame",
    "encode_mcp_frame",
    "DispatchTicket",
    "BoundedDispatcher",
    "MCPDispatcher",
    "Dispatcher",
    "serve_stdio",
]
