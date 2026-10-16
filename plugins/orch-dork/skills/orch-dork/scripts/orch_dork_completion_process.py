"""Observe one retained qualification owner's POSIX group after source capture.

Binding requires the live Unix peer, exact captured argv/cwd, and a direct
child owned by the calling host in its own session and process group. Linux
process identity is retained before exit; missing telemetry never proves
cleanup. This module sends no termination signal, signs no release receipt,
and provides no native action or qualification authority.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
from typing import Any

import orch_dork_governed_native_controller as native
import orch_dork_local_task_runtime as owner

SCHEMA = "orch-dork/completion-process-observation/v1"
BINDING_SCHEMA = "orch-dork/completion-process-binding/v1"
_MINT = object()
_ISSUES = {"completion_process:identity_changed", "completion_process:telemetry_unavailable"}


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("completion_process:binding_invalid")


def _proc_bytes(pid: int, name: str) -> bytes:
    descriptor = os.open(f"/proc/{pid}/{name}", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid())
        raw = os.read(descriptor, 65_537)
        _require(0 < len(raw) <= 65_536)
        return raw
    finally:
        os.close(descriptor)


def _process_identity(pid: int) -> dict:
    """Read stable Linux fields; do not confuse a reused PID with this child."""
    raw = _proc_bytes(pid, "stat")
    end = raw.rfind(b") ")
    _require(end > 0 and int(raw.split(b" ", 1)[0]) == pid)
    fields = raw[end + 2:].split()
    _require(len(fields) >= 20)
    argv = _proc_bytes(pid, "cmdline")
    _require(argv.endswith(b"\0"))
    cwd = os.readlink(f"/proc/{pid}/cwd")
    _require(cwd.startswith("/") and not cwd.endswith(" (deleted)"))
    return {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]), "sid": int(fields[3]),
        "start_ticks": int(fields[19]), "uid": os.getuid(),
        "argv_sha256": hashlib.sha256(argv).hexdigest(), "cwd": cwd}


def _capture_selection(capture: Any) -> tuple[dict, str]:
    _require(native.validate_verified_completion_source_capture(capture)["valid"] is True)
    _require(capture["status"] == "OBSERVED")
    inventory = capture["source_observation"]["evidence"]["owner_before"]
    return inventory["expectation"], inventory["observation"]["sources"]["root"]["cwd"]


def _check_binding(binding: Any, capture: Any) -> None:
    from orch_dork_governed_native_reports import _digest, _json

    expected, cwd = _capture_selection(capture)
    _require(type(binding) is dict and set(binding) == {"schema", "completion_capture_sha256", "controller_id",
        "controller_cursor", "observer_pid", "owner_identity", "socket_path", "process"})
    _json(binding)
    _require(binding["schema"] == BINDING_SCHEMA and binding["completion_capture_sha256"] == capture["report_sha256"])
    _require(binding["controller_id"] == capture["controller_report"]["controller_id"])
    _require(native._canonical(binding["controller_cursor"]) == native._canonical(capture["controller_report"]["cursor"]))
    process, identity = binding["process"], binding["owner_identity"]
    _require(type(process) is dict and set(process) == {"pid", "ppid", "pgid", "sid", "start_ticks", "uid", "argv_sha256", "cwd"})
    for key in ("pid", "ppid", "pgid", "sid", "start_ticks"):
        _require(type(process[key]) is int and process[key] > 0)
    _require(type(process["uid"]) is int and process["uid"] >= 0)
    _require(type(binding["observer_pid"]) is int and binding["observer_pid"] > 0)
    _require(process["ppid"] == binding["observer_pid"] != process["pid"])
    _require(process["pgid"] == process["sid"] == process["pid"])
    _require(_digest(process["argv_sha256"]) and process["argv_sha256"] == expected["app_server_argv_sha256"])
    _require(process["cwd"] == cwd)
    path = binding["socket_path"]
    _require(type(path) is str and 0 < len(path) <= 4096 and Path(path).is_absolute() and "\0" not in path
             and all(part not in ("", ".", "..") for part in path.split("/")[1:]))
    _require(type(identity) is dict and set(identity) == {"schema", "socket", "peer"})
    _require(identity["schema"] == "orch-dork/local-task-owner-identity/v1")
    _require(type(identity["socket"]) is dict and set(identity["socket"]) == {"device", "inode", "ctime_ns", "uid"})
    _require(type(identity["peer"]) is dict and set(identity["peer"]) == {"pid", "uid", "gid"})
    for value in (*identity["socket"].values(), *identity["peer"].values()):
        _require(type(value) is int and value >= 0)
    _require(identity["peer"]["pid"] == process["pid"])
    _require(identity["socket"]["uid"] == identity["peer"]["uid"] == process["uid"])
    _require(native._sha(identity) == expected["owner_identity_sha256"])


def _report(binding: dict, status: str, observation: dict | None, issues: list[str]) -> dict:
    core = deepcopy({"schema": SCHEMA, "status": status, "binding": binding, "observation": observation,
        "issues": issues, "scope": "owned_posix_process_group", "resource_release_proven": False,
        "terminal_claim_permitted": False, "provider_free": True, "model_calls": 0,
        "native_calls": 0, "task_creations": 0, "credential_reads": 0, "process_signals_sent": 0})
    return {**core, "report_sha256": native._sha(core)}


def validate_completion_process_observation(report: Any, completion_capture: Any) -> dict:
    """Validate canonical joins, without authenticating a supplied host report."""
    try:
        from orch_dork_governed_native_reports import _json

        _require(type(report) is dict)
        _json(report)
        _require(len(native._canonical(report)) <= 65_536)
        binding = report["binding"]
        _check_binding(binding, completion_capture)
        status, observation, issues = report["status"], report["observation"], report["issues"]
        _require(type(status) is str and status in {"OBSERVED", "PENDING", "REFUSED"})
        if status == "REFUSED":
            _require(observation is None and type(issues) is list and len(issues) == 1 and issues[0] in _ISSUES)
        else:
            _require(issues == [] and type(observation) is dict and set(observation) == {"leader_returncode", "group_members", "group_absent"})
            code = observation["leader_returncode"]
            _require(code is None or type(code) is int and -255 <= code <= 255)
            _require(observation["group_absent"] is (status == "OBSERVED"))
            if status == "OBSERVED":
                _require(type(code) is int and type(observation["group_members"]) is int and observation["group_members"] == 0)
            else:
                _require(observation["group_members"] is None)
        _require(native._canonical(report) == native._canonical(_report(binding, status, observation, issues)))
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return {"valid": False, "issues": ["completion_process:transport_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


class BoundCompletionProcess:
    """An in-memory host observation handle; it cannot be restored from JSON.

    PENDING permits another read of the same owned child. An observed closure
    or refused observation is final for this handle; neither causes a retry,
    sends a signal, nor releases a lane.
    """
    def __init__(self, process: subprocess.Popen, binding: dict, *, _key=None):
        _require(_key is _MINT)
        self._process = process
        self._binding = deepcopy(binding)
        self._final = None

    def observe_cleanup(self) -> dict:
        if self._final is not None:
            return deepcopy(self._final)
        binding = self._binding
        try:
            if os.getpid() != binding["observer_pid"] or self._process.pid != binding["process"]["pid"]:
                raise ValueError("completion_process:identity_changed")
            returncode = self._process.poll()
            try:
                current = _process_identity(self._process.pid)
            except FileNotFoundError:
                current = None
                returncode = self._process.poll()
                if returncode is None:
                    raise ValueError("completion_process:telemetry_unavailable")
            if current is not None and native._canonical(current) != native._canonical(binding["process"]):
                raise ValueError("completion_process:identity_changed")
            try:
                os.killpg(binding["process"]["pgid"], 0)
                absent = False
            except ProcessLookupError:
                absent = True
            if absent and (returncode is None or current is not None):
                raise ValueError("completion_process:telemetry_unavailable")
            status = "OBSERVED" if absent else "PENDING"
            result = _report(binding, status, {"leader_returncode": returncode,
                "group_members": 0 if absent else None, "group_absent": absent}, [])
        except (OSError, ValueError) as error:
            issue = str(error) if str(error) in _ISSUES else "completion_process:telemetry_unavailable"
            result = _report(binding, "REFUSED", None, [issue])
        if result["status"] != "PENDING":
            self._final = deepcopy(result)
        return result


def bind_verified_completion_process(completion_capture: Any, process: subprocess.Popen, *, env=None) -> BoundCompletionProcess:
    """Bind a live direct child to the captured Unix peer before host cleanup.

    The caller already owns its launch and bounded cleanup. A separate raw
    peer connection performs no RPC and does not replace the root subscription.
    Unsupported platforms, foreign groups and changed owner epochs refuse.
    """
    try:
        _require(sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"))
        _require(isinstance(process, subprocess.Popen) and type(process.pid) is int and process.pid > 0)
        expected, cwd = _capture_selection(completion_capture)
        _require(process.poll() is None)
        before = _process_identity(process.pid)
        _require(before["ppid"] == os.getpid() and before["pid"] == before["pgid"] == before["sid"])
        _require(before["cwd"] == cwd and before["argv_sha256"] == expected["app_server_argv_sha256"])
        path = owner._owner_socket_path(os.environ if env is None else env)
        epoch = owner._socket_epoch(path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(owner.RPC_TIMEOUT_SECONDS)
            connection.connect(str(path))
            owner._OwnerClient._verify_peer_owner(connection, epoch[3])
            peer = owner._OwnerClient._peer_identity(connection)
            identity = {"schema": "orch-dork/local-task-owner-identity/v1",
                "socket": dict(zip(("device", "inode", "ctime_ns", "uid"), epoch)), "peer": peer}
            _require(peer["pid"] == process.pid and native._sha(identity) == expected["owner_identity_sha256"])
            invocation = owner._inspect_peer_invocation(peer)
            _require(invocation["status"] == "PASS" and invocation["app_server_argv_sha256"] == before["argv_sha256"])
            _require(epoch == owner._socket_epoch(path) and native._canonical(before) == native._canonical(_process_identity(process.pid)))
        binding = {"schema": BINDING_SCHEMA, "completion_capture_sha256": completion_capture["report_sha256"],
            "controller_id": completion_capture["controller_report"]["controller_id"],
            "controller_cursor": deepcopy(completion_capture["controller_report"]["cursor"]),
            "observer_pid": os.getpid(), "owner_identity": identity, "socket_path": str(path), "process": before}
        _check_binding(binding, completion_capture)
        return BoundCompletionProcess(process, binding, _key=_MINT)
    except (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError) as error:
        raise ValueError("completion_process:binding_invalid") from error


__all__ = ["bind_verified_completion_process", "validate_completion_process_observation", "BoundCompletionProcess"]
