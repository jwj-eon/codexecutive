"""Bounded POSIX fixture capture: one local socket, PTY and Python child.

No Codex process, task, credential, provider, controller or authority is used.
Capture is explicit; replaying the checked-in corpus never invokes this module.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

from lifecycle_conformance import values

LIMIT = 65536
CHILD = """import json, os, socket
keys = ('HOME', 'CODEX_HOME', 'ORCH_DORK_APP_SERVER_SOCKET')
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
    peer.settimeout(3)
    peer.connect(os.environ['ORCH_DORK_APP_SERVER_SOCKET'])
    peer.sendall((json.dumps({k: os.environ[k] for k in keys}, sort_keys=True) + '\\n').encode())
    reply = peer.recv(1024)
print(json.dumps({'isatty': os.isatty(1), 'reply': reply.decode()}, sort_keys=True), flush=True)
"""


def _group_absent(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    return False


def _file(path: Path, kind: str) -> dict:
    info = path.lstat()
    return {"kind": kind, "owner_uid": info.st_uid, "caller_uid": os.getuid(),
            "mode": stat.S_IMODE(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode)}


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise values.LifecycleContractError("host_probe:timeout")
    return remaining


def capture_posix_fixtures() -> dict:
    """Capture real local transport observations and independently prove cleanup."""
    started = time.monotonic()
    deadline = started + 5
    process = None
    descriptors = set()
    result = None
    with tempfile.TemporaryDirectory(prefix="orch-host-fixture-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        home, codex = root / "home", root / "codex"
        home.mkdir(mode=0o700)
        codex.mkdir(mode=0o700)
        owned = root / "owned.json"
        owned.write_text('{"fixture":true}\n')
        owned.chmod(0o600)
        address = root / "owner.sock"
        env = {"HOME": str(home), "CODEX_HOME": str(codex), "ORCH_DORK_APP_SERVER_SOCKET": str(address)}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.settimeout(3)
            server.bind(str(address))
            address.chmod(0o600)
            server.listen(1)
            master, slave = pty.openpty()
            descriptors.update((master, slave))
            try:
                process = subprocess.Popen([sys.executable, "-B", "-c", CHILD], cwd=root,
                                           env={**env, "PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
                                           stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.PIPE,
                                           start_new_session=True)
                os.close(slave)
                descriptors.remove(slave)
                server.settimeout(min(3, _remaining(deadline)))
                with server.accept()[0] as peer:
                    wire = bytearray()
                    while not wire.endswith(b"\n"):
                        peer.settimeout(min(3, _remaining(deadline)))
                        chunk = peer.recv(4096)
                        if not chunk or len(wire) + len(chunk) > LIMIT:
                            raise values.LifecycleContractError("host_probe:socket_frame")
                        wire.extend(chunk)
                    peer.settimeout(_remaining(deadline))
                    peer.sendall(b'{"status":"fixture-echo"}\n')
                stdout = bytearray()
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([master], [], [], _remaining(deadline))
                    if not ready:
                        raise values.LifecycleContractError("host_probe:timeout")
                    try:
                        chunk = os.read(master, 4096)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    if len(stdout) + len(chunk) > LIMIT:
                        raise values.LifecycleContractError("host_probe:pty_size")
                    stdout.extend(chunk)
                else:
                    raise values.LifecycleContractError("host_probe:timeout")
                _, stderr = process.communicate(timeout=_remaining(deadline))
                if process.returncode != 0 or len(stderr) > LIMIT:
                    raise values.LifecycleContractError("host_probe:child_failed")
                if not _group_absent(process.pid):
                    raise values.LifecycleContractError("host_probe:descendants")
                child = json.loads(stdout)
                result = {"schema": "orch-dork/posix-host-fixture-capture/v1",
                          "environment": {"parent": env, "child": json.loads(wire)},
                          "socket_frame": wire.decode(),
                          "files": [_file(owned, "file"), _file(root, "directory"), _file(address, "socket")],
                          "pty": {"isatty": child["isatty"], "exit_code": process.returncode,
                                  "stdout": stdout.decode(), "stderr": stderr.decode(), "owned_descendants": 0},
                          "socket_reply": child["reply"]}
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
                descriptors.clear()
                if process is not None:
                    if not _group_absent(process.pid):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=1)
                    if process.stderr is not None:
                        process.stderr.close()
                    if not _group_absent(process.pid):
                        raise values.LifecycleContractError("host_probe:cleanup_unknown")
    if result is None or root.exists() or descriptors:
        raise values.LifecycleContractError("host_probe:cleanup_unknown")
    result["cleanup"] = {"process_group_absent": True, "temporary_root_absent": True,
                         "owned_descriptors_closed": True}
    return result
