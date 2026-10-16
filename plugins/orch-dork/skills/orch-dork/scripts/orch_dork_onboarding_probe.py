#!/usr/bin/env python3
"""Onboard one model Codex can spawn into an Orch Dork profile (ADR 0012).

The onboarding probe of Issue 203, shipped in the runtime by Issue 194 so a
user's enrollment can onboard models from the chat.  It writes the host-local
orch-dork/onboarded-profile/v1 that admission reads; racetrack/onboard.py is
its development command line.

    python3 -B orch_dork_onboarding_probe.py --model MODEL [--effort EFFORT] [--force]
    python3 -B orch_dork_onboarding_probe.py --list

One onboarding is three steps and one spawn, and tests no capability:

1. Two dry runs against a stand-in provider that refuses every request, so
   no model is called: the surface Codex assigns under the user's own
   catalog and V2 setting, then under the governed runner's all-v1 catalog
   copy with V2 off.
2. One live probe on the first of those that reaches V1: the model, as the
   root of a private task, spawns itself once as a V1 worker that reads one
   file and writes one small JSON artifact, then closes it.
3. The observations become one dated profile.  A failed observation is a
   named finding on the profile; admission never refuses.

Every run uses a private Codex home holding a copy of the user's login and
only the route settings of the user's configuration, a temporary workspace,
and an owned process group that is killed on exit.  Nothing in the user's
own Codex changes.  The final line printed is one JSON object.

Started from a chat, onboarding runs as one detached job per request: the
job onboards its models one after another and records their progress, and
the chat reads that record (read_onboarding).  One job runs at a time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9 and 3.10: the vendored parser below
    tomllib = None

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if tomllib is None:  # the macOS system python3 is 3.9
    import orch_dork_toml as tomllib  # noqa: E402

import orch_dork_onboarded_profiles as profiles  # noqa: E402

HARNESS = "orch_dork_onboarding_probe.py"
# Where OpenCodex states its routes; a test or a separate install names
# another file.
OPENCODEX_CONFIG_ENV = "ORCH_DORK_OPENCODEX_CONFIG"
OPENCODEX_CONFIG = (
    Path(os.environ[OPENCODEX_CONFIG_ENV]) if os.environ.get(OPENCODEX_CONFIG_ENV)
    else Path.home() / ".opencodex" / "config.json"
)
PHASE_ENV = "ORCH_DORK_ONBOARDING_PHASE"
INPUT_FILE = "onboarding-input.txt"
ARTIFACT_FILE = "onboarding-artifact.json"
MAX_WIRE_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 65_536
# The managed prompt helper is a small prompt-side script.  The host
# helper is measured at ~12 KB; a file longer than 65,536 bytes is a
# different script masquerading as the helper and the staging must
# refuse without touching the source or the provider.  This is an
# independent bound from MAX_ARTIFACT_BYTES so a future change to the
# artifact ceiling does not silently move the helper ceiling.
MAX_HELPER_BYTES = 65_536
DRY_RUN_SECONDS = 60
LIVE_SECONDS = 270
INTERRUPT_SECONDS = 15
# Route settings copied from the user's configuration; nothing else is.
ROUTE_KEYS = (
    "model_provider",
    "openai_base_url",
    "chatgpt_base_url",
    "experimental_realtime_ws_base_url",
    "forced_login_method",
)
# Provider settings that carry credentials, left out of a dry run's copy.
CREDENTIAL_KEYS = (
    "env_key",
    "env_key_instructions",
    "http_headers",
    "env_http_headers",
    "experimental_bearer_token",
    "auth",
)


class ProbeError(RuntimeError):
    """A harness failure that leaves no profile to write."""


class QuietServer(ThreadingHTTPServer):
    """The stand-in's server; a client dropping its connection is expected."""

    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


# ---------------------------------------------------------------- configuration


def codex_config_home() -> Path:
    configured = os.environ.get("CODEX_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".codex"


def read_user_config() -> dict[str, Any]:
    path = codex_config_home() / "config.toml"
    if tomllib is None:
        raise ProbeError("reading " + str(path) + " needs Python 3.11 or later")
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError:
        return {}


def v2_feature_enabled(config: Mapping[str, Any]) -> bool:
    features = config.get("features")
    if not isinstance(features, Mapping):
        return False
    value = features.get("multi_agent_v2")
    if isinstance(value, Mapping):
        return value.get("enabled") is True
    return value is True


def load_catalog(config: Mapping[str, Any]) -> tuple[Path | None, dict[str, Any] | None]:
    raw = config.get("model_catalog_json")
    if not isinstance(raw, str):
        return None, None
    path = Path(raw).expanduser()
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("models"), list):
        raise ProbeError(str(path) + " is not a Codex model catalog")
    return path, value


def catalog_row(catalog: Mapping[str, Any] | None, model: str) -> dict[str, Any] | None:
    if catalog is None:
        return None
    for row in catalog["models"]:
        if isinstance(row, dict) and row.get("slug") == model:
            return row
    return None


def effective_catalog(codex: str) -> dict[str, Any] | None:
    """The catalog the user's app server would load, as Codex renders it.

    The governed runner's overlay replaces the whole catalog, so without a
    catalog file it is copied from Codex's own (codex debug models), keeping
    every model the user has.  None when Codex does not render one.
    """

    try:
        completed = subprocess.run(
            [codex, "debug", "models"], capture_output=True, text=True, timeout=60, check=False
        )
        value = json.loads(completed.stdout) if completed.returncode == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("models"), list):
        return None
    return value


def opencodex_routes(path: Path | None = None) -> dict[str, Any] | None:
    """The route facts OpenCodex states, without any credential it holds."""

    try:
        value = json.loads((OPENCODEX_CONFIG if path is None else path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("providers"), dict):
        return None
    providers = {}
    for name, provider in value["providers"].items():
        if not isinstance(provider, dict):
            continue
        providers[name] = {
            "baseUrl": provider.get("baseUrl") if isinstance(provider.get("baseUrl"), str) else None,
            "modelMaxOutputTokens": {
                key: item
                for key, item in (provider.get("modelMaxOutputTokens") or {}).items()
                if isinstance(key, str) and type(item) is int
            } if isinstance(provider.get("modelMaxOutputTokens"), dict) else {},
            "defaultMaxOutputTokens": (
                provider.get("defaultMaxOutputTokens")
                if type(provider.get("defaultMaxOutputTokens")) is int
                else None
            ),
        }
    return {
        "port": value.get("port") if type(value.get("port")) is int else None,
        "defaultProvider": value.get("defaultProvider") if isinstance(value.get("defaultProvider"), str) else None,
        "providers": providers,
    }


def route_facts(config: Mapping[str, Any], model: str) -> tuple[dict[str, Any], int | None]:
    """The model's route and any maximum output its provider states."""

    provider_id = config.get("model_provider") if isinstance(config.get("model_provider"), str) else "openai"
    providers = config.get("model_providers") if isinstance(config.get("model_providers"), Mapping) else {}
    if provider_id == "openai":
        base_url = config.get("openai_base_url")
        base_url = base_url if isinstance(base_url, str) else "https://api.openai.com/v1"
    else:
        entry = providers.get(provider_id) if isinstance(providers.get(provider_id), Mapping) else {}
        base_url = entry.get("base_url") if isinstance(entry.get("base_url"), str) else None
    route = {
        "provider_id": provider_id,
        "base_url": base_url,
        "via": "direct",
        "upstream_provider": None,
        "upstream_base_url": None,
    }
    max_output = None
    opencodex = opencodex_routes()
    parts = urlsplit(base_url) if isinstance(base_url, str) else None
    if (
        opencodex is not None
        and parts is not None
        and profiles._loopback(base_url)
        and parts.port is not None
        and parts.port == opencodex["port"]
    ):
        prefix, _, rest = model.partition("/")
        if rest and prefix in opencodex["providers"]:
            upstream, upstream_model = prefix, rest
        else:
            upstream, upstream_model = opencodex["defaultProvider"], model
        provider = opencodex["providers"].get(upstream) if upstream else None
        route.update({
            "via": "opencodex",
            "upstream_provider": upstream,
            "upstream_base_url": provider["baseUrl"] if provider else None,
        })
        if provider:
            max_output = provider["modelMaxOutputTokens"].get(upstream_model, provider["defaultMaxOutputTokens"])
    location, basis = profiles.classify_location(route)
    route.update({"location": location, "location_basis": basis})
    return route, max_output


def catalog_facts(
    source: str, row: Mapping[str, Any] | None, max_output: int | None
) -> dict[str, Any]:
    def fact(field: str, kinds: tuple[type, ...]) -> dict[str, Any]:
        value = row.get(field) if row is not None else None
        if value is not None and type(value) in kinds:
            return profiles.stated(value, "catalog")
        return profiles.unknown("not_stated")

    rewritten = row.get("opencodex_multi_agent_version_origin") if row is not None else None
    return {
        "source": source if row is not None else "absent",
        "entry_sha256": profiles.catalog_entry_sha256(row),
        "row_surface": row.get("multi_agent_version") if row is not None and row.get("multi_agent_version") in profiles.SURFACES else None,
        "rewritten_from": rewritten if isinstance(rewritten, str) and rewritten != row.get("multi_agent_version") else None,
        "context_window": fact("context_window", (int,)),
        "max_output_tokens": (
            profiles.stated(max_output, "provider") if max_output is not None else profiles.unknown("not_stated")
        ),
        "default_effort": fact("default_reasoning_level", (str,)),
        "parallel_tool_calls": fact("supports_parallel_tool_calls", (bool,)),
    }


# ---------------------------------------------------------------- private Codex homes


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ",".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, Mapping):
        return "{" + ",".join(json.dumps(str(key)) + "=" + _toml_value(item) for key, item in value.items()) + "}"
    raise ProbeError("unsupported configuration value " + repr(type(value)))


def write_codex_home(
    codex_home: Path,
    *,
    model: str,
    effort: str,
    config: Mapping[str, Any],
    catalog: Mapping[str, Any] | None,
    all_v1: bool,
    v2_enabled: bool,
    stand_in: str | None,
) -> None:
    """A private home: the user's route settings, a catalog copy, one feature set."""

    codex_home.mkdir(mode=0o700, parents=True)
    lines = [f"model={json.dumps(model)}", f"model_reasoning_effort={json.dumps(effort)}"]
    for key in ROUTE_KEYS:
        if isinstance(config.get(key), str):
            value = config[key]
            if stand_in is not None and key in ("openai_base_url", "chatgpt_base_url", "experimental_realtime_ws_base_url"):
                value = stand_in
            lines.append(f"{key}={json.dumps(value)}")
    if stand_in is not None and not isinstance(config.get("openai_base_url"), str):
        lines.append(f"openai_base_url={json.dumps(stand_in)}")
    if catalog is not None:
        copy = json.loads(json.dumps(catalog))
        if all_v1:
            for row in copy["models"]:
                if isinstance(row, dict):
                    row["multi_agent_version"] = "v1"
        (codex_home / "catalog.json").write_text(json.dumps(copy), encoding="utf-8")
        os.chmod(codex_home / "catalog.json", 0o600)
        lines.append(f"model_catalog_json={json.dumps(str(codex_home / 'catalog.json'))}")
    lines.extend([
        'approval_policy="never"', 'sandbox_mode="workspace-write"',
        "[analytics]", "enabled=false", "[history]", 'persistence="none"',
        "[features]", "multi_agent=true",
        "[features.multi_agent_v2]", "enabled=" + ("true" if v2_enabled else "false"),
        "[agents]", "enabled=true", "max_threads=2",
    ])
    providers = config.get("model_providers") if isinstance(config.get("model_providers"), Mapping) else {}
    for name, entry in providers.items():
        if not isinstance(entry, Mapping):
            continue
        lines.append("[model_providers." + json.dumps(str(name)) + "]")
        for key, value in entry.items():
            if stand_in is not None and key in CREDENTIAL_KEYS:
                continue
            if stand_in is not None and key == "base_url":
                value = stand_in
            lines.append(json.dumps(str(key)) + "=" + _toml_value(value))
        if stand_in is not None:
            lines.extend(["request_max_retries=0", "stream_max_retries=0"])
    (codex_home / "config.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(codex_home / "config.toml", 0o600)
    if stand_in is not None:
        (codex_home / "auth.json").write_text(json.dumps({"OPENAI_API_KEY": "orch-dork-stand-in"}), encoding="utf-8")
    else:
        login = codex_config_home() / "auth.json"
        if login.is_file():
            shutil.copyfile(login, codex_home / "auth.json")
    if (codex_home / "auth.json").exists():
        os.chmod(codex_home / "auth.json", 0o600)

def prepare_private_home(home: Path, *, source: Path | None = None) -> dict[str, Any]:
    """Copy the bounded managed prompt helper once into a private HOME.

    The default source is ``$HOME/.local/libexec/codex_maintenance.py``:
    Codex resolves this helper beneath ``HOME`` at every start, so a private
    Codex home without the helper stops the probe before any worker spawn.
    This function copies the helper into ``home/.local/libexec/`` with
    explicit 0o600 mode (no exec bit preservation, no umask propagation),
    leaves the private state directory under ``home/.local/state`` for
    the helper's update state, and returns a factual staged record.

    Initial missing, symlink, oversized, or target-already-present findings
    return ``staged=False`` with a reason; the public probe path keeps
    running.  Post-write source drift (changed bytes or source grew past
    the bounded ceiling) raises :class:`ProbeError` because the staged
    helper would be stale at this point; admission must not silently
    accept it.
    """

    helper_name = "codex_maintenance.py"
    state = home / ".local" / "state"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = source if source is not None else Path.home() / ".local" / "libexec" / helper_name
    # Every initial reason and the success path return the same factual
    # field set.  ``source`` is the observed path; ``source_missing``
    # leaves it None to mean "no observed source".  ``sha256``,
    # ``target``, ``size``, and ``limit`` default to None and are
    # populated only when the field is factual.  ``staged=False``
    # reasons never imply admission.
    record = {"source": str(source), "state": str(state), "helper": helper_name,
              "staged": False, "reason": None, "sha256": None, "target": None,
              "size": None, "limit": None}
    if source.is_symlink():
        return {**record, "reason": "source_is_symlink"}
    if not source.is_file():
        return {**record, "source": None, "reason": "source_missing"}
    with source.open("rb") as stream:
        raw = stream.read(MAX_HELPER_BYTES + 1)
    if len(raw) > MAX_HELPER_BYTES:
        return {**record, "reason": "source_oversized",
                "size": len(raw), "limit": MAX_HELPER_BYTES}
    target = home / ".local" / "libexec" / helper_name
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        return {**record, "reason": "target_already_present",
                "target": str(target)}
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(target), flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    with target.open("rb") as stream:
        copied = stream.read(MAX_HELPER_BYTES + 1)
    with source.open("rb") as stream:
        current = stream.read(MAX_HELPER_BYTES + 1)
    if copied != raw or current != raw:
        raise ProbeError("managed prompt helper changed during private-home preparation")
    return {**record, "staged": True, "sha256": hashlib.sha256(raw).hexdigest(),
            "target": str(target), "size": len(raw)}


class StandIn:
    """A provider that refuses every request, so a dry run calls no model."""

    def __init__(self) -> None:
        self.requests = 0
        self.bodies = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _refuse(self) -> None:
                owner.requests += 1
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    owner.bodies += 1
                    self.rfile.read(min(length, MAX_WIRE_BYTES))
                body = json.dumps({"error": {
                    "message": "orch-dork onboarding stand-in refuses every request",
                    "type": "invalid_request_error", "code": "orch_dork_stand_in",
                }}).encode()
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = _refuse

            def log_message(self, *_args: Any) -> None:
                pass

        self.server = QuietServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return "http://127.0.0.1:" + str(self.server.server_address[1]) + "/v1"

    def __enter__(self) -> StandIn:
        self.thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


class AppServer:
    """One owned Codex app server spoken to over JSON lines."""

    def __init__(self, codex: str, codex_home: Path, home: Path, workspace: Path, phase: str) -> None:
        environment = dict(os.environ)
        # Drop any inherited ``XDG_STATE_HOME`` so the helper's update
        # state cannot leak outside the private HOME when no private
        # state directory exists.  When prepare_private_home staged a
        # managed prompt helper into the private home, the override
        # below restores ``XDG_STATE_HOME`` to that private path; the
        # helper's HOME-based default then remains inside the private
        # HOME.
        environment.pop("XDG_STATE_HOME", None)
        environment.update({
            "CODEX_HOME": str(codex_home), "HOME": str(home), PHASE_ENV: phase,
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        # The private HOME carries its own maintenance state under
        # ``home/.local/state``.  When the private state directory
        # exists, ``XDG_STATE_HOME`` points at it; this is the only
        # environment variable Codex passes through to the helper.
        private_state = home / ".local" / "state"
        if private_state.is_dir():
            environment["XDG_STATE_HOME"] = str(private_state)
        self.stderr_path = codex_home.parent / ("app-server-" + phase + ".stderr")
        self._stderr = self.stderr_path.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            [codex, "app-server", "--stdio"], cwd=workspace, env=environment,
            start_new_session=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self._stderr,
        )
        self.next_id = 1
        self.buffer = bytearray()
        self.notifications: list[dict[str, Any]] = []

    def send(self, value: Mapping[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write((json.dumps(value, separators=(",", ":")) + "\n").encode())
        self.process.stdin.flush()

    def receive(self, timeout: float) -> dict[str, Any] | None:
        assert self.process.stdout is not None
        descriptor = self.process.stdout.fileno()
        deadline = time.monotonic() + timeout
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self.buffer[:newline])
                del self.buffer[: newline + 1]
                value = json.loads(line.decode("utf-8"))
                if not isinstance(value, dict):
                    raise ProbeError("app server sent a non-object message")
                value["_received"] = time.monotonic()
                return value
            if len(self.buffer) > MAX_WIRE_BYTES:
                raise ProbeError("app server message limit exceeded")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([descriptor], [], [], remaining)
            if not ready:
                return None
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                raise ProbeError("app server closed its connection: " + self.stderr_tail())
            self.buffer.extend(chunk)

    def call(self, method: str, params: Mapping[str, Any], timeout: float = 60) -> dict[str, Any]:
        request = self.next_id
        self.next_id += 1
        self.send({"id": request, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            message = self.receive(max(0.0, deadline - time.monotonic()))
            if message is None:
                raise ProbeError(method + " timed out")
            if message.get("id") != request:
                self.notifications.append(message)
                continue
            if "error" in message:
                error = message["error"]
                raise ProbeError(method + ": " + str(error.get("message") if isinstance(error, dict) else error))
            result = message.get("result")
            if not isinstance(result, dict):
                raise ProbeError(method + ": invalid result")
            return result

    def initialize(self) -> None:
        self.call("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {"experimentalApi": True},
            "clientInfo": {"name": "orch-dork-onboarding", "version": "1"},
        })
        self.send({"method": "initialized", "params": {}})

    def stderr_tail(self) -> str:
        self._stderr.flush()
        try:
            return self.stderr_path.read_text(encoding="utf-8", errors="replace")[-600:]
        except OSError:
            return ""

    def close(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(self.process.pid, sig)
            except ProcessLookupError:
                break
            try:
                self.process.wait(timeout=5)
                break
            except subprocess.TimeoutExpired:
                continue
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                stream.close()
        self._stderr.close()


# ---------------------------------------------------------------- rollouts


def read_rollouts(codex_home: Path) -> list[dict[str, Any]]:
    """Per rollout: its session, turn contexts, tool calls, and last token count."""

    found = []
    for path in sorted((codex_home / "sessions").rglob("rollout-*.jsonl")):
        record: dict[str, Any] = {
            "id": None, "parent": None, "contexts": [], "calls": 0, "parse_errors": 0, "tokens": None,
        }
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            payload = entry.get("payload") if isinstance(entry, dict) else None
            if not isinstance(payload, dict):
                continue
            kind = entry.get("type")
            if kind == "session_meta":
                record["id"] = payload.get("id")
                source = payload.get("source")
                spawn = source.get("subagent", {}).get("thread_spawn", {}) if isinstance(source, dict) else {}
                record["parent"] = spawn.get("parent_thread_id") if isinstance(spawn, dict) else None
            elif kind == "turn_context":
                record["contexts"].append({
                    key: payload.get(key) for key in ("model", "effort", "multi_agent_version")
                })
            elif kind == "response_item" and payload.get("type") in ("function_call", "custom_tool_call"):
                record["calls"] += 1
            elif kind == "response_item" and payload.get("type") in (
                "function_call_output", "custom_tool_call_output"
            ):
                if "failed to parse" in json.dumps(payload.get("output")).lower():
                    record["parse_errors"] += 1
            elif kind == "event_msg" and payload.get("type") == "token_count":
                record["tokens"] = payload.get("info")
        found.append(record)
    return found


# ---------------------------------------------------------------- dry runs


def dry_run(
    codex: str, temp: Path, *, name: str, model: str, effort: str, config: Mapping[str, Any],
    catalog: Mapping[str, Any] | None, all_v1: bool, v2_enabled: bool,
) -> dict[str, Any]:
    """The surface Codex assigns the model, observed with no model call."""

    base = temp / ("dry-" + name)
    home, workspace = base / "home", base / "workspace"
    home.mkdir(parents=True)
    workspace.mkdir()
    staged = prepare_private_home(home)
    with StandIn() as stand_in:
        write_codex_home(
            base / "codex-home", model=model, effort=effort, config=config, catalog=catalog,
            all_v1=all_v1, v2_enabled=v2_enabled, stand_in=stand_in.url,
        )
        server = AppServer(codex, base / "codex-home", home, workspace, "dry_run")
        try:
            server.initialize()
            listed = None
            if name == "user":
                rows = server.call("model/list", {}).get("data") or []
                listed = next(
                    (row for row in rows if isinstance(row, dict) and model in (row.get("id"), row.get("model"))),
                    None,
                )
            thread = server.call("thread/start", {
                "approvalPolicy": "never", "cwd": str(workspace), "model": model,
                "sandbox": "read-only", "serviceName": "orch-dork-onboarding",
            })["thread"]["id"]
            turn = server.call("turn/start", {
                "threadId": thread, "input": [{"type": "text", "text": "onboarding dry run"}],
            })["turn"]["id"]
            deadline = time.monotonic() + DRY_RUN_SECONDS
            completed = False
            while time.monotonic() < deadline and not completed:
                message = server.receive(deadline - time.monotonic())
                if message is None:
                    break
                params = message.get("params") or {}
                completed = (
                    message.get("method") == "turn/completed"
                    and (params.get("turn") or {}).get("id") == turn
                )
            surfaces = [
                context.get("multi_agent_version")
                for rollout in read_rollouts(base / "codex-home")
                for context in rollout["contexts"]
                if context.get("model") == model
            ]
            surface = surfaces[0] if surfaces else None
            return {
                "surface": surface,
                "error": None if surface else "no turn context recorded",
                "model_calls": stand_in.bodies,
                "listed": listed,
                "managed_prompt_support": staged,
            }
        except ProbeError as error:
            return {"surface": None, "error": str(error),
                    "model_calls": stand_in.bodies, "listed": None,
                    "managed_prompt_support": staged}
        finally:
            server.close()


# ---------------------------------------------------------------- live probe


def probe_prompt(model: str, effort: str) -> str:
    worker = (
        "Read the file " + INPUT_FILE + " in the current working directory; it holds one line, "
        "a nonce. Write the file " + ARTIFACT_FILE + " in the same directory containing exactly "
        "this JSON object with that nonce: "
        + json.dumps({"schema": profiles.ARTIFACT_SCHEMA, "model": model, "nonce": "<nonce>"},
                     separators=(",", ":"))
        + ". Then reply ONBOARDING_WORKER_DONE."
    )
    spawn = {"fork_context": False, "message": worker, "model": model, "reasoning_effort": effort}
    return (
        "This is an Orch Dork onboarding probe. Execute exactly in order: call spawn_agent with "
        + json.dumps(spawn, separators=(",", ":"), sort_keys=True)
        + '; wait_agent with exactly these arguments: {"targets":["<returned worker id>"],'
        '"timeout_ms":240000} until it reports completed; close_agent with exactly these '
        'arguments: {"target":"<returned worker id>"}. Call no other tools. '
        "Finish with ONBOARDING_ROOT_DONE."
    )


def live_probe(
    codex: str, temp: Path, *, model: str, effort: str, config: Mapping[str, Any],
    catalog: Mapping[str, Any] | None, all_v1: bool, v2_enabled: bool, nonce: str,
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run the one-spawn probe; return the observation and the latency/token sample."""

    base = temp / "live"
    home, workspace = base / "home", base / "workspace"
    home.mkdir(parents=True)
    workspace.mkdir()
    staged = prepare_private_home(home)
    (workspace / INPUT_FILE).write_text(nonce + "\n", encoding="utf-8")
    os.chmod(workspace / INPUT_FILE, 0o600)
    write_codex_home(
        base / "codex-home", model=model, effort=effort, config=config, catalog=catalog,
        all_v1=all_v1, v2_enabled=v2_enabled, stand_in=None,
    )
    observation: dict[str, Any] = {"turn": {}, "spawn": {}, "worker": {},
                                "managed_prompt_support": staged}
    sample: dict[str, Any] = {
        "effort": effort, "effective_context_window": None, "first_output_ms": None,
        "root_turn_ms": None, "worker_turn_ms": None,
        "tokens": {"input": None, "cached_input": None, "output": None, "total": None},
    }
    server = AppServer(codex, base / "codex-home", home, workspace, "live")
    try:
        server.initialize()
        thread = server.call("thread/start", {
            "approvalPolicy": "never", "cwd": str(workspace), "model": model,
            "sandbox": "workspace-write", "serviceName": "orch-dork-onboarding",
            "config": {"model_reasoning_effort": effort},
        })["thread"]["id"]
        turn = server.call("turn/start", {
            "threadId": thread, "input": [{"type": "text", "text": probe_prompt(model, effort)}],
            "approvalPolicy": "never",
        })["turn"]["id"]
        started = time.monotonic()
        deadline = started + timeout
        usage: dict[str, Any] = {}
        worker_started: dict[str, float] = {}
        worker_done: dict[str, dict[str, Any]] = {}
        first_output = None
        root_turn = None
        interrupted_for = None
        while root_turn is None:
            remaining = deadline - time.monotonic()
            message = server.receive(max(0.0, remaining)) if remaining > 0 else None
            if message is None:
                interrupted_for = "timeout"
                break
            method = message.get("method")
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            owner = params.get("threadId")
            if method == "thread/tokenUsage/updated" and isinstance(params.get("tokenUsage"), dict):
                usage[owner] = params["tokenUsage"]
            elif method in ("item/started", "item/agentMessage/delta", "item/reasoning/summaryTextDelta"):
                item = params.get("item") if isinstance(params.get("item"), dict) else {}
                if owner == thread and first_output is None and item.get("type") != "userMessage":
                    first_output = message["_received"]
            elif method == "turn/started" and owner != thread:
                worker_started.setdefault(owner, message["_received"])
            elif method == "turn/completed":
                completed = params.get("turn") if isinstance(params.get("turn"), dict) else {}
                if owner == thread and completed.get("id") == turn:
                    root_turn = completed
                    root_turn["_received"] = message["_received"]
                elif owner != thread:
                    worker_done[owner] = {"turn": completed, "at": message["_received"]}
            elif method == "error" and owner == thread:
                error = params.get("error") if isinstance(params.get("error"), dict) else {}
                text = str(error.get("message") or "")
                if params.get("willRetry") and "waiting for network" in text.lower():
                    observation["turn"].update({
                        "error_info": error.get("codexErrorInfo"), "error_message": text,
                    })
                    interrupted_for = "unreachable"
                    break
        if interrupted_for is not None:
            observation["turn"]["interrupted_for"] = interrupted_for
            try:
                server.call("turn/interrupt", {"threadId": thread, "turnId": turn}, timeout=INTERRUPT_SECONDS)
            except ProbeError:
                pass
        else:
            error = root_turn.get("error") if isinstance(root_turn.get("error"), dict) else None
            observation["turn"].update({
                "status": root_turn.get("status"),
                "error_info": error.get("codexErrorInfo") if error else None,
                "error_message": error.get("message") if error else None,
            })
            sample["root_turn_ms"] = int((root_turn["_received"] - started) * 1000)
        if first_output is not None:
            sample["first_output_ms"] = int((first_output - started) * 1000)
        try:
            history = server.call("thread/read", {"threadId": thread, "includeTurns": True})
        except ProbeError:
            history = {}
        items = [
            item
            for entry in (history.get("thread") or {}).get("turns", [])
            if isinstance(entry, dict)
            for item in entry.get("items", [])
            if isinstance(item, dict)
        ]
        spawns = [
            item for item in items
            if item.get("type") == "collabAgentToolCall" and item.get("tool") == "spawnAgent"
        ]
        output_items = [item for item in items if item.get("type") in ("agentMessage", "reasoning")]
        worker_ids = [
            worker for item in spawns for worker in item.get("receiverThreadIds") or []
            if isinstance(worker, str)
        ]
        if spawns:
            last = spawns[-1]
            states = last.get("agentsStates") if isinstance(last.get("agentsStates"), dict) else {}
            observation["spawn"] = {
                "called": True,
                "status": last.get("status"),
                "worker_ids": worker_ids,
                "detail": None if last.get("status") == "completed" else json.dumps(states)[:400],
            }
        rollouts = read_rollouts(base / "codex-home")
        root_rollout = next((row for row in rollouts if row["id"] == thread), None)
        workers = [row for row in rollouts if row["parent"] == thread]
        worker = next((row for row in workers if row["id"] in worker_ids), workers[0] if workers else None)
        if root_rollout is not None:
            contexts = [row for row in root_rollout["contexts"] if row.get("model") == model]
            observation["root_surface"] = contexts[0].get("multi_agent_version") if contexts else None
            observation["root_tool_calls"] = root_rollout["calls"]
            observation["root_tool_parse_errors"] = root_rollout["parse_errors"]
        if worker is not None:
            contexts = [row for row in worker["contexts"]]
            finished = worker_done.get(worker["id"]) or {}
            status = (finished.get("turn") or {}).get("status")
            if status is None:
                for item in items:
                    states = item.get("agentsStates") if isinstance(item.get("agentsStates"), dict) else {}
                    state = states.get(worker["id"])
                    if isinstance(state, dict) and state.get("status") in ("completed", "errored", "failed"):
                        status = state.get("status")
            observation["worker"] = {
                "found": True,
                "surface": contexts[0].get("multi_agent_version") if contexts else None,
                "model": contexts[0].get("model") if contexts else None,
                "status": "completed" if status == "completed" else (status or "unknown"),
                "tool_calls": worker["calls"],
                "tool_parse_errors": worker["parse_errors"],
                "detail": None if status == "completed" else "worker status " + str(status),
            }
            if worker["id"] in worker_started and worker["id"] in worker_done:
                sample["worker_turn_ms"] = int(
                    (worker_done[worker["id"]]["at"] - worker_started[worker["id"]]) * 1000
                )
        totals = {"input": 0, "cached_input": 0, "output": 0, "total": 0}
        counted = False
        for owner, value in usage.items():
            total = value.get("total") if isinstance(value.get("total"), dict) else {}
            for field, key in (("input", "inputTokens"), ("cached_input", "cachedInputTokens"),
                               ("output", "outputTokens"), ("total", "totalTokens")):
                if type(total.get(key)) is int:
                    totals[field] += total[key]
                    counted = True
            if owner == thread and type(value.get("modelContextWindow")) is int:
                sample["effective_context_window"] = value["modelContextWindow"]
        if counted:
            sample["tokens"] = totals
        observation["root_output"] = bool(
            output_items or spawns or (counted and totals["output"] > 0)
            or observation.get("root_tool_calls")
        )
        artifact = workspace / ARTIFACT_FILE
        if artifact.is_file() and artifact.stat().st_size <= MAX_ARTIFACT_BYTES:
            observation["artifact_text"] = artifact.read_text(encoding="utf-8", errors="replace")
        elif artifact.exists():
            observation["artifact_text"] = ""
    finally:
        server.close()
    return observation, sample


# ---------------------------------------------------------------- onboarding


def onboard(args: argparse.Namespace) -> dict[str, Any]:
    began = time.monotonic()
    version = subprocess.run([args.codex, "--version"], capture_output=True, text=True, timeout=30)
    codex_version = version.stdout.strip()
    if version.returncode != 0 or not codex_version:
        raise ProbeError("codex --version failed: " + version.stderr.strip()[-300:])
    config = read_user_config()
    _, catalog = load_catalog(config)
    row = catalog_row(catalog, args.model)
    source = "model_catalog_json"
    if row is not None:
        reused = reuse(args, row, codex_version)
        if reused is not None:
            return reused
    effort = args.effort or (row or {}).get("default_reasoning_level") or "medium"
    route, max_output = route_facts(config, args.model)
    user_v2 = v2_feature_enabled(config)
    nonce = secrets.token_hex(8)
    temp = Path(tempfile.mkdtemp(prefix="orch-dork-onboarding-"))
    os.chmod(temp, 0o700)
    try:
        dry_runs = {"user_codex": dry_run(
            args.codex, temp, name="user", model=args.model, effort=effort, config=config,
            catalog=catalog, all_v1=False, v2_enabled=user_v2,
        )}
        listed = dry_runs["user_codex"].pop("listed", None)
        if row is None and isinstance(listed, dict):
            # Codex's own catalog read through model/list: the row Codex
            # states, with the metadata model/list does not carry unknown.
            source = "model_list"
            row = {
                "slug": args.model,
                "multi_agent_version": listed.get("multiAgentVersion"),
                "default_reasoning_level": listed.get("defaultReasoningEffort"),
            }
            reused = reuse(args, row, codex_version)
            if reused is not None:
                shutil.rmtree(temp, ignore_errors=True)
                return reused
            effort = args.effort or row.get("default_reasoning_level") or effort
        catalog_record = catalog_facts(source, row, max_output)
        # The governed runner loads an all-v1 copy of the catalog the app
        # server would otherwise load: the user's catalog file, else Codex's.
        runner_catalog = catalog if catalog is not None else effective_catalog(args.codex)
        dry_runs["governed_runner"] = dry_run(
            args.codex, temp, name="runner", model=args.model, effort=effort, config=config,
            catalog=runner_catalog, all_v1=True, v2_enabled=False,
        )
        dry_runs["governed_runner"].pop("listed", None)
        model_calls = sum(run.pop("model_calls", 0) for run in dry_runs.values())
        if model_calls:
            raise ProbeError("a dry run sent a request body to the stand-in provider")
        location = next(
            (name for name in profiles.V1_LOCATIONS if dry_runs[name]["surface"] == "v1"),
            "governed_runner",
        )
        observation, sample = live_probe(
            args.codex, temp, model=args.model, effort=effort, config=config,
            catalog=runner_catalog if location == "governed_runner" else catalog,
            all_v1=location == "governed_runner", v2_enabled=user_v2 if location == "user_codex" else False,
            nonce=nonce, timeout=args.timeout,
        )
        observation["catalog_row_present"] = row is not None
        observation["dry_runs"] = dry_runs
        verdict = profiles.classify_probe(observation, model=args.model, nonce=nonce)
        profile = profiles.build_profile(
            model=args.model,
            onboarded_at=profiles.utc_now(),
            codex_version=codex_version,
            route=route,
            catalog=catalog_record,
            v2_feature_enabled=user_v2,
            verdict=verdict,
            sample=sample,
            probe={
                "spawns": 1 if observation.get("spawn", {}).get("called") else 0,
                "duration_ms": int((time.monotonic() - began) * 1000),
                "dry_run_model_calls": 0,
                "harness": HARNESS,
            },
        )
        path = profiles.write_profile(profile, args.store)
    except BaseException:
        if not args.keep_temp:
            preserved = profiles.store_root(args.store) / "failed" / temp.name
            preserved.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            for login in temp.rglob("auth.json"):
                login.unlink()
            shutil.move(str(temp), str(preserved))
            print("onboarding state preserved without credentials at " + str(preserved), file=sys.stderr)
        raise
    if args.keep_temp:
        print("onboarding state kept at " + str(temp), file=sys.stderr)
    else:
        shutil.rmtree(temp, ignore_errors=True)
    return {
        "status": "ONBOARDED",
        "model": args.model,
        "profile": str(path),
        "profile_sha256": profile["profile_sha256"],
        "reachability": profile["reachability"],
        "v1_location": profile["surface"]["v1_location"],
        "findings": [entry["code"] for entry in profile["findings"]],
        "duration_ms": profile["probe"]["duration_ms"],
    }


def list_stored(store: Any) -> dict[str, Any]:
    rows = []
    for profile in profiles.list_profiles(store):
        rows.append({
            "model": profile["model"],
            "onboarded_at": profile["onboarded_at"],
            "codex_version": profile["codex_version"],
            "family": profile["family"].get("value"),
            "location": profile["route"]["location"],
            "v1_location": profile["surface"]["v1_location"],
            "reachability": profile["reachability"],
            "findings": [entry["code"] for entry in profile["findings"]],
        })
    return {"status": "LISTED", "store": str(profiles.store_root(store)), "profiles": rows}


def v1_change(args: argparse.Namespace) -> dict[str, Any]:
    """Plan, or apply after confirmation, the opt-in that moves the user's own
    Codex to V1 (ADR 0012).  Without --v1-apply nothing changes; --v1-apply
    takes the plan digest the plan printed as the confirmation."""

    config = read_user_config()
    catalog_path, catalog = load_catalog(config)
    if catalog is None:
        catalog = effective_catalog(args.codex)
    if catalog is None:
        raise ProbeError("Codex rendered no model catalog")
    rows = profiles.catalog_rows(catalog)
    arguments = {
        "codex_home": codex_config_home(),
        "catalog": catalog,
        "v2_feature_enabled": v2_feature_enabled(config),
        # OpenCodex's multiAgentMode moves the catalog only when OpenCodex
        # writes the catalog the user's Codex loads.
        "opencodex_config": (
            OPENCODEX_CONFIG
            if catalog_path is not None and OPENCODEX_CONFIG.is_file()
            and catalog_path.name == "opencodex-catalog.json"
            else None
        ),
    }
    location = profiles.v1_location(rows, v2_feature_enabled=arguments["v2_feature_enabled"])
    plan = profiles.plan_user_codex_v1_change(**arguments)
    result = {"status": "PLANNED", "v1_location": location, "plan": plan}
    if args.v1_apply is not None:
        result = {
            "status": "APPLY",
            "v1_location": location,
            "report": profiles.apply_user_codex_v1_change(plan, confirmation=args.v1_apply, **arguments),
        }
    return result


def reuse(args: argparse.Namespace, row: Mapping[str, Any], codex_version: str) -> dict[str, Any] | None:
    """The stored profile's summary when it is current, else None."""

    if args.force:
        return None
    try:
        existing = profiles.read_profile(args.model, args.store)
    except (OSError, ValueError):
        return None
    if existing is None or profiles.redo_reasons(
        existing, model=args.model, catalog_entry=row, codex_version=codex_version
    ):
        return None
    return {
        "status": "REUSED", "model": args.model,
        "profile": str(profiles.profile_path(args.model, args.store)),
        "findings": [entry["code"] for entry in existing["findings"]],
    }


def default_codex() -> str:
    return shutil.which("codex") or str(Path.home() / ".local" / "bin" / "codex")


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["--detach-job"] and len(argv) == 2:
        return _detach_job(Path(argv[1]))
    if argv[:1] == ["--job-dir"] and len(argv) == 2:
        return run_job(Path(argv[1]))
    parser = argparse.ArgumentParser(description="Onboard one model into an Orch Dork profile (ADR 0012).")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--model", help="the exact model identifier Codex spawns")
    target.add_argument("--list", action="store_true", help="list the stored profiles")
    target.add_argument(
        "--v1-plan", action="store_true",
        help="show where governed runs hold V1 and the opt-in change to your own Codex; changes nothing",
    )
    target.add_argument(
        "--v1-apply", metavar="PLAN_SHA256",
        help="apply the opt-in change --v1-plan showed, confirmed by its plan digest",
    )
    parser.add_argument("--effort", help="reasoning effort for the probe; default: the catalog's")
    parser.add_argument("--force", action="store_true", help="onboard again even when the profile is current")
    parser.add_argument("--codex", default=default_codex(), help="the Codex executable")
    parser.add_argument("--store", help="profile store; default: $" + profiles.STORE_ENV + " or the user's onboarding state")
    parser.add_argument("--timeout", type=float, default=LIVE_SECONDS, help="live probe bound in seconds")
    parser.add_argument("--keep-temp", action="store_true", help="keep the private Codex home for inspection")
    args = parser.parse_args(argv)
    try:
        if args.list:
            result = list_stored(args.store)
        elif args.v1_plan or args.v1_apply is not None:
            result = v1_change(args)
        else:
            result = onboard(args)
        status = 0
    except (ProbeError, OSError, ValueError, subprocess.SubprocessError) as error:
        result = {"status": "FAILED", "model": args.model, "error": str(error)}
        status = 1
    print(json.dumps(result, sort_keys=True))
    return status


# ---------------------------------------------------------------- jobs from a chat


JOB_SCHEMA = "orch-dork/onboarding-job/v1"
JOB_STATUS_SCHEMA = "orch-dork/onboarding-job-status/v1"
READ_SCHEMA = "orch-dork/onboarding-read/v1"
# The MCP input of read_onboarding, named by the lifecycle map.
READ_INPUT_SCHEMA = "orch-dork/onboarding-read-input/v1"
MAX_READ_WAIT_SECONDS = 50
DEFAULT_READ_WAIT_SECONDS = 45
MAX_JOB_MODELS = 8
# A job queued behind a running one waits this long for its turn.
QUEUE_WAIT_SECONDS = 1800
_JOB_ID = re.compile(r"\Aob-\d{8}-[0-9a-f]{8}\Z")


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sealed(core: Mapping[str, Any], field: str) -> dict[str, Any]:
    value = {key: item for key, item in core.items() if key != field}
    return {**value, field: _sha256(value)}


def _write_private(path: Path, value: Any, *, create_only: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    if create_only:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        return
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _read_private(path: Path) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
        raise ProbeError("unreadable onboarding record " + path.name)
    return json.loads(path.read_text(encoding="utf-8"))


def jobs_root(store: Any = None) -> Path:
    return profiles.store_root(store) / "jobs"


def _process_start(pid: int) -> str | None:
    try:
        raw = Path("/proc", str(pid), "stat").read_text(encoding="utf-8")
        return "proc:" + raw[raw.rindex(")") + 2:].split()[19]
    except (OSError, ValueError, IndexError):
        pass
    try:
        started = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True,
                                 text=True, timeout=5, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return "ps:" + started if started else None


def _holder_alive(holder: Any) -> bool:
    pid = holder.get("pid") if isinstance(holder, Mapping) else None
    if type(pid) is not int or pid < 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return holder.get("process_start") in (None, _process_start(pid))


def active_job(store: Any = None) -> str | None:
    """The job running now, if one is."""

    try:
        holder = _read_private(jobs_root(store) / "active.json")
    except (OSError, ValueError, ProbeError):
        return None
    return holder.get("job_id") if _holder_alive(holder) else None


def start_job(
    models: Any, *, codex: str | None, store: Any = None, codex_home: Any = None,
    effort: str | None = None, launch: bool = True, force: bool = False,
) -> dict[str, Any]:
    """Record one onboarding job and start it detached; report at once.

    A job started while another runs waits for it, so onboarding is never
    lost to a busy machine and two probes never run at once.
    """

    if type(force) is not bool:
        raise ProbeError("onboarding force must be a boolean")
    names = list(dict.fromkeys(models)) if isinstance(models, (list, tuple)) else []
    if not 1 <= len(names) <= MAX_JOB_MODELS or any(
        not isinstance(name, str) or not name or len(name) > 256 for name in names
    ):
        raise ProbeError("an onboarding job names one to eight models")
    job_id = "ob-" + time.strftime("%Y%m%d", time.gmtime()) + "-" + secrets.token_hex(4)
    job_dir = jobs_root(store) / job_id
    job_dir.mkdir(parents=True, mode=0o700)
    request = _sealed({
        "schema": JOB_SCHEMA,
        "job_id": job_id,
        "models": names,
        "codex": codex or default_codex(),
        "codex_home": str(Path(codex_home) if codex_home else codex_config_home()),
        "store": str(profiles.store_root(store)),
        "effort": effort,
        "force": force,
        "requested_at": profiles.utc_now(),
    }, "request_sha256")
    _write_private(job_dir / "request.json", request, create_only=True)
    _write_status(job_dir, "QUEUED", {name: {"state": "pending"} for name in names})
    if launch:
        environment = dict(os.environ)
        environment["CODEX_HOME"] = request["codex_home"]
        environment[profiles.STORE_ENV] = request["store"]
        trampoline = subprocess.run(
            [sys.executable, "-B", str(Path(__file__).resolve()), "--detach-job", str(job_dir)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False,
            env=environment,
        )
        if trampoline.returncode != 0:
            _write_status(job_dir, "FAILED", {name: {"state": "failed", "error": "job did not start"}
                                              for name in names})
            raise ProbeError("onboarding job did not start: " + (trampoline.stderr or "")[-300:])
    return {"status": "STARTED", "job_id": job_id, "models": names}


def _write_status(job_dir: Path, state: str, models: Mapping[str, Any]) -> None:
    _write_private(job_dir / "status.json", _sealed({
        "schema": JOB_STATUS_SCHEMA, "job_id": job_dir.name, "state": state,
        "models": dict(models), "updated_at": profiles.utc_now(),
    }, "status_sha256"))


def _detach_job(job_dir: Path) -> int:
    log = open(job_dir / "job.log", "ab")
    try:
        subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__).resolve()), "--job-dir", str(job_dir)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, close_fds=True,
            cwd=str(job_dir),
        )
    finally:
        log.close()
    return 0


def run_job(job_dir: Path) -> int:
    """Onboard each of a job's models in turn, recording progress after each."""

    request = _read_private(job_dir / "request.json")
    if request.get("request_sha256") != _sha256({k: v for k, v in request.items() if k != "request_sha256"}):
        raise ProbeError("onboarding job request altered")
    lock = jobs_root(request["store"]) / "active.json"
    holder = {"job_id": request["job_id"], "pid": os.getpid(), "process_start": _process_start(os.getpid())}
    deadline = time.monotonic() + QUEUE_WAIT_SECONDS
    while True:
        try:
            _write_private(lock, holder, create_only=True)
            break
        except FileExistsError:
            try:
                current = _read_private(lock)
            except (OSError, ValueError, ProbeError):
                current = {}
            if not _holder_alive(current):
                try:
                    lock.unlink()
                except FileNotFoundError:
                    pass
                continue
            if time.monotonic() >= deadline:
                _write_status(job_dir, "FAILED", {name: {"state": "failed", "error": "another job ran too long"}
                                                  for name in request["models"]})
                return 1
            time.sleep(2)
    models: dict[str, Any] = {name: {"state": "pending"} for name in request["models"]}
    try:
        for name in request["models"]:
            models[name] = {"state": "running", "started_at": profiles.utc_now()}
            _write_status(job_dir, "RUNNING", models)
            arguments = argparse.Namespace(
                model=name, effort=request["effort"], force=request.get("force", False), codex=request["codex"],
                store=request["store"], timeout=LIVE_SECONDS, keep_temp=False,
            )
            try:
                result = onboard(arguments)
            except (ProbeError, OSError, ValueError, subprocess.SubprocessError) as error:
                models[name] = {"state": "failed", "error": str(error)[-500:]}
                continue
            models[name] = {
                "state": "reused" if result.get("status") == "REUSED" else "onboarded",
                "findings": result.get("findings", []),
                "reachability": result.get("reachability"),
                "v1_location": result.get("v1_location"),
                "duration_ms": result.get("duration_ms"),
            }
        _write_status(job_dir, "DONE", models)
    finally:
        try:
            if _read_private(lock).get("job_id") == request["job_id"]:
                lock.unlink()
        except (OSError, ValueError, ProbeError):
            pass
    return 0


def read_job(job_id: Any, *, store: Any = None, wait_seconds: float = 0) -> dict[str, Any]:
    """A job's progress, waiting a bounded time for it to finish."""

    if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
        raise ProbeError("unknown onboarding job")
    job_dir = jobs_root(store) / job_id
    deadline = time.monotonic() + max(0.0, wait_seconds)
    while True:
        status = _read_private(job_dir / "status.json")
        if status.get("state") in ("DONE", "FAILED") or time.monotonic() >= deadline:
            return status
        time.sleep(0.5)


def read_from_task(arguments: Mapping[str, Any], *, store: Any = None) -> dict[str, Any]:
    """The read_onboarding tool: a job's progress and whether governed runs may start."""

    wait = arguments.get("wait_seconds", DEFAULT_READ_WAIT_SECONDS)
    if type(wait) is not int or not 0 <= wait <= MAX_READ_WAIT_SECONDS:
        return _sealed({"schema": READ_SCHEMA, "status": "REFUSED", "reason": "onboarding:request_invalid"},
                       "report_sha256")
    try:
        status = read_job(arguments.get("job_id"), store=store, wait_seconds=wait)
    except (OSError, ValueError, ProbeError) as error:
        return _sealed({"schema": READ_SCHEMA, "status": "REFUSED", "reason": "onboarding:job_unknown",
                        "detail": str(error)[:200]}, "report_sha256")
    rows = []
    for name, state in status["models"].items():
        profile = profiles.onboarded(name, store)
        reasons = profiles.not_passed_reasons(profile) if profile is not None else ["not_onboarded"]
        rows.append({"model": name, **state, "passed": not reasons, "reasons": reasons})
    gate = profiles.governed_admission(list(status["models"]), root=store)
    return _sealed({
        "schema": READ_SCHEMA,
        "status": status["state"],
        "job_id": status["job_id"],
        "models": rows,
        "governed_runs": gate["status"],
        "governed_runs_refused_for": gate["issues"],
    }, "report_sha256")


if __name__ == "__main__":
    raise SystemExit(main())
