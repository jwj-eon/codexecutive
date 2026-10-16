#!/usr/bin/env python3
"""A session-scoped loopback view and enrollment client (Issue 197).

The helper owns no governed task or action authority. Its write surface is
limited to the same enrollment/model seams used by chat; runs are projections.
Packaged assets work without a CDN, build tool, sign-in, or hosted service.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlsplit


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

ASSETS = SCRIPT_DIR.parent / "ui"
MAX_BODY = 32_768
MAX_RESPONSE = 1_048_576
MAX_TAILSCALE_OUTPUT = 1_048_576
DEFAULT_LIFETIME = 1800
TAILNET_PORT = 8197
# Tailscale Serve adds these to every request it forwards and passes the
# client's own Host through unchanged, so their presence marks a forwarded
# request whatever Host it presents.
SERVE_FORWARDING_HEADERS = ("Tailscale-User-Login", "Tailscale-User-Name", "Tailscale-Headers-Info",
                            "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto")
HOSTNAME_LABEL = re.compile("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
TAILNET_SETUP_COMMAND = "tailscale serve --bg --https=8197 http://127.0.0.1:8197"
OPEN_SCHEMA = "orch-dork/local-ui-open/v1"
OPEN_INPUT_SCHEMA = "orch-dork/local-ui-open-input/v1"
RUN_ID = re.compile(r"\Agr-\d{8}-[0-9a-f]{8}\Z")
PLAN_ID = re.compile(r"\Aplan-[0-9a-f]{64}\Z")
JOB_ID = re.compile(r"\Aob-\d{8}-[0-9a-f]{8}\Z")
STATIC_FILES = {"": ("index.html", "text/html; charset=utf-8"),
                "index.html": ("index.html", "text/html; charset=utf-8"),
                "app.js": ("app.js", "text/javascript; charset=utf-8"),
                "styles.css": ("styles.css", "text/css; charset=utf-8")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _bounded(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if depth > 16 or count[0] > 4096:
        raise ValueError("request structure too large")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("finite JSON required")
    if isinstance(value, dict):
        for child in value.values():
            _bounded(child, depth + 1, count)
    elif isinstance(value, list):
        for child in value:
            _bounded(child, depth + 1, count)


class TailnetPortBusy(Exception):
    """Tailnet port is in use; refuse to bind it."""


def _kill_tailscale_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _read_tailscale_json(argv, *, timeout=5.0, max_output=MAX_TAILSCALE_OUTPUT):
    """Run `tailscale ...` and parse its single JSON document.

    The CLI is resolved with `shutil.which`; argv is fixed to the two
    whitelisted commands called through `tailnet_endpoint`. The process
    starts its own session and is killed (whole group) on a ~5 s timeout.
    Output is capped at 1 MiB. Any nonzero exit, missing CLI, oversized
    document, or unparsed JSON is a refusal callers translate.
    """
    exe = shutil.which(str(argv[0]))
    if not exe:
        raise FileNotFoundError("tailscale CLI missing")
    process = subprocess.Popen([exe, *argv[1:]], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                start_new_session=True)
    try:
        try:
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tailscale_group(process)
            try:
                process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            raise TimeoutError("tailscale timeout")
    except BaseException:
        _kill_tailscale_group(process)
        try:
            process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        raise
    if process.returncode != 0:
        raise ValueError("tailscale exit " + str(process.returncode))
    if stdout is None or len(stdout) > max_output:
        raise ValueError("tailscale output too large")
    return json.loads(stdout.decode("utf-8"))


def _hostname_valid(name):
    """Validate a normalized DNS hostname as a tailnet label sequence."""
    if not name or len(name) > 253:
        return False
    for label in name.split("."):
        if not HOSTNAME_LABEL.fullmatch(label):
            return False
    return True


def tailnet_endpoint(port, *, tailscale_json=None):
    """Return the tailnet endpoint triplet or one named refusal string.

    The optional `tailscale_json` callable runs one argv and returns one
    parsed JSON document. It is injectable so tests never call the real
    `tailscale` CLI. The default calls `_read_tailscale_json`.
    """
    reader = tailscale_json if tailscale_json is not None else _read_tailscale_json
    try:
        status = reader(["tailscale", "status", "--json"])
        serve = reader(["tailscale", "serve", "status", "--json"])
    except (FileNotFoundError, TimeoutError, OSError, ValueError,
            subprocess.SubprocessError, json.JSONDecodeError):
        return "tailnet_unavailable"
    if not isinstance(status, dict) or not isinstance(serve, dict):
        return "tailnet_unavailable"
    if status.get("BackendState") != "Running":
        return "tailnet_unavailable"
    self_node = status.get("Self")
    if not isinstance(self_node, dict):
        return "tailnet_unavailable"
    raw_dns = self_node.get("DNSName")
    user_id = self_node.get("UserID")
    users = status.get("User")
    if (not isinstance(raw_dns, str) or not isinstance(user_id, int)
            or not isinstance(users, dict)):
        return "tailnet_unavailable"
    login = users.get(str(user_id))
    if not isinstance(login, dict):
        return "tailnet_unavailable"
    login_name = login.get("LoginName")
    if not isinstance(login_name, str) or not login_name:
        return "tailnet_unavailable"
    if not raw_dns.endswith("."):
        dns = raw_dns.lower()
    else:
        dns = raw_dns[:-1].lower()
    if not _hostname_valid(dns):
        return "tailnet_unavailable"
    port_label = str(port)
    web_key = dns + ":" + port_label
    tcp = serve.get("TCP") if isinstance(serve.get("TCP"), dict) else {}
    web = serve.get("Web") if isinstance(serve.get("Web"), dict) else {}
    tcp_entry = tcp.get(port_label)
    web_entry = web.get(web_key)
    if not isinstance(tcp_entry, dict) and not isinstance(web_entry, dict):
        return "tailnet_mapping_missing"
    expected_proxy = "http://127.0.0.1:" + port_label
    if (not isinstance(tcp_entry, dict)
            or tcp_entry.get("HTTPS") is not True
            or not isinstance(web_entry, dict)
            or web_entry.get("Handlers") != {"/": {"Proxy": expected_proxy}}):
        return "tailnet_mapping_mismatch"
    allow = serve.get("AllowFunnel")
    if isinstance(allow, dict) and allow.get(web_key):
        return "tailnet_funnel_exposed"
    return {"host": web_key, "origin": "https://" + web_key, "login": login_name}

class LocalSession:
    """One ephemeral capability, numeric loopback listener and finite session."""

    def __init__(self, backend: Any, *, assets: Path = ASSETS,
                 lifetime: int = DEFAULT_LIFETIME, clock: Callable[[], float] = time.monotonic,
                 tailnet: Mapping[str, Any] | None = None,
                 port: int | None = None):
        # The bare local view serves only loopback; tailnet serves through the
        # host's persistent Tailscale Serve mapping to the same loopback port.
        self.view = "tailnet" if tailnet is not None else "local"
        if type(lifetime) is not int or not 1 <= lifetime <= 3600:
            raise ValueError("session lifetime must be 1 to 3600 seconds")
        self.backend = backend
        self.assets = Path(assets)
        self.secret = secrets.token_urlsafe(32)
        self.clock = clock
        self.deadline = clock() + lifetime
        self.ended = False
        if tailnet is not None:
            if (not isinstance(tailnet, Mapping) or not {"host", "origin", "login"} <= set(tailnet)
                    or not all(isinstance(tailnet[name], str) and tailnet[name] for name in ("host", "origin", "login"))):
                raise ValueError("tailnet endpoint incomplete")
            if tailnet["origin"] != "https://" + tailnet["host"]:
                raise ValueError("tailnet endpoint origin does not match its host")
            if port is None:
                port = TAILNET_PORT
            try:
                self.server = HTTPServer(("127.0.0.1", port), _Handler)
            except OSError as error:
                raise TailnetPortBusy("port " + str(port) + " busy: " + str(error)) from error
            self.tailnet = {"host": tailnet["host"], "origin": tailnet["origin"], "login": tailnet["login"]}
        else:
            self.server = HTTPServer(("127.0.0.1", 0), _Handler)
            self.tailnet = None
        self.server.session = self
        self.server.timeout = 0.5
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        # Static navigation needs the capability too. The fragment supplies
        # the script's non-ambient API bearer; neither is written to a log.
        self.local_url = self.origin + "/s/" + self.secret + "/#session=" + self.secret
        if self.tailnet is not None:
            self.url = self.tailnet["origin"] + "/s/" + self.secret + "/#session=" + self.secret
        else:
            self.url = self.local_url

    def alive(self) -> bool:
        return not self.ended and self.clock() < self.deadline

    def end(self) -> None:
        self.ended = True

    def serve(self) -> None:
        try:
            while self.alive():
                self.server.handle_request()
        finally:
            self.end()
            self.server.server_close()


class _Handler(BaseHTTPRequestHandler):
    server_version = "OrchDork"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, _format: str, *args: Any) -> None:
        # A request path can contain the session capability.
        pass

    def _reply(self, status: int, value: Any, content_type: str = "application/json") -> None:
        raw = value if isinstance(value, bytes) else canonical(value)
        if len(raw) > MAX_RESPONSE:
            status, raw = 413, canonical({"status": "REFUSED", "reason": "response_too_large"})
            content_type = "application/json"
        try:
            self.send_response(status)
            for key, text in {"Content-Type": content_type, "Content-Length": str(len(raw)),
                              "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                              "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                              "Content-Security-Policy": CSP, "Connection": "close"}.items():
                self.send_header(key, text)
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            # Navigating away can abandon a poll. There is no remaining
            # client to receive a refusal; do not write a second response.
            self.close_connection = True

    def _refuse(self, status: int, reason: str) -> None:
        self._reply(status, {"status": "REFUSED", "reason": reason})

    def _authorized(self, *, static: bool = False) -> bool:
        session = self.server.session
        if not session.alive():
            return False
        host = self.headers.get_all("Host", [])
        origins = self.headers.get_all("Origin", [])
        fetch_sites = self.headers.get_all("Sec-Fetch-Site", [])
        tailnet = session.tailnet
        loopback_host = session.origin.removeprefix("http://")
        allowed_hosts = {loopback_host}
        paired_origin_for_host: dict[str, str] = {loopback_host: session.origin}
        if tailnet is not None:
            tailnet_host = tailnet["host"]
            tailnet_origin = tailnet["origin"]
            allowed_hosts.add(tailnet_host)
            paired_origin_for_host[tailnet_host] = tailnet_origin
        if len(host) != 1 or host[0] not in allowed_hosts:
            return False
        expected_origin = paired_origin_for_host[host[0]]
        # Safari's no-referrer POST has Origin: null. Fetch Metadata is
        # browser-set (the Sec- prefix is forbidden to page scripts); require
        # one exact same-origin value before accepting that write shape.
        same_origin = origins == [expected_origin] or (
            self.command == "POST" and origins == ["null"] and fetch_sites == ["same-origin"]
        )
        if origins and not same_origin:
            return False
        if self.command == "POST" and not same_origin:
            return False
        if fetch_sites and fetch_sites not in (["none"], ["same-origin"]):
            return False
        via_tailnet = tailnet is not None and host[0] == tailnet_host
        forwarded = any(self.headers.get_all(name) for name in SERVE_FORWARDING_HEADERS)
        # A forwarded request must use the tailnet Host and pass the owner gate;
        # a local session never serves one.
        if forwarded and not via_tailnet:
            return False
        if via_tailnet and not self._tailnet_identity_ok(tailnet["login"]):
            return False
        if static:
            prefix = "/s/" + session.secret + "/"
            return self.path.startswith(prefix)
        auth = self.headers.get_all("Authorization", [])
        return len(auth) == 1 and hmac.compare_digest(auth[0].encode("utf-8"),
                                                     ("Bearer " + session.secret).encode("ascii"))

    def _tailnet_identity_ok(self, login: str) -> bool:
        users = self.headers.get_all("Tailscale-User-Login", [])
        xffs = self.headers.get_all("X-Forwarded-For", [])
        if (len(users) != 1 or users[0] != login
                or len(xffs) != 1 or not xffs[0] or "," in xffs[0]):
            return False
        try:
            address = ipaddress.ip_address(xffs[0].strip())
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv4Address):
            return address in ipaddress.ip_network("100.64.0.0/10")
        return address in ipaddress.ip_network("fd7a:115c:a1e0::/48")

    def do_OPTIONS(self) -> None:
        self._refuse(403, "origin_or_session")

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        static = parts.path.startswith("/s/")
        if not self._authorized(static=static):
            self._refuse(403, "origin_or_session")
            return
        if static:
            name = parts.path[len("/s/" + self.server.session.secret + "/"):]
            asset = STATIC_FILES.get(name)
            if asset is None or parts.query:
                self._refuse(404, "not_found")
                return
            path = self.server.session.assets / asset[0]
            if path.is_symlink() or not path.is_file():
                self._refuse(404, "not_found")
                return
            self._reply(200, path.read_bytes(), asset[1])
            return
        try:
            # Python 3.9 (the macOS system python3) refuses an empty query under
            # strict parsing; a path without one has no fields.
            query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True) if parts.query else {}
            backend = self.server.session.backend
            if parts.path == "/api/state" and not query:
                result = backend.state()
                if isinstance(result, dict):
                    # The helper owns the loopback vs tailnet decision; the
                    # backend reports only the records. Surface the kind of
                    # session so the page can vary the sidebar subtitle.
                    result = {**result, "view": self.server.session.view}
            elif parts.path == "/api/run" and set(query) == {"run_id"} and len(query["run_id"]) == 1:
                run_id = query["run_id"][0]
                if not (RUN_ID.fullmatch(run_id) or PLAN_ID.fullmatch(run_id)):
                    raise ValueError("run identifier invalid")
                result = backend.run(run_id)
            elif parts.path == "/api/online-diagram" and set(query) == {"run_id"} and len(query["run_id"]) == 1:
                # Same identifier rules as /api/run: the hosted copy is
                # admitted only for known run or plan ids. A view that the
                # sanitizer refuses becomes a 400 with no other content.
                run_id = query["run_id"][0]
                if not (RUN_ID.fullmatch(run_id) or PLAN_ID.fullmatch(run_id)):
                    raise ValueError("run identifier invalid")
                result = backend.online_diagram(run_id)
            elif parts.path == "/api/onboarding" and set(query) == {"job_id"} and len(query["job_id"]) == 1:
                job_id = query["job_id"][0]
                if not JOB_ID.fullmatch(job_id):
                    raise ValueError("job identifier invalid")
                result = backend.job(job_id)
            elif parts.path in ("/api/run", "/api/onboarding", "/api/online-diagram"):
                raise ValueError("query invalid")
            else:
                self._refuse(404, "not_found")
                return
            self._reply(200, result)
        except (ValueError, OSError):
            self._refuse(400, "request_or_record_invalid")

    def do_POST(self) -> None:
        if not self._authorized():
            self._refuse(403, "origin_or_session")
            return
        routes = {"/api/propose": ("propose", {"project_root"}),
                  "/api/confirm": ("confirm", {"confirmed", "arguments"}),
                  "/api/onboard": ("onboard", {"confirmed", "model"}),
                  "/api/v1/propose": ("propose_v1", set()),
                  "/api/v1/apply": ("apply_v1", {"confirmed", "plan_sha256"})}
        route = routes.get(self.path)
        if route is None:
            self._refuse(404, "not_found")
            return
        try:
            if self.headers.get_all("Content-Type") != ["application/json"] or self.headers.get("Transfer-Encoding"):
                raise ValueError("JSON required")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                raise ValueError("body length invalid")
            length = int(lengths[0])
            if length > MAX_BODY:
                self._refuse(413, "request_too_large")
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("body incomplete")
            body = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("finite JSON required")))
            _bounded(body)
            if not isinstance(body, dict) or set(body) != route[1]:
                raise ValueError("fields invalid")
            if "confirmed" in body and body["confirmed"] is not True:
                raise ValueError("confirmation required")
            if route[0] == "confirm" and not isinstance(body["arguments"], dict):
                raise ValueError("answers invalid")
            self._reply(200, getattr(self.server.session.backend, route[0])(body))
        except (ValueError, UnicodeError, OSError, TimeoutError):
            self._refuse(400, "request_or_record_invalid")


def _read_record(path: Path, *, limit: int = 4 * 1024 * 1024) -> dict[str, Any]:
    """Read one known regular file without following its final link."""

    if path.parent.is_symlink():
        raise ValueError("record directory is linked")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("record size or type invalid")
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("record grew too large")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    if not isinstance(value, dict):
        raise ValueError("record is not an object")
    return value


class LocalBackend:
    """Adapt existing records and enrollment seams; never act on a run."""

    def __init__(self, *, requesting_thread_id: str, records: Path | None = None,
                 home: Path | None = None, onboarding_root: Path | None = None,
                 registry: Path | None = None, codex: str | None = None,
                 connect: Any = None, start_onboarding: Any = None):
        import orch_dork_guided_enrollment as guided
        import orch_dork_governed_run_watcher as watcher
        import orch_dork_local_ui_projection as projection
        self.guided, self.watcher, self.projection = guided, watcher, projection
        self.records = records if records is not None else watcher.records_root()
        self.home = home if home is not None else watcher.codex_home()
        self.onboarding_root = onboarding_root
        self.registry = registry
        self.codex = codex or watcher.resolve_codex_executable()
        self.thread_id = requesting_thread_id
        # None reads the packaged runtime file; tests point it at a private copy.
        self.site_origin_path = None
        self.connect = connect or guided.app_server.AppServerConnection
        self.start_onboarding = start_onboarding
        self.proposals: set[str] = set()
        self.jobs: set[str] = set()
        self.v1_plan: dict[str, Any] | None = None
        self.catalog_cache: tuple[float, dict[str, Any]] | None = None

    def catalog(self) -> dict[str, Any]:
        # A dashboard poll must not reopen the shared daemon every three
        # seconds. Changes are reflected in at most ten seconds.
        moment = time.monotonic()
        if self.catalog_cache is None or moment - self.catalog_cache[0] > 10:
            self.catalog_cache = (moment, self.guided.codex_models(self.home, connect=self.connect))
        return self.catalog_cache[1]

    def state(self) -> dict[str, Any]:
        guided, watcher = self.guided, self.watcher
        listed = self.catalog()
        projects, runs, issues = [], [], []
        directory = self.records / "enrollments"
        for path in sorted(directory.glob("*.json"))[:256] if directory.is_dir() and not directory.is_symlink() else []:
            try:
                value = _read_record(path)
                root = Path(value["project_root"])
                if path.name != watcher.enrollment_path(self.records, root).name or watcher.enrollment_issues(value, root):
                    raise ValueError("enrollment invalid")
                projects.append({"project_root": str(root), **guided._summary(value)})
            except (KeyError, ValueError, OSError):
                issues.append("enrollment_record_unreadable")
        directory = self.records / "runs"
        for path in sorted(directory.iterdir(), key=lambda p: p.name, reverse=True)[:100] if directory.is_dir() and not directory.is_symlink() else []:
            if not RUN_ID.fullmatch(path.name) or path.is_symlink() or not path.is_dir():
                continue
            try:
                runs.append(self.projection.dashboard_row(self.run(path.name)))
            except (ValueError, OSError):
                issues.append("run_record_unreadable")
        directory = self.records / "plan-views"
        for path in sorted(directory.iterdir(), key=lambda p: p.name)[:100] if directory.is_dir() and not directory.is_symlink() else []:
            if not PLAN_ID.fullmatch("plan-" + path.name) or path.is_symlink() or not path.is_dir():
                continue
            try:
                preview = self.run("plan-" + path.name)
                if preview["state"] == "AWAITING_APPROVAL":
                    runs.append(self.projection.dashboard_row(preview))
            except (ValueError, OSError):
                issues.append("plan_view_unreadable")
        profiles = guided.onboarded.list_profiles(self.onboarding_root)
        names = list(dict.fromkeys([*listed["models"], *(p["model"] for p in profiles)]))
        models = []
        for name in names[:256]:
            profile = guided.onboarded.onboarded(name, self.onboarding_root)
            row = guided.model_status(name, onboarding_root=self.onboarding_root)
            surface = profile["surface"] if profile else {}
            models.append({**row, "privacy": row.get("location") or "unknown",
                           "v1_status": "available" if surface.get("v1_location") else "unavailable",
                           "v1_reason": None if surface.get("v1_location") else guided.onboarded.v1_refusal_reason(profile),
                           "v1_location": surface.get("v1_location"),
                           "profile_sha256": profile.get("profile_sha256") if profile else None})
        return {"schema": "orch-dork/local-ui-state/v1", "status": "PASS",
                "generation": json.loads((SCRIPT_DIR.parents[2] / ".codex-plugin/plugin.json").read_text())["version"],
                "projects": projects, "runs": runs, "models": models, "models_source": listed["source"],
                "v1": listed.get("location") or {"location": "unknown", "reason": "catalog_unavailable"},
                "workflow_profiles": list(guided.admission.WORKFLOW_PROFILES), "issues": sorted(set(issues))}

    def run(self, run_id: str) -> dict[str, Any]:
        if PLAN_ID.fullmatch(run_id):
            return self.plan(run_id)
        watcher = self.watcher
        run_dir = watcher.run_directory(self.records, run_id)
        if run_dir.is_symlink() or (self.records / "runs").is_symlink():
            raise ValueError("run directory is linked")
        state: dict[str, Any] = {"state": "UNKNOWN"}
        for name, key, seal in (("record.json", "record", "record_sha256"),
                                ("status.json", "status", "status_sha256"),
                                ("progress.json", "progress", "progress_sha256")):
            path = run_dir / name
            if not path.exists() and not path.is_symlink():
                continue
            value = _read_record(path)
            if not watcher.seal_valid(value, seal) or value.get("run_id") != run_id:
                raise ValueError("run record is not sealed for this run")
            state[key] = value
        if "record" in state:
            state["state"] = "TERMINAL"
        elif "status" in state:
            state["state"] = state["status"]["state"]
        request, claim = None, None
        path = run_dir / "request.json"
        if path.exists():
            request = _read_record(path)
            watcher.validate_request(request)
        path = watcher.claim_path(run_dir)
        if path.exists():
            claim = _read_record(path)
            if (not watcher.seal_valid(claim, "claim_sha256") or claim.get("run_id") != run_id
                    or (request is not None and claim.get("request_sha256") != watcher.policy.sha256(request))):
                raise ValueError("run claim does not bind this request")
        # A revision's frozen request summary supersedes the initial plan.
        revision = (state.get("record") or state.get("progress") or {}).get("revision", 1)
        if revision > 1:
            # Revisions have their own format; never substitute the initial
            # plan's lanes when the live plan changed and those facts are absent.
            request = None
        return self.projection.project_run(run_id, state, request=request, claim=claim)

    def plan(self, run_id: str) -> dict[str, Any]:
        digest = run_id.removeprefix("plan-")
        directory = self.records / "plan-views"
        if directory.is_symlink():
            raise ValueError("plan directory is linked")
        value = _read_record(directory / digest / "view.json")
        view = value.get("run")
        if (value.get("schema") != "orch-dork/local-ui-plan/v1"
                or not self.watcher.seal_valid(value, "view_sha256")
                or not isinstance(view, dict) or view.get("run_id") != run_id
                or view.get("canonical_digest") != digest
                or (view.get("graph") or {}).get("canonical_digest") != digest):
            raise ValueError("plan view does not bind this plan")
        task = value.get("requesting_thread_id")
        if not isinstance(task, str):
            raise ValueError("plan view task missing")
        ask_path = self.watcher.ask_path(self.records, digest, task)
        if (self.records / "asks").is_symlink():
            raise ValueError("ask directory is linked")
        try:
            ask = _read_record(ask_path)
        except FileNotFoundError:
            ask = None
        if (not self.guided.admission.ask_open(ask, now=datetime.now(timezone.utc), requesting_thread_id=task)
                or ask.get("plan_sha256") != digest):
            view["state"] = "PLAN_CLOSED"
        return view

    def propose(self, body: Mapping[str, Any]) -> dict[str, Any]:
        root = body.get("project_root")
        if not isinstance(root, str) or not Path(root).is_absolute():
            raise ValueError("absolute project path required")
        result = self.guided.propose(Path(root), requesting_thread_id=self.thread_id,
                                     records=self.records, home=self.home, registry=self.registry,
                                     onboarding_root=self.onboarding_root, codex=self.codex, connect=self.connect)
        digest = result.get("draft_sha256")
        if digest:
            self.proposals.add(digest)
        return result

    def confirm(self, body: Mapping[str, Any]) -> dict[str, Any]:
        args = body["arguments"]
        permitted = {"draft_sha256", "second_model", "keep_local", "checks", "chat_model", "v1_opt_in",
                     *self.guided.AUTHORITY_SETTINGS}
        if set(args) - permitted or args.get("draft_sha256") not in self.proposals:
            raise ValueError("answers do not bind this session's proposal")
        try:
            result = self.guided.confirm(args, requesting_thread_id=self.thread_id, records=self.records,
                                         home=self.home, onboarding_root=self.onboarding_root,
                                         codex=self.codex, start_onboarding=self.start_onboarding)
        except self.guided.EnrollmentBlocked as error:
            return {"status": "BLOCKED", "reason": error.reason,
                    "question": {"code": error.reason, "text": error.text, "options": error.options}}
        if result.get("onboarding"):
            self.jobs.add(result["onboarding"]["job_id"])
        return result

    def onboard(self, body: Mapping[str, Any]) -> dict[str, Any]:
        profile = self.guided.onboarded.onboarded(body["model"], self.onboarding_root)
        result = self.guided.onboard_from_task({"model": body["model"], "re_onboard": profile is not None},
                                              home=self.home, onboarding_root=self.onboarding_root,
                                              codex=self.codex, start_onboarding=self.start_onboarding)
        if result.get("job_id"):
            self.jobs.add(result["job_id"])
        return result

    def job(self, job_id: str) -> dict[str, Any]:
        if job_id not in self.jobs:
            raise ValueError("job not started by this session")
        return self.guided.onboarding_probe.read_job(job_id, store=self.onboarding_root)

    def propose_v1(self, _body: Mapping[str, Any]) -> dict[str, Any]:
        listed = self.catalog()
        v2 = listed.get("v2_feature_enabled")
        if v2 is None:
            return {"status": "REFUSED", "reason": "catalog_unavailable"}
        self.v1_plan = self.guided.v1_opt_in_plan(self.home, v2, self.codex)
        return self.v1_plan or {"status": "REFUSED", "reason": "v1_change_unavailable"}

    def online_diagram(self, run_id: str) -> dict[str, Any]:
        # The same run or plan view as /api/run, admitted to the hosted class.
        # A view the sanitizer refuses raises ValueError, which the handler
        # turns into its bare 400; the helper never contacts the Site.
        import orch_dork_online_diagram as online_diagram
        view = self.run(run_id)
        return online_diagram.offer(view, online_diagram.load_site_origin(self.site_origin_path))

    def apply_v1(self, body: Mapping[str, Any]) -> dict[str, Any]:
        if self.v1_plan is None or body.get("plan_sha256") != self.v1_plan.get("plan_sha256"):
            raise ValueError("confirmation does not bind this session's V1 plan")
        listed = self.catalog()
        result = self.guided.apply_v1_opt_in(self.home, self.v1_plan, bool(listed["v2_feature_enabled"]), self.codex)
        self.v1_plan = None
        self.catalog_cache = None
        return result


def _tailnet_refusal_payload(reason: str) -> dict[str, Any]:
    payload = {"schema": OPEN_SCHEMA, "status": "REFUSED", "reason": reason}
    if reason == "tailnet_mapping_missing":
        payload["setup_command"] = TAILNET_SETUP_COMMAND
    return payload


def start_from_task(arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
                    launch: Any = subprocess.Popen) -> dict[str, Any]:
    """Launch a finite owned helper, return its secret URL only to this task."""
    if not requesting_thread_id or not re.fullmatch(r"[0-9A-Za-z-]{8,64}", requesting_thread_id):
        return {"schema": OPEN_SCHEMA, "status": "REFUSED", "reason": "request_invalid"}
    view = None
    if isinstance(arguments, Mapping):
        keys = set(arguments)
        if keys == set():
            view = "local"
        elif keys == {"view"} and arguments.get("view") in ("local", "tailnet"):
            view = arguments["view"]
        else:
            return {"schema": OPEN_SCHEMA, "status": "REFUSED", "reason": "request_invalid"}
    else:
        return {"schema": OPEN_SCHEMA, "status": "REFUSED", "reason": "request_invalid"}

    cmd = [sys.executable, "-B", str(Path(__file__).resolve()), "--serve",
           "--view", view,
           "--requesting-thread-id", requesting_thread_id]
    process = launch(cmd,
                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                     # Keep startup and server diagnostics on the host's
                     # existing stderr capture rather than discarding them.
                     stderr=None,
                     start_new_session=True)
    try:
        import select
        readable, _, _ = select.select([process.stdout], [], [], 10)
        if not readable:
            raise ValueError("helper did not start")
        line = process.stdout.readline(4097)
        result = json.loads(line.decode("utf-8"))
        if len(line) > 4096:
            raise ValueError("helper response invalid")
        if result.get("status") == "OPEN":
            if (result.get("pid") != process.pid
                    or not str(result.get("url", ""))):
                raise ValueError("helper response invalid")
        elif result.get("status") != "REFUSED":
            raise ValueError("helper response invalid")
        if result.get("status") == "REFUSED":
            reason = result.get("reason")
        else:
            url = str(result.get("url", ""))
            local_url = str(result.get("local_url", ""))
            if view == "local":
                if not url.startswith("http://127.0.0.1:"):
                    raise ValueError("helper response invalid")
            else:
                if not url.startswith("https://") or "/s/" not in url:
                    raise ValueError("helper response invalid")
                if not local_url.startswith("http://127.0.0.1:" + str(TAILNET_PORT) + "/"):
                    raise ValueError("helper response invalid")
        if result.get("status") == "REFUSED":
            tailnet_reasons = {"tailnet_unavailable", "tailnet_mapping_missing",
                                "tailnet_mapping_mismatch", "tailnet_funnel_exposed",
                                "tailnet_port_busy"}
            if reason not in tailnet_reasons:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                return {"schema": OPEN_SCHEMA, "status": "REFUSED", "reason": "helper_unavailable"}
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            return _tailnet_refusal_payload(reason)
        # Keep the child handle until its finite session exits, then reap it.
        # Returning the link must not leave a zombie in a long-lived MCP host.
        threading.Thread(target=process.wait, name="orch-dork-local-ui-reaper", daemon=True).start()
        if view == "tailnet":
            result.setdefault("view", "tailnet")
        return result
    except (ValueError, OSError):
        try:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        except Exception:
            pass
        return {"schema": OPEN_SCHEMA, "status": "REFUSED", "reason": "helper_unavailable"}
    finally:
        try:
            process.stdout.close()
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--view", choices=("local", "tailnet"), default="local")
    parser.add_argument("--requesting-thread-id", required=True)
    args = parser.parse_args(argv)
    if not args.serve:
        return 2
    backend = LocalBackend(requesting_thread_id=args.requesting_thread_id)
    if args.view == "tailnet":
        endpoint = tailnet_endpoint(TAILNET_PORT)
        if isinstance(endpoint, str):
            payload = _tailnet_refusal_payload(endpoint)
        else:
            try:
                session = LocalSession(backend, tailnet=endpoint, port=TAILNET_PORT)
            except TailnetPortBusy:
                payload = _tailnet_refusal_payload("tailnet_port_busy")
            else:
                payload = {"schema": OPEN_SCHEMA, "status": "OPEN",
                            "url": session.url, "local_url": session.local_url,
                            "view": "tailnet",
                            "pid": os.getpid(), "lifetime_seconds": DEFAULT_LIFETIME,
                            "notice": ("Loopback view at " + session.local_url +
                                        "; tailnet view at " + session.url +
                                        ". Stop a running attempt in chat.")}
                print(json.dumps(payload), flush=True)
                sys.stdout.close()
                session.serve()
                return 0
        print(json.dumps(payload), flush=True)
        sys.stdout.close()
        return 0
    session = LocalSession(backend)
    print(json.dumps({"schema": OPEN_SCHEMA, "status": "OPEN", "url": session.url,
                      "pid": os.getpid(), "lifetime_seconds": DEFAULT_LIFETIME,
                      "notice": "Only setup and future settings can change here. Stop a running attempt in chat."}), flush=True)
    sys.stdout.close()
    session.serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
