#!/usr/bin/env python3
"""Portable, provider-free entry point for the Orch Dork MCP service.

The plugin descriptor intentionally names the portable ``python3`` command
instead of a machine-specific interpreter path.  This small launcher owns the
runtime contract and performs a bounded local preflight before importing the
policy service.  It never contacts a provider, reads credentials, creates a
task, or changes project state.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

# Governed controller tool calls legitimately run for tens of seconds.  The
# transport's default 10 s dispatch wall answered them with a timeout instead
# of their result (rehearsal runs 17 and 19); this wall stays below Codex's
# 300 s MCP tool timeout so a stuck call still returns an error first.
TOOL_CALL_DISPATCH_WALL_SECONDS = 270.0


RUNTIME_SCHEMA = "orch-dork/runtime-contract/v1"
PREFLIGHT_SCHEMA = "orch-dork/runtime-preflight/v1"
SUPPORTED_RUNTIME_CONTRACT: dict[str, Any] = {
    "schema": RUNTIME_SCHEMA,
    "implementation": "CPython",
    "command": "python3",
    # The macOS system ``python3`` supplied by supported hosts is currently
    # Python 3.9; the runtime code uses only syntax and stdlib available there.
    "minimum_version": {"major": 3, "minor": 9},
    "invocation": ["-B"],
    "provider_free": True,
}

# Keep the probe bounded.  It is only used for an explicitly requested
# alternate interpreter and cannot consume input or make network calls.
_PROBE_TIMEOUT_SECONDS = 1.0
_PROBE = (
    "import platform,sys; "
    "print(f'{sys.implementation.name}|{sys.version_info.major}|"
    "{sys.version_info.minor}|{sys.version_info.micro}')"
)


def plugin_root() -> Path:
    """Return the installed plugin root from this file, independent of cwd."""

    return Path(__file__).resolve().parents[1]


def policy_script(root: Path | None = None) -> Path:
    """Return the policy entry point in the installed runtime subtree."""

    return (root or plugin_root()) / "skills" / "orch-dork" / "scripts" / "orch_dork_policy.py"


def runtime_contract() -> dict[str, Any]:
    """Return a copy of the declared supported-runtime contract."""

    return json.loads(json.dumps(SUPPORTED_RUNTIME_CONTRACT, sort_keys=True))


def _version_text(parts: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in parts)


def _minimum_version() -> tuple[int, int]:
    minimum = SUPPORTED_RUNTIME_CONTRACT["minimum_version"]
    return int(minimum["major"]), int(minimum["minor"])


def _interpreter_command(value: str | os.PathLike[str] | None) -> str:
    if value is None:
        return str(SUPPORTED_RUNTIME_CONTRACT["command"])
    return os.fspath(value)


def _interpreter_label(value: str | os.PathLike[str] | None) -> str:
    """Return a stable non-host-specific interpreter label for diagnostics."""

    command = _interpreter_command(value)
    path = Path(command)
    return path.name if path.is_absolute() or path.parent != Path(".") else command


def resolve_interpreter(value: str | os.PathLike[str] | None = None) -> str | None:
    """Resolve a supported-runtime command without exposing its host path."""

    command = _interpreter_command(value)
    candidate = Path(command)
    if candidate.is_absolute() or candidate.parent != Path("."):
        return str(candidate) if candidate.is_file() else None
    return shutil.which(command)


def _probe_interpreter(command: str) -> tuple[str, tuple[int, int, int]] | None:
    """Read only version metadata from an interpreter with a short timeout."""

    try:
        completed = subprocess.run(
            [command, "-B", "-c", _PROBE],
            check=False,
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    fields = completed.stdout.strip().split("|")
    if len(fields) != 4 or not fields[0] or not all(item.isdigit() for item in fields[1:]):
        return None
    return fields[0], (int(fields[1]), int(fields[2]), int(fields[3]))


def _runtime_report(
    *,
    root: Path,
    interpreter: str | os.PathLike[str] | None,
) -> tuple[dict[str, Any], list[str]]:
    """Collect bounded local runtime facts and named failure tokens."""

    issues: list[str] = []
    command_name = _interpreter_label(interpreter)
    resolved = resolve_interpreter(interpreter)
    observation: dict[str, Any] = {
        "command": command_name,
        "implementation": None,
        "version": None,
        "available": resolved is not None,
    }
    if resolved is None:
        issues.append(f"interpreter:missing:{command_name}")
    else:
        # The running process is authoritative for the normal descriptor
        # command.  Probe an explicitly supplied command so tests and callers
        # can receive a named unsupported/runtime failure without any guess.
        if interpreter is None or os.path.realpath(resolved) == os.path.realpath(sys.executable):
            implementation = sys.implementation.name
            version = (
                sys.version_info.major,
                sys.version_info.minor,
                sys.version_info.micro,
            )
        else:
            probed = _probe_interpreter(resolved)
            if probed is None:
                issues.append(f"interpreter:runtime-failure:{command_name}")
                implementation = None
                version = None
            else:
                implementation, version = probed
        observation["implementation"] = implementation
        observation["version"] = _version_text(version) if version else None
        if implementation and implementation != SUPPORTED_RUNTIME_CONTRACT["implementation"].lower():
            # CPython reports ``cpython`` via sys.implementation.name while
            # the contract is intentionally human-readable as ``CPython``.
            if implementation.lower() != SUPPORTED_RUNTIME_CONTRACT["implementation"].lower():
                issues.append(f"interpreter:unsupported-implementation:{implementation}")
        minimum = _minimum_version()
        if version and (version[0], version[1]) < minimum:
            issues.append(f"interpreter:unsupported-version:{_version_text(version)}")

    required_files = {
        "launcher": Path(__file__).resolve(),
        "policy": policy_script(root),
    }
    for label, path in required_files.items():
        if not path.is_file():
            issues.append(f"runtime:missing:{label}")
        elif not os.access(path, os.R_OK):
            issues.append(f"runtime:unreadable:{label}")

    # Importability is checked without running the MCP loop.  The import is
    # provider-free and gives a stable name instead of leaking an exception.
    if not any(item.startswith("runtime:missing:policy") for item in issues):
        scripts_dir = policy_script(root).parent
        if str(scripts_dir) not in sys.path:
            sys.path.insert(0, str(scripts_dir))
        try:
            spec = importlib.util.spec_from_file_location("orch_dork_policy_preflight", policy_script(root))
            if spec is None or spec.loader is None:
                raise ImportError
            module = importlib.util.module_from_spec(spec)
            # The import must not leave `__pycache__` inside the plugin tree.
            # Preflight is a read-only check and frequently runs against a
            # verified package or a clean checkout, where a written `.pyc`
            # would be an unexpected runtime artifact.
            previous = sys.dont_write_bytecode
            sys.dont_write_bytecode = True
            try:
                spec.loader.exec_module(module)
            finally:
                sys.dont_write_bytecode = previous
        except Exception:  # pragma: no cover - exact cause is intentionally private.
            issues.append("runtime:policy-import-failure")

    report = {
        "schema": PREFLIGHT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "contract": runtime_contract(),
        "interpreter": observation,
        "plugin_root_bound": root == plugin_root(),
        "issues": sorted(set(issues)),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return report, issues


def preflight(
    *,
    root: str | os.PathLike[str] | Path | None = None,
    interpreter: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Run the bounded provider-free runtime preflight."""

    selected_root = Path(root).resolve() if root is not None else plugin_root()
    return _runtime_report(root=selected_root, interpreter=interpreter)[0]


# Explicit alias for callers that use the operation name rather than the
# shorter public helper.
runtime_preflight = preflight


def configure_observer_authority(
    *,
    environ: dict[str, str] | None = None,
    state_dir: str | os.PathLike[str] | Path | None = None,
) -> dict[str, Any]:
    """Discover validated host-owned receipt state without replacing overrides."""

    scripts_dir = policy_script().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        authority = importlib.import_module("orch_dork_observer_authority")
        return authority.configure_verifier_environment(
            os.environ if environ is None else environ,
            state_dir=state_dir,
        )
    except Exception:  # pragma: no cover - startup remains available but untrusted.
        return {
            "schema": "orch-dork/observer-authority-discovery/v1",
            "status": "UNAVAILABLE",
            "disposition": "NOT_CONFIGURED",
            "configured": [],
            "preserved": [],
            "issues": ["authority:discovery_failed"],
            "provider_free": True,
        }


def _serve(*, require_thread_id: bool = False) -> int:
    report = preflight()
    if report["status"] != "PASS":
        print(json.dumps(report, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2

    scripts_dir = policy_script().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    configure_observer_authority()
    transport_dir = plugin_root() / "scripts"
    if str(transport_dir) not in sys.path:
        sys.path.insert(0, str(transport_dir))
    try:
        policy = importlib.import_module("orch_dork_policy")
        transport = importlib.import_module("orch_dork_mcp_server")
        methods = {
            "initialize",
            "ping",
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/read",
            "resources/templates/list",
            "notifications/initialized",
            "notifications/cancelled",
        }
        def dispatch(message: dict[str, Any]) -> dict[str, Any]:
            return policy.dispatch(
                message,
                require_mcp_task_id=require_thread_id,
            )

        from dataclasses import replace

        profile = replace(
            transport.PROFILE,
            dispatch_wall_seconds=TOOL_CALL_DISPATCH_WALL_SECONDS,
        )
        return int(
            transport.serve_stdio(
                {method: dispatch for method in methods}, profile=profile
            )
            or 0
        )
    except Exception:  # pragma: no cover - sanitized startup failure boundary.
        print(
            json.dumps(
                {
                    "schema": PREFLIGHT_SCHEMA,
                    "status": "FAIL",
                    "contract": runtime_contract(),
                    "issues": ["runtime:policy-start-failure"],
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    preflight_parser = subcommands.add_parser("preflight")
    preflight_parser.add_argument("--interpreter", default=None)
    preflight_parser.add_argument("--root", default=None)
    serve_parser = subcommands.add_parser("serve")
    serve_parser.add_argument("--require-thread-id", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "preflight":
        report = preflight(root=args.root, interpreter=args.interpreter)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0 if report["status"] == "PASS" else 2
    return _serve(require_thread_id=args.require_thread_id)


if __name__ == "__main__":
    raise SystemExit(main())
