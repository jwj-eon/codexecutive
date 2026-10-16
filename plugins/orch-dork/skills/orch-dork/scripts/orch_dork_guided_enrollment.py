#!/usr/bin/env python3
"""Guided enrollment of a project for governed runs (Issue 194, FR69).

One chat exchange enrolls a project.  enroll_from_task inspects the project
and proposes: the check commands it can read from the project's own
declarations, the model the user chats with as Codex recorded it, the models
Codex reports with a suggested second model from a different family, where
governed runs reach V1 and the opt-in that moves the user's own Codex there,
and default standing limits.  An ambiguous or unsupported project gets a
named question instead of a guessed check.  confirm_from_task then applies
the user's answers: the project-ground enrollment through the existing
project-ground layer (its binding manifest and external record, with a
pinned adapter), one sealed enrollment record carrying the checks, the two
models, the V1 location, the keep-on-my-machine choice and the standing
authority, and an onboarding job for whichever of the two models has not
passed onboarding (ADR 0012).

Check commands and paths live only in host-local records and change only
through this seam, from the chat or the local command line; a governed run
cannot edit them.  The module grants no run: admission against the standing
authority happens when a run is requested.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
from typing import Any, Callable, Mapping, Sequence

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9 and 3.10: the vendored parser below
    tomllib = None


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if tomllib is None:  # the macOS system python3 is 3.9
    import orch_dork_toml as tomllib  # noqa: E402

import orch_dork_app_server_client as app_server  # noqa: E402
import orch_dork_governed_admission as admission  # noqa: E402
import orch_dork_governed_run_watcher as watcher  # noqa: E402
import orch_dork_onboarded_profiles as onboarded  # noqa: E402
import orch_dork_onboarding_probe as onboarding_probe  # noqa: E402
import orch_dork_project_ground as project_ground  # noqa: E402


DETECTION_SCHEMA = "orch-dork/project-detection/v1"
DRAFT_SCHEMA = "orch-dork/governed-enrollment-draft/v1"
PROPOSAL_SCHEMA = "orch-dork/governed-enrollment-proposal/v1"
CONFIRMATION_SCHEMA = "orch-dork/governed-enrollment-confirmation/v1"
ONBOARDING_START_SCHEMA = "orch-dork/model-onboarding-start/v1"
ONBOARDING_INPUT_SCHEMA = "orch-dork/model-onboarding-input/v1"
# The MCP inputs of enroll_project and confirm_enrollment, named by the
# lifecycle map.
ENROLL_INPUT_SCHEMA = "orch-dork/governed-enrollment-input/v1"
CONFIRM_INPUT_SCHEMA = "orch-dork/governed-enrollment-confirm-input/v1"
REGISTRY_ENV = "ORCH_DORK_ENROLLMENT_REGISTRY_ROOT"
CLIENT_NAME = "orch-dork-guided-enrollment"
CHECK_TIMEOUT_SECONDS = 600
DRAFT_LIFETIME = timedelta(days=1)
ADAPTER_RELATIVE = ".orch-dork/adapter.py"
ADAPTER_COMMAND = ("python3", ADAPTER_RELATIVE)
NPM_PLACEHOLDER = "no test specified"
LOCKFILES = (
    ("package-lock.json", "npm"), ("npm-shrinkwrap.json", "npm"), ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"), ("bun.lockb", "bun"), ("bun.lock", "bun"),
)
# The package managers and Makefile names are the watcher's, which pins the
# declarations behind each check it runs.
RUN_SCRIPT = {runner: (runner, "run") for runner in sorted(watcher.SCRIPT_RUNNERS)}
EXTRA_SCRIPTS = ("lint", "typecheck")
PYTHON_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg", "pytest.ini", "tox.ini", "requirements.txt")
MAKEFILES = watcher.MAKEFILES
_THREAD = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z-]{7,63}\Z")
_IDENTIFIER_UNSAFE = re.compile(r"[^A-Za-z0-9_.:@+-]+")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")

# Written into an enrolled project as its project-ground adapter and pinned
# by digest in the external enrollment record.  It accepts well-formed
# project-ground operations and returns their digest, and nothing else.
ADAPTER_SOURCE = '''"""Project-ground adapter written by Orch Dork's guided enrollment."""

import hashlib
import json
import re
import sys

MAX_INPUT_BYTES = 262_144
MAX_DEPTH = 32
MAX_NODES = 4_096
SCHEMA = "orch-dork/project-ground-operation/v1"
FIELDS = frozenset({"schema", "kind", "input", "source_pointer"})
SENSITIVE = re.compile(
    r"(?:prompt|message|reasoning|credential|secret|password|token|authorization|cookie|private[_-]?key)",
    re.IGNORECASE,
)


def validate(value, depth=0, nodes=None):
    nodes = nodes if nodes is not None else [0]
    nodes[0] += 1
    if depth > MAX_DEPTH or nodes[0] > MAX_NODES:
        raise ValueError("input_structure_bound")
    if value is None or type(value) in (bool, int, float, str):
        return
    if isinstance(value, list):
        for child in value:
            validate(child, depth + 1, nodes)
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or SENSITIVE.search(key):
                raise ValueError("sensitive_or_invalid_key")
            validate(child, depth + 1, nodes)
        return
    raise ValueError("non_json_type")


def evaluate(raw):
    if len(raw) > MAX_INPUT_BYTES:
        return 2, {"decision": "DENY", "reason": "input_bytes_exceeded"}
    try:
        value = json.loads(raw.decode("utf-8"))
        validate(value)
        if not isinstance(value, dict) or set(value) != FIELDS or value.get("schema") != SCHEMA:
            raise ValueError("operation_shape_invalid")
        if not isinstance(value.get("kind"), str) or not value["kind"].strip():
            raise ValueError("operation_kind_invalid")
        if not isinstance(value.get("input"), dict):
            raise ValueError("operation_input_invalid")
        if not isinstance(value.get("source_pointer"), str) or not value["source_pointer"].strip():
            raise ValueError("operation_source_pointer_invalid")
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                               allow_nan=False).encode("utf-8")
    except (UnicodeError, ValueError, TypeError, OverflowError):
        return 2, {"decision": "DENY", "reason": "invalid_or_sensitive_operation"}
    return 0, {"accepted_operation_sha256": hashlib.sha256(canonical).hexdigest(),
               "kind": value["kind"], "provider_free": True}


if __name__ == "__main__":
    code, report = evaluate(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\\n")
    raise SystemExit(code)
'''
ADAPTER_BYTES = ADAPTER_SOURCE.encode("utf-8")
ADAPTER_SHA256 = hashlib.sha256(ADAPTER_BYTES).hexdigest()


class EnrollmentBlocked(RuntimeError):
    """Enrollment cannot proceed; reason is a named code, text the question."""

    def __init__(self, reason: str, text: str, *, options: Sequence[Any] = ()) -> None:
        super().__init__(reason)
        self.reason = reason
        self.text = text
        self.options = list(options)


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def registry_root() -> Path:
    """The project-ground registry the qualification workspace also uses."""

    configured = os.environ.get(REGISTRY_ENV)
    if configured:
        return Path(configured).expanduser()
    state = os.environ.get("XDG_STATE_HOME")
    base = Path(state).expanduser() if state else Path.home() / ".local" / "state"
    return base / "orch-dork" / "project-enrollment-registry"


# ---------------------------------------------------------------- detection


def _question(code: str, text: str, options: Sequence[Sequence[str]] = ()) -> dict[str, Any]:
    return {"code": code, "text": text, "options": [list(option) for option in options]}


def _check(check_id: str, argv: Sequence[str]) -> dict[str, Any]:
    return {"id": check_id, "argv": list(argv), "timeout_seconds": CHECK_TIMEOUT_SECONDS}


def _read_text(path: Path, limit: int = 1_048_576) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _python(root: Path) -> tuple[list[str], dict[str, Any] | None, dict[str, Any] | None]:
    """Python: pytest only when the project configures it; otherwise a question."""

    facts = []
    pyproject = _read_text(root / "pyproject.toml")
    if pyproject is not None:
        configured = False
        if tomllib is not None:
            try:
                tool = tomllib.loads(pyproject).get("tool")
                configured = isinstance(tool, Mapping) and isinstance(tool.get("pytest"), Mapping) and (
                    "ini_options" in tool["pytest"]
                )
            except (ValueError, TypeError):
                configured = False
        else:
            configured = re.search(r"(?m)^\s*\[tool\.pytest\.ini_options\]", pyproject) is not None
        if configured:
            facts.append("pyproject.toml configures pytest")
    if (root / "pytest.ini").is_file():
        facts.append("pytest.ini")
    if (root / "conftest.py").is_file():
        facts.append("conftest.py")
    for name, header in (("setup.cfg", r"(?m)^\s*\[tool:pytest\]"), ("tox.ini", r"(?m)^\s*\[pytest\]")):
        text = _read_text(root / name)
        if text is not None and re.search(header, text):
            facts.append(name + " configures pytest")
    if facts:
        return facts, _check("tests", ["python3", "-m", "pytest"]), None
    return facts, None, _question(
        "python:test_runner_unknown",
        "This Python project does not configure pytest. Which command runs its tests "
        "(for example python3 -m unittest)?",
    )


def _node(root: Path) -> tuple[list[str], list[dict[str, Any]] | None, dict[str, Any] | None]:
    """Node: the package's own test script, run by the package manager its lockfile names."""

    text = _read_text(root / "package.json")
    try:
        package = json.loads(text) if text is not None else None
    except ValueError:
        package = None
    if not isinstance(package, Mapping):
        return ["package.json"], None, _question(
            "node:package_unreadable", "package.json could not be read. Which command runs this project's tests?",
        )
    scripts = package.get("scripts") if isinstance(package.get("scripts"), Mapping) else {}
    test = scripts.get("test")
    if not isinstance(test, str) or not test.strip() or NPM_PLACEHOLDER in test:
        return ["package.json"], None, _question(
            "node:test_script_missing",
            "package.json declares no test script. Which command runs this project's tests?",
        )
    managers = sorted({manager for name, manager in LOCKFILES if (root / name).is_file()})
    declared = package.get("packageManager")
    if isinstance(declared, str) and declared.split("@", 1)[0] in RUN_SCRIPT:
        managers = sorted(set(managers) | {declared.split("@", 1)[0]})
    if len(managers) > 1:
        return ["package.json"], None, _question(
            "node:package_manager_ambiguous",
            "This project has lockfiles for " + " and ".join(managers) + ". Which one runs its scripts?",
            [[manager, "test"] for manager in managers],
        )
    manager = managers[0] if managers else "npm"
    facts = ["package.json scripts.test", (manager + " lockfile") if managers else "no lockfile: npm"]
    runner = RUN_SCRIPT[manager]
    checks = [_check("tests", [*runner, "test"])]
    for name in EXTRA_SCRIPTS:
        if isinstance(scripts.get(name), str) and scripts[name].strip():
            facts.append("package.json scripts." + name)
            checks.append(_check(name, [*runner, name]))
    return facts, checks, None


def _make_test(root: Path) -> str | None:
    for name in MAKEFILES:
        text = _read_text(root / name)
        if text is not None and re.search(r"(?m)^test\s*:(?!=)", text):
            return name
    return None


def detect_project(project_root: Path) -> dict[str, Any]:
    """The project's check commands from its own declarations, or one named question.

    A check is proposed only from an explicit declaration: a pytest
    configuration, a package's test script (with its lint and typecheck
    scripts when it declares them), a Cargo or Go module, or a Makefile test
    target.  More than one candidate, or none, is a question.
    """

    root = Path(os.path.realpath(project_root))
    evidence: list[dict[str, Any]] = []
    for name in (*PYTHON_MARKERS, "conftest.py", "package.json", "Cargo.toml", "go.mod", *MAKEFILES,
                 *(lock for lock, _ in LOCKFILES)):
        path = root / name
        if path.is_file() and not path.is_symlink():
            try:
                evidence.append({"file": name, "sha256": _sha_file(path)})
            except OSError:
                continue
    ecosystems: dict[str, tuple[list[str], list[dict[str, Any]] | None, dict[str, Any] | None]] = {}
    if any((root / name).is_file() for name in PYTHON_MARKERS):
        facts, check, question = _python(root)
        ecosystems["python"] = (facts, [check] if check else None, question)
    if (root / "package.json").is_file():
        ecosystems["node"] = _node(root)
    if (root / "Cargo.toml").is_file():
        ecosystems["rust"] = (["Cargo.toml"], [_check("tests", ["cargo", "test"])], None)
    if (root / "go.mod").is_file():
        ecosystems["go"] = (["go.mod"], [_check("tests", ["go", "test", "./..."])], None)
    makefile = _make_test(root)
    facts: list[str] = []
    checks: list[dict[str, Any]] = []
    question = None
    project_type = None
    if len(ecosystems) > 1:
        question = _question(
            "project:ambiguous_ecosystem",
            "This project has " + " and ".join(sorted(ecosystems)) + " files at its root. "
            "Which command runs its checks?",
            [row["argv"] for _, (_, found, _) in sorted(ecosystems.items()) for row in (found or [])[:1]]
            + ([["make", "test"]] if makefile else []),
        )
    elif ecosystems:
        project_type, (facts, found, question) = next(iter(ecosystems.items()))
        if question is None and makefile is not None:
            question = _question(
                "project:ambiguous_test_command",
                makefile + " has a test target and the project also declares "
                + " ".join(found[0]["argv"]) + ". Which one runs its checks?",
                [found[0]["argv"], ["make", "test"]],
            )
        elif question is None:
            checks = list(found or [])
    elif makefile is not None:
        project_type, facts, checks = "make", [makefile + " test target"], [_check("tests", ["make", "test"])]
    else:
        question = _question(
            "project:unsupported",
            "Orch Dork could not tell how this project is checked. Which command runs its tests?",
        )
    if question is None:
        missing = sorted({row["argv"][0] for row in checks if shutil.which(row["argv"][0]) is None})
        if missing:
            question = _question(
                "check:executable_missing",
                "The check command needs " + ", ".join(missing) + ", which is not on this machine's PATH. "
                "Which command runs this project's checks?",
            )
            checks = []
    core = {
        "schema": DETECTION_SCHEMA,
        "project_root": str(root),
        "status": "QUESTION" if question else "DETECTED",
        "project_type": project_type,
        "facts": facts,
        "evidence": evidence,
        "checks": [] if question else checks,
        "question": question,
    }
    return admission.sealed(core, "detection_sha256")


# ---------------------------------------------------------------- models


def observe_thread_model(home: Path, thread_id: Any) -> dict[str, Any] | None:
    """The model the requesting task runs, from the last turn context Codex recorded."""

    if not isinstance(thread_id, str) or not _THREAD.fullmatch(thread_id):
        return None
    sessions = Path(home) / "sessions"
    candidates = sorted(sessions.glob("*/*/*/rollout-*-" + thread_id + ".jsonl")) if sessions.is_dir() else []
    for path in reversed(candidates):
        model = effort = None
        try:
            with path.open("rb") as handle:
                for line in handle:
                    if b'"turn_context"' not in line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    payload = entry.get("payload") if isinstance(entry, dict) else None
                    if entry.get("type") == "turn_context" and isinstance(payload, dict):
                        if isinstance(payload.get("model"), str) and payload["model"]:
                            model, effort = payload["model"], payload.get("effort")
        except OSError:
            continue
        if model is not None:
            return {"model": model, "effort": effort if isinstance(effort, str) else None}
    return None


def _config_v2(home: Path) -> bool | None:
    if tomllib is None:
        return None
    try:
        with (Path(home) / "config.toml").open("rb") as handle:
            config = tomllib.load(handle)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return None
    features = config.get("features") if isinstance(config.get("features"), Mapping) else {}
    value = features.get("multi_agent_v2")
    return bool(value.get("enabled")) if isinstance(value, Mapping) else value is True


def codex_models(
    home: Path, *, connect: Callable[[Path], Any] = app_server.AppServerConnection,
) -> dict[str, Any]:
    """The models Codex reports and its V2 setting.

    From the shared app server when it answers, else from the catalog file
    the user's configuration names.  Hidden models are not offered.
    """

    rows: list[Mapping[str, Any]] = []
    v2: bool | None = None
    source = "app_server"
    try:
        connection = connect(app_server.resolve_socket(watcher.shared_socket_path(home)))
        try:
            connection.initialize(CLIENT_NAME)
            rows = watcher.model_list(connection)
            config = (connection.request("config/read", {"includeLayers": False}) or {}).get("config") or {}
        finally:
            connection.close()
        features = config.get("features") if isinstance(config.get("features"), Mapping) else {}
        value = features.get("multi_agent_v2")
        v2 = bool(value.get("enabled")) if isinstance(value, Mapping) else bool(value)
    except (OSError, ValueError, ConnectionError, TimeoutError, app_server.AppServerRequestError):
        source = "catalog"
        path = onboarded.configured_catalog_path(home)
        try:
            rows = onboarded.catalog_rows(json.loads(Path(path).read_text(encoding="utf-8"))) if path else []
        except (OSError, ValueError):
            rows = []
        v2 = _config_v2(home)
    models = []
    for row in rows:
        model = onboarded.row_model(row)
        if model and row.get("hidden") is not True and model not in models:
            models.append(model)
    location = onboarded.v1_location(rows, v2_feature_enabled=bool(v2)) if rows and v2 is not None else None
    return {"source": source, "models": models, "v2_feature_enabled": v2, "location": location}


def model_status(model: str, *, onboarding_root: Any = None) -> dict[str, Any]:
    profile = onboarded.onboarded(model, onboarding_root)
    if profile is None:
        return {"model": model, "family": onboarded.family_for_model(model), "onboarding": "not_onboarded",
                "reasons": [], "location": None}
    reasons = onboarded.not_passed_reasons(profile)
    return {"model": model, "family": profile["family"].get("value"),
            "onboarding": "not_passed" if reasons else "passed", "reasons": reasons,
            "location": profile["route"]["location"]}


def _local_models(statuses: Sequence[Mapping[str, Any]]) -> list[str]:
    """The local models among these that passed onboarding: the Local lineup's pool."""

    return [row["model"] for row in statuses if row["location"] == "local" and row["onboarding"] == "passed"]


def suggest_second_model(chat_model: str | None, models: Sequence[str], *, onboarding_root: Any = None) -> str | None:
    """A second model from a different family when the list has one (ADR 0012).

    Among those, one that already passed onboarding comes first; otherwise
    the list's order decides.
    """

    others = [model for model in models if model != chat_model]
    family = onboarded.family_for_model(chat_model) if chat_model else None
    different = [model for model in others if family is not None
                 and onboarded.family_for_model(model) not in (None, family)]
    pool = different or others
    passed = {model for model in pool if model_status(model, onboarding_root=onboarding_root)["onboarding"] == "passed"}
    ranked = sorted(pool, key=lambda model: (model not in passed, others.index(model)))
    return ranked[0] if ranked else None


# ---------------------------------------------------------------- V1 opt-in


def _catalog_for_v1(home: Path, codex: str | None) -> dict[str, Any] | None:
    path = onboarded.configured_catalog_path(home)
    if path is not None:
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
    if codex is None:
        return None
    try:
        completed = subprocess.run([codex, "debug", "models"], capture_output=True, text=True,
                                   timeout=60, check=False)
        value = json.loads(completed.stdout) if completed.returncode == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return value if isinstance(value, dict) and isinstance(value.get("models"), list) else None


def _opencodex_config(home: Path) -> Path | None:
    path = onboarded.configured_catalog_path(home)
    config = Path.home() / ".opencodex" / "config.json"
    if path is not None and Path(path).name == "opencodex-catalog.json" and config.is_file():
        return config
    return None


def v1_opt_in_plan(home: Path, v2_feature_enabled: bool, codex: str | None) -> dict[str, Any] | None:
    """The sealed opt-in that moves the user's own Codex to V1, when one applies."""

    catalog = _catalog_for_v1(home, codex)
    if catalog is None:
        return None
    return onboarded.plan_user_codex_v1_change(
        codex_home=home, catalog=catalog, v2_feature_enabled=v2_feature_enabled,
        opencodex_config=_opencodex_config(home),
    )


def apply_v1_opt_in(home: Path, plan: Mapping[str, Any], v2_feature_enabled: bool, codex: str | None) -> dict[str, Any]:
    catalog = _catalog_for_v1(home, codex)
    return onboarded.apply_user_codex_v1_change(
        plan, confirmation=plan.get("plan_sha256"), codex_home=home, catalog=catalog,
        v2_feature_enabled=v2_feature_enabled, opencodex_config=_opencodex_config(home),
    )


# ---------------------------------------------------------------- project ground


def _identifier(text: str, fallback: str) -> str:
    value = _IDENTIFIER_UNSAFE.sub("-", text).strip("-._:@+")[:64]
    return value if value and value[0].isalnum() else fallback


def _enrollment_program(root: Path, registry: Path, source_pointer: str) -> dict[str, Any]:
    key = watcher.project_key(root)
    git_marker = root / ".git"
    return {
        "schema": project_ground.PROGRAM_SCHEMA,
        "operation": "enroll",
        "registry_root": str(registry),
        "project_root": str(root),
        "identity": {
            "project_id": _identifier(root.name, "project") + "-" + key[:8],
            "host_id": _identifier(socket.gethostname(), "host"),
            "environment_id": "codex",
            "saved_project_id": None,
            "workspace_id": "workspace-" + key[:16],
            "repository_kind": "git" if git_marker.exists() else "directory",
            "worktree_id": ("worktree-" + key[:16]) if git_marker.is_file() else None,
            "canonical_initial_root": str(root),
            "source_pointer": source_pointer + "#identity",
        },
        "binding": {
            "protocol": project_ground.PROTOCOL,
            "generation": 1,
            "adapter_command": list(ADAPTER_COMMAND),
            "adapter_sha256": ADAPTER_SHA256,
            "required": True,
            "source_pointer": source_pointer + "#binding",
        },
        "expected_registry": {"version": 0, "record_sha256": None},
        "maintenance": {
            "active_writer": False,
            "reason": "guided enrollment for governed runs",
            "source_pointer": source_pointer + "#maintenance",
        },
        "source_pointer": source_pointer,
    }


def _ground_summary(report: Mapping[str, Any], registry: Path, decision: str) -> dict[str, Any]:
    record = report.get("current_record") or report.get("proposed_record") or {}
    return {
        "registry_root": str(registry),
        "identity_key": str(report.get("identity_key")),
        "record_sha256": str(record.get("record_sha256")),
        "manifest_sha256": str(record.get("manifest_sha256")),
        "decision": decision,
    }


def inspect_project_ground(root: Path, registry: Path) -> dict[str, Any] | None:
    """The project's active project-ground enrollment, if it already has one."""

    try:
        program = project_ground.build_active_inspection_program(
            root, registry, maintenance_reason="guided enrollment check",
            source_pointer="orch-dork:guided-enrollment",
        )
    except project_ground.ProjectEnrollmentInspectionError:
        return None
    report = project_ground.evaluate_project_enrollment(program)
    if report["decision"] != "ACTIVE":
        raise EnrollmentBlocked(
            "project_ground:" + report["decision"].lower(),
            "The project's existing Orch Dork binding does not match its enrollment record ("
            + ", ".join(report["issues"][:3]) + "); Orch Dork will not overwrite it.",
        )
    return _ground_summary(report, registry, "ACTIVE")


def ensure_project_ground(root: Path, registry: Path, *, source_pointer: str) -> dict[str, Any]:
    """Reuse the project's active project-ground enrollment, or create it.

    A new enrollment writes the pinned adapter and then lets the existing
    project-ground layer write the binding manifest and the external record
    under its own compare-and-swap lock.  Anything that layer refuses blocks
    enrollment with its reasons; nothing is overwritten.
    """

    registry.mkdir(parents=True, exist_ok=True, mode=0o700)
    registry = registry.resolve(strict=True)
    existing = inspect_project_ground(root, registry)
    if existing is not None:
        return existing
    binding = root / ".orch-dork" / "binding.json"
    if binding.exists() or binding.is_symlink():
        raise EnrollmentBlocked(
            "project_ground:binding_without_record",
            "The project already has an Orch Dork binding that no enrollment record matches; "
            "Orch Dork will not overwrite it.",
        )
    adapter = root / ".orch-dork" / "adapter.py"
    if adapter.is_symlink() or (adapter.exists() and adapter.read_bytes() != ADAPTER_BYTES):
        raise EnrollmentBlocked(
            "project_ground:adapter_conflict",
            "The project already has a different .orch-dork/adapter.py; Orch Dork will not overwrite it.",
        )
    if not adapter.exists():
        adapter.parent.mkdir(exist_ok=True)
        with open(adapter, "xb") as handle:
            handle.write(ADAPTER_BYTES)
    report = project_ground.apply_project_enrollment(_enrollment_program(root, registry, source_pointer))
    if report["decision"] not in ("ENROLLED", "ALREADY_ENROLLED"):
        raise EnrollmentBlocked(
            "project_ground:" + report["decision"].lower(),
            "Orch Dork could not enroll this project: " + ", ".join(report["issues"][:5]) + ".",
        )
    return _ground_summary(report, registry, report["decision"])


# ---------------------------------------------------------------- records


def _check_rows(checks: Any) -> list[dict[str, Any]]:
    try:
        return watcher.check_rows(checks)
    except watcher.WatcherError as error:
        raise EnrollmentBlocked("checks:invalid", "The check commands are not valid: " + error.detail) from error


def write_enrollment(
    records: Path,
    root: Path,
    *,
    detection: Mapping[str, Any] | None,
    checks: Sequence[Mapping[str, Any]],
    check_sources: Mapping[str, str],
    ground: Mapping[str, Any],
    models: Mapping[str, Any],
    v1: Mapping[str, Any],
    authority: Mapping[str, Any],
    confirmed: Mapping[str, Any],
) -> dict[str, Any]:
    """Seal and write the project's one enrollment record, replacing the last."""

    path = watcher.enrollment_path(records, root)
    previous = None
    if path.exists():
        try:
            previous = watcher.read_json(path)
        except (OSError, ValueError, watcher.WatcherError):
            previous = None
    rows = _check_rows([dict(row) for row in checks])
    core = {
        "schema": watcher.ENROLLMENT_SCHEMA,
        "version": (previous.get("version", 0) + 1) if isinstance(previous, Mapping) else 1,
        "project_root": str(root),
        "project_key": watcher.project_key(root),
        "project_type": detection.get("project_type") if detection else None,
        "detection_sha256": detection.get("detection_sha256") if detection else None,
        "project_ground": dict(ground),
        "checks": rows,
        "check_sources": dict(check_sources),
        "pinned_files": watcher.pinned_check_files(root, rows),
        "models": dict(models),
        "v1": dict(v1),
        "standing_authority": dict(authority),
        "confirmed": dict(confirmed),
        "previous_record_sha256": previous.get("record_sha256") if isinstance(previous, Mapping) else None,
    }
    record = watcher.sealed(core, "record_sha256")
    issues = watcher.enrollment_issues(record, root)
    if issues:
        raise EnrollmentBlocked("enrollment:invalid", "The enrollment record is not valid: " + issues[0])
    watcher.write_json(path, record)
    return record


def _draft_path(records: Path, digest: str) -> Path:
    return records / "enrollments" / "drafts" / (digest + ".json")


def _defaults(chat_model: str | None, second: str | None, local_models: Sequence[str]) -> dict[str, Any]:
    return {
        "keep_local": False,
        "lineup_preset": "cheap",
        "lineups": admission.lineup_presets(chat_model, second, local_models=local_models)
        if chat_model and second else {},
        "workers_max": admission.DEFAULT_WORKERS,
        "per_run_cost_usd": admission.dollars(admission.DEFAULT_PER_RUN_CENTS)[1:],
        "daily_cost_usd": admission.dollars(admission.DEFAULT_DAILY_CENTS)[1:],
        "allowed_workflow_profiles": list(admission.DEFAULT_ALLOWED_PROFILES),
        "per_run_approval": False,
    }


def _report(schema: str, **values: Any) -> dict[str, Any]:
    return admission.sealed({"schema": schema, **values, "provider_free_entry": True}, "report_sha256")


ONBOARDING_NOTICE = (
    "Onboarding runs one short probe per model in a private Codex home that uses your login: the "
    "model spawns itself once on a trivial task and the result is recorded. It takes about a "
    "minute per hosted model, spends a few thousand tokens, and changes nothing in your own Codex."
)


def propose(
    project_root: Path,
    *,
    requesting_thread_id: str | None,
    records: Path,
    home: Path,
    onboarding_root: Any = None,
    registry: Path | None = None,
    codex: str | None = None,
    connect: Callable[[Path], Any] = app_server.AppServerConnection,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Inspect a project and write the draft the user confirms."""

    root = Path(os.path.realpath(project_root))
    if not root.is_dir():
        return _report(PROPOSAL_SCHEMA, status="BLOCKED", draft_sha256=None, project_root=str(root),
                       question=_question("project:root_missing", "That project directory does not exist."))
    registry = registry or registry_root()
    detection = detect_project(root)
    chat = observe_thread_model(home, requesting_thread_id)
    listed = codex_models(home, connect=connect)
    # A typed route that passed onboarding remains usable even when Codex
    # omits it from model/list (ADR 0012). Chat and UI share these choices.
    models = list(dict.fromkeys([*listed["models"],
                               *(profile["model"] for profile in onboarded.list_profiles(onboarding_root))]))
    statuses = [model_status(model, onboarding_root=onboarding_root) for model in models]
    chat_model = chat["model"] if chat else None
    suggested = suggest_second_model(chat_model, models, onboarding_root=onboarding_root)
    local_models = _local_models(statuses)
    location = listed["location"]
    opt_in = None
    if location is not None and location["location"] == "governed_runner" and listed["v2_feature_enabled"] is not None:
        plan = v1_opt_in_plan(home, bool(listed["v2_feature_enabled"]), codex)
        if plan is not None and plan["status"] == "CONFIRMATION_REQUIRED":
            opt_in = plan
    blocked = None
    try:
        ground = inspect_project_ground(root, registry.resolve() if registry.exists() else registry)
    except EnrollmentBlocked as error:
        ground, blocked = None, _question(error.reason, error.text)
    try:
        existing = watcher.read_json(watcher.enrollment_path(records, root))
    except (OSError, ValueError, watcher.WatcherError):
        existing = None
    moment = now or datetime.now(timezone.utc)
    draft = admission.sealed({
        "schema": DRAFT_SCHEMA,
        "project_root": str(root),
        "requesting_thread_id": requesting_thread_id,
        "created_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "detection": detection,
        "chat_model": chat,
        "models": models,
        "models_source": listed["source"],
        "suggested_second_model": suggested,
        "v2_feature_enabled": listed["v2_feature_enabled"],
        "v1_location": location,
        "v1_opt_in_plan": opt_in,
        "registry_root": str(registry),
    }, "draft_sha256")
    watcher.write_json(_draft_path(records, draft["draft_sha256"]), draft)
    question = blocked or detection["question"]
    return _report(
        PROPOSAL_SCHEMA,
        status="BLOCKED" if question else "NEEDS_CONFIRMATION",
        draft_sha256=draft["draft_sha256"],
        project_root=str(root),
        project_type=detection["project_type"],
        detected_from=detection["facts"],
        checks=detection["checks"],
        question=question,
        chat_model=chat,
        chat_model_question=None if chat else (
            "Codex did not record this task's model where Orch Dork can read it; "
            "name the model you chat with."
        ),
        models=statuses,
        suggested_second_model=suggested,
        v1={
            "location": location["location"] if location else "unknown",
            "rows_not_v1": location["rows_not_v1"] if location else [],
            "opt_in_offer": None if opt_in is None else {
                "plan_sha256": opt_in["plan_sha256"],
                "edits": opt_in["edits"],
                "text": "Governed runs would run in a separate Orch Dork runner because your Codex "
                "does not run every model on V1. Orch Dork can change your Codex so every model "
                "runs on V1; that also moves your own chats to V1 and takes effect after Codex "
                "restarts. Say whether to make that change.",
            },
        },
        project_ground={
            "status": "active" if ground else ("blocked" if blocked else "will_enroll"),
            "writes": [] if ground else [".orch-dork/binding.json", ADAPTER_RELATIVE],
        },
        defaults=_defaults(chat_model, suggested, local_models),
        workflow_profiles=list(admission.WORKFLOW_PROFILES),
        current_enrollment=_summary(existing) if isinstance(existing, Mapping) else None,
        onboarding_notice=ONBOARDING_NOTICE,
    )


def _summary(record: Mapping[str, Any]) -> dict[str, Any]:
    authority = record.get("standing_authority") or {}
    return {
        "version": record.get("version"),
        "checks": record.get("checks"),
        "models": record.get("models"),
        "keep_local": authority.get("keep_local"),
        "role_lineup": authority.get("role_lineup"),
        "workers_max": authority.get("workers_max"),
        "per_run_cost": admission.dollars(authority["per_run_cost_cents"]) if "per_run_cost_cents" in authority else None,
        "daily_cost": admission.dollars(authority["daily_cost_cents"]) if "daily_cost_cents" in authority else None,
        "allowed_workflow_profiles": authority.get("allowed_workflow_profiles"),
        "per_run_approval": authority.get("per_run_approval"),
        "v1": record.get("v1"),
        "record_sha256": record.get("record_sha256"),
    }


def _read_draft(records: Path, digest: Any, now: datetime) -> dict[str, Any]:
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise EnrollmentBlocked("draft:invalid", "That enrollment proposal is not known; propose again.")
    try:
        draft = watcher.read_json(_draft_path(records, digest))
    except (OSError, ValueError, watcher.WatcherError) as error:
        raise EnrollmentBlocked("draft:missing", "That enrollment proposal is not known; propose again.") from error
    if not admission.seal_valid(draft, "draft_sha256") or draft.get("draft_sha256") != digest:
        raise EnrollmentBlocked("draft:invalid", "That enrollment proposal was altered; propose again.")
    created = datetime.strptime(draft["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if now - created > DRAFT_LIFETIME:
        raise EnrollmentBlocked("draft:expired", "That enrollment proposal is more than a day old; propose again.")
    return draft


def _choice(arguments: Mapping[str, Any], name: str, default: Any) -> Any:
    value = arguments.get(name)
    return default if value is None else value


# The standing-authority settings confirm_enrollment and the command line name.
AUTHORITY_SETTINGS = (
    "lineup_preset", "workers_max", "per_run_cost_usd", "daily_cost_usd", "allowed_workflow_profiles",
    "per_run_approval",
)


def _standing_authority(
    settings: Mapping[str, Any], *, chat: str, second: str, keep_local: bool, local_models: Sequence[str],
) -> dict[str, Any]:
    """Standing authority from the user's answers, the defaults filling the rest.

    The chat's confirm_enrollment arguments and the command line's flags name
    the same AUTHORITY_SETTINGS; any other name is refused, so a misspelled
    limit never falls back to its default.
    """

    unknown = sorted(set(settings) - set(AUTHORITY_SETTINGS))
    if unknown:
        raise EnrollmentBlocked("settings:unknown", "Orch Dork has no setting named " + ", ".join(unknown) + ".")
    presets = admission.lineup_presets(chat, second, local_models=local_models)
    preset = _choice(settings, "lineup_preset", "local" if keep_local and "local" in presets else "cheap")
    if preset not in presets:
        raise EnrollmentBlocked("role_lineup:preset_unavailable",
                                "That lineup is not available; choose one of " + ", ".join(presets) + ".")
    lineup = {"preset": preset, **{role: presets[preset][role] for role in admission.ROLES}}
    try:
        return admission.build_authority(
            workers_max=_choice(settings, "workers_max", admission.DEFAULT_WORKERS),
            per_run_cost_cents=admission.cents(
                _choice(settings, "per_run_cost_usd", admission.DEFAULT_PER_RUN_CENTS / 100), field="per_run_cost"),
            daily_cost_cents=admission.cents(
                _choice(settings, "daily_cost_usd", admission.DEFAULT_DAILY_CENTS / 100), field="daily_cost"),
            allowed_workflow_profiles=_choice(settings, "allowed_workflow_profiles",
                                              list(admission.DEFAULT_ALLOWED_PROFILES)),
            lineup=lineup,
            per_run_approval=_choice(settings, "per_run_approval", False),
            keep_local=keep_local,
        )
    except admission.AdmissionError as error:
        raise EnrollmentBlocked("authority:" + str(error), "That standing limit is not valid: " + str(error)) from error


def confirm(
    arguments: Mapping[str, Any],
    *,
    requesting_thread_id: str | None,
    records: Path,
    home: Path,
    onboarding_root: Any = None,
    codex: str | None = None,
    start_onboarding: Callable[..., Mapping[str, Any]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Apply the user's answers to a draft: enroll, record, and start onboarding."""

    moment = now or datetime.now(timezone.utc)
    draft = _read_draft(records, arguments.get("draft_sha256"), moment)
    root = Path(draft["project_root"])
    detection = detect_project(root)
    if detection["detection_sha256"] != draft["detection"]["detection_sha256"]:
        raise EnrollmentBlocked("draft:project_changed",
                                "The project's files changed since the proposal; propose again.")
    stated = arguments.get("checks")
    if stated is not None:
        checks = _check_rows(stated)
        sources = {row["id"]: "stated" for row in checks}
    elif detection["status"] == "DETECTED":
        checks = _check_rows(detection["checks"])
        sources = {row["id"]: "detected" for row in checks}
    else:
        question = detection["question"]
        raise EnrollmentBlocked(question["code"], question["text"], options=question["options"])
    chat = draft["chat_model"]["model"] if draft["chat_model"] else arguments.get("chat_model")
    if not isinstance(chat, str) or not chat:
        raise EnrollmentBlocked("models:chat_model_unknown", "Name the model you chat with.")
    second = arguments.get("second_model")
    if not isinstance(second, str) or second not in draft["models"]:
        raise EnrollmentBlocked(
            "models:second_model_not_listed",
            "Pick the second model from the models Codex reports: " + ", ".join(draft["models"][:12]) + ".",
        )
    if second == chat:
        raise EnrollmentBlocked("models:same_model",
                                "The second model must differ from the model you chat with.")
    keep_local = arguments.get("keep_local")
    if not isinstance(keep_local, bool):
        raise EnrollmentBlocked("keep_local:unanswered",
                                "Say whether to keep this project on your machine (local models only).")
    statuses = [model_status(model, onboarding_root=onboarding_root) for model in draft["models"]]
    authority = _standing_authority({name: arguments[name] for name in AUTHORITY_SETTINGS if name in arguments},
                                    chat=chat, second=second, keep_local=keep_local,
                                    local_models=_local_models(statuses))
    answer = arguments.get("v1_opt_in")
    plan = draft["v1_opt_in_plan"]
    if plan is not None and answer not in ("accept", "decline"):
        raise EnrollmentBlocked("v1_opt_in:unanswered", "Say whether Orch Dork should move your Codex to V1.")
    source_pointer = "codex-task:" + (requesting_thread_id or "unknown") + "#guided-enrollment"
    ground = ensure_project_ground(root, Path(draft["registry_root"]), source_pointer=source_pointer)
    opt_in, opt_in_report = "not_needed", None
    if plan is not None and answer == "decline":
        opt_in = "declined"
    elif plan is not None:
        report = apply_v1_opt_in(home, plan, bool(draft["v2_feature_enabled"]), codex)
        opt_in = "applied" if report["status"] == "APPLIED" else "not_applied"
        opt_in_report = report["report_sha256"]
    location = draft["v1_location"]
    record = write_enrollment(
        records, root,
        detection=detection,
        checks=checks,
        check_sources=sources,
        ground=ground,
        models={"chat_model": chat, "chat_model_source": "observed" if draft["chat_model"] else "stated",
                "second_model": second, "suggested_second_model": draft["suggested_second_model"]},
        v1={"location": location["location"] if location else "unknown",
            "location_sha256": location["report_sha256"] if location else None,
            "opt_in": opt_in, "opt_in_report_sha256": opt_in_report},
        authority=authority,
        confirmed={"at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": "chat",
                   "requesting_thread_id": requesting_thread_id, "draft_sha256": draft["draft_sha256"]},
    )
    pending = [model for model in (chat, second)
               if model_status(model, onboarding_root=onboarding_root)["onboarding"] != "passed"]
    job = None
    if pending:
        job = (start_onboarding or onboarding_probe.start_job)(
            pending, codex=codex, store=onboarding_root, codex_home=home,
        )
    gate = onboarded.governed_admission([second], local_only=keep_local, root=onboarding_root)
    return _report(
        CONFIRMATION_SCHEMA,
        status="ONBOARDING" if job is not None else "ENROLLED",
        project_root=str(root),
        record_path=str(watcher.enrollment_path(records, root)),
        record_sha256=record["record_sha256"],
        enrollment=_summary(record),
        project_ground=ground,
        written_to_project=[] if ground["decision"] == "ACTIVE" else [".orch-dork/binding.json", ADAPTER_RELATIVE],
        onboarding=None if job is None else {"job_id": job.get("job_id"), "models": pending,
                                             "notice": ONBOARDING_NOTICE},
        governed_runs=gate["status"],
        governed_runs_refused_for=[admission.refusal_sentence(issue) for issue in gate["issues"]],
        v1_opt_in=opt_in,
    )


# ---------------------------------------------------------------- entries


def onboard_from_task(
    arguments: Mapping[str, Any], *, home: Path | None = None, onboarding_root: Any = None,
    codex: str | None = None, start_onboarding: Callable[..., Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The chat and models page share one onboarding/re-onboarding operation.

    A typed name is admissible without appearing in model/list (ADR 0012).
    Only a real Codex probe can prove its reachability; re-onboarding forces
    that probe and preserves the earlier profile in the existing history.
    """

    name = arguments.get("model")
    force = arguments.get("re_onboard", False)
    if (set(arguments) - {"model", "re_onboard"} or not isinstance(name, str)
            or not watcher._MODEL.fullmatch(name) or type(force) is not bool):
        return _report(ONBOARDING_START_SCHEMA, status="REFUSED", reason="onboarding:request_invalid")
    job = (start_onboarding or onboarding_probe.start_job)(
        [name], codex=codex or watcher.resolve_codex_executable(), store=onboarding_root,
        codex_home=home or watcher.codex_home(), force=force,
    )
    return _report(ONBOARDING_START_SCHEMA, status="STARTED", job_id=job["job_id"],
                   models=[name], re_onboard=force, notice=ONBOARDING_NOTICE)


def enroll_from_task(
    arguments: Mapping[str, Any], *, requesting_thread_id: str | None, records: Path | None = None,
    onboarding_root: Any = None,
) -> dict[str, Any]:
    """The enroll_project tool: propose an enrollment for the user to confirm."""

    root = arguments.get("project_root")
    if not isinstance(root, str) or not Path(root).is_absolute():
        return _report(PROPOSAL_SCHEMA, status="BLOCKED", draft_sha256=None, project_root=None,
                       question=_question("project:root_invalid", "Name the project's absolute path."))
    return propose(
        Path(root), requesting_thread_id=requesting_thread_id, records=records or watcher.records_root(),
        home=watcher.codex_home(), onboarding_root=onboarding_root, codex=watcher.resolve_codex_executable(),
    )


def confirm_from_task(
    arguments: Mapping[str, Any], *, requesting_thread_id: str | None, records: Path | None = None,
    onboarding_root: Any = None,
) -> dict[str, Any]:
    """The confirm_enrollment tool: apply the user's answers or name what is missing."""

    try:
        return confirm(
            arguments, requesting_thread_id=requesting_thread_id, records=records or watcher.records_root(),
            home=watcher.codex_home(), onboarding_root=onboarding_root,
            codex=watcher.resolve_codex_executable(),
        )
    except EnrollmentBlocked as error:
        return _report(CONFIRMATION_SCHEMA, status="BLOCKED", reason=error.reason,
                       question={"code": error.reason, "text": error.text, "options": error.options})


def enroll_locally(
    project_root: Path,
    *,
    checks: Sequence[Mapping[str, Any]],
    chat_model: str,
    second_model: str,
    records: Path,
    registry: Path | None = None,
    keep_local: bool = False,
    settings: Mapping[str, Any] | None = None,
    onboarding_root: Any = None,
    home: Path | None = None,
    connect: Callable[[Path], Any] = app_server.AppServerConnection,
) -> dict[str, Any]:
    """Enroll from this machine's command line, where commands and paths are edited.

    It writes the same project-ground enrollment and record as the chat does,
    from the stated checks and models and the settings confirm_enrollment
    takes, and starts no onboarding.  The Local lineup is available when both
    named models are local and passed onboarding.  Given the user's Codex
    home it records where governed runs reach V1 as the chat does; the V1
    opt-in itself is the probe module's --v1-plan and --v1-apply.
    """

    root = Path(os.path.realpath(project_root))
    rows = _check_rows([dict(row) for row in checks])
    statuses = [model_status(model, onboarding_root=onboarding_root) for model in (chat_model, second_model)]
    authority = _standing_authority(settings or {}, chat=chat_model, second=second_model, keep_local=keep_local,
                                    local_models=_local_models(statuses))
    location = codex_models(home, connect=connect)["location"] if home is not None else None
    ground = ensure_project_ground(root, registry or registry_root(), source_pointer="orch-dork:local-enrollment")
    return write_enrollment(
        records, root, detection=None, checks=rows, check_sources={row["id"]: "stated" for row in rows},
        ground=ground,
        models={"chat_model": chat_model, "chat_model_source": "stated", "second_model": second_model,
                "suggested_second_model": None},
        v1={"location": location["location"] if location else "unknown",
            "location_sha256": location["report_sha256"] if location else None,
            "opt_in": "not_needed" if location and location["location"] == "user_codex" else "not_offered",
            "opt_in_report_sha256": None},
        authority=authority,
        confirmed={"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "source": "local",
                   "requesting_thread_id": None, "draft_sha256": None},
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Orch Dork guided enrollment (Issue 194).")
    commands = parser.add_subparsers(dest="command", required=True)
    detect = commands.add_parser("detect", help="show the checks Orch Dork reads from a project")
    detect.add_argument("--project-root", required=True)
    enroll = commands.add_parser("enroll", help="enroll a project from this machine")
    enroll.add_argument("--project-root", required=True)
    enroll.add_argument("--checks-json", required=True, help='[{"id":..., "argv":[...], "timeout_seconds":N}]')
    enroll.add_argument("--chat-model", required=True)
    enroll.add_argument("--second-model", required=True)
    enroll.add_argument("--keep-local", action="store_true")
    enroll.add_argument("--lineup-preset", choices=("cheap", "balanced", "local"))
    enroll.add_argument("--workers-max", type=int)
    enroll.add_argument("--per-run-cost-usd")
    enroll.add_argument("--daily-cost-usd")
    enroll.add_argument("--allowed-workflow-profiles",
                        help="comma-separated Workflow Profiles, for example direct/v1,parallel_join/v1")
    enroll.add_argument("--per-run-approval", action="store_true")
    show = commands.add_parser("show", help="show a project's enrollment")
    show.add_argument("--project-root", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "detect":
            result: Any = detect_project(Path(args.project_root))
        elif args.command == "show":
            result = watcher.read_enrollment(watcher.records_root(), Path(args.project_root))
        else:
            profiles = args.allowed_workflow_profiles
            result = enroll_locally(
                Path(args.project_root), checks=json.loads(args.checks_json), chat_model=args.chat_model,
                second_model=args.second_model, records=watcher.records_root(), keep_local=args.keep_local,
                settings={
                    "lineup_preset": args.lineup_preset,
                    "workers_max": args.workers_max,
                    "per_run_cost_usd": args.per_run_cost_usd,
                    "daily_cost_usd": args.daily_cost_usd,
                    "allowed_workflow_profiles": None if profiles is None
                    else [item.strip() for item in profiles.split(",") if item.strip()],
                    "per_run_approval": args.per_run_approval,
                },
                home=watcher.codex_home(),
            )
    except (EnrollmentBlocked, admission.AdmissionError, watcher.WatcherError, ValueError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": getattr(error, "reason", str(error)),
                          "text": getattr(error, "text", str(error))}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
