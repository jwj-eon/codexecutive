#!/usr/bin/env python3
"""Run one governed task from an ordinary Codex task (Issue 193, FR69).

The governed-run watcher is a client of Codex's app server.  Asked by a
requesting task, it runs the provider-free startup self-test, starts the
governed task in its own Codex task with explicit model, effort, approval,
sandbox and instructions, binds that task's thread id for the plugin hooks
before the first turn, observes the turn to its end on the connection that
started it, cross-checks the hooks' action records against the owner rail,
runs the enrolled project's checks itself, and records one host-computed
verdict.  It publishes no native action and grants no authority, and a
model's statement about its own work is never a verdict input.

This first slice governs zero workers.  A zero-worker run makes no native
spawn, continue or stop action, so the governed native controller's grants
have nothing to bind; the hooks instead refuse every worker action for the
bound task, and the watcher is section 5.6's external completion controller:
the run's success exists only in the verdict it computes after the turn,
outside the observed attempt.  It runs on the user's shared app-server daemon
when that daemon holds every model on V1 and otherwise in the governed runner,
a dedicated app server launched with an all-v1 copy of the user's catalog
(ADR 0012).  Run records live under a host-local state root that neither a
plugin update nor an uninstall touches.

Issue 194 puts a guided enrollment and standing authority in front of it.  A
run reads the project's enrollment record (its checks, models and standing
authority, bound to the project-ground enrollment that names the project),
and starts only from a sealed admission claim: the front door compares the
frozen plan with the standing authority and either writes the claim and
starts the watcher, asks with every exceeded limit named, or refuses while
two different models have not passed onboarding.  The watcher re-derives the
plan and consumes the claim once.  An approval answers one recorded question
and the run it starts consumes it.  A stop request from the requesting task
ends the run as Stopped by you with the usual cleanup, and says so when the
governed task's turn did not confirm it ended.

Issue 195 lets a run fan out to lane workers (Owner decision 2026-10-03).
The governed task then coordinates and does no lane work itself: it spawns
one worker per lane with exactly the spawn_agent arguments the admitted plan
gives, waits for them and closes them.  The binding holds one spawn
permission per lane, which the hooks claim once and bind to the worker the
spawn started, and the watcher joins every root and worker action the hooks
recorded to Codex's own record of the root's and each worker's thread.  It
then runs each lane's checks and the project's checks on the joined tree; a
failed check gets exactly one repair round, whose one worker is spawned with
a message the watcher computes from the failed checks, before every check
runs again.  One governed run per repository and at most eight lane workers
per machine run at once, and every run ends with a cost summary built from
Codex's per-thread token counts, with billing reported as unknown.
"""

from __future__ import annotations

import argparse
import configparser
import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
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

# Every sibling the watcher uses is imported once at start, so a plugin
# update that replaces the installed directory mid-run cannot break it.
import orch_dork_app_server_client as app_server  # noqa: E402
import orch_dork_governed_admission as admission  # noqa: E402
import orch_dork_governed_run_cost as run_cost  # noqa: E402
import orch_dork_governed_run_cleanup as task_cleanup  # noqa: E402
import orch_dork_governed_run_controls as controls  # noqa: E402
import orch_dork_governed_run_policy as policy  # noqa: E402
import orch_dork_onboarded_profiles as onboarded  # noqa: E402
import orch_dork_project_ground as project_ground  # noqa: E402
import orch_dork_work_intake as work_intake  # noqa: E402


REQUEST_SCHEMA = "orch-dork/governed-run-request/v3"
ENROLLMENT_SCHEMA = "orch-dork/governed-enrollment/v1"
SELF_TEST_SCHEMA = "orch-dork/governed-run-self-test/v1"
CROSS_CHECK_SCHEMA = "orch-dork/governed-run-cross-check/v1"
LANE_CROSS_CHECK_SCHEMA = "orch-dork/governed-run-lane-cross-check/v1"
STATUS_SCHEMA = "orch-dork/governed-run-status/v1"
RECORD_SCHEMA = "orch-dork/governed-run-record/v4"
CLAIM_SCHEMA = "orch-dork/governed-run-admission-claim/v1"
STOP_SCHEMA = "orch-dork/governed-run-stop/v1"
START_SCHEMA = "orch-dork/governed-run-start/v1"
READ_SCHEMA = "orch-dork/governed-run-read/v1"
STOP_REPORT_SCHEMA = "orch-dork/governed-run-stop-report/v1"
TEST_TREE_SCHEMA = "orch-dork/governed-run-test-tree/v1"
# Issue 246: the most of a project's test tree one run pins, and the most
# entries its walk of the project visits.
MAX_TEST_TREE_FILES = 10_000
MAX_TEST_TREE_BYTES = 256 * 1024 * 1024
MAX_TEST_TREE_ENTRIES = 200_000
# The MCP inputs of start_governed_run, read_governed_run and
# stop_governed_run.  Only the lifecycle map names them; a schema constant
# here is what makes the map's references resolvable.
START_INPUT_SCHEMA = "orch-dork/governed-run-start-input/v1"
READ_INPUT_SCHEMA = "orch-dork/governed-run-read-input/v1"
STOP_INPUT_SCHEMA = "orch-dork/governed-run-stop-input/v1"
STEER_INPUT_SCHEMA = "orch-dork/governed-run-steer-input/v1"
REVISION_INPUT_SCHEMA = "orch-dork/governed-run-revise-input/v1"
STEER_REPORT_SCHEMA = "orch-dork/governed-run-steer-report/v1"
REVISION_REPORT_SCHEMA = "orch-dork/governed-run-revise-report/v1"
KNOWN_GOOD_SCHEMA = "orch-dork/known-good-codex/v1"
KNOWN_GOOD_PATH = ("skills", "orch-dork", "runtime", "governed-mode", "known-good-codex.json")
# Issue 219: the role-guidance document is the admitted packaged source for
# the planner section the engine injects into the planner's
# developerInstructions.  The runtime does not read every Markdown file in
# the repository; only this admitted packaged path, when present, complete,
# and bound into the run record at start time, is consumed.  The schema
# constant names the contract every sealed digest and parser return uses.
ROLE_GUIDANCE_SCHEMA = "orch-dork/role-guidance/v1"
ROLE_GUIDANCE_RELATIVE_PATH = ("skills", "orch-dork", "references", "roles.md")
# The admitted packaged source's joined path, joined once so every
# diagnostic, prompt label, freeze check, and refusal reuses the exact
# same string.
ROLE_GUIDANCE_PACKAGED_PATH = "/".join(ROLE_GUIDANCE_RELATIVE_PATH)
# The canonical sections the parser requires, in their fixed order.  The
# engine injects only the planner section today; the other sections stay
# reference material and the engine never puts them in any prompt.
ROLE_GUIDANCE_SECTIONS: tuple[str, ...] = ("planner", "implementer", "reviewer")
# The one role the engine consumes today.  Add another active consumer
# only after a demonstrated gap and a separately reviewed scope.  The
# frozenset view (used by record, prompt label, and freeze checks) is
# derived from this scalar so the "one consumer today" rule has exactly
# one source.
ROLE_GUIDANCE_CONSUMED_SECTION: str = "planner"
ROLE_GUIDANCE_CONSUMED_SECTIONS: frozenset[str] = frozenset({ROLE_GUIDANCE_CONSUMED_SECTION})
# The pre-thread refusal reasons raised by the role-guidance loader and
# parser, named once so the watcher's exception-diagnostic path can
# reference the set without restating the two reason strings.
ROLE_GUIDANCE_MISSING: str = "governed_run:role_guidance_missing"
ROLE_GUIDANCE_INVALID: str = "governed_run:role_guidance_invalid"
ROLE_GUIDANCE_REFUSALS: frozenset[str] = frozenset({
    ROLE_GUIDANCE_MISSING,
    ROLE_GUIDANCE_INVALID,
})
RECORDS_ENV = "ORCH_DORK_GOVERNED_RUNS_ROOT"
CODEX_ENV = "ORCH_DORK_CODEX_EXECUTABLE"
CLIENT_NAME = "orch-dork-governed-run-watcher"
SERVICE_NAME = "orch-dork-governed-run"

VERIFIED = "Verified"
FAILED_CHECKS = "Failed checks"
INTERRUPTED = "Interrupted \u2014 not verified"
STOPPED = "Stopped by you"
REFUSED = "Refused"
VERDICTS = (VERIFIED, FAILED_CHECKS, INTERRUPTED, STOPPED, REFUSED)

# The self-test's named refusals, in the order they are reported.
SELF_TEST_REFUSALS = {
    "governed_mode:app_server_unavailable": (
        "Codex's shared app-server daemon could not be reached or did not "
        "answer; use a Codex desktop app that runs on the shared daemon, or "
        "the Codex CLI"
    ),
    "governed_mode:codex_version_unknown": (
        "this Codex version is not on the installed generation's known-good list"
    ),
    "governed_mode:hooks_missing": "Orch Dork's five plugin hooks are not all registered",
    "governed_mode:hooks_disabled": "Orch Dork's plugin hooks are disabled in Codex",
    "governed_mode:hooks_untrusted": (
        "Orch Dork's plugin hooks have not been reviewed and trusted in Codex"
    ),
    "governed_mode:hooks_modified": (
        "Orch Dork's plugin hooks changed since they were trusted, or belong to "
        "another installed generation"
    ),
    "governed_mode:hook_scope_unverified": (
        "the installed hook did not pass an ungoverned task through unchanged"
    ),
    "governed_mode:collaboration_tools_unavailable": (
        "Codex's collaboration tools are disabled"
    ),
    "governed_mode:v1_unavailable": (
        "no Codex app server here holds every model on the V1 surface"
    ),
}
RUN_REFUSALS = {
    "governed_run:request_invalid": "the governed-run request is malformed",
    "governed_run:project_not_enrolled": "the project is not enrolled for governed runs",
    "governed_run:onboarding_required": (
        "governed runs need two different onboarded models, including the task's model"
    ),
    "governed_run:repository_busy": "another governed run is active in this repository",
    "governed_run:task_start_failed": "Codex did not start the governed task",
    "governed_run:binding_failed": "the governed task could not be bound for the hooks",
    "governed_run:hook_records_unavailable": "the hooks' action records could not be read",
    "governed_run:hook_owner_disagreement": (
        "the hooks' action records and the owner connection disagree"
    ),
    "governed_run:worker_activity": "a worker acted in a run that admits zero workers",
    "governed_run:hooks_changed_during_run": (
        "Orch Dork's hooks changed while the run was in progress"
    ),
    "governed_run:check_changed": (
        "the governed task or a worker changed a file the project's checks run, one of its tests or "
        "its test configuration"
    ),
    "governed_run:test_tree_too_large": (
        "the project's tests are more than one run pins: at most " + format(MAX_TEST_TREE_FILES, ",")
        + " files and " + str(MAX_TEST_TREE_BYTES // (1024 * 1024)) + " MiB of tests, in a project of at most "
        + format(MAX_TEST_TREE_ENTRIES, ",") + " files and folders outside hidden, dependency and build folders"
    ),
    "governed_run:admission_invalid": (
        "the run has no admission matching its plan and the project's standing authority"
    ),
    "governed_run:machine_workers_busy": (
        "the machine's governed runs already use the workers this run needs; at most "
        "eight lane workers run on one machine at a time"
    ),
    "governed_run:codex_agent_limit": (
        "this Codex lets one task keep fewer agents open at once (agents.max_threads) than the run "
        "has lanes"
    ),
    ROLE_GUIDANCE_MISSING: (
        "the admitted packaged role-guidance document at "
        + ROLE_GUIDANCE_PACKAGED_PATH + " is missing or unreadable"
    ),
    ROLE_GUIDANCE_INVALID: (
        "the admitted packaged role-guidance document is malformed: see the named issue in the record"
    ),
}
# The refusals an ordinary advisory run can stand in for.
ADVISORY_REASONS = {
    **SELF_TEST_REFUSALS,
    "governed_run:onboarding_required": RUN_REFUSALS["governed_run:onboarding_required"],
}
OUTCOME_MESSAGES = {
    "governed_run:checks_failed": (
        "the governed task finished and at least one of the project's checks failed"
    ),
    "governed_run:checks_failed_after_repair": (
        "at least one check still failed after the run's one repair round"
    ),
    "governed_run:stopped_by_you": (
        "you stopped the run before it finished, so nothing was verified"
    ),
    "governed_run:stop_unconfirmed": (
        "you stopped the run, but the governed task's turn did not confirm it ended; Orch Dork "
        "ended the run's binding, so its hooks refuse the task's further tool calls, and nothing "
        "was verified"
    ),
    "governed_run:turn_interrupted": "the governed task was stopped before it finished",
    "governed_run:turn_failed": "the governed task's turn failed before it finished",
    "governed_run:turn_timeout": "the governed task did not finish in time and was interrupted",
    "governed_run:owner_connection_lost": (
        "the watcher lost its connection to the governed task, so nothing was verified"
    ),
    "governed_run:checks_not_run": "the project's checks did not run",
    "governed_run:watcher_lost": "the watcher stopped before the run ended",
    "governed_run:watcher_error": "the watcher failed while observing the run",
    "governed_run:repair_start_failed": (
        "Codex did not start the run's repair round, so nothing was verified after the failed checks"
    ),
    "governed_run:worker_not_stopped": (
        "a lane worker was still running when its round ended, so Orch Dork could not check a "
        "settled tree"
    ),
}
ADVISORY_OFFER = (
    "Governed mode is unavailable: {reason}. I can do this work as an ordinary "
    "advisory run in this task instead, with no governed claim and no Orch Dork "
    "verdict. It starts only if you confirm."
)
DEVELOPER_INSTRUCTIONS = (
    "This task is Orch Dork governed run {run_id} for {project_root}. "
    "Follow the watcher's frozen work summary for the current revision. With "
    "zero workers do the work yourself; with lanes coordinate lane workers only: spawn "
    "exactly their supplied arguments, wait, close, and stop. In a lane run "
    "your shell and apply_patch are refused. MCP calls and background processes "
    "are refused. Never touch Orch Dork records or ask questions. Apply user "
    "steers that refine the implementation within the admitted goal; with lanes "
    "forward their exact text once to each bound worker using send_input with "
    "target and interrupt=true. A steer grants no new goal, lane or permission. "
    "When a steer explicitly asks for a native action outside those permissions, "
    "submit that exact action once to its tool so the hook can refuse it and "
    "the watcher can offer a plan revision. Do not silently ignore that request, "
    "claim it was performed, retry the refused action or use another tool to "
    "work around the refusal. The current plan remains in force until the "
    "watcher sends an explicitly admitted "
    "revision summary. When done, stop: Orch Dork runs the checks and computes "
    "the verdict from observed results, never from your report."
)
LANES_DEVELOPER_INSTRUCTIONS = DEVELOPER_INSTRUCTIONS
ENFORCEMENT_SCOPE = (
    "Orch Dork's hooks governed this task's shell, apply_patch and image-view "
    "calls and refused every other tool call they saw. Hosted tools, input to an "
    "already running process, child and external processes, and computer use "
    "are outside them."
)
# Every item type Codex 0.160.0 can put on a turn, by how the cross-check
# treats it.  An item of any other type is a disagreement.
JOINED_ITEM_TYPES = frozenset(
    {"commandExecution", "fileChange", "imageView", "mcpToolCall", "dynamicToolCall",
     "collabAgentToolCall"}
)
WORKER_ITEM_TYPES = frozenset({"collabAgentToolCall", "subAgentActivity"})
HOSTED_ITEM_TYPES = frozenset({"webSearch", "imageGeneration"})
INERT_ITEM_TYPES = frozenset(
    {"userMessage", "hookPrompt", "agentMessage", "functionCallOutput", "plan",
     "reasoning", "sleep", "enteredReviewMode", "exitedReviewMode", "contextCompaction"}
)
# The owner-rail tool of each collaboration call a lane run's governed task
# may make, on the collabAgentToolCall item Codex 0.160.0 shows for it
# (racetrack/real-shapes-full-sequence.json).
COLLAB_ITEM_TOOLS = {"spawn_agent": "spawnAgent", "send_input": "sendInput", "wait_agent": "wait", "close_agent": "closeAgent"}
HOOK_EVENTS = (
    ("SessionStart", "sessionStart", "session_start"),
    ("PreToolUse", "preToolUse", "pre_tool_use"),
    ("PostToolUse", "postToolUse", "post_tool_use"),
    ("Stop", "stop", "stop"),
    ("SubagentStop", "subagentStop", "subagent_stop"),
)
DEFAULT_TURN_SECONDS = 1800
MAX_TURN_SECONDS = 7200
# Codex ends an MCP tool call after its default 60-second tool timeout, and
# the plugin's MCP registration sets no other, so every start or read call
# returns well inside it; the requesting task reads again until the run
# reports TERMINAL.
START_WAIT_SECONDS = 25.0
MAX_READ_WAIT_SECONDS = 50
DEFAULT_READ_WAIT_SECONDS = 45
STOP_WAIT_SECONDS = 20.0
# After a stop request the turn gets this long to end before the watcher
# records it as not ending and cleans up anyway.
STOP_GRACE_SECONDS = 30
# How often the watcher looks for a stop request while it waits.
POLL_SECONDS = 1.0
MAX_CHECKS = 16
MAX_CHECK_SECONDS = 1800
CHECK_OUTPUT_TAIL = 8192
PROBE_OUTPUT_TAIL = 2000
_RUN_ID = re.compile(r"\Agr-(\d{8})-[0-9a-f]{8}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
# At most eight lane workers run at once on one machine, across every
# governed run and repository (FR69); a run's lanes are its workers.
MACHINE_WORKERS = 8
MAX_LANE_CHECKS = 4
MAX_SELECTORS = 8
MAX_LANE_GOAL = 4000
# How long the front door counts a claimed run whose watcher has not yet
# taken its repository lock as one that holds its workers.
CLAIM_START_SECONDS = 120
# How long a lane worker still running when its round's governed turn ended
# gets to confirm the interrupt the watcher sends it.
WORKER_SETTLE_SECONDS = 15.0
_LANE_ID = re.compile(r"\A[a-z][a-z0-9-]{0,31}\Z")
_SELECTOR = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_./:@+=,\[\]-]{0,255}\Z")
_MODEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_EFFORT = re.compile(r"\A[a-z]{2,16}\Z")
_CHECK_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_VERSION = re.compile(r"/(\d+\.\d+\.\d+)")


class WatcherError(RuntimeError):
    """A named refusal or interruption raised inside the watcher."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason + (": " + detail if detail else ""))
        self.reason = reason
        self.detail = detail


def message_for(reason: str | None) -> str | None:
    """The user-facing sentence for a verdict or refusal reason."""

    if reason is None:
        return None
    for table in (SELF_TEST_REFUSALS, RUN_REFUSALS, OUTCOME_MESSAGES):
        if reason in table:
            return table[reason]
    for prefix, text in OUTCOME_MESSAGES.items():
        if reason.startswith(prefix + ":"):
            return text
    return None


def advisory_offer(reason: str | None) -> str | None:
    """The advisory run offered in place of a governed one this refusal stops."""

    return ADVISORY_OFFER.format(reason=ADVISORY_REASONS[reason]) if reason in ADVISORY_REASONS else None


# ---------------------------------------------------------------- utilities


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sealed(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    core = {key: item for key, item in value.items() if key != field}
    return {**core, field: policy.sha256(core)}


def seal_valid(value: Any, field: str) -> bool:
    return bool(
        isinstance(value, Mapping)
        and value.get(field)
        == policy.sha256({key: item for key, item in value.items() if key != field})
    )


def new_run_id(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    return "gr-" + moment.strftime("%Y%m%d") + "-" + secrets.token_hex(4)


def run_date(run_id: str) -> str | None:
    """The UTC day, as YYYYMMDD, a run id was made on; None for anything else."""

    match = _RUN_ID.fullmatch(run_id)
    return match.group(1) if match else None


def _private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise WatcherError("governed_run:records_unsafe", str(path))
    return path


def write_json(path: Path, value: Any, *, create_only: bool = False) -> None:
    """Owner-only JSON; replaced atomically unless create_only."""

    _private_directory(path.parent)
    payload = policy.canonical(value) + b"\n"
    if create_only:
        # Another process may read this file while it is written (a stop request, a run's request or record),
        # so it appears only when complete (Issue 244).
        policy.create_whole(path, payload, staging=path.parent)
        return
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_json(path: Path, *, limit: int = 4 * 1024 * 1024) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise WatcherError("governed_run:records_unsafe", str(path))
    return json.loads(path.read_text(encoding="utf-8"))


def _tail(text: str, limit: int) -> str:
    return text[-limit:] if isinstance(text, str) else ""


# ---------------------------------------------------------------- locations


def plugin_root() -> Path:
    return SCRIPT_DIR.parents[2]


def plugin_identity(root: Path) -> tuple[str, str, Path | None]:
    """The plugin id, its data-directory name and the Codex home of an install.

    An installed generation lives at <codex>/plugins/cache/<marketplace>/
    <plugin>/<version>; a checkout reports the default local identity.
    """

    parts = Path(root).resolve().parts
    if len(parts) >= 6 and parts[-5] == "plugins" and parts[-4] == "cache":
        marketplace, plugin = parts[-3], parts[-2]
        return plugin + "@" + marketplace, plugin + "-" + marketplace, Path(*parts[:-5])
    return "orch-dork@orch-dork-local", "orch-dork-orch-dork-local", None


def codex_home(root: Path | None = None) -> Path:
    installed = plugin_identity(root or plugin_root())[2]
    configured = os.environ.get("CODEX_HOME")
    if configured:
        return Path(configured).expanduser()
    return installed or Path.home() / ".codex"


def plugin_data_root(root: Path | None = None, home: Path | None = None) -> Path:
    selected = root or plugin_root()
    return (home or codex_home(selected)) / "plugins" / "data" / plugin_identity(selected)[1]


def records_root() -> Path:
    configured = os.environ.get(RECORDS_ENV)
    if configured:
        return Path(configured).expanduser()
    state = os.environ.get("XDG_STATE_HOME")
    base = Path(state).expanduser() if state else Path.home() / ".local" / "state"
    return base / "orch-dork" / "governed-runs"


def shared_socket_path(home: Path | None = None) -> Path:
    return (home or codex_home()) / "app-server-control" / "app-server-control.sock"


def resolve_codex_executable() -> str:
    """The Codex this plugin runs under, for the governed runner and onboarding.

    The plugin's MCP server is a child of the Codex app server that launched
    it, so the parent process's executable is that exact Codex, whatever
    other Codex PATH names.  A configured executable wins; PATH is the last
    resort.
    """

    configured = os.environ.get(CODEX_ENV)
    if configured:
        return configured
    parent: Path | None = None
    try:
        parent = Path("/proc", str(os.getppid()), "exe").resolve(strict=True)
    except OSError:
        try:
            named = subprocess.run(
                ["ps", "-o", "comm=", "-p", str(os.getppid())], capture_output=True,
                text=True, timeout=5, check=False,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            named = ""
        parent = Path(named) if named and Path(named).is_absolute() else None
    if parent is not None and parent.name.startswith("codex") and os.access(parent, os.X_OK):
        return str(parent)
    return shutil.which("codex") or "codex"


def project_key(project_root: Path) -> str:
    return hashlib.sha256(os.fsencode(os.path.realpath(project_root))).hexdigest()[:32]


def run_directory(records: Path, run_id: str) -> Path:
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise WatcherError("governed_run:request_invalid", "run id")
    return records / "runs" / run_id


def load_known_good(root: Path | None = None) -> list[str]:
    path = (root or plugin_root()).joinpath(*KNOWN_GOOD_PATH)
    value = json.loads(path.read_text(encoding="utf-8"))
    versions = value.get("versions") if isinstance(value, Mapping) else None
    if (
        value.get("schema") != KNOWN_GOOD_SCHEMA
        or not isinstance(versions, list)
        or not versions
        or any(not isinstance(item, str) or not re.fullmatch(r"\d+\.\d+\.\d+", item) for item in versions)
    ):
        raise ValueError("known_good:invalid")
    return list(versions)


# ---------------------------------------------------------------- role guidance

# Bounded role-guidance document. The admitted packaged source must be a
# small, strict document; the parser enforces a single schema line, a
# single sections line, three non-empty section bodies in the canonical
# order, no foreign role markers, and a byte bound that keeps reads safe.
ROLE_GUIDANCE_MAX_BYTES = 65_536
# Match any `<!-- role-X begin|end -->` marker; sections outside the
# canonical list trigger the foreign-section refusal.
_ROLE_GUIDANCE_ANY_MARKER = re.compile(
    r"<!--\s*role-(?P<section>[a-z][a-z0-9_-]*)\s+(?P<kind>begin|end)\s*-->"
)
_ROLE_GUIDANCE_HEADER_LINE = re.compile(
    r"<!--\s*role-guidance-schema:\s*(?P<schema>[^\s]+)\s*-->"
)
_ROLE_GUIDANCE_SECTIONS_LINE = re.compile(
    r"<!--\s*role-sections:\s*(?P<sections>[^\s]+(?:\s*,\s*[^\s]+)*)\s*-->"
)


def _role_guidance_path(root: Path | None = None) -> Path:
    """The admitted packaged source path of the role-guidance document.

    The path resolves under the plugin root, never an arbitrary workspace:
    a development checkout, an installed runtime copy, or a frozen
    historical replay all resolve to the same canonical relative path.
    """

    return (root or plugin_root()).joinpath(*ROLE_GUIDANCE_RELATIVE_PATH)


def _role_guidance_parse(raw: bytes) -> dict[str, Any]:
    """Strict parse of the admitted packaged role-guidance document.

    Returns the schema line, the canonical sections line, the file's
    SHA-256 digest, the parsed section bodies, and the order they
    appeared in. Raises ``ValueError`` with a named issue for every
    malformed condition; ``FileNotFoundError`` for an unreadable file.
    The parser enforces: bounded bytes, single schema line, single
    sections line matching the canonical order, three non-empty
    section bodies, exactly one begin and one end per section,
    canonical ordering of all markers, and no foreign role markers.
    """

    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("role_guidance:bytes")
    if len(raw) > ROLE_GUIDANCE_MAX_BYTES:
        raise ValueError("role_guidance:too_large:" + str(len(raw)))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("role_guidance:encoding:" + str(error)) from error
    schema_matches = list(_ROLE_GUIDANCE_HEADER_LINE.finditer(text))
    if len(schema_matches) != 1:
        raise ValueError("role_guidance:schema_lines:" + str(len(schema_matches)))
    if schema_matches[0].group("schema") != ROLE_GUIDANCE_SCHEMA:
        raise ValueError("role_guidance:schema")
    sections_matches = list(_ROLE_GUIDANCE_SECTIONS_LINE.finditer(text))
    if len(sections_matches) != 1:
        raise ValueError("role_guidance:sections_line:" + str(len(sections_matches)))
    declared = tuple(
        name.strip() for name in sections_matches[0].group("sections").split(",") if name.strip()
    )
    if declared != ROLE_GUIDANCE_SECTIONS:
        raise ValueError("role_guidance:sections_line")
    markers = list(_ROLE_GUIDANCE_ANY_MARKER.finditer(text))
    if not markers:
        raise ValueError("role_guidance:no_markers")
    # Hold each match's start offset in one clearly named structure that
    # is built directly from the regex's own output.  The keys are
    # (section_name, kind) and the values are the match.start() offset;
    # the body bounds are derived from these in a single pass so there
    # is no separate extraction loop and no -1 sentinel.
    marker_offsets: dict[tuple[str, str], int] = {}
    foreign: list[str] = []
    for match in markers:
        name = match.group("section")
        kind = match.group("kind")
        if name in ROLE_GUIDANCE_SECTIONS:
            key = (name, kind)
            if key in marker_offsets:
                raise ValueError("role_guidance:marker_duplicate:" + name + ":" + kind)
            marker_offsets[key] = match.start()
        else:
            foreign.append(name)
    if foreign:
        raise ValueError("role_guidance:foreign_section:" + ",".join(sorted(set(foreign))))
    for name in ROLE_GUIDANCE_SECTIONS:
        for kind in ("begin", "end"):
            if (name, kind) not in marker_offsets:
                raise ValueError("role_guidance:marker_missing:" + name + ":" + kind)
    # Canonical order: planner begin, planner end, implementer begin,
    # implementer end, reviewer begin, reviewer end. Sort the markers by
    # offset and confirm the labels appear in this exact order, so a
    # crossed marker (e.g., reviewer text inside planner body, or an
    # implementer block spanning two planner halves) is refused before
    # any section body is extracted.
    ordered_markers = sorted(
        ((offset, name, kind) for (name, kind), offset in marker_offsets.items()),
        key=lambda row: row[0],
    )
    expected = [(name, kind) for name in ROLE_GUIDANCE_SECTIONS for kind in ("begin", "end")]
    actual = [(name, kind) for _, name, kind in ordered_markers]
    if actual != expected:
        raise ValueError("role_guidance:crossed_marker")
    # Each section body is the substring between its begin match's end
    # and its end match's start, derived directly from the stored
    # marker offsets.  Using the regex's match.end() / match.start()
    # honors any whitespace the role-X_begin/----> delimiter permits
    # (the marker regex matches `<!--\s*...\s*-->`) and avoids a
    # fragile `text.index` lookup against the same substring.
    bodies: dict[str, str] = {}
    for match in markers:
        name = match.group("section")
        kind = match.group("kind")
        if kind == "begin":
            bodies[name] = text[match.end():marker_offsets[(name, "end")]].strip()
    for name in ROLE_GUIDANCE_SECTIONS:
        if not bodies.get(name):
            raise ValueError("role_guidance:section_empty:" + name)
    return {
        "schema": ROLE_GUIDANCE_SCHEMA,
        "digest": hashlib.sha256(raw).hexdigest(),
        "sections": bodies,
        "section_order": ROLE_GUIDANCE_SECTIONS,
        "consumed_sections": tuple(sorted(ROLE_GUIDANCE_CONSUMED_SECTIONS)),
        "bytes": len(raw),
    }


def load_role_guidance(root: Path | None = None) -> dict[str, Any]:
    """Load the admitted packaged role-guidance document and parse it.

    The read is bounded to ``ROLE_GUIDANCE_MAX_BYTES + 1`` so a path
    that resolves to a much larger file never allocates a multi-megabyte
    buffer; the parser still rejects anything above the bound with a
    named ``too_large`` issue. A missing document raises
    ``FileNotFoundError``; a malformed document raises ``ValueError``
    with a named issue. Both are distinguished by the caller so a
    refused run names the precise failure.
    """

    path = _role_guidance_path(root)
    with path.open("rb") as handle:
        raw = handle.read(ROLE_GUIDANCE_MAX_BYTES + 1)
    return _role_guidance_parse(raw)


def required_role_guidance(root: Path) -> dict[str, Any]:
    """Load packaged guidance with the same named refusals at both boundaries."""

    try:
        return load_role_guidance(root)
    except FileNotFoundError as error:
        raise WatcherError(ROLE_GUIDANCE_MISSING,
                           ROLE_GUIDANCE_PACKAGED_PATH + " " + str(error)) from error
    except (ValueError, OSError) as error:
        raise WatcherError(ROLE_GUIDANCE_INVALID, str(error)) from error


def role_guidance_block(role: str, body: str, digest: str) -> str:
    """Format the consumed role-guidance block for the developerInstructions.

    The block clearly labels the active prompt consumption, repeats the
    admitted packaged digest, and is appended after the watcher's
    existing developerInstructions text so the prompt identity stays
    bound to the record.
    """

    return (
        "\n\nOrch Dork role guidance (consumed: " + role + ", "
        "admitted packaged source " + ROLE_GUIDANCE_PACKAGED_PATH + ", "
        "sha256=" + digest + ", schema=" + ROLE_GUIDANCE_SCHEMA + "):\n\n" + body
    )


def _role_guidance_active_section(guidance: Mapping[str, Any], role: str) -> str | None:
    """The body of the section this role consumes today, or None.

    Only ``ROLE_GUIDANCE_CONSUMED_SECTIONS`` are returned; a request for a
    section the engine does not yet consume returns ``None`` so the caller
    can refuse the active consumption rather than silently injecting
    reference material.
    """

    if role not in ROLE_GUIDANCE_CONSUMED_SECTIONS:
        return None
    body = guidance.get("sections", {}).get(role)
    if not isinstance(body, str) or not body:
        return None
    return body


def planner_role_guidance(guidance: Mapping[str, Any]) -> tuple[str, str]:
    """Select the fixed planner consumer for both dispatch and context freeze."""

    role = ROLE_GUIDANCE_CONSUMED_SECTION
    body = _role_guidance_active_section(guidance, role)
    if body is None:
        raise WatcherError(ROLE_GUIDANCE_INVALID,
                           role + "_consumption_unavailable")
    return role, body


def hook_definition(root: Path) -> str:
    """The digest of the installed hook script a binding pins."""

    return hashlib.sha256((root / "hooks" / "project_ground_hook.py").read_bytes()).hexdigest()


# ---------------------------------------------------------------- self-test


def codex_version(initialize_result: Mapping[str, Any]) -> str | None:
    agent = initialize_result.get("userAgent") if isinstance(initialize_result, Mapping) else None
    match = _VERSION.search(agent) if isinstance(agent, str) else None
    return match.group(1) if match else None


def codex_hook_hash(event_snake: str, group: Mapping[str, Any], handler: Mapping[str, Any]) -> str:
    """Codex's currentHash for one hook handler of a hooks.json group.

    Reproduced on Codex 0.160.0 against the shared daemon's hooks/list: the
    sha256 of the canonical JSON of the event name, the handler as written in
    hooks.json with async defaulting to false, and the group's matcher.
    """

    entry = dict(handler)
    entry.setdefault("async", False)
    value: dict[str, Any] = {"event_name": event_snake, "hooks": [entry]}
    if group.get("matcher") is not None:
        value["matcher"] = group["matcher"]
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def expected_hooks(root: Path) -> dict[str, dict[str, Any]]:
    """Each required event's key suffix and Codex hash for an installed root."""

    manifest = json.loads((root / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    groups = manifest.get("hooks") if isinstance(manifest, Mapping) else None
    expected: dict[str, dict[str, Any]] = {}
    for event, camel, snake in HOOK_EVENTS:
        rows = groups.get(event) if isinstance(groups, Mapping) else None
        if not isinstance(rows, list) or not rows or not rows[0].get("hooks"):
            raise ValueError("hooks_manifest:" + event + "_missing")
        group = rows[0]
        expected[camel] = {
            "key_suffix": ":" + snake + ":0:0",
            "current_hash": codex_hook_hash(snake, group, group["hooks"][0]),
        }
    return expected


def evaluate_hooks(listed: Any, *, root: Path, plugin_id: str) -> tuple[list[str], list[dict[str, Any]]]:
    """Named issues and the observed rows for the five required plugin hooks.

    ADR 0011 requires each hook user-trusted through Codex's own review, so a
    managed status is not accepted in its place.
    """

    rows = [
        hook
        for scope in (listed.get("data") if isinstance(listed, Mapping) else None) or []
        if isinstance(scope, Mapping)
        for hook in scope.get("hooks") or []
        if isinstance(hook, Mapping) and hook.get("pluginId") == plugin_id
    ]
    source = str((root / "hooks" / "hooks.json").resolve())
    expected = expected_hooks(root)
    issues: list[str] = []
    observed: list[dict[str, Any]] = []
    for camel, want in expected.items():
        matches = [
            hook for hook in rows
            if hook.get("eventName") == camel and str(hook.get("key", "")).endswith(want["key_suffix"])
        ]
        if len(matches) != 1:
            issues.append("governed_mode:hooks_missing")
            observed.append({"event": camel, "present": False})
            continue
        hook = matches[0]
        row = {
            "event": camel,
            "present": True,
            "key": hook.get("key"),
            "enabled": hook.get("enabled"),
            "trust_status": hook.get("trustStatus"),
            "current_hash": hook.get("currentHash"),
            "expected_hash": want["current_hash"],
            "source_path_matches": str(hook.get("sourcePath")) == source,
        }
        observed.append(row)
        if hook.get("enabled") is not True:
            issues.append("governed_mode:hooks_disabled")
        if hook.get("trustStatus") == "modified":
            issues.append("governed_mode:hooks_modified")
        elif hook.get("trustStatus") != "trusted":
            issues.append("governed_mode:hooks_untrusted")
        if hook.get("currentHash") != want["current_hash"] or not row["source_path_matches"]:
            issues.append("governed_mode:hooks_modified")
    return _ordered(issues), observed


def run_hook_scope_probe(root: Path, *, timeout: float = 20.0) -> dict[str, Any]:
    """Run the installed hook on synthetic ungoverned events in a private root.

    The hook must answer each with Codex's pass-through output and write
    nothing, the way it treats every task no governed state binds.  Each
    event keeps the hook's exit code and the tails of its stdout and stderr.
    """

    hook = root / "hooks" / "project_ground_hook.py"
    session = "orch-dork-scope-probe-" + secrets.token_hex(8)
    events = (
        {"hook_event_name": "SessionStart", "source": "startup"},
        {"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "turn_id": "probe-turn",
         "tool_use_id": "probe-1", "tool_input": {"command": "*** Begin Patch\n*** End Patch\n"}},
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "turn_id": "probe-turn",
         "tool_use_id": "probe-2", "tool_input": {"command": "touch probe.txt"}},
        {"hook_event_name": "Stop", "turn_id": "probe-turn", "stop_hook_active": False},
    )
    results = []
    with tempfile.TemporaryDirectory(prefix="od-scope-") as temporary:
        data = Path(temporary) / "plugin-data"
        workspace = Path(temporary) / "workspace"
        data.mkdir(mode=0o700)
        workspace.mkdir()
        environment = {
            key: value for key, value in os.environ.items()
            if key not in {"ORCH_DORK_QUALIFICATION_HOST_PREPARATION", "PLUGIN_DATA", "PLUGIN_ROOT"}
        }
        environment.update(
            {"PLUGIN_ROOT": str(root), "PLUGIN_DATA": str(data), "PYTHONDONTWRITEBYTECODE": "1"}
        )
        for event in events:
            payload = {**event, "session_id": session, "cwd": str(workspace)}
            expected = (
                {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
                if event["hook_event_name"] == "PreToolUse"
                else {"continue": True}
            )
            row: dict[str, Any] = {"event": event["hook_event_name"], "exit_code": None,
                                   "stdout_tail": "", "stderr_tail": "", "error": None}
            try:
                completed = subprocess.run(
                    [sys.executable, "-B", str(hook)], input=json.dumps(payload),
                    capture_output=True, text=True, timeout=timeout, env=environment,
                    cwd=workspace, check=False,
                )
                row.update(exit_code=completed.returncode,
                           stdout_tail=_tail(completed.stdout, PROBE_OUTPUT_TAIL),
                           stderr_tail=_tail(completed.stderr, PROBE_OUTPUT_TAIL))
                output = json.loads(completed.stdout) if completed.stdout.strip() else None
            except subprocess.TimeoutExpired as error:
                output = None
                row["error"] = "timeout"
                row["stdout_tail"] = _tail(str(error.stdout or ""), PROBE_OUTPUT_TAIL)
                row["stderr_tail"] = _tail(str(error.stderr or ""), PROBE_OUTPUT_TAIL)
            except (OSError, ValueError) as error:
                output = None
                row["error"] = type(error).__name__ + ": " + str(error)[:400]
            row["passed_through"] = row["exit_code"] == 0 and output == expected
            results.append(row)
        written = sorted(str(path.relative_to(data)) for path in data.rglob("*"))
    passed = all(row["passed_through"] for row in results) and not written
    return {"status": "PASS" if passed else "FAIL", "events": results, "files_written": written}


def _ordered(issues: Sequence[str]) -> list[str]:
    order = list(SELF_TEST_REFUSALS)
    return sorted(set(issues), key=lambda item: order.index(item) if item in order else len(order))


def model_list(connection: app_server.AppServerConnection) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cursor = None
    for _ in range(32):
        params: dict[str, Any] = {"includeHidden": True, "limit": 200}
        if cursor:
            params["cursor"] = cursor
        page = connection.request("model/list", params) or {}
        rows.extend(row for row in page.get("data") or [] if isinstance(row, dict))
        cursor = page.get("nextCursor")
        if not cursor:
            return rows
    raise ValueError("model list did not end")


_TRANSPORT_ERRORS = (OSError, ValueError, TimeoutError, ConnectionError, app_server.AppServerRequestError)


def startup_self_test(
    connection: app_server.AppServerConnection,
    initialize_result: Mapping[str, Any],
    *,
    root: Path,
    project_root: Path,
    known_good: Sequence[str],
    hook_probe: Callable[[Path], Mapping[str, Any]] = run_hook_scope_probe,
) -> dict[str, Any]:
    """The provider-free self-test of FR69 against one connected app server.

    Each failure is reported under the check it belongs to, with the error
    detail kept: an app server that does not answer is unavailable, never a
    missing hook.
    """

    issues: list[str] = []
    detail: dict[str, str] = {}

    def fail(reason: str, error: BaseException | str) -> None:
        issues.append(reason)
        detail.setdefault(reason, (str(error) if isinstance(error, str)
                                   else type(error).__name__ + ": " + str(error))[:400])

    version = codex_version(initialize_result)
    if version is None or version not in known_good:
        fail("governed_mode:codex_version_unknown", "observed " + str(version))
    plugin_id = plugin_identity(root)[0]
    hooks: list[dict[str, Any]] = []
    try:
        listed = connection.request("hooks/list", {"cwds": [str(project_root)]})
    except _TRANSPORT_ERRORS as error:
        fail("governed_mode:app_server_unavailable", error)
    else:
        hook_issues, hooks = evaluate_hooks(listed, root=root, plugin_id=plugin_id)
        for reason in hook_issues:
            fail(reason, "hooks/list")
    probe = dict(hook_probe(root))
    if probe.get("status") != "PASS":
        fail("governed_mode:hook_scope_unverified", "synthetic ungoverned events")
    location: dict[str, Any] | None = None
    collaboration: dict[str, Any] = {"multi_agent": None, "max_threads": None}
    try:
        config = (connection.request("config/read", {"includeLayers": False}) or {}).get("config") or {}
    except _TRANSPORT_ERRORS as error:
        fail("governed_mode:app_server_unavailable", error)
    else:
        features = config.get("features") if isinstance(config.get("features"), Mapping) else {}
        collaboration["multi_agent"] = features.get("multi_agent")
        agents = config.get("agents") if isinstance(config.get("agents"), Mapping) else {}
        collaboration["max_threads"] = agents.get("max_threads") if type(agents.get("max_threads")) is int else None
        if features.get("multi_agent") is False:
            fail("governed_mode:collaboration_tools_unavailable", "features.multi_agent = false")
        v2 = features.get("multi_agent_v2")
        v2_enabled = bool(v2.get("enabled")) if isinstance(v2, Mapping) else bool(v2)
        try:
            location = onboarded.v1_location(model_list(connection), v2_feature_enabled=v2_enabled)
        except _TRANSPORT_ERRORS as error:
            fail("governed_mode:v1_unavailable", error)
    ordered = _ordered(issues)
    refusal = ordered[0] if ordered else None
    core = {
        "schema": SELF_TEST_SCHEMA,
        "status": "REFUSED" if refusal else "PASS",
        "refusal": refusal,
        "issues": ordered,
        "detail": {reason: detail[reason] for reason in ordered},
        "codex_version": version,
        "known_good": list(known_good),
        "plugin_id": plugin_id,
        "hooks": hooks,
        "hook_scope_probe": probe,
        "collaboration": collaboration,
        "location": location,
        "advisory_offer": advisory_offer(refusal),
        "provider_free": True,
        "model_calls": 0,
        "task_creations": 0,
    }
    return sealed(core, "report_sha256")


def unavailable_self_test(reason: str, detail: str = "") -> dict[str, Any]:
    core = {
        "schema": SELF_TEST_SCHEMA,
        "status": "REFUSED",
        "refusal": reason,
        "issues": [reason],
        "detail": {reason: detail[:400]},
        "advisory_offer": advisory_offer(reason),
        "provider_free": True,
        "model_calls": 0,
        "task_creations": 0,
    }
    return sealed(core, "report_sha256")


# ---------------------------------------------------------------- enrollment


def check_rows(checks: Any) -> list[dict[str, Any]]:
    """The enrolled checks in their closed shape, refused by the first bad one."""

    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS:
        raise WatcherError("governed_run:project_not_enrolled", "checks")
    rows = []
    for check in checks:
        if (
            not isinstance(check, Mapping)
            or set(check) != {"id", "argv", "timeout_seconds"}
            or not isinstance(check.get("id"), str)
            or not _CHECK_ID.fullmatch(check["id"])
            or not isinstance(check.get("argv"), list)
            or not 1 <= len(check["argv"]) <= 64
            or any(not isinstance(part, str) or not part or "\x00" in part for part in check["argv"])
            or type(check.get("timeout_seconds")) is not int
            or not 1 <= check["timeout_seconds"] <= MAX_CHECK_SECONDS
        ):
            raise WatcherError("governed_run:project_not_enrolled", "check shape")
        rows.append({"id": check["id"], "argv": list(check["argv"]), "timeout_seconds": check["timeout_seconds"]})
    if len({row["id"] for row in rows}) != len(rows):
        raise WatcherError("governed_run:project_not_enrolled", "duplicate check id")
    return rows


MAKEFILES = ("GNUmakefile", "makefile", "Makefile")
SCRIPT_RUNNERS = frozenset({"npm", "pnpm", "yarn", "bun"})
# The declarations that define what a pytest check runs, each pinned as a
# whole file or as the one section that configures pytest.
PYTEST_DECLARATIONS = (
    "pyproject.toml#tool.pytest", "pytest.ini", "conftest.py", "setup.cfg#tool:pytest", "tox.ini#pytest",
)


def pin_digest(root: Path, key: str) -> str | None:
    """The digest one pin covers: a whole file, or the section of it that
    defines a check (package.json#scripts, pyproject.toml#tool.pytest,
    setup.cfg#tool:pytest, tox.ini#pytest), by the file's name in any
    folder; None when it is absent."""

    relative, _, section = key.partition("#")
    path = Path(root) / relative
    name = path.name
    try:
        if path.is_symlink() or not path.is_file():
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if not section:
        return hashlib.sha256(data).hexdigest()
    text = data.decode("utf-8", errors="replace")
    value: Any = None
    try:
        if name == "package.json" and section == "scripts":
            loaded = json.loads(text)
            value = loaded.get("scripts") if isinstance(loaded, Mapping) else None
        elif name == "pyproject.toml" and section == "tool.pytest":
            if tomllib is None:
                return hashlib.sha256(data).hexdigest()
            tool = tomllib.loads(text).get("tool")
            value = tool.get("pytest") if isinstance(tool, Mapping) else None
        elif name in ("setup.cfg", "tox.ini"):
            parser = configparser.RawConfigParser(strict=False, interpolation=None)
            parser.read_string(text)
            value = dict(parser.items(section)) if parser.has_section(section) else None
        else:
            return hashlib.sha256(data).hexdigest()
    except (ValueError, TypeError, configparser.Error):
        return hashlib.sha256(data).hexdigest()
    return None if value is None else policy.sha256(value)


def _definition_pins(root: Path, argv: Sequence[str]) -> list[str]:
    """The declarations that define what a check command actually runs."""

    command = Path(argv[0]).name
    if command == "make":
        return [next((name for name in MAKEFILES if (root / name).is_file()), "Makefile")]
    if command in SCRIPT_RUNNERS:
        return ["package.json#scripts"]
    if "pytest" in argv or command == "pytest":
        return [key for key in PYTEST_DECLARATIONS if pin_digest(root, key) is not None]
    return []


def pinned_check_files(project_root: Path, checks: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """What each check runs, pinned at enrollment.

    A governed task may change the project, so every project file a check's
    argv names is pinned, and so is the declaration that defines the command:
    the Makefile for make, package.json's scripts (hooks such as pretest
    included) for a package manager, and pytest's own configuration.  A
    changed or missing pin refuses the run instead of trusting a check the
    task could have rewritten; the tests a check runs stay the project's own.
    """

    root = Path(os.path.realpath(project_root))
    pins: dict[str, str] = {}
    for check in checks:
        for argument in check["argv"]:
            candidate = Path(argument) if Path(argument).is_absolute() else root / argument
            try:
                resolved = Path(os.path.realpath(candidate))
                relative = resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            if resolved.is_file():
                pins[relative.as_posix()] = hashlib.sha256(resolved.read_bytes()).hexdigest()
        for key in _definition_pins(root, check["argv"]):
            digest = pin_digest(root, key)
            if digest is not None:
                pins[key] = digest
    return dict(sorted(pins.items()))


# ---------------------------------------------------------------- test tree

# Issue 246: what a run pins of the project's tests.  A folder with one of
# these names holds tests; so does a pytest testpaths entry.
TEST_DIRECTORIES = frozenset({"test", "tests", "__tests__", "spec", "specs"})
_TEST_FILE = re.compile(
    r"\A(?:test_.+\.py|.+_test\.py|conftest\.py|.+_test\.go|.+_spec\.rb|.+\.(?:test|spec)\.[cm]?[jt]sx?)\Z"
)
# Folders whose files are not the project's own tests; hidden ones are skipped too.
SKIPPED_TEST_TREE_DIRECTORIES = frozenset(
    {"node_modules", "__pycache__", "site-packages", "venv", "vendor", "build", "dist", "target"}
)
# Every file pytest may read its configuration from, by name, with the
# section that configures it ("" for the whole file).  pytest takes its
# configuration file from the folder of the tests it runs or one above,
# and loads every conftest.py on the way.
PYTEST_FILES = {
    "conftest.py": "", "pytest.ini": "", "pyproject.toml": "tool.pytest", "tox.ini": "pytest",
    "setup.cfg": "tool:pytest",
}
# The test configuration at the project root, pinned present or absent.
TEST_CONFIGURATION = (
    *PYTEST_DECLARATIONS,
    *("jest.config." + suffix for suffix in ("js", "ts", "mjs", "cjs", "json")),
    *("vitest.config." + suffix for suffix in ("js", "ts", "mjs", "cjs", "mts")),
)


def _too_large() -> WatcherError:
    return WatcherError("governed_run:test_tree_too_large", RUN_REFUSALS["governed_run:test_tree_too_large"])


def _configuration_key(relative: str) -> str:
    section = PYTEST_FILES[Path(relative).name]
    return relative + ("#" + section if section else "")


def _testpaths(root: Path) -> list[str]:
    """pytest's testpaths at the project root: each a plain relative folder or file."""

    values: list[Any] = []
    try:
        loaded = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        pytest = (loaded.get("tool") or {}).get("pytest") or {}
        for table in (pytest, pytest.get("ini_options") or {}):
            values.append(table.get("testpaths"))
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    for name, section in (("pytest.ini", "pytest"), ("tox.ini", "pytest"), ("setup.cfg", "tool:pytest")):
        parser = configparser.RawConfigParser(strict=False, interpolation=None)
        try:
            parser.read_string((root / name).read_text(encoding="utf-8"))
            if parser.has_option(section, "testpaths"):
                values.append(parser.get(section, "testpaths").split())
        except (OSError, ValueError, configparser.Error):
            pass
    paths = []
    for value in values:
        for entry in ([value] if isinstance(value, str) else value if isinstance(value, list) else []):
            entry = entry.strip().rstrip("/") if isinstance(entry, str) else ""
            parts = Path(entry).parts
            if (entry and not Path(entry).is_absolute() and ".." not in parts
                    and not any(character in entry for character in "*?[")):
                paths.append(Path(entry).as_posix())
    return sorted(set(paths))


def _tree_digest(root: Path, relative: str, limit: int) -> tuple[str | None, int]:
    """One test-tree file's digest and size: a regular file by its bytes, a
    symbolic link by its target, never through a linked folder; None when
    it is absent or is neither.  A file larger than limit is not read: its
    digest names its size, which no pinned digest equals."""

    path = root / relative
    try:
        if os.path.realpath(path.parent) != str(path.parent):
            return None, 0
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            return hashlib.sha256(b"symlink:" + os.fsencode(os.readlink(path))).hexdigest(), 0
        if not stat.S_ISREG(info.st_mode):
            return None, 0
        if info.st_size > limit:
            return "size:" + str(info.st_size), info.st_size
        return hashlib.sha256(path.read_bytes()).hexdigest(), info.st_size
    except OSError:
        return None, 0


def _project_files(root: Path):
    """Every file in the project outside hidden, dependency, cache and build
    folders, as (relative path, whether it is in the test tree); symbolic
    links to folders are not followed."""

    testpaths = _testpaths(root)
    entries = 0
    for directory, folders, files in os.walk(root):
        folders[:] = sorted(name for name in folders
                            if not name.startswith(".") and name not in SKIPPED_TEST_TREE_DIRECTORIES)
        entries += len(folders) + len(files)
        if entries > MAX_TEST_TREE_ENTRIES:
            raise _too_large()
        here = Path(directory).relative_to(root)
        tests_folder = any(part in TEST_DIRECTORIES for part in here.parts)
        for name in sorted(files):
            relative = (here / name).as_posix()
            yield relative, (tests_folder or _TEST_FILE.fullmatch(name) is not None or any(
                relative == path or relative.startswith(path + "/") for path in testpaths))


def _current_pin(root: Path, key: str) -> str | None:
    return pin_digest(root, key) if "#" in key else _tree_digest(root, key, MAX_TEST_TREE_BYTES)[0]


def test_tree_pins(project_root: Path) -> dict[str, str | None]:
    """The project's test tree, pinned when a run starts (Issue 246).

    Every file in a tests folder, under a pytest testpaths entry or named
    like a test, by its digest; every file pytest may read its
    configuration from, by the section that configures pytest; and the
    test configuration at the project root, present or absent (None).
    Enrollment pins the configuration that decides which files these are,
    and these bytes are pinned per run, so the user's own edits between
    runs refuse nothing.
    """

    root = Path(os.path.realpath(project_root))
    pins: dict[str, str | None] = {}
    count = size = 0
    for relative, in_tree in _project_files(root):
        if in_tree:
            digest, length = _tree_digest(root, relative, MAX_TEST_TREE_BYTES - size)
            if digest is not None:
                count, size = count + 1, size + length
                if count > MAX_TEST_TREE_FILES or size > MAX_TEST_TREE_BYTES:
                    raise _too_large()
                pins[relative] = digest
        if Path(relative).name in PYTEST_FILES:
            key = _configuration_key(relative)
            pins[key] = _current_pin(root, key)
    for key in TEST_CONFIGURATION:
        pins[key] = _current_pin(root, key)
    return dict(sorted(pins.items()))


def changed_test_tree(project_root: Path, pins: Mapping[str, str | None]) -> list[str]:
    """What a run changed of the test tree pinned when it started: a pinned
    file or section that changed, appeared or disappeared, and any new file
    that configures pytest.  A new test file is not a change."""

    root = Path(os.path.realpath(project_root))
    changed = {key for key, digest in pins.items() if _current_pin(root, key) != digest}
    for relative, _in_tree in _project_files(root):
        name = Path(relative).name
        if name in PYTEST_FILES and _configuration_key(relative) not in pins:
            key = _configuration_key(relative)
            if name in ("conftest.py", "pytest.ini") or _current_pin(root, key) is not None:
                changed.add(key)
    return sorted(changed)


def write_test_tree(run_dir: Path, run_id: str, pins: Mapping[str, str | None]) -> None:
    write_json(run_dir / "test-tree.json",
               sealed({"schema": TEST_TREE_SCHEMA, "run_id": run_id, "pins": dict(pins)}, "record_sha256"),
               create_only=True)


ENROLLMENT_FIELDS = frozenset({
    "schema", "version", "project_root", "project_key", "project_type", "detection_sha256",
    "project_ground", "checks", "check_sources", "pinned_files", "models", "v1",
    "standing_authority", "confirmed", "previous_record_sha256", "record_sha256",
})
_GROUND_FIELDS = frozenset({"registry_root", "identity_key", "record_sha256", "manifest_sha256", "decision"})
_MODELS_FIELDS = frozenset({"chat_model", "chat_model_source", "second_model", "suggested_second_model"})
_V1_FIELDS = frozenset({"location", "location_sha256", "opt_in", "opt_in_report_sha256"})
_CONFIRMED_FIELDS = frozenset({"at", "source", "requesting_thread_id", "draft_sha256"})
V1_OPT_IN = ("not_needed", "declined", "applied", "not_applied", "not_offered")


def enrollment_path(records: Path, project_root: Path) -> Path:
    return records / "enrollments" / (project_key(project_root) + ".json")


def enrollment_issues(value: Any, project_root: Path) -> list[str]:
    """Why an enrollment record is not valid for this project; empty when it is."""

    if not isinstance(value, Mapping) or set(value) != ENROLLMENT_FIELDS:
        return ["enrollment:shape"]
    issues = []
    root = os.path.realpath(project_root)
    if value.get("schema") != ENROLLMENT_SCHEMA or type(value.get("version")) is not int or value["version"] < 1:
        issues.append("enrollment:schema")
    if value.get("project_root") != root or value.get("project_key") != project_key(Path(root)):
        issues.append("enrollment:project_root")
    ground = value.get("project_ground")
    if not isinstance(ground, Mapping) or set(ground) != _GROUND_FIELDS:
        issues.append("enrollment:project_ground")
    try:
        rows = check_rows(value.get("checks"))
    except WatcherError:
        issues.append("enrollment:checks")
    else:
        sources = value.get("check_sources")
        if not isinstance(sources, Mapping) or set(sources) != {row["id"] for row in rows} or any(
            item not in ("detected", "stated") for item in sources.values()
        ):
            issues.append("enrollment:check_sources")
    pins = value.get("pinned_files")
    if not isinstance(pins, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in pins.items()
    ):
        issues.append("enrollment:pinned_files")
    models = value.get("models")
    if not isinstance(models, Mapping) or set(models) != _MODELS_FIELDS or any(
        not isinstance(models.get(key), str) or not _MODEL.fullmatch(models[key])
        for key in ("chat_model", "second_model")
    ) or models.get("chat_model") == models.get("second_model"):
        issues.append("enrollment:models")
    v1 = value.get("v1")
    if not isinstance(v1, Mapping) or set(v1) != _V1_FIELDS or v1.get("opt_in") not in V1_OPT_IN:
        issues.append("enrollment:v1")
    confirmed = value.get("confirmed")
    if not isinstance(confirmed, Mapping) or set(confirmed) != _CONFIRMED_FIELDS or confirmed.get(
        "source"
    ) not in ("chat", "local"):
        issues.append("enrollment:confirmed")
    issues.extend("enrollment:" + item for item in admission.authority_issues(value.get("standing_authority")))
    if not issues and not seal_valid(value, "record_sha256"):
        issues.append("enrollment:seal")
    return issues


def read_enrollment(records: Path, project_root: Path) -> dict[str, Any]:
    """The project's enrollment record, still bound by its project-ground enrollment.

    The record names the project-ground enrollment it was written against;
    the binding manifest and external record must still be that exact
    active enrollment, read without following links and without walking the
    project tree.
    """

    path = enrollment_path(records, project_root)
    try:
        value = read_json(path)
    except (OSError, ValueError, WatcherError) as error:
        raise WatcherError("governed_run:project_not_enrolled", str(project_root)) from error
    issues = enrollment_issues(value, project_root)
    if issues:
        raise WatcherError("governed_run:project_not_enrolled", issues[0])
    ground = value["project_ground"]
    try:
        program = project_ground.build_active_inspection_program(
            Path(value["project_root"]), Path(ground["registry_root"]),
            maintenance_reason="governed-run enrollment check",
            source_pointer="orch-dork:governed-run",
        )
    except project_ground.ProjectEnrollmentInspectionError as error:
        raise WatcherError("governed_run:project_not_enrolled", "project ground: " + str(error)) from error
    if program["expected_registry"]["record_sha256"] != ground["record_sha256"]:
        raise WatcherError("governed_run:project_not_enrolled", "project-ground record changed")
    return value


# ---------------------------------------------------------------- request


def validate_request(value: Any) -> dict[str, Any]:
    fields = {"schema", "run_id", "project_root", "goal", "model", "effort",
              "requesting_thread_id", "turn_seconds", "cost_budget_cents",
              "lanes", "worker_model", "worker_effort"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("schema") != REQUEST_SCHEMA:
        raise WatcherError("governed_run:request_invalid", "shape")
    if not isinstance(value.get("run_id"), str) or not _RUN_ID.fullmatch(value["run_id"]):
        raise WatcherError("governed_run:request_invalid", "run_id")
    root = value.get("project_root")
    if not isinstance(root, str) or not Path(root).is_absolute():
        raise WatcherError("governed_run:request_invalid", "project_root")
    goal = value.get("goal")
    if not isinstance(goal, str) or not goal.strip() or len(goal) > 16_000:
        raise WatcherError("governed_run:request_invalid", "goal")
    if not isinstance(value.get("model"), str) or not _MODEL.fullmatch(value["model"]):
        raise WatcherError("governed_run:request_invalid", "model")
    if not isinstance(value.get("effort"), str) or not _EFFORT.fullmatch(value["effort"]):
        raise WatcherError("governed_run:request_invalid", "effort")
    requester = value.get("requesting_thread_id")
    if requester is not None and (not isinstance(requester, str) or not requester or len(requester) > 256):
        raise WatcherError("governed_run:request_invalid", "requesting_thread_id")
    seconds = value.get("turn_seconds")
    if type(seconds) is not int or not 60 <= seconds <= MAX_TURN_SECONDS:
        raise WatcherError("governed_run:request_invalid", "turn_seconds")
    budget = value.get("cost_budget_cents")
    if budget is not None and (type(budget) is not int or not 1 <= budget <= admission.MAX_CENTS):
        raise WatcherError("governed_run:request_invalid", "cost_budget_cents")
    lanes = value.get("lanes")
    if not isinstance(lanes, list) or len(lanes) > admission.MAX_WORKERS:
        raise WatcherError("governed_run:request_invalid", "lanes")
    seen: set[str] = set()
    for lane in lanes:
        _validate_lane(lane, seen)
    owned = [(lane["id"], path) for lane in lanes for path in lane.get("writes", [])]
    for index, (lane_id, path) in enumerate(owned):
        for other_id, other in owned[index + 1:]:
            if other_id != lane_id and policy.writes_overlap(path, other):
                raise WatcherError("governed_run:request_invalid",
                                   "lanes " + lane_id + " and " + other_id + " own overlapping paths")
    worker_model, worker_effort = value.get("worker_model"), value.get("worker_effort")
    if lanes and (not isinstance(worker_model, str) or not _MODEL.fullmatch(worker_model)):
        raise WatcherError("governed_run:request_invalid", "worker_model")
    if lanes and (not isinstance(worker_effort, str) or not _EFFORT.fullmatch(worker_effort)):
        raise WatcherError("governed_run:request_invalid", "worker_effort")
    if not lanes and (worker_model is not None or worker_effort is not None):
        raise WatcherError("governed_run:request_invalid", "worker_model without lanes")
    return dict(value)


def _validate_lane(lane: Any, seen: set[str]) -> None:
    """One lane: an id, a goal, its checks and, optionally, the paths it owns
    (Issue 247), each canonical and relative to the project."""

    if not isinstance(lane, Mapping) or set(lane) not in (
        {"id", "goal", "checks"}, {"id", "goal", "checks", "writes"}
    ):
        raise WatcherError("governed_run:request_invalid", "lane")
    lane_id = lane.get("id")
    if not isinstance(lane_id, str) or not _LANE_ID.fullmatch(lane_id) or lane_id in seen:
        raise WatcherError("governed_run:request_invalid", "lane id")
    seen.add(lane_id)
    goal = lane.get("goal")
    if not isinstance(goal, str) or not goal.strip() or len(goal) > MAX_LANE_GOAL:
        raise WatcherError("governed_run:request_invalid", "lane " + lane_id + " goal")
    checks = lane.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_LANE_CHECKS:
        raise WatcherError("governed_run:request_invalid", "lane " + lane_id + " checks")
    for check in checks:
        selectors = check.get("selectors") if isinstance(check, Mapping) else None
        if (
            not isinstance(check, Mapping)
            or set(check) != {"check", "selectors"}
            or not isinstance(check.get("check"), str)
            or not _CHECK_ID.fullmatch(check["check"])
            or not isinstance(selectors, list)
            or len(selectors) > MAX_SELECTORS
            or any(not _selector_valid(selector) for selector in selectors)
        ):
            raise WatcherError("governed_run:request_invalid", "lane " + lane_id + " check")
    if "writes" in lane:
        writes = lane["writes"]
        if (
            not isinstance(writes, list)
            or not 1 <= len(writes) <= policy.MAX_LANE_WRITES
            or not all(policy.write_path_valid(path) for path in writes)
            or len(set(writes)) != len(writes)
        ):
            raise WatcherError("governed_run:request_invalid", "lane " + lane_id + " writes")


def _selector_valid(value: Any) -> bool:
    """A relative path inside the project, optionally with a pytest node id."""

    return (
        isinstance(value, str)
        and _SELECTOR.fullmatch(value) is not None
        and ".." not in value.split("::", 1)[0].split("/")
    )


def build_request(
    *,
    project_root: str,
    goal: Any,
    model: Any,
    effort: Any,
    requesting_thread_id: str | None = None,
    turn_seconds: int = DEFAULT_TURN_SECONDS,
    run_id: str | None = None,
    cost_budget_cents: int | None = None,
    lanes: Sequence[Mapping[str, Any]] = (),
    worker_model: str | None = None,
    worker_effort: str | None = None,
) -> dict[str, Any]:
    """A run request; a budget of None is the project's per-run cost limit.

    Each lane is {id, goal, checks: [{check, selectors}]} and optionally
    writes, the paths it owns; a check without selectors may leave them out.
    """

    return validate_request({
        "schema": REQUEST_SCHEMA,
        "run_id": run_id or new_run_id(),
        "project_root": str(project_root),
        "goal": goal,
        "model": model,
        "effort": effort,
        "requesting_thread_id": requesting_thread_id,
        "turn_seconds": turn_seconds,
        "cost_budget_cents": cost_budget_cents,
        "lanes": _lane_requests(lanes),
        "worker_model": worker_model,
        "worker_effort": worker_effort,
    })


def _lane_requests(lanes: Any) -> Any:
    if not isinstance(lanes, (list, tuple)):
        return lanes
    normal = []
    for lane in lanes:
        if isinstance(lane, Mapping) and isinstance(lane.get("checks"), (list, tuple)):
            checks = [
                {"check": check.get("check"), "selectors": list(check.get("selectors") or [])}
                if isinstance(check, Mapping) and set(check) <= {"check", "selectors"} else check
                for check in lane["checks"]
            ]
            lane = {**dict(lane), "checks": checks}
        if isinstance(lane, Mapping) and isinstance(lane.get("writes"), tuple):
            lane = {**dict(lane), "writes": list(lane["writes"])}
        normal.append(dict(lane) if isinstance(lane, Mapping) else lane)
    return normal


# ---------------------------------------------------------------- lanes


def lane_check_argv(argv: Sequence[str], selectors: Sequence[str]) -> list[str]:
    """An enrolled check narrowed to the files that hold a lane's acceptance tests.

    Selectors follow pytest's arguments, or a package script's after "--";
    another runner takes none, so its lane check is the enrolled check as it is.
    """

    argv = list(argv)
    if not selectors:
        return argv
    command = Path(argv[0]).name
    if command in SCRIPT_RUNNERS and len(argv) >= 3 and argv[1] == "run":
        return [*argv, "--", *selectors]
    if command == "pytest" or "pytest" in argv:
        return [*argv, *selectors]
    raise WatcherError("governed_run:request_invalid", "lane check selectors: " + command + " takes none")


def resolve_lanes(request: Mapping[str, Any], enrollment: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The request's lanes, their checks resolved and their acceptance files pinned.

    A lane check is one of the enrolled checks, optionally narrowed to the
    files that hold the lane's acceptance tests, so a lane runs only commands
    the user enrolled on this machine.  Every file a selector names must exist
    and is pinned in the work summary, so a run that changed a lane's own
    acceptance test is refused like one that changed an enrolled check.
    A path a lane owns may not pass through a symbolic link (Issue 247).
    """

    root = Path(os.path.realpath(request["project_root"]))
    enrolled = {row["id"]: row for row in enrollment["checks"]}
    resolved = []
    for lane in request["lanes"]:
        checks: list[dict[str, Any]] = []
        pins: dict[str, str] = {}
        used: dict[str, int] = {}
        for reference in lane["checks"]:
            row = enrolled.get(reference["check"])
            if row is None:
                raise WatcherError("governed_run:request_invalid",
                                   "lane " + lane["id"] + " names no enrolled check " + reference["check"])
            for selector in reference["selectors"]:
                relative = selector.split("::", 1)[0]
                target = Path(os.path.realpath(root / relative))
                try:
                    inside = target.relative_to(root).as_posix()
                except ValueError:
                    inside = None
                if inside is None or (root / relative).is_symlink() or not target.is_file():
                    raise WatcherError("governed_run:request_invalid",
                                       "lane " + lane["id"] + ": " + relative + " is not a file in the project")
                pins[inside] = hashlib.sha256(target.read_bytes()).hexdigest()
            used[reference["check"]] = used.get(reference["check"], 0) + 1
            count = used[reference["check"]]
            checks.append({
                "id": lane["id"] + "." + reference["check"] + ("" if count == 1 else "." + str(count)),
                "argv": lane_check_argv(row["argv"], reference["selectors"]),
                "timeout_seconds": row["timeout_seconds"],
            })
        writes = list(lane.get("writes") or [])
        for path in writes:
            current = root
            for part in Path(path).parts:
                current = current / part
                if current.is_symlink():
                    raise WatcherError("governed_run:request_invalid",
                                       "lane " + lane["id"] + ": " + path + " passes through a symbolic link")
        resolved.append({"id": lane["id"], "goal": lane["goal"].strip(), "checks": checks,
                         "pins": dict(sorted(pins.items())), "writes": writes})
    return resolved


PATCH_TOOL_GUIDANCE = (
    "If you use apply_patch, pass its patch as a raw string. Use *** Begin Patch, "
    "then *** Add File: path, *** Update File: path or *** Delete File: path, "
    "and end with *** End Patch. Every line of an added file starts with +. An "
    "update uses @@, then lines that start with a space for unchanged context, + "
    "for added and - for removed; read the file first. Do not use unified-diff "
    "---/+++ headers: Codex rejects a malformed patch before it records a "
    "file-change item.\n\n"
)


def check_command(argv: Sequence[str]) -> str:
    """A check's command line as a shell would need it typed.

    The spawn messages carrying it are copied exactly; a command with an
    unquoted argument invites a careful model to correct it, and any change
    to a message is a spawn outside the plan.
    """

    return shlex.join(argv)


def lane_message(goal: str, lane: Mapping[str, Any], others: Sequence[str] = ()) -> str:
    """The exact spawn_agent message of one lane's worker.

    It names no run id, so the plan it is part of keeps one digest across the
    calls that ask for it and approve it.
    """

    checks = "\n".join("- " + check_command(row["argv"]) for row in lane["checks"])
    own = list(lane.get("writes") or [])
    ownership = [
        *(["Your lane owns " + ", ".join(own) + "."] if own else []),
        *(["Other lanes own " + ", ".join(others) + "; Orch Dork refuses your writes to their paths, "
           "and you may read them."] if others else []),
    ]
    return (
        "Orch Dork governed run, lane " + lane["id"] + ".\n\nThe run's goal: " + goal
        + "\n\nYour lane: " + lane["goal"]
        + ("\n\nWrite ownership: " + " ".join(ownership) if ownership else "")
        + "\n\n" + PATCH_TOOL_GUIDANCE
        + "Do this lane's work yourself in this workspace "
        "with your shell and apply_patch tools. Do not spawn or message other agents, do not "
        "call MCP tools, and do not change the acceptance checks below or the files they name. "
        "When you finish, Orch Dork runs these checks itself:\n" + checks
        + "\n\nReply with a short summary of what you changed, then stop."
    )


def repair_message(goal: str, failed: Sequence[Mapping[str, Any]]) -> str:
    """The exact spawn_agent message of the one repair round's worker.

    It names the failed checks' commands and none of their output, so the
    task coordinating the repair can copy it exactly.
    """

    commands = list(dict.fromkeys(check_command(row["argv"]) for row in failed))
    return (
        "Orch Dork governed run, repair round.\n\nThe run's goal: " + goal
        + "\n\nThese checks failed after the lanes finished:\n"
        + "\n".join("- " + command for command in commands)
        + "\n\n" + PATCH_TOOL_GUIDANCE
        + "Run them to see the failures, then fix the project so they pass. Do this work "
        "yourself with your shell and apply_patch tools. Do not spawn or message other agents, "
        "do not call MCP tools, and do not change the checks or the files they name. Reply with "
        "a short summary of what you changed, then stop."
    )


def spawn_arguments(message: str, model: str, effort: str) -> dict[str, Any]:
    """The spawn_agent arguments a lane or repair worker is started with."""

    return {"message": message, "model": model, "reasoning_effort": effort, "fork_context": False}


def work_summary(
    request: Mapping[str, Any], project: Mapping[str, Any], lanes: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """What the governed task is bound to: the goal, the checks and its lanes.

    Write ownership appears only when some lane declares it, so a plan
    without it keeps the digest it had before Issue 247.
    """

    goal = request["goal"].strip()
    owned = any(lane.get("writes") for lane in lanes)

    def others(lane: Mapping[str, Any]) -> list[str]:
        return [path for other in lanes if other["id"] != lane["id"] for path in other.get("writes") or []]

    return {
        "goal": goal,
        "checks": [{"id": row["id"], "argv": row["argv"]} for row in project["checks"]],
        "workers": len(lanes),
        "lanes": [
            {
                "id": lane["id"],
                "goal": lane["goal"],
                "checks": [{"id": row["id"], "argv": row["argv"]} for row in lane["checks"]],
                "pins": dict(lane["pins"]),
                **({"writes": list(lane.get("writes") or [])} if owned else {}),
                "spawn": spawn_arguments(lane_message(goal, lane, others(lane)), request["worker_model"],
                                         request["worker_effort"]),
            }
            for lane in lanes
        ],
    }


def summary_text(run_id: str, summary: Mapping[str, Any], open_workers: Sequence[str] = ()) -> str:
    closing = (
        "Before any new spawn or implementation, call close_agent once for each old worker "
        "below, using exactly its target argument. Their turns have ended and were archived; "
        "closing them also releases their native agent slots. Do not retry a close that "
        "reports the worker already unavailable.\n"
        + "\n".join("close_agent: " + json.dumps({"target": worker}) for worker in open_workers) + "\n\n"
    ) if open_workers else ""
    checks = "\n".join(
        "- " + row["id"] + ": " + check_command(row["argv"]) for row in summary["checks"]
    )
    if summary["lanes"]:
        spawns = "\n\n".join(
            "Lane " + lane["id"] + ": call spawn_agent with exactly these arguments:\n"
            + json.dumps(lane["spawn"], ensure_ascii=False)
            for lane in summary["lanes"]
        )
        return (
            "Orch Dork governed run " + run_id + ".\n\nGoal:\n" + summary["goal"]
            + "\n\n" + closing + "You coordinate " + str(len(summary["lanes"])) + " lane workers and do no lane "
            "work yourself; your own shell, apply_patch and MCP calls are refused.\n"
            "1. Call spawn_agent once for each lane below, with exactly the arguments given, "
            "before you wait for any of them.\n"
            "2. Call wait_agent with {\"targets\": [the workers' ids]}; when it times out, call it again, "
            "until every worker has finished.\n"
            "3. Call close_agent once for each worker, with {\"target\": its id}.\n"
            "4. Stop.\n\nAfter you stop, Orch Dork runs each lane's checks, then these checks "
            "on the joined result, gives the run one repair round if a check fails, and "
            "computes the verdict from the results:\n" + checks + "\n\n" + spawns + "\n"
        )
    return (
        "Orch Dork governed run " + run_id + ".\n\nGoal:\n" + summary["goal"]
        + "\n\n" + closing + "Workers: none. Do this work yourself in this task.\n\n"
        + PATCH_TOOL_GUIDANCE
        + "After you stop, Orch Dork runs these checks itself and the verdict "
        + "comes from their results:\n" + checks + "\n"
    )


def repair_text(run_id: str, arguments: Mapping[str, Any], open_workers: Sequence[str] = ()) -> str:
    """The turn that starts the run's one repair round.

    A lane worker the first round left open still takes one of the agents
    Codex lets a task keep open, so the turn names each one to close before
    the repair worker is spawned.
    """

    steps = []
    if open_workers:
        steps.append("Close the lane workers still open, one close_agent call each: "
                     + ", ".join(json.dumps({"target": worker}) for worker in open_workers) + ".")
    steps += [
        "Call spawn_agent once with exactly these arguments:\n" + json.dumps(dict(arguments), ensure_ascii=False),
        "Call wait_agent with {\"targets\": [its id]}; when it times out, call it again, until it has finished.",
        "Call close_agent for it, with {\"target\": its id}.",
        "Stop.",
    ]
    return (
        "Orch Dork governed run " + run_id + ": repair round.\n\nSome checks failed after the "
        "lanes finished. You coordinate one repair worker and do no work yourself.\n"
        + "".join(str(number) + ". " + step + "\n" for number, step in enumerate(steps, 1))
        + "\nAfter you stop, Orch Dork runs every check again and computes the verdict from the results.\n"
    )


def onboarding_admission(
    models: Sequence[str], enrollment: Mapping[str, Any], *, codex_version: str | None = None,
    onboarding_root: Any = None,
) -> dict[str, Any]:
    """ADR 0012's admission for the run's models over the onboarded profiles.

    A profile records Codex's version as its command line prints it
    ("codex-cli X.Y.Z"); the self-test reads the bare version from the app
    server, so it is compared in the profile's form.
    """

    return onboarded.governed_admission(
        list(dict.fromkeys(models)), local_only=enrollment["standing_authority"]["keep_local"],
        codex_version=None if codex_version is None else "codex-cli " + codex_version,
        root=onboarding_root,
    )


def run_models(request: Mapping[str, Any]) -> list[str]:
    """The models a run uses: the governed task's, and its lane workers'."""

    return [request["model"], *([request["worker_model"]] if request["lanes"] else [])]


# ---------------------------------------------------------------- plan and admission claim


def run_plan(
    request: Mapping[str, Any], enrollment: Mapping[str, Any],
    lanes: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The frozen plan of a run: zero workers, or one worker per lane.

    The governed task's model writes the code of a zero-worker run; with
    lanes it plans and the workers' model writes the code.
    """

    authority = enrollment["standing_authority"]
    budget = request["cost_budget_cents"]
    lanes = resolve_lanes(request, enrollment) if lanes is None else lanes
    workers = len(lanes)
    return admission.build_plan(
        enrollment_sha256=enrollment["record_sha256"],
        summary_sha256=policy.sha256(work_summary(request, enrollment, lanes)),
        workflow_profile=admission.workflow_profile_for(workers),
        workers=workers,
        models=(
            {"planner": request["model"], "implementer": request["worker_model"]}
            if workers else {"implementer": request["model"]}
        ),
        effort=request["effort"],
        budget_cents=authority["per_run_cost_cents"] if budget is None else budget,
    )


def local_date(now: datetime | None = None) -> str:
    """The user's day, by this host's local time, that daily limits count."""

    return (now or datetime.now(timezone.utc)).astimezone().date().isoformat()


def claim_path(run_dir: Path) -> Path:
    return run_dir / "admission.json"


def reserved_today(records: Path, project_root: Path, day: str) -> int:
    """Budgets admitted today for this project, each counted in full.

    Billing is not observable, so an admitted run counts its whole budget
    unless it ended before a governed task existed, which spends nothing.
    """

    key = project_key(project_root)
    stamp = datetime.fromisoformat(day)
    # Run ids carry the UTC date, which is at most a day from the local one.
    days = {(stamp + timedelta(days=offset)).strftime("%Y%m%d") for offset in (-1, 0, 1)}
    total = 0
    runs = records / "runs"
    for run_dir in sorted(runs.iterdir()) if runs.is_dir() else ():
        if run_date(run_dir.name) not in days:
            continue
        try:
            claim = read_json(claim_path(run_dir))
        except (OSError, ValueError, WatcherError):
            continue
        decision = claim.get("admission") if isinstance(claim, Mapping) else None
        if (
            not seal_valid(claim, "claim_sha256")
            or claim.get("project_key") != key
            or not isinstance(decision, Mapping)
            or decision.get("decision") != "START"
        ):
            continue
        try:
            record = read_json(run_dir / "record.json") if (run_dir / "record.json").exists() else None
        except (OSError, ValueError, WatcherError):
            record = None
        if isinstance(record, Mapping) and record.get("governed_thread_id") is None:
            continue
        if decision.get("local_date") == day:
            total += int(decision.get("budget_cents") or 0)
        for revision in controls.revisions(run_dir):
            revised = revision.get("admission") or {}
            if revised.get("decision") == "START" and revised.get("local_date") == day:
                total += int(revised.get("budget_cents") or 0)
    return total


def admit_request(
    request: Mapping[str, Any],
    *,
    records: Path,
    onboarding_root: Any = None,
    approved_plan_sha256: str | None = None,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """The enrollment, frozen plan and admission decision for one request."""

    moment = now or datetime.now(timezone.utc)
    project_root = Path(os.path.realpath(request["project_root"]))
    enrollment = read_enrollment(records, project_root)
    plan = run_plan(request, enrollment)
    day = local_date(moment)
    decision = admission.admit(
        plan, enrollment["standing_authority"],
        reserved_today_cents=reserved_today(records, project_root, day),
        local_date=day,
        onboarding=onboarding_admission(run_models(request), enrollment, onboarding_root=onboarding_root),
        approval=read_ask(records, approved_plan_sha256, now=moment,
                          requesting_thread_id=request["requesting_thread_id"]) if approved_plan_sha256 else None,
    )
    return enrollment, plan, decision


def ask_path(records: Path, plan_sha256: str, requesting_thread_id: str | None) -> Path:
    """Where the question about one plan put to one task is kept."""

    task = hashlib.sha256((requesting_thread_id or "").encode("utf-8")).hexdigest()[:32]
    return records / "asks" / plan_sha256 / (task + ".json")


def approval_path(run_dir: Path) -> Path:
    return run_dir / "approval.json"


def write_ask(records: Path, request: Mapping[str, Any], decision: Mapping[str, Any], *,
              plan: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Record the question an ASK decision puts to the user in the requesting
    task; a newer question there about the same plan replaces it."""

    ask = admission.build_ask(decision, asked_at=utc_now(), requesting_thread_id=request["requesting_thread_id"])
    write_json(ask_path(records, ask["plan_sha256"], ask["requesting_thread_id"]), ask)
    if plan is not None:
        import orch_dork_local_ui_projection as projection
        # A separate, sanitized view cannot be submitted as an approval.
        view = sealed({"schema": "orch-dork/local-ui-plan/v1",
                       "requesting_thread_id": ask["requesting_thread_id"],
                       "run": projection.plan_view(request, plan)}, "view_sha256")
        write_json(records / "plan-views" / ask["plan_sha256"] / "view.json", view)
    return ask


def read_ask(records: Path, plan_sha256: Any, *, now: datetime,
             requesting_thread_id: str | None) -> dict[str, Any] | None:
    """The unused question an approval names, while the task it was put to
    can still answer it."""

    if not isinstance(plan_sha256, str) or not _SHA256.fullmatch(plan_sha256):
        return None
    try:
        ask = read_json(ask_path(records, plan_sha256, requesting_thread_id))
    except (OSError, ValueError, WatcherError):
        return None
    return ask if admission.ask_open(ask, now=now, requesting_thread_id=requesting_thread_id) else None


def _return_question(records: Path, request: Mapping[str, Any], plan_sha256: str, run_dir: Path) -> None:
    """Undo a consumption that did not match the approval: put the question
    back unless a newer one replaced it, and remove the unclaimed run."""

    moved = approval_path(run_dir)
    try:
        os.link(moved, ask_path(records, plan_sha256, request["requesting_thread_id"]))
    except OSError:
        pass
    try:
        moved.unlink()
        run_dir.rmdir()
    except OSError:
        pass


def write_claim(records: Path, request: Mapping[str, Any], plan: Mapping[str, Any],
                decision: Mapping[str, Any]) -> dict[str, Any]:
    """Record one START admission for one run, create-only (ADR 0002).

    An approved admission consumes the question it answers: the ask moves
    into the run's directory, so one approval cannot start a second run.
    """

    if decision.get("decision") != "START" or decision.get("plan_sha256") != plan.get("plan_sha256"):
        raise WatcherError("governed_run:admission_invalid", "not a start decision for this plan")
    run_dir = run_directory(records, request["run_id"])
    _private_directory(run_dir)
    if decision.get("approved"):
        question = ask_path(records, plan["plan_sha256"], request["requesting_thread_id"])
        try:
            os.rename(question, approval_path(run_dir))
        except FileNotFoundError as error:
            try:
                run_dir.rmdir()
            except OSError:
                pass
            raise WatcherError("governed_run:admission_invalid", "approval already used") from error
        try:
            consumed = read_json(approval_path(run_dir))
        except (OSError, ValueError, WatcherError):
            consumed = None
        if not isinstance(consumed, Mapping) or consumed.get("ask_sha256") != decision.get("approval_sha256"):
            _return_question(records, request, plan["plan_sha256"], run_dir)
            raise WatcherError("governed_run:admission_invalid", "approval replaced before it was used")
    claim = sealed({
        "schema": CLAIM_SCHEMA,
        "run_id": request["run_id"],
        "project_key": project_key(Path(request["project_root"])),
        "request_sha256": policy.sha256(dict(request)),
        "plan": dict(plan),
        "admission": dict(decision),
        "claimed_at": utc_now(),
    }, "claim_sha256")
    write_json(claim_path(run_dir), claim, create_only=True)
    return claim


def verify_claim(
    run_dir: Path, request: Mapping[str, Any], enrollment: Mapping[str, Any],
    lanes: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The run's admission claim, when it binds this request, plan and authority."""

    try:
        claim = read_json(claim_path(run_dir))
    except (OSError, ValueError, WatcherError) as error:
        raise WatcherError("governed_run:admission_invalid", "no admission claim") from error
    plan = run_plan(request, enrollment, lanes)
    decision = claim.get("admission") if isinstance(claim, Mapping) else None
    if (
        not seal_valid(claim, "claim_sha256")
        or claim.get("schema") != CLAIM_SCHEMA
        or claim.get("run_id") != request["run_id"]
        or claim.get("request_sha256") != policy.sha256(dict(request))
        or claim.get("plan") != plan
        or not admission.seal_valid(decision, "admission_sha256")
        or decision.get("decision") != "START"
        or decision.get("plan_sha256") != plan["plan_sha256"]
        or decision.get("authority_sha256") != enrollment["standing_authority"]["authority_sha256"]
    ):
        raise WatcherError("governed_run:admission_invalid", "claim does not bind this run")
    if decision.get("approved"):
        try:
            consumed = read_json(approval_path(run_dir))
        except (OSError, ValueError, WatcherError) as error:
            raise WatcherError("governed_run:admission_invalid", "approval not consumed") from error
        if (
            not admission.seal_valid(consumed, "ask_sha256")
            or consumed.get("ask_sha256") != decision.get("approval_sha256")
            or consumed.get("plan_sha256") != plan["plan_sha256"]
        ):
            raise WatcherError("governed_run:admission_invalid", "approval does not bind this run")
    return claim


# ---------------------------------------------------------------- stop


def stop_path(run_dir: Path) -> Path:
    return run_dir / "stop.json"


def stop_requested(run_dir: Path) -> bool:
    return stop_path(run_dir).is_file()


def request_stop(records: Path, run_id: str, requesting_thread_id: str | None) -> dict[str, Any]:
    """Record that the user asked to stop a run; the watcher acts on it."""

    run_dir = run_directory(records, run_id)
    if not run_dir.is_dir():
        raise WatcherError("governed_run:request_invalid", "unknown run")
    value = sealed({
        "schema": STOP_SCHEMA,
        "run_id": run_id,
        "requesting_thread_id": requesting_thread_id,
        "requested_at": utc_now(),
    }, "stop_sha256")
    try:
        write_json(stop_path(run_dir), value, create_only=True)
    except FileExistsError:
        value = read_json(stop_path(run_dir))
    return value


def observed_stop(run_dir: Path, where: str) -> dict[str, Any]:
    """What the watcher records when it acts on a stop request."""

    try:
        request = read_json(stop_path(run_dir))
    except (OSError, ValueError, WatcherError):
        request = {}
    return {
        "observed": where,
        "stop_sha256": request.get("stop_sha256") if isinstance(request, Mapping) else None,
        "interrupt_sent": False,
        "turn_ended": None,
    }


# ---------------------------------------------------------------- run lock


def _process_start(pid: int) -> str | None:
    """A token for one process instance that a recycled pid cannot share."""

    try:
        raw = Path("/proc", str(pid), "stat").read_text(encoding="utf-8")
        return "proc:" + raw[raw.rindex(")") + 2:].split()[19]
    except (OSError, ValueError, IndexError):
        pass
    try:
        started = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True,
            timeout=5, check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return "ps:" + started if started else None


def holder_alive(holder: Mapping[str, Any]) -> bool:
    """Whether the process that took a run lock is the one still running."""

    pid = holder.get("pid")
    if type(pid) is not int or pid < 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    recorded = holder.get("process_start")
    return recorded is None or _process_start(pid) == recorded


@contextlib.contextmanager
def machine_lock(records: Path) -> Any:
    """Serialize every front door and watcher that counts the machine's workers."""

    _private_directory(records)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(records / "machine-workers.lock", flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _worker_count(value: Any) -> int:
    """The workers one readable holder or claim records; a count it records
    in any other shape counts as the whole cap."""

    if value is None:
        return 0
    return value if type(value) is int and 0 <= value <= MACHINE_WORKERS else MACHINE_WORKERS


def machine_runs(records: Path, *, now: datetime | None = None, exclude_run: str | None = None) -> dict[str, Any]:
    """The lane workers and repositories that live runs and runs about to start hold.

    A live run is one whose watcher still holds its repository lock.  A run
    about to start has a START claim from the last CLAIM_START_SECONDS and
    neither a lock nor a record yet, so two front doors a moment apart both
    count it.  Holder and claim files are written whole and create-only, so
    an unreadable one is what a process that died mid-write left: it holds
    nothing, the same reading acquire_lock gives it when it reaps it.
    """

    moment = now or datetime.now(timezone.utc)
    workers = 0
    projects: set[str] = set()
    locked: set[str] = set()
    directory = records / "active"
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else ():
        try:
            holder = read_json(path)
        except (OSError, ValueError, WatcherError):
            continue
        if not isinstance(holder, dict) or not holder_alive(holder):
            continue
        locked.add(str(holder.get("run_id")))
        if holder.get("run_id") != exclude_run:
            workers += _worker_count(holder.get("workers"))
            projects.add(path.stem)
    days = {(moment + timedelta(days=offset)).strftime("%Y%m%d") for offset in (-1, 0)}
    runs = records / "runs"
    for run_dir in sorted(runs.iterdir()) if runs.is_dir() else ():
        if (
            run_date(run_dir.name) not in days
            or run_dir.name in locked
            or run_dir.name == exclude_run
            or (run_dir / "record.json").exists()
        ):
            continue
        try:
            claim = read_json(claim_path(run_dir))
            claimed = datetime.strptime(str(claim["claimed_at"]), "%Y-%m-%dT%H:%M:%SZ")
            starting = (
                seal_valid(claim, "claim_sha256")
                and claim["admission"]["decision"] == "START"
                and moment - claimed.replace(tzinfo=timezone.utc) <= timedelta(seconds=CLAIM_START_SECONDS)
            )
            count = _worker_count(claim["plan"]["workers"]) if starting else 0
        except (OSError, ValueError, KeyError, TypeError, WatcherError):
            continue
        if starting:
            workers += count
            projects.add(str(claim.get("project_key")))
    return {"workers": workers, "projects": projects}


def _refuse_past_machine_cap(held: Mapping[str, Any], workers: int) -> None:
    """Refuse a run whose workers would take the machine past MACHINE_WORKERS."""

    if held["workers"] + workers > MACHINE_WORKERS:
        raise WatcherError("governed_run:machine_workers_busy", str(held["workers"]) + " workers in use")


def reserve_start(
    records: Path, request: Mapping[str, Any], plan: Mapping[str, Any], decision: Mapping[str, Any],
    *, now: datetime | None = None,
) -> dict[str, Any]:
    """Write the START claim of an admitted plan, or refuse at the front door.

    One governed run per repository and at most MACHINE_WORKERS lane workers
    per machine (FR69): a repository with a live or starting run, or a plan
    whose workers the machine's other runs already hold, is refused before
    anything is claimed, and is never queued.
    """

    with machine_lock(records):
        held = machine_runs(records, now=now)
        if project_key(Path(request["project_root"])) in held["projects"]:
            raise WatcherError("governed_run:repository_busy", "a governed run holds this repository")
        _refuse_past_machine_cap(held, int(plan["workers"]))
        return write_claim(records, request, plan, decision)


def acquire_lock(
    records: Path, project_root: Path, run_id: str, *, reap: Callable[[Mapping[str, Any]], None],
    workers: int = 0,
) -> Path:
    """One governed run per repository and at most MACHINE_WORKERS lane
    workers per machine; a dead holder's run is reaped first."""

    path = records / "active" / (project_key(project_root) + ".json")
    holder_record = {"run_id": run_id, "pid": os.getpid(), "process_start": _process_start(os.getpid()),
                     "started_at": utc_now(), "workers": workers}
    with machine_lock(records):
        for _attempt in range(2):
            try:
                write_json(path, holder_record, create_only=True)
                break
            except FileExistsError as error:
                try:
                    holder = read_json(path)
                except (OSError, ValueError, WatcherError):
                    holder = {}
                if isinstance(holder, dict) and holder_alive(holder):
                    raise WatcherError("governed_run:repository_busy", str(holder.get("run_id"))) from error
                reap(holder if isinstance(holder, dict) else {})
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
        else:
            raise WatcherError("governed_run:repository_busy", "lock contended")
        try:
            _refuse_past_machine_cap(machine_runs(records, exclude_run=run_id), workers)
        except WatcherError:
            path.unlink()
            raise
    return path


def active_runs(records: Path | None = None) -> list[dict[str, Any]]:
    """Governed runs whose watcher is still alive; a plugin update waits on these."""

    directory = (records or records_root()) / "active"
    found = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else ():
        try:
            holder = read_json(path)
        except (OSError, ValueError, WatcherError):
            continue
        if isinstance(holder, dict) and holder_alive(holder):
            found.append({"run_id": holder.get("run_id"), "pid": holder.get("pid")})
    return found


# ---------------------------------------------------------------- binding


def write_binding(
    data_root: Path,
    *,
    run_id: str,
    thread_id: str,
    project_root: Path,
    summary_sha256: str,
    hook_definition_sha256: str,
    protected_paths: Sequence[str],
    workers: int = 0,
    grants: Sequence[Mapping[str, Any]] = (),
    lane_writes: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Bind the governed task's thread for the hooks: its first round, holding
    one spawn permission per lane and the paths each owning lane owns."""

    binding = policy.seal_binding({
        "schema": policy.BINDING_SCHEMA,
        "run_id": run_id,
        "thread_id": thread_id,
        "project_root": os.path.realpath(project_root),
        "workers": workers,
        "round": 1,
        "grants": [dict(grant) for grant in grants],
        "status": "ACTIVE",
        "summary_sha256": summary_sha256,
        "hook_definition_sha256": hook_definition_sha256,
        "protected_paths": sorted({str(path) for path in protected_paths}),
        "bound_at": utc_now(),
        "lane_writes": {grant_id: list(paths) for grant_id, paths in (lane_writes or {}).items()},
    })
    issues = policy.binding_issues(binding, session_id=thread_id)
    if issues:
        raise WatcherError("governed_run:binding_failed", ";".join(issues))
    write_json(policy.binding_path(data_root, thread_id), binding, create_only=True)
    return binding


def end_binding(data_root: Path, binding: Mapping[str, Any]) -> dict[str, Any]:
    ended = policy.seal_binding({**binding, "status": "TERMINAL"})
    write_json(policy.binding_path(data_root, str(binding["thread_id"])), ended)
    return ended


def bind_repair_round(data_root: Path, binding: Mapping[str, Any], grant: Mapping[str, Any]) -> dict[str, Any]:
    """Re-open an ended binding for the run's one repair round.

    It holds only the repair worker's spawn permission, so no lane worker of
    the first round is bound any longer, and no lane owns a path: the repair
    worker fixes the joined tree.
    """

    value = policy.seal_binding({
        **binding, "status": "ACTIVE", "round": 2, "grants": [dict(grant)],
        "continuations": [], "lane_writes": {}, "bound_at": utc_now(),
    })
    issues = policy.binding_issues(value, session_id=binding["thread_id"])
    if issues:
        raise WatcherError("governed_run:binding_failed", ";".join(issues))
    write_json(policy.binding_path(data_root, str(binding["thread_id"])), value)
    return value


# ---------------------------------------------------------------- observation


def _item_row(turn_id: Any, item: Any) -> dict[str, Any] | None:
    """One action-bearing item without its output, diff or prompt.

    A collaboration item also keeps the workers it names, the model and
    effort it started a worker with and its prompt's digest, which a lane
    run's cross-check compares with the spawn permission it used.  None for
    a message or reasoning item.
    """

    if not isinstance(item, Mapping) or item.get("type") in ("userMessage", "agentMessage", "reasoning"):
        return None
    row = {
        "turn_id": turn_id,
        "id": item.get("id"),
        "type": item.get("type"),
        "status": item.get("status"),
        "exit_code": item.get("exitCode"),
        "tool": item.get("tool"),
    }
    if item.get("type") == "collabAgentToolCall":
        receivers = item.get("receiverThreadIds")
        row.update({
            "receivers": [str(value) for value in receivers] if isinstance(receivers, list) else None,
            "model": item.get("model"),
            "effort": item.get("reasoningEffort"),
            "prompt_sha256": policy.message_digest(item.get("prompt")),
        })
    return row


def owner_items(thread: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every action-bearing item of every turn, without outputs, diffs or prompts."""

    rows = []
    for turn in (thread.get("turns") if isinstance(thread, Mapping) else None) or []:
        if not isinstance(turn, Mapping):
            continue
        for item in turn.get("items") or []:
            row = _item_row(turn.get("id"), item)
            if row is not None:
                rows.append(row)
    return rows


def thread_turns(thread: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Each turn of a thread read, by id and status."""

    return [
        {"id": turn.get("id"), "status": turn.get("status")}
        for turn in (thread.get("turns") if isinstance(thread, Mapping) else None) or []
        if isinstance(turn, Mapping)
    ]


def cross_check(
    items: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    *,
    turn_id: str,
    ended_at_ns: int | None = None,
) -> dict[str, Any]:
    """Join the hooks' action records to the owner rail by tool-use id.

    Every item type Codex 0.160.0 can show is classed: an action item needs
    one allowed PreToolUse record with its id and a matching tool, every
    allowed call of a tool that shows an item needs that item, a refused call
    leaves no item, and an item of an unknown type, a worker item or record,
    a missing healthy SessionStart, activity in another turn, or a hook that
    changed during the run is a disagreement.  Records the hook made after the
    binding ended belong to no run and are only counted.

    A call Codex rejected before running it, such as a malformed patch, fires
    PreToolUse but no PostToolUse and shows no item; with neither record of it
    finishing it changed nothing, so it is counted as not run.  An allowed call
    with no item that did finish is a disagreement.
    """

    window = [
        row for row in events
        if ended_at_ns is None or int(row.get("observed_at_ns") or 0) <= ended_at_ns
    ]
    finished = {row.get("tool_use_id") for row in events if row.get("hook_event_name") == "PostToolUse"}
    issues: list[str] = []
    covered: dict[Any, Mapping[str, Any]] = {}
    outside: dict[str, int] = {}
    worker = False
    for item in items:
        kind = str(item.get("type"))
        if item.get("turn_id") != turn_id:
            issues.append("foreign_turn_item")
        if kind in WORKER_ITEM_TYPES:
            worker = True
        if kind in JOINED_ITEM_TYPES:
            if item.get("id") in covered:
                issues.append("duplicate_owner_item")
            covered[item.get("id")] = item
        elif kind in HOSTED_ITEM_TYPES:
            outside[kind] = outside.get(kind, 0) + 1
        elif kind not in INERT_ITEM_TYPES and kind not in WORKER_ITEM_TYPES:
            issues.append("unknown_item_type:" + kind[:64])
    pre = [row for row in window if row.get("hook_event_name") == "PreToolUse"]
    allowed: dict[Any, Mapping[str, Any]] = {}
    denied: dict[Any, Mapping[str, Any]] = {}
    for row in pre:
        if row.get("tool_use_id") in allowed or row.get("tool_use_id") in denied:
            issues.append("duplicate_hook_record")
        (allowed if row.get("decision") == "ALLOW" else denied)[row.get("tool_use_id")] = row
    for item_id, item in covered.items():
        if item_id in denied:
            issues.append("refused_call_ran:" + str(item.get("type")))
        elif item_id not in allowed:
            issues.append("owner_item_without_hook_record:" + str(item.get("type")))
        elif policy.item_type_for_tool(allowed[item_id].get("tool_name")) != item.get("type"):
            issues.append("item_tool_mismatch:" + str(item.get("type")))
    quiet: dict[str, int] = {}
    not_run: dict[str, int] = {}
    for tool_use_id, row in allowed.items():
        name = str(row.get("tool_name") or "")
        if policy.item_type_for_tool(name) is not None:
            if tool_use_id not in covered and tool_use_id not in finished:
                not_run[name[:64]] = not_run.get(name[:64], 0) + 1
            elif tool_use_id not in covered:
                issues.append("hook_record_without_owner_item:" + name[:64])
        elif policy.quiet_tool(name):
            quiet[name] = quiet.get(name, 0) + 1
        else:
            issues.append("allowed_call_outside_policy:" + name[:64])
    if any(row.get("agent_id") is not None for row in window) or any(
        row.get("hook_event_name") == "SubagentStop" for row in window
    ):
        worker = True
    starts = [row for row in window if row.get("hook_event_name") == "SessionStart"]
    if not window or not starts or starts[0].get("decision") != "HEALTHY" or window[0] is not starts[0]:
        issues.append("session_start_unhealthy")
    if any(
        row.get("turn_id") not in (None, turn_id)
        for row in window
        if row.get("hook_event_name") != "SessionStart"
    ):
        issues.append("foreign_turn_hook_record")
    changed = any("governed_run:hook_generation_changed" in (row.get("reasons") or []) for row in window)
    reason = (
        "governed_run:worker_activity" if worker
        else "governed_run:hooks_changed_during_run" if changed
        else "governed_run:hook_owner_disagreement" if issues else None
    )
    core = {
        "schema": CROSS_CHECK_SCHEMA,
        "status": "DISAGREED" if reason else "AGREED",
        "reason": reason,
        "issues": sorted(set(issues)),
        "covered_items": len(covered),
        "allowed_calls": len(allowed),
        "refused_calls": len(denied),
        "hook_records": len(window),
        "records_after_binding_ended": len(events) - len(window),
        "items_outside_hooks": dict(sorted(outside.items())),
        "calls_without_owner_items": dict(sorted(quiet.items())),
        "allowed_calls_not_run": dict(sorted(not_run.items())),
        "worker_activity": worker,
    }
    return sealed(core, "report_sha256")


def lane_cross_check(
    root_items: Sequence[Mapping[str, Any]],
    workers: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    *,
    turn_id: str,
    round_number: int,
    grants: Sequence[Mapping[str, Any]],
    grant_state: Mapping[str, Any],
    continuations: Sequence[Mapping[str, Any]] = (),
    earlier_turns: Sequence[str] = (),
    earlier_workers: Sequence[str] = (),
    after_ns: int | None = None,
    until_ns: int | None = None,
) -> dict[str, Any]:
    """Join one lane round's hook records to Codex's record of the root and its workers.

    The round's records are the ones the hooks made while its binding was
    active.  Each spawn permission the round used must have been claimed by
    one allowed spawn whose item started exactly the worker its outcome bound,
    with the permission's model, effort and message; a wait or close item may
    name only those workers; every other action item of the root or a worker
    needs one allowed record from the same thread with a matching tool, and
    every allowed record that shows an item needs that item.  An allowed
    shell or patch call of a root whose current plan has worker grants, a
    record from a worker the round did not bind, an unreadable worker thread,
    an item of a type the V1 surface does
    not show, activity in another turn, or a hook that changed during the
    round is a disagreement.  workers maps each bound worker to its thread's
    turns and items, with items None when its thread could not be read.

    A spawn Codex itself refused (for one, past agents.max_threads) fires
    PreToolUse but no PostToolUse, and the owner rail shows it failed with no
    worker and a blank model (racetrack/codex-facts/hooks-spawn-limit-0.160.0.json):
    its claimed permission started nothing, and the report names it.
    Likewise a root or worker shell or patch call Codex rejected before
    running it fires PreToolUse but no PostToolUse and shows no item; it is
    counted as not run.  A root shell or patch call under worker grants stays
    a disagreement even when Codex rejected it.
    """

    window = [
        row for row in events
        if (after_ns is None or int(row.get("observed_at_ns") or 0) > after_ns)
        and (until_ns is None or int(row.get("observed_at_ns") or 0) <= until_ns)
    ]
    finished = {
        (row.get("agent_id"), row.get("tool_use_id")) for row in events
        if row.get("hook_event_name") == "PostToolUse"
    }
    issues: list[str] = []
    outside: dict[str, int] = {}
    quiet: dict[str, int] = {}
    not_run: dict[str, int] = {}
    grant_by_id = {grant["grant_id"]: grant for grant in grants}
    failed_spawns = {
        item.get("id") for item in root_items
        if item.get("turn_id") == turn_id and item.get("type") == "collabAgentToolCall"
        and item.get("tool") == "spawnAgent" and item.get("status") == "failed" and item.get("receivers") == []
    }
    claimed: dict[Any, str] = {}
    bound: dict[str, str] = {}
    refused_by_codex: list[str] = []
    for grant in grants:
        entry = grant_state.get(grant["grant_id"]) or {}
        claim, outcome = entry.get("claim"), entry.get("outcome")
        if claim is None:
            if outcome is not None:
                issues.append("spawn_outcome_without_claim")
            continue
        if claim.get("round") != round_number or claim.get("turn_id") != turn_id:
            issues.append("spawn_claim_outside_round")
        claimed[claim.get("tool_use_id")] = grant["grant_id"]
        if outcome is None and claim.get("tool_use_id") in failed_spawns:
            refused_by_codex.append(grant["grant_id"])
        elif outcome is None:
            issues.append("spawn_outcome_missing")
        elif outcome.get("tool_use_id") != claim.get("tool_use_id"):
            issues.append("spawn_outcome_mismatch")
        elif isinstance(outcome.get("agent_id"), str):
            if outcome["agent_id"] in bound:
                issues.append("worker_bound_twice")
            bound[outcome["agent_id"]] = grant["grant_id"]
    for grant in continuations:
        entry = grant_state.get(grant["grant_id"]) or {}
        claim, outcome = entry.get("claim"), entry.get("outcome")
        if claim is None:
            if outcome is not None:
                issues.append("continuation_outcome_without_claim")
            continue
        if claim.get("round") != round_number or claim.get("turn_id") != turn_id:
            issues.append("continuation_claim_outside_round")
        if grant.get("turn_id") != turn_id or grant.get("target") not in bound:
            issues.append("continuation_outside_plan")
        claimed[claim.get("tool_use_id")] = grant["grant_id"]
        grant_by_id[grant["grant_id"]] = grant
        if outcome is None:
            issues.append("continuation_outcome_missing")
        elif outcome.get("tool_use_id") != claim.get("tool_use_id") or outcome.get("agent_id") != grant["target"]:
            issues.append("continuation_outcome_mismatch")
    allowed: dict[tuple[Any, Any], Mapping[str, Any]] = {}
    denied: set[tuple[Any, Any]] = set()
    current: list[Mapping[str, Any]] = []
    for row in window:
        agent = row.get("agent_id")
        pre = row.get("hook_event_name") == "PreToolUse"
        if agent is not None and agent not in bound:
            if agent not in earlier_workers:
                issues.append("unknown_worker")
            elif pre and row.get("decision") == "ALLOW":
                issues.append("earlier_worker_acted")
            continue
        current.append(row)
        for problem in ("spawn_result_unclaimed", "continuation_result_unclaimed"):
            if "governed_run:" + problem in (row.get("reasons") or []):
                issues.append(problem)
        if not pre:
            continue
        key = (agent, row.get("tool_use_id"))
        if key in allowed or key in denied:
            issues.append("duplicate_hook_record")
        if row.get("decision") == "ALLOW":
            allowed[key] = row
        else:
            denied.add(key)
    starts = [row for row in current if row.get("hook_event_name") == "SessionStart"]
    if any(row.get("decision") != "HEALTHY" for row in starts) or (
        round_number == 1 and not earlier_turns and (not current or not starts or current[0] is not starts[0])
    ):
        issues.append("session_start_unhealthy")
    turns = {
        agent: {turn.get("id") for turn in facts.get("turns") or []}
        for agent, facts in workers.items() if facts.get("items") is not None
    }
    for row in current:
        agent = row.get("agent_id")
        if row.get("hook_event_name") == "SessionStart":
            continue
        if (agent is None and row.get("turn_id") not in (None, turn_id)) or (
            agent in turns and row.get("turn_id") not in turns[agent]
        ):
            issues.append("foreign_turn_hook_record")
    covered: set[tuple[Any, Any]] = set()

    def join(agent: str | None, item: Mapping[str, Any]) -> None:
        kind = str(item.get("type"))
        if kind in HOSTED_ITEM_TYPES:
            outside[kind] = outside.get(kind, 0) + 1
            return
        if kind in INERT_ITEM_TYPES:
            return
        if kind not in JOINED_ITEM_TYPES:
            issues.append("unknown_item_type:" + kind[:64])
            return
        key = (agent, item.get("id"))
        if key in covered:
            issues.append("duplicate_owner_item")
        covered.add(key)
        record = allowed.get(key)
        if key in denied:
            issues.append("refused_call_ran:" + kind)
        elif record is None:
            issues.append("owner_item_without_hook_record:" + kind)
        elif kind == "collabAgentToolCall" and agent is None:
            issues.extend(_collab_item_issues(item, record, claimed, grant_by_id, grant_state, bound,
                                              closable=set(bound) | set(earlier_workers)))
        elif policy.item_type_for_tool(record.get("tool_name")) != kind:
            issues.append("item_tool_mismatch:" + kind)

    for item in root_items:
        if item.get("turn_id") in earlier_turns:
            continue
        if item.get("turn_id") != turn_id:
            issues.append("foreign_turn_item")
            continue
        join(None, item)
    for agent, facts in workers.items():
        if facts.get("items") is None:
            issues.append("worker_thread_unreadable")
            continue
        for item in facts["items"]:
            join(agent, item)
    for key, record in allowed.items():
        name = policy.canonical_tool_name(record.get("tool_name"))
        item_type = policy.item_type_for_tool(name)
        if key[0] is None and item_type is not None and grants:
            issues.append("root_implementation")
        elif item_type is not None and key not in covered and key not in finished:
            not_run[name[:64]] = not_run.get(name[:64], 0) + 1
        elif item_type is not None or (key[0] is None and name in COLLAB_ITEM_TOOLS):
            if key not in covered:
                issues.append("hook_record_without_owner_item:" + name[:64])
        elif policy.quiet_tool(name):
            quiet[name] = quiet.get(name, 0) + 1
        else:
            issues.append("allowed_call_outside_policy:" + name[:64])
    if any((None, tool_use_id) not in allowed for tool_use_id in claimed):
        issues.append("spawn_claim_without_allowed_call")
    changed = any("governed_run:hook_generation_changed" in (row.get("reasons") or []) for row in window)
    reason = (
        "governed_run:hooks_changed_during_run" if changed
        else "governed_run:hook_owner_disagreement" if issues else None
    )
    core = {
        "schema": LANE_CROSS_CHECK_SCHEMA,
        "round": round_number,
        "status": "DISAGREED" if reason else "AGREED",
        "reason": reason,
        "issues": sorted(set(issues)),
        "covered_items": len(covered),
        "allowed_calls": len(allowed),
        "refused_calls": len(denied),
        "hook_records": len(window),
        "records_outside_round": len(events) - len(window),
        "items_outside_hooks": dict(sorted(outside.items())),
        "calls_without_owner_items": dict(sorted(quiet.items())),
        "allowed_calls_not_run": dict(sorted(not_run.items())),
        "workers": sorted(bound),
        "spawns_codex_refused": sorted(refused_by_codex),
    }
    return sealed(core, "report_sha256")


def _collab_item_issues(
    item: Mapping[str, Any],
    record: Mapping[str, Any],
    claimed: Mapping[Any, str],
    grants: Mapping[str, Mapping[str, Any]],
    grant_state: Mapping[str, Any],
    bound: Mapping[str, str],
    *,
    closable: set[str],
) -> list[str]:
    """Why one root collaboration item does not match the call the hooks allowed.

    A wait names only this round's workers; a close may also name a worker
    an earlier round left open.
    """

    name = policy.canonical_tool_name(record.get("tool_name"))
    receivers = item.get("receivers")
    if COLLAB_ITEM_TOOLS.get(name) != item.get("tool") or not isinstance(receivers, list):
        return ["item_tool_mismatch:collabAgentToolCall"]
    if name == "wait_agent":
        return [] if all(receiver in bound for receiver in receivers) else ["collaboration_outside_plan"]
    if name == "close_agent":
        if len(receivers) != 1 or receivers[0] not in closable:
            return ["collaboration_outside_plan"]
        return [] if record.get("tool_input_sha256") == policy.sha256({"target": receivers[0]}) else [
            "close_worker_mismatch"]
    grant_id = claimed.get(item.get("id"))
    if grant_id is None:
        return ["continuation_without_claim" if name == "send_input" else "spawn_without_claim"]
    grant = grants[grant_id]
    agent = ((grant_state.get(grant_id) or {}).get("outcome") or {}).get("agent_id")
    if name == "send_input":
        issues = []
        if receivers != [grant.get("target")] or agent != grant.get("target"):
            issues.append("continuation_worker_mismatch")
        if item.get("prompt_sha256") != grant.get("message_sha256"):
            issues.append("continuation_message_mismatch")
        return issues
    issues = []
    if receivers != ([agent] if isinstance(agent, str) else []):
        issues.append("spawn_worker_mismatch")
    refused = item.get("status") == "failed" and not receivers and agent is None
    if not refused and (item.get("model") != grant["model"] or item.get("effort") != grant["reasoning_effort"]):
        issues.append("spawn_model_mismatch")
    if item.get("prompt_sha256") != grant["message_sha256"]:
        issues.append("spawn_message_mismatch")
    return issues


# ---------------------------------------------------------------- checks


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_group(pgid: int, *, grace: float = 5.0) -> bool:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return True
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if not _group_alive(pgid):
                return True
            time.sleep(0.05)
    return not _group_alive(pgid)


def stop_process_group(process: subprocess.Popen[Any], *, grace: float = 5.0) -> bool:
    """End one owned process group and reap its leader; True when none is left.

    The leader is reaped before the group is judged, because a killed but
    unreaped leader still answers a group probe as a zombie.
    """

    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            continue
        deadline = time.monotonic() + grace
        while _group_alive(process.pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if not _group_alive(process.pid):
            break
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        return False
    return not _group_alive(process.pid)


def _file_tail(path: Path) -> str:
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - CHECK_OUTPUT_TAIL))
        return handle.read().decode("utf-8", errors="replace")


def changed_check_files(project_root: Path, pins: Mapping[str, str]) -> list[str]:
    root = Path(os.path.realpath(project_root))
    return [key for key, digest in sorted(pins.items()) if pin_digest(root, key) != digest]


def run_check(
    check: Mapping[str, Any], project_root: Path, *, stop: Callable[[], bool] = lambda: False,
) -> dict[str, Any]:
    """Run one enrolled check in its own process group and observe its exit.

    A stop request ends the check's process group at once; the check then
    neither passes nor fails, it was stopped.
    """

    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("ORCH_DORK_", "PLUGIN_", "CODEX_"))
    }
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="od-check-") as temporary:
        stdout_path = Path(temporary) / "stdout"
        stderr_path = Path(temporary) / "stderr"
        with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
            try:
                process = subprocess.Popen(
                    list(check["argv"]), cwd=str(project_root), env=environment,
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                    start_new_session=True, close_fds=True,
                )
            except OSError as error:
                return {
                    "id": check["id"], "argv": list(check["argv"]), "exit_code": None,
                    "timed_out": False, "launch_error": type(error).__name__ + ": " + str(error)[:200],
                    "duration_ms": 0, "passed": False, "leftovers_killed": False,
                    "group_cleared": True, "stdout_tail": "", "stderr_tail": "", "stopped": False,
                }
            timed_out = False
            stopped = False
            forced_cleared = None
            deadline = time.monotonic() + check["timeout_seconds"]
            while True:
                try:
                    code = process.wait(timeout=max(0.0, min(POLL_SECONDS, deadline - time.monotonic())))
                    break
                except subprocess.TimeoutExpired:
                    stopped = stop()
                    if stopped or time.monotonic() >= deadline:
                        timed_out = not stopped
                        forced_cleared = stop_process_group(process)
                        code = process.poll()
                        break
            leftovers = _group_alive(process.pid)
            cleared = (forced_cleared if forced_cleared is not None
                       else _terminate_group(process.pid) if leftovers else True)
        return {
            "id": check["id"],
            "argv": list(check["argv"]),
            "exit_code": code,
            "timed_out": timed_out,
            "launch_error": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "passed": code == 0 and not timed_out and not stopped,
            "leftovers_killed": leftovers,
            "group_cleared": cleared,
            "stdout_tail": _file_tail(stdout_path),
            "stderr_tail": _file_tail(stderr_path),
            "stopped": stopped,
        }


# ---------------------------------------------------------------- verdict


def compute_verdict(
    *,
    refusal: str | None,
    turn_status: str | None,
    interruption: str | None,
    cross: Mapping[str, Any] | None,
    checks: Sequence[Mapping[str, Any]],
    stop: Mapping[str, Any] | None = None,
    repaired: bool = False,
) -> dict[str, Any]:
    """Exactly one label, computed only from host-observed facts.

    A refusal outranks a stop, so a run that broke the rules before the user
    stopped it is still recorded as refused; a stop the watcher acted on
    outranks everything else, and its reason says when the turn did not
    confirm it ended.  The facts are those of the run's last round: after a
    repair round, the checks it ran again decide between Verified and Failed
    checks.
    """

    if refusal:
        label, reason = REFUSED, refusal
    elif stop is not None:
        label = STOPPED
        reason = "governed_run:stop_unconfirmed" if stop.get("turn_ended") is False else "governed_run:stopped_by_you"
    elif turn_status == "interrupted" and interruption is None:
        label, reason = STOPPED, "governed_run:turn_interrupted"
    elif turn_status != "completed" or interruption is not None:
        label, reason = INTERRUPTED, interruption or "governed_run:turn_" + str(turn_status)
    elif cross is None or cross.get("status") != "AGREED":
        label = REFUSED
        reason = (cross or {}).get("reason") or "governed_run:hook_owner_disagreement"
    elif not checks:
        label, reason = INTERRUPTED, "governed_run:checks_not_run"
    elif all(row.get("passed") is True for row in checks):
        label, reason = VERIFIED, None
    else:
        label = FAILED_CHECKS
        reason = "governed_run:checks_failed_after_repair" if repaired else "governed_run:checks_failed"
    return {
        "label": label,
        "reason": reason,
        "message": message_for(reason),
        "steered_by_you": False,
        "inputs": {
            "turn_status": turn_status,
            "interruption": interruption,
            "cross_check": None if cross is None else cross.get("status"),
            "checks": [
                {"id": row.get("id"), "exit_code": row.get("exit_code"), "timed_out": row.get("timed_out")}
                for row in checks
            ],
        },
        "model_text_used": False,
    }


# ---------------------------------------------------------------- governed runner


class GovernedRunner:
    """A dedicated app server that holds every model on V1 (ADR 0012)."""

    def __init__(self, codex: str, home: Path, project_root: Path, run_dir: Path) -> None:
        catalog_path = onboarded.configured_catalog_path(home)
        if catalog_path is None or not Path(catalog_path).is_file():
            raise WatcherError("governed_mode:v1_unavailable", "no catalog to copy")
        catalog = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
        self.process: subprocess.Popen[bytes] | None = None
        self._stderr = None
        # A short root keeps the socket path under the AF_UNIX length limit.
        self.root = Path(tempfile.mkdtemp(prefix="od-gr-", dir=str(Path(os.sep) / "tmp")))
        self.socket = self.root / "s"
        try:
            os.chmod(self.root, 0o700)
            overlay = run_dir / "catalog-v1.json"
            onboarded.write_all_v1_overlay(catalog, overlay)
            argv = [
                codex, *onboarded.governed_runner_overrides(overlay),
                "app-server", "--listen", "unix://" + str(self.socket),
            ]
            environment = dict(os.environ)
            environment["CODEX_HOME"] = str(home)
            self.stderr_path = run_dir / "governed-runner.stderr"
            self._stderr = open(self.stderr_path, "wb")
            self.process = subprocess.Popen(
                argv, cwd=str(project_root), env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=self._stderr, start_new_session=True, close_fds=True,
            )
            deadline = time.monotonic() + 20
            while not self.socket.exists():
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise WatcherError("governed_mode:app_server_unavailable", "governed runner did not listen")
                time.sleep(0.05)
        except BaseException:
            self.close()
            raise

    def close(self) -> dict[str, Any]:
        cleared = True
        if self.process is not None:
            cleared = stop_process_group(self.process)
        if self._stderr is not None:
            self._stderr.close()
        try:
            self.socket.unlink()
        except FileNotFoundError:
            pass
        try:
            self.root.rmdir()
        except OSError:
            pass
        return {
            "runner_group_cleared": cleared,
            "runner_socket_removed": not self.socket.exists(),
            "runner_root_removed": not self.root.exists(),
        }


# ---------------------------------------------------------------- the run


def _status(run_dir: Path, run_id: str, state: str, **facts: Any) -> None:
    write_json(run_dir / "status.json", sealed(
        {"schema": STATUS_SCHEMA, "run_id": run_id, "state": state, "updated_at": utc_now(), **facts},
        "status_sha256",
    ))


def _new_record(request: Mapping[str, Any], run_dir: Path) -> dict[str, Any]:
    return {
        "schema": RECORD_SCHEMA,
        "run_id": request["run_id"],
        "requesting_thread_id": request["requesting_thread_id"],
        "governed_thread_id": None,
        "turn_id": None,
        "project_root": os.path.realpath(request["project_root"]),
        "model": request["model"],
        "observed_model": None,
        "effort": request["effort"],
        "worker_model": request.get("worker_model"),
        "worker_effort": request.get("worker_effort"),
        "location": None,
        "summary_sha256": None,
        "self_test": None,
        "binding_sha256": None,
        "turn_status": None,
        "interruption": None,
        "server_requests_declined": 0,
        "enrollment_sha256": None,
        "plan_sha256": None,
        "admission_sha256": None,
        # Only planner lane runs load guidance; failures retain a named reason and detail.
        "role_guidance_sha256": None,
        "role_guidance_consumed_sections": [],
        "role_guidance_loaded": False,
        "role_guidance_issue": None,
        "stop": None,
        "cross_check": None,
        "changed_check_files": [],
        "checks": [],
        "lanes": [],
        "rounds": [],
        "repair": None,
        "steers": [],
        "control_results": [],
        "revision": 1,
        "revisions": [],
        "revision_offer": None,
        "revision_answers": [],
        "cost": None,
        "verdict": None,
        "cleanup": {},
        "_started_monotonic_ns": time.monotonic_ns(),
        "started_at": utc_now(),
        "ended_at": None,
        "record_path": str(run_dir / "record.json"),
    }


def record_verdict(record: Mapping[str, Any], refusal: str | None) -> dict[str, Any]:
    """The verdict a run record's observed facts give."""

    repair = record.get("repair") or {}
    verdict = compute_verdict(
        refusal=refusal,
        turn_status=record["turn_status"],
        interruption=record["interruption"],
        cross=record["cross_check"],
        checks=record["checks"],
        stop=record["stop"],
        repaired=bool(repair.get("turn_id")) and repair.get("turn_id") == record["turn_id"],
    )
    verdict["steered_by_you"] = bool(record.get("steers"))
    return verdict


def _finish(record: dict[str, Any], run_dir: Path, refusal: str | None) -> dict[str, Any]:
    started = record.pop("_started_monotonic_ns", None)
    record["elapsed_ms"] = max(1, (time.monotonic_ns() - started) // 1000000) if type(started) is int else None
    record["verdict"] = record_verdict(record, refusal)
    offer = advisory_offer(refusal)
    if offer is not None:
        record["verdict"]["advisory_offer"] = offer
    if record["cost"] is None:
        record["cost"] = run_cost.cost_summary(
            threads=[], usage={}, frontier_model=None, budget_cents=None, daily_cents=None,
            run_workers=len(record["lanes"]), machine_workers=MACHINE_WORKERS,
        )
    record["ended_at"] = utc_now()
    final = sealed(record, "record_sha256")
    write_json(run_dir / "record.json", final, create_only=True)
    _status(run_dir, record["run_id"], "TERMINAL", verdict=final["verdict"]["label"],
            governed_thread_id=final["governed_thread_id"], record_path=final["record_path"])
    return final


def reap_stale_run(records: Path, data_root: Path, holder: Mapping[str, Any]) -> None:
    """Close the run of a watcher that died: Interrupted, binding ended.

    A dead watcher's run never ran its checks, so it is recorded honestly as
    not verified, its binding is ended so the task stays fail-closed, and its
    repository lock is released by the caller.
    """

    run_id = holder.get("run_id")
    try:
        run_dir = run_directory(records, str(run_id))
    except WatcherError:
        return
    if (run_dir / "record.json").exists():
        return
    status: Mapping[str, Any] = {}
    try:
        status = read_json(run_dir / "status.json")
    except (OSError, ValueError, WatcherError):
        status = {}
    try:
        request = read_json(run_dir / "request.json")
    except (OSError, ValueError, WatcherError):
        return
    record = _new_record(request, run_dir)
    # A replacement watcher did not observe the original run's duration.
    record.pop("_started_monotonic_ns", None)
    record["governed_thread_id"] = status.get("governed_thread_id") if isinstance(status, Mapping) else None
    record["interruption"] = "governed_run:watcher_lost"
    thread = record["governed_thread_id"]
    if isinstance(thread, str):
        try:
            binding = policy.read_binding(policy.binding_path(data_root, thread))
            if not policy.binding_issues(binding, session_id=thread) and binding["status"] == "ACTIVE":
                end_binding(data_root, binding)
            record["cleanup"]["binding_status"] = "TERMINAL"
        except (OSError, ValueError):
            record["cleanup"]["binding_status"] = "UNKNOWN"
    record["cleanup"]["reaped"] = True
    _finish(record, run_dir, None)


class RunControlSession:
    """Consume user controls on this run's owner connection.

    The initial turn message is identified by its client id. All other
    user messages in the governed task are steers, and are joined to any
    queued forwarded request by client id and exact text. A steer does not
    replace the plan: only an admitted, explicit revision does that.
    """

    def __init__(self, record: dict[str, Any], request: Mapping[str, Any], *,
                 run_dir: Path, data_root: Path, binding: dict[str, Any],
                 project: Mapping[str, Any], records: Path, onboarding_root: Any = None):
        self.record = record
        self.request = dict(request)
        self.run_dir = run_dir
        self.data_root = data_root
        self.binding = binding
        self.project = project
        self.records = records
        self.onboarding_root = onboarding_root
        self.initial_messages: set[str] = set()
        self.user_items: set[str] = set()
        self.forwarded: dict[str, dict[str, Any]] = {}
        self.accepted: dict[str, Any] | None = None
        self.offer_written = False
        self.offers_by_plan: dict[str, dict[str, Any]] = {}
        self.offer_after_ns = 0
        self.last_progress: bytes | None = None

    def progress(self) -> None:
        self.record["control_results"] = controls.results(self.run_dir)
        value = sealed({
            "schema": controls.PROGRESS_SCHEMA, "run_id": self.record["run_id"],
            "revision": self.record["revision"], "plan_sha256": self.record["plan_sha256"],
            "governed_thread_id": self.record["governed_thread_id"],
            "turn_id": self.record["turn_id"], "steers": self.record["steers"],
            "revision_offer": self.record["revision_offer"],
            "revision_answers": self.record["revision_answers"],
            "control_results": self.record["control_results"],
            # These are the owner's observed facts, shared by chat and the
            # local view. Progress remains a projection, never permission.
            "model": self.record["model"], "observed_model": self.record.get("observed_model"),
            "worker_model": self.record["worker_model"],
            "location": self.record.get("location"), "started_at": self.record["started_at"],
            "lanes": [{key: lane.get(key) for key in (
                "id", "worker_thread_id", "worker_status", "worker_closed",
                "checks_passed", "checks_passed_after_repair", "overclaim", "observed_model",
            )} for lane in self.record.get("lanes", [])],
        }, "progress_sha256")
        payload = policy.canonical(value)
        if payload != self.last_progress:
            write_json(self.run_dir / "progress.json", value)
            self.last_progress = payload

    def _source_turn(self, connection: app_server.AppServerConnection, control: Mapping[str, Any]) -> str:
        source = control.get("source_turn_id")
        if isinstance(source, str) and source:
            return source
        reply = connection.request("thread/read", {
            "threadId": control["source_thread_id"], "includeTurns": True,
        }, timeout=15)
        turns = (reply or {}).get("thread", {}).get("turns") or []
        active = [turn for turn in turns if turn.get("status") == "inProgress"]
        if len(active) != 1 or not isinstance(active[0].get("id"), str):
            raise WatcherError("governed_run:steer_source_unavailable")
        return active[0]["id"]

    def poll(self, connection: app_server.AppServerConnection, observed: OwnerObservations,
             *, can_forward: bool = True) -> None:
        try:
            queued = controls.pending(self.run_dir, run_id=self.record["run_id"])
        except (OSError, ValueError, TypeError) as error:
            raise WatcherError("governed_run:control_invalid", str(error)) from error
        for control in queued:
            if control["source_thread_id"] not in {
                self.record["requesting_thread_id"], self.record["governed_thread_id"],
            }:
                controls.record_result(self.run_dir, control, status="REFUSED", reason="source_task_mismatch")
                continue
            if control["kind"] == "revision":
                try:
                    self.answer_revision(connection, control)
                except (WatcherError, admission.AdmissionError, ValueError) as error:
                    controls.record_result(self.run_dir, control, status="REFUSED", reason=str(error))
                continue
            source_reason = None
            try:
                source_turn = self._source_turn(connection, control)
            except (WatcherError, *_TRANSPORT_ERRORS):
                source_turn = control.get("source_turn_id")
                source_reason = "source_turn_unavailable"
            steer = {
                "id": control["control_id"], "text": control["text"],
                "source": "requesting_task", "source_thread_id": control["source_thread_id"],
                "source_turn_id": source_turn, "governed_turn_id": self.record["turn_id"],
                "client_id": "orch-dork-steer-" + control["control_id"],
                "request_sha256": control["request_sha256"], "observed_at": utc_now(),
                "observed_at_ns": time.time_ns(),
                "forwarded": False, "owner_observed": False, "item_id": None,
            }
            self.record["steers"].append(steer)
            if steer["text"].strip().casefold() in {"stop", "stop."}:
                steer["reason"] = "stop_requested"
                request_stop(self.records, self.record["run_id"], control["source_thread_id"])
                controls.record_result(self.run_dir, control, status="STOP_REQUESTED")
                continue
            if source_reason or len(self.record["steers"]) > controls.MAX_STEERS:
                steer["reason"] = source_reason or "steer_limit"
                controls.record_result(self.run_dir, control, status="REFUSED", reason=steer["reason"])
                continue
            if not can_forward or self.record["stop"] is not None:
                steer["reason"] = "turn_no_longer_active"
                controls.record_result(self.run_dir, control, status="REFUSED", reason=steer["reason"])
                continue
            self.forwarded[steer["client_id"]] = steer
            self.refresh_permissions(observed)
            try:
                connection.request("turn/steer", {
                    "threadId": self.record["governed_thread_id"], "expectedTurnId": self.record["turn_id"],
                    "input": [{"type": "text", "text": steer["text"]}],
                    "clientUserMessageId": steer["client_id"],
                }, timeout=15)
                steer["forwarded"] = True
                controls.record_result(self.run_dir, control, status="FORWARDED", turn_id=self.record["turn_id"])
            except _TRANSPORT_ERRORS as error:
                steer["reason"] = type(error).__name__
                controls.record_result(self.run_dir, control, status="REFUSED", reason=steer["reason"])
                self.record["interruption"] = self.record["interruption"] or "governed_run:steer_not_confirmed"
                raise WatcherError("governed_run:steer_not_confirmed", str(error)) from error
        self.refresh_permissions(observed)
        self.offer_refused_action()
        self.progress()

    def user_message(self, item: Mapping[str, Any], turn_id: Any, observed: OwnerObservations) -> None:
        client = item.get("clientId")
        identifier = item.get("id")
        if client in self.initial_messages or not isinstance(identifier, str) or identifier in self.user_items:
            return
        parts = item.get("content")
        if not isinstance(parts, list) or not parts or any(
            not isinstance(part, Mapping) or part.get("type") != "text" or not isinstance(part.get("text"), str)
            for part in parts
        ):
            return
        text = "\n".join(part["text"] for part in parts)
        self.user_items.add(identifier)
        forwarded = self.forwarded.get(client) if isinstance(client, str) else None
        if forwarded is not None:
            if text != forwarded["text"] or turn_id != forwarded["governed_turn_id"]:
                self.record["interruption"] = "governed_run:steer_owner_disagreement"
            forwarded.update(owner_observed=True, item_id=identifier)
        else:
            steer = {
                "id": secrets.token_hex(16), "text": text, "source": "governed_task",
                "source_thread_id": self.record["governed_thread_id"], "source_turn_id": turn_id,
                "governed_turn_id": turn_id, "client_id": client, "request_sha256": None,
                "observed_at": utc_now(), "observed_at_ns": time.time_ns(),
                "forwarded": False, "owner_observed": True,
                "item_id": identifier,
            }
            self.record["steers"].append(steer)
            if turn_id != self.record["turn_id"]:
                self.record["interruption"] = "governed_run:foreign_turn_steer"
            if text.strip().casefold() in {"stop", "stop."}:
                steer["reason"] = "stop_requested"
                request_stop(self.records, self.record["run_id"], self.record["governed_thread_id"])
            elif len(self.record["steers"]) > controls.MAX_STEERS:
                steer["reason"] = "steer_limit"
                self.record["interruption"] = self.record["interruption"] or "governed_run:steer_limit"
        self.refresh_permissions(observed)
        self.progress()

    def refresh_permissions(self, observed: OwnerObservations) -> None:
        if not self.binding.get("workers") or self.binding.get("status") != "ACTIVE":
            return
        state = policy.read_grant_state(self.data_root, self.record["run_id"])
        targets = policy.round_workers(self.binding, state) - observed.closed_workers
        grants = list(self.binding.get("continuations") or [])
        known = {grant["grant_id"] for grant in grants}
        for steer in self.record["steers"]:
            if steer.get("governed_turn_id") != self.record["turn_id"] or steer.get("reason"):
                continue
            for target in sorted(targets):
                identifier = "continue:" + steer["id"] + "-" + policy.session_key(target)[:32]
                if identifier not in known:
                    grants.append(policy.continuation_grant(identifier, target, steer["text"],
                                                            turn_id=self.record["turn_id"], interrupt=True))
                    known.add(identifier)
        if grants != self.binding.get("continuations", []):
            value = policy.seal_binding({**self.binding, "continuations": grants})
            if policy.binding_issues(value, session_id=self.record["governed_thread_id"]):
                raise WatcherError("governed_run:binding_failed", "continuation permissions")
            write_json(policy.binding_path(self.data_root, self.record["governed_thread_id"]), value)
            self.binding.clear()
            self.binding.update(value)

    def offer_refused_action(self) -> None:
        if not self.record["steers"] or self.offer_written or self.record["revision"] >= controls.MAX_REVISIONS:
            return
        events = policy.read_events(self.data_root, self.record["run_id"])
        steers = [row for row in self.record["steers"]
                  if row["governed_turn_id"] == self.record["turn_id"] and not row.get("reason")]
        if not steers:
            return
        steer_at = max(self.offer_after_ns, min(row["observed_at_ns"] for row in steers))
        workers = policy.round_workers(self.binding, policy.read_grant_state(self.data_root, self.record["run_id"]))
        for event in events:
            reasons = event.get("reasons") or []
            if (event.get("hook_event_name") == "PreToolUse" and event.get("decision") == "DENY"
                and ((event.get("agent_id") is None and event.get("turn_id") == self.record["turn_id"])
                     or event.get("agent_id") in workers)
                and int(event.get("observed_at_ns") or 0) >= steer_at
                and any(reason.endswith("outside_plan") or reason in {
                            "governed_run:root_implementation", "governed_run:worker_collaboration"}
                        for reason in reasons)):
                plan = self.record["plan_sha256"]
                offer = self.offers_by_plan.get(plan)
                if offer is None:
                    offer = controls.revision_offer(
                        self.run_dir, run_id=self.record["run_id"], revision=self.record["revision"],
                        parent_plan_sha256=plan,
                        steer_ids=[row["id"] for row in steers],
                        refusal={key: event.get(key) for key in ("tool_use_id", "turn_id", "tool_name", "agent_id",
                                                                "tool_input_sha256", "reasons", "record_sha256")},
                    )
                    self.offers_by_plan[plan] = offer
                self.record["revision_offer"] = offer
                self.offer_written = True
                break

    def answer_revision(self, connection: app_server.AppServerConnection, control: Mapping[str, Any]) -> None:
        offer = self.record["revision_offer"]
        if (offer is None or self.accepted is not None or
            control["offer_sha256"] != offer["offer_sha256"] or
            offer["parent_plan_sha256"] != self.record["plan_sha256"]):
            controls.record_result(self.run_dir, control, status="REFUSED", reason="revision_offer_changed")
            return
        source_turn = self._source_turn(connection, control)
        answer = {"control_id": control["control_id"], "offer_sha256": offer["offer_sha256"],
                  "accept": control["accept"], "source_thread_id": control["source_thread_id"],
                  "source_turn_id": source_turn, "observed_at": utc_now()}
        self.record["revision_answers"].append(answer)
        if not control["accept"]:
            self.record["revision_offer"] = None
            self.offer_written = False
            # Reopen the same immutable N+1 choice only for a later refusal.
            # Earlier denials and their original evidence remain untouched.
            self.offer_after_ns = time.time_ns()
            controls.record_result(self.run_dir, control, status="DECLINED", plan_sha256=self.record["plan_sha256"])
            return
        candidate = {**self.request, "goal": control["goal"], "lanes": _lane_requests(control["lanes"]),
                     "worker_model": self.request["worker_model"] if control["lanes"] else None,
                     "worker_effort": self.request["worker_effort"] if control["lanes"] else None}
        # The lineup stays fixed; changing a zero-worker run into a lane run
        # uses the enrolled implementer at the original effort.
        if control["lanes"] and candidate["worker_model"] is None:
            candidate.update(worker_model=self.project["standing_authority"]["role_lineup"]["implementer"],
                             worker_effort=self.request["effort"])
        candidate = validate_request(candidate)
        lanes = resolve_lanes(candidate, self.project) if candidate["lanes"] else []
        plan = run_plan(candidate, self.project, lanes)
        with machine_lock(self.records):
            holder_path = self.records / "active" / (project_key(Path(candidate["project_root"])) + ".json")
            holder = read_json(holder_path)
            if holder.get("run_id") != self.record["run_id"] or not holder_alive(holder):
                raise WatcherError("governed_run:revision_owner_lost")
            _refuse_past_machine_cap(machine_runs(self.records, exclude_run=self.record["run_id"]), len(lanes))
            limit = (self.record.get("self_test") or {}).get("collaboration", {}).get("max_threads")
            if type(limit) is int and len(lanes) > limit:
                raise WatcherError("governed_run:codex_agent_limit")
            decision = admission.admit(
                plan, self.project["standing_authority"],
                reserved_today_cents=reserved_today(self.records, Path(candidate["project_root"]), local_date()),
                local_date=local_date(),
                onboarding=onboarding_admission(run_models(candidate), self.project,
                                                 onboarding_root=self.onboarding_root),
                approval=self.revision_approval(control, plan),
            )
            if decision["decision"] != "START":
                if decision["decision"] == "ASK":
                    ask = admission.build_ask(decision, asked_at=utc_now(),
                                              requesting_thread_id=control["source_thread_id"])
                    write_json(self.revision_ask_path(control, plan["plan_sha256"]), ask)
                controls.record_result(self.run_dir, control, status="APPROVAL_REQUIRED" if decision["decision"] == "ASK"
                                       else "REFUSED", admission=decision,
                                       question=admission.ask_text(decision) if decision["decision"] == "ASK" else None)
                return
            frozen = controls.write_revision(self.run_dir, {
                "run_id": self.record["run_id"], "revision": offer["revision"],
                "parent_plan_sha256": self.record["plan_sha256"], "plan": plan,
                "summary": work_summary(candidate, self.project, lanes), "admission": decision,
                "answer": answer, "offer_sha256": offer["offer_sha256"], "frozen_at": utc_now(),
            })
            # During transition the old workers are still held; no old and
            # new workers overlap. The reservation is reduced after cleanup.
            write_json(holder_path, {**holder, "workers": max(holder["workers"], len(lanes))})
            if decision["approved"]:
                self.revision_ask_path(control, plan["plan_sha256"]).unlink()
        self.record["revisions"].append(frozen)
        self.accepted = {"request": candidate, "lanes": lanes, "plan": plan, "admission": decision,
                         "offer": offer, "answer": answer, "control": dict(control), "frozen": frozen}
        controls.record_result(self.run_dir, control, status="ADMITTED", plan_sha256=plan["plan_sha256"],
                               revision_sha256=frozen["revision_sha256"])

    def revision_ask_path(self, control: Mapping[str, Any], digest: str) -> Path:
        return self.run_dir / "revision-asks" / digest / (policy.session_key(control["source_thread_id"]) + ".json")

    def revision_approval(self, control: Mapping[str, Any], plan: Mapping[str, Any]) -> Mapping[str, Any] | None:
        if control.get("approve_plan_sha256") != plan["plan_sha256"]:
            return None
        try:
            ask = read_json(self.revision_ask_path(control, plan["plan_sha256"]))
        except (OSError, ValueError, WatcherError):
            return None
        return ask if admission.ask_open(ask, now=datetime.now(timezone.utc),
                                         requesting_thread_id=control["source_thread_id"]) else None

    def reconcile_messages(self, thread: Mapping[str, Any], observed: OwnerObservations) -> None:
        """Join missing notifications through Codex's final read, without inventing steers."""
        for turn in thread.get("turns") or []:
            for item in turn.get("items") or []:
                if item.get("type") == "userMessage":
                    self.user_message(item, turn.get("id"), observed)
        if any(row["forwarded"] and not row["owner_observed"] for row in self.record["steers"]):
            self.record["interruption"] = self.record["interruption"] or "governed_run:steer_not_confirmed"
        self.offer_refused_action()
        self.progress()


# slots=True needs Python 3.10; the supported macOS system python3 is 3.9.
@dataclass(**({"slots": True} if sys.version_info >= (3, 10) else {}))
class OwnerObservations:
    """What the owner connection reported while a run's turns ran.

    usage maps each thread to its cumulative token totals; workers are the
    threads the governed task's own spawn items name, the only ones the
    watcher interrupts; worker_turns keeps every other thread's turns by
    status (None while running) and items its action-bearing items.
    """

    usage: dict[str, dict[str, int]] = field(default_factory=dict)
    workers: set[str] = field(default_factory=set)
    worker_turns: dict[str, dict[str, str | None]] = field(default_factory=dict)
    items: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    closed_workers: set[str] = field(default_factory=set)
    controls: RunControlSession | None = None


def _lane_entry(lane: Mapping[str, Any]) -> dict[str, Any]:
    """A lane as the run record keeps it, before its worker has run.

    checks_passed and overclaim are the lane round's own result;
    checks_passed_after_repair is its checks' result after a repair round.
    """

    return {
        "id": lane["id"], "grant_id": "lane:" + lane["id"], "worker_thread_id": None,
        "worker_status": None, "worker_closed": None, "checks": [row["id"] for row in lane["checks"]],
        "checks_passed": None, "overclaim": None, "checks_passed_after_repair": None,
    }


def run_governed_task(
    request: Mapping[str, Any],
    *,
    root: Path | None = None,
    home: Path | None = None,
    records: Path | None = None,
    onboarding_root: Any = None,
    connect: Callable[[Path], app_server.AppServerConnection] = app_server.AppServerConnection,
    hook_probe: Callable[[Path], Mapping[str, Any]] = run_hook_scope_probe,
    codex_executable: str | None = None,
    launch_runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """One governed run, start to verdict; returns the sealed run record."""

    request = validate_request(request)
    root = root or plugin_root()
    home = home or codex_home(root)
    records = records or records_root()
    data_root = plugin_data_root(root, home)
    run_id = request["run_id"]
    run_dir = run_directory(records, run_id)
    _private_directory(run_dir)
    write_json(run_dir / "request.json", request, create_only=True)
    _status(run_dir, run_id, "STARTING")
    project_root = Path(os.path.realpath(request["project_root"]))
    record = _new_record(request, run_dir)
    refusal: str | None = None
    connection: app_server.AppServerConnection | None = None
    runner: Any = None
    lock: Path | None = None
    binding: dict[str, Any] | None = None
    ended_at_ns: int | None = None
    round_after_ns: int | None = None
    project: Mapping[str, Any] = {}
    claim: Mapping[str, Any] = {}
    lanes: list[dict[str, Any]] = []
    tree: dict[str, str | None] = {}
    summary: Mapping[str, Any] = {}
    observed = OwnerObservations()

    def archive_unbound_task(thread_id: str) -> None:
        try:
            connection.request("thread/archive", {"threadId": thread_id}, timeout=15)
            record["cleanup"]["task_archived"] = True
        except _TRANSPORT_ERRORS:
            record["cleanup"]["task_archived"] = False

    try:
        project = read_enrollment(records, project_root)
        lanes = resolve_lanes(request, project) if request["lanes"] else []
        claim = verify_claim(run_dir, request, project, lanes)
        tree = test_tree_pins(project_root)
        write_test_tree(run_dir, run_id, tree)
        record["enrollment_sha256"] = project["record_sha256"]
        record["plan_sha256"] = claim["plan"]["plan_sha256"]
        record["admission_sha256"] = claim["admission"]["admission_sha256"]
        summary = work_summary(request, project, lanes)
        record["summary_sha256"] = policy.sha256(summary)
        record["lanes"] = [_lane_entry(lane) for lane in lanes]
        try:
            connection = connect(app_server.resolve_socket(shared_socket_path(home)))
            initialized = connection.initialize(CLIENT_NAME)
        except _TRANSPORT_ERRORS as error:
            record["self_test"] = unavailable_self_test(
                "governed_mode:app_server_unavailable", type(error).__name__ + ": " + str(error)
            )
            raise WatcherError("governed_mode:app_server_unavailable") from error
        known_good = load_known_good(root)
        self_test = startup_self_test(
            connection, initialized, root=root, project_root=project_root,
            known_good=known_good, hook_probe=hook_probe,
        )
        if self_test["status"] == "PASS" and (self_test.get("location") or {}).get("location") == "governed_runner":
            connection.close()
            connection = None
            runner = (launch_runner or GovernedRunner)(
                codex_executable or resolve_codex_executable(), home, project_root, run_dir,
            )
            connection = connect(runner.socket)
            initialized = connection.initialize(CLIENT_NAME)
            self_test = startup_self_test(
                connection, initialized, root=root, project_root=project_root,
                known_good=known_good, hook_probe=hook_probe,
            )
            if self_test["status"] == "PASS" and (self_test.get("location") or {}).get("location") != "user_codex":
                self_test = unavailable_self_test("governed_mode:v1_unavailable", "governed runner")
            record["location"] = "governed_runner"
        elif self_test["status"] == "PASS":
            record["location"] = "user_codex"
        record["self_test"] = self_test
        write_json(run_dir / "self-test.json", self_test)
        if self_test["status"] != "PASS":
            raise WatcherError(str(self_test["refusal"]))
        onboarding = onboarding_admission(
            run_models(request), project, codex_version=self_test.get("codex_version"),
            onboarding_root=onboarding_root,
        )
        if onboarding["status"] != "ADMITTED":
            raise WatcherError("governed_run:onboarding_required", ",".join(onboarding["issues"]))
        # Issue 219: the admitted packaged role-guidance document is loaded
        # before freeze_context so the planner section bytes are bound into
        # the same frozen configuration the planner's developerInstructions
        # is built from. Zero-worker implementer runs do not load the
        # document: only the planner is an active consumer today, and
        # implementer/reviewer stay reference-only.
        guidance: dict[str, Any] | None = None
        if lanes:
            guidance = required_role_guidance(root)
            record["role_guidance_loaded"] = True
            record["role_guidance_sha256"] = guidance["digest"]
            consumed_role, active_section = planner_role_guidance(guidance)
            record["role_guidance_consumed_sections"] = [consumed_role]
        import orch_dork_project_improvements as project_improvements
        project_improvements.freeze_context(request, claim["plan"], onboarding,
                                            source_root=root, run_dir=run_dir,
                                            onboarding_root=onboarding_root, records=records,
                                            role_guidance=guidance)
        limit = (self_test.get("collaboration") or {}).get("max_threads")
        if type(limit) is int and len(lanes) > limit:
            raise WatcherError("governed_run:codex_agent_limit",
                               str(len(lanes)) + " lanes, agents.max_threads " + str(limit))
        lock = acquire_lock(records, project_root, run_id, workers=len(lanes),
                            reap=lambda holder: reap_stale_run(records, data_root, holder))
        developer_instructions = (LANES_DEVELOPER_INSTRUCTIONS if lanes else DEVELOPER_INSTRUCTIONS).format(
            run_id=run_id, project_root=project_root,
        )
        if guidance is not None:
            developer_instructions = developer_instructions + role_guidance_block(
                consumed_role, active_section, guidance["digest"],
            )
        try:
            started = connection.request("thread/start", {
                "model": request["model"],
                "cwd": str(project_root),
                "approvalPolicy": "never",
                "sandbox": "workspace-write",
                "developerInstructions": developer_instructions,
                "serviceName": SERVICE_NAME,
                "config": {"model_reasoning_effort": request["effort"]},
            })
            thread_id = started["thread"]["id"]
        except (KeyError, TypeError, *_TRANSPORT_ERRORS) as error:
            raise WatcherError("governed_run:task_start_failed", str(error)) from error
        record["governed_thread_id"] = thread_id
        record["observed_model"] = started.get("model") if isinstance(started.get("model"), str) else None
        # Bind before anything else: SessionStart fires at the first turn.
        try:
            binding = write_binding(
                data_root, run_id=run_id, thread_id=thread_id, project_root=project_root,
                summary_sha256=record["summary_sha256"],
                hook_definition_sha256=hook_definition(root),
                protected_paths=[
                    str(data_root), str(records), str(project_root / ".orch-dork"),
                    str(project["project_ground"]["registry_root"]),
                ],
                workers=len(lanes),
                grants=[policy.spawn_grant("lane:" + lane["id"], lane["spawn"]) for lane in summary["lanes"]],
                lane_writes={"lane:" + lane["id"]: lane["writes"] for lane in lanes if lane["writes"]},
            )
        except (OSError, ValueError, WatcherError) as error:
            archive_unbound_task(thread_id)
            raise WatcherError("governed_run:binding_failed", str(error)) from error
        record["binding_sha256"] = binding["binding_sha256"]
        observed.controls = RunControlSession(
            record, request, run_dir=run_dir, data_root=data_root, binding=binding,
            project=project, records=records, onboarding_root=onboarding_root,
        )
        observed.controls.progress()
        try:
            connection.request("thread/name/set", {
                "threadId": thread_id, "name": "Orch Dork governed run " + run_id,
            })
        except _TRANSPORT_ERRORS:
            record["cleanup"]["task_named"] = False
        _status(run_dir, run_id, "RUNNING", governed_thread_id=thread_id, location=record["location"])
        if stop_requested(run_dir):
            record["stop"] = observed_stop(run_dir, "before_turn")
            archive_unbound_task(thread_id)
        else:
            observe(connection, record, request, summary_text(run_id, summary), run_dir=run_dir,
                    on_unstarted=archive_unbound_task, observed=observed)
            if lanes and record["turn_status"] is not None:
                settle_workers(connection, record, observed)
    except WatcherError as error:
        if error.reason in ROLE_GUIDANCE_REFUSALS:
            record["role_guidance_issue"] = {"reason": error.reason, "detail": error.detail}
        if error.reason in SELF_TEST_REFUSALS or error.reason in RUN_REFUSALS:
            refusal = error.reason
        else:
            record["interruption"] = record["interruption"] or error.reason
    except (OSError, ConnectionError, TimeoutError, ValueError, KeyError, TypeError,
            app_server.AppServerRequestError) as error:
        record["interruption"] = record["interruption"] or "governed_run:watcher_error:" + type(error).__name__
    finally:
        if binding is not None:
            ended_at_ns = time.time_ns()
            try:
                binding = end_binding(data_root, binding)
                if observed.controls is not None:
                    observed.controls.binding = binding
                record["cleanup"]["binding_status"] = binding["status"]
            except (OSError, ValueError):
                record["cleanup"]["binding_status"] = "UNKNOWN"
    try:
        while True:
            if binding is not None and connection is not None and record["turn_id"] and refusal is None:
                refusal = _finish_round(connection, record, data_root, run_dir, root=root, binding=binding,
                                        lanes=lanes, observed=observed, until_ns=ended_at_ns, after_ns=round_after_ns)
            session = observed.controls
            if session is not None and connection is not None:
                session.poll(connection, observed, can_forward=False)
            if refusal is None:
                await_revision_answer(connection, record, observed, run_dir=run_dir, request=request)
            if session is not None and session.accepted is not None and (
                (record["cross_check"] or {}).get("status") != "AGREED"
            ):
                refusal = (record["cross_check"] or {}).get("reason") or "governed_run:hook_owner_disagreement"
            if refusal is None and _round_agreed(record) and not (session and session.accepted):
                refusal = _run_round_checks(record, project, lanes, project_root, run_dir, tree=tree,
                                            connection=connection, observed=observed)
                _judge_lanes(record, after_repair=False)
            if refusal is None and lanes and _repair_due(record) and not (session and session.accepted):
                refusal = _repair_round(
                    connection, record, request, summary, data_root, run_dir, root=root, binding=binding,
                    project=project, lanes=lanes, project_root=project_root, observed=observed, tree=tree,
                )
                if session is not None:
                    binding = session.binding
            if (session is None or session.accepted is None or refusal is not None
                    or record["stop"] is not None or record["interruption"] is not None):
                break
            cleanup = _settle_run_tasks(connection, record, observed, data_root=data_root,
                                       connect=None, socket_path=None, interrupt_root=True,
                                       transition=True)
            record["cleanup"].setdefault("revision_transitions", []).append(cleanup)
            if cleanup["status"] != "PASS":
                record["interruption"] = "governed_run:revision_cleanup_unconfirmed"
                break
            _close_round(record)
            accepted = session.accepted
            request, lanes = accepted["request"], accepted["lanes"]
            summary = accepted["frozen"]["summary"]
            binding = activate_revision(session, accepted, records=records, data_root=data_root)
            session.binding = binding
            session.request = dict(request)
            session.accepted = None
            session.offer_written = False
            session.progress()
            _status(run_dir, run_id, "RUNNING", governed_thread_id=record["governed_thread_id"],
                    location=record["location"], revision=record["revision"])
            round_after_ns = time.time_ns()
            try:
                observe(connection, record, request,
                        "Orch Dork explicitly admitted revision " + str(record["revision"]) + ".\n"
                        + summary_text(run_id, summary, sorted(
                            set(cleanup["owned_worker_thread_ids"]) - set(cleanup["closed_worker_thread_ids"])
                        )), run_dir=run_dir,
                        on_unstarted=lambda _thread: None, observed=observed)
                if lanes and record["turn_status"] is not None:
                    settle_workers(connection, record, observed)
            finally:
                ended_at_ns = time.time_ns()
                binding = end_binding(data_root, binding)
                session.binding = binding
                record["cleanup"]["binding_status"] = binding["status"]
    except WatcherError as error:
        if error.reason in RUN_REFUSALS:
            refusal = refusal or error.reason
        else:
            record["interruption"] = record["interruption"] or error.reason
    except (OSError, ConnectionError, TimeoutError, ValueError, KeyError, TypeError,
            app_server.AppServerRequestError) as error:
        record["interruption"] = record["interruption"] or "governed_run:watcher_error:" + type(error).__name__
    finally:
        if record["turn_id"] is not None and all(row["turn_id"] != record["turn_id"] for row in record["rounds"]):
            _close_round(record)
        if connection is not None:
            _drain(connection, record, observed)
        if record["governed_thread_id"] and not record["cleanup"].get("task_archived"):
            cleanup = _settle_run_tasks(
                connection, record, observed, data_root=data_root, connect=connect,
                socket_path=runner.socket if runner is not None else shared_socket_path(home),
                # Even when every worker was closed, confirm the retained
                # owner's root is idle at the terminal boundary. Disconnect
                # here is still interruption, never a successful empty cleanup.
                interrupt_root=True,
            )
            record["cleanup"]["owned_tasks"] = cleanup
            if cleanup["connection"]["caller_connection_lost"]:
                record["interruption"] = record["interruption"] or "governed_run:owner_connection_lost"
            if any(turn != record["turn_id"] for turn in cleanup["root"]["interrupted_turn_ids"]):
                record["interruption"] = record["interruption"] or "governed_run:foreign_turn_steer"
            if cleanup["status"] != "PASS":
                record["interruption"] = record["interruption"] or "governed_run:cleanup_unconfirmed"
        label = record_verdict(record, refusal)["label"]
        if connection is not None:
            if binding is not None and record["governed_thread_id"]:
                try:
                    connection.request("thread/name/set", {
                        "threadId": record["governed_thread_id"],
                        "name": "Orch Dork governed run " + run_id + " \u2014 " + label,
                    }, timeout=15)
                except _TRANSPORT_ERRORS:
                    record["cleanup"]["task_renamed"] = False
            connection.close()
            record["cleanup"]["owner_connection_closed"] = True
        if runner is not None:
            record["cleanup"].update(runner.close())
        if lock is not None:
            try:
                lock.unlink()
            except FileNotFoundError:
                pass
            record["cleanup"]["repository_lock_released"] = not lock.exists()
        record["cleanup"]["check_groups_cleared"] = all(
            row.get("group_cleared") is True for round_row in record["rounds"] for row in round_row["checks"]
        ) and all(row.get("group_cleared") is True for row in record["checks"])
        record["cost"] = run_cost_summary(record, project, claim, observed)
    return _finish(record, run_dir, refusal)



def await_revision_answer(
    connection: Any, record: dict[str, Any], observed: OwnerObservations, *,
    run_dir: Path, request: Mapping[str, Any],
) -> None:
    """Keep a completed round's offer answerable without a model turn."""
    session = observed.controls
    if (session is None or session.record["revision_offer"] is None
            or session.accepted is not None or not _round_agreed(record)):
        return
    _status(run_dir, record["run_id"], "AWAITING_REVISION", governed_thread_id=record["governed_thread_id"],
            revision=record["revision"], location=record["location"])
    deadline = time.monotonic() + int(request["turn_seconds"])
    while session.record["revision_offer"] is not None and session.accepted is None:
        _drain(connection, record, observed)
        if record["interruption"] is not None:
            return
        session.poll(connection, observed, can_forward=False)
        if stop_requested(run_dir):
            record["stop"] = observed_stop(run_dir, "awaiting_revision")
            record["stop"]["turn_ended"] = True
            return
        if time.monotonic() >= deadline:
            record["interruption"] = "governed_run:turn_timeout"
            return
        time.sleep(POLL_SECONDS)


def _settle_run_tasks(
    connection: Any, record: dict[str, Any], observed: OwnerObservations, *,
    data_root: Path, connect: Any, socket_path: Path | None, interrupt_root: bool,
    transition: bool = False,
) -> dict[str, Any]:
    """Settle ids this run's own spawn items or durable spawn outcomes prove."""
    workers = set(observed.workers)
    evidence_issue = None
    try:
        state = policy.read_grant_state(data_root, record["run_id"])
        workers.update(
            entry["outcome"]["agent_id"] for grant_id, entry in state.items()
            if not grant_id.startswith("continue:") and isinstance(entry.get("outcome"), Mapping)
            and isinstance(entry["outcome"].get("agent_id"), str)
        )
    except (OSError, ValueError) as error:
        evidence_issue = "spawn_ownership_unreadable:" + str(error)[:200]
    settled_before = {
        row["thread_id"]: dict(row)
        for report in record["cleanup"].get("revision_transitions", [])
        if task_cleanup.report_valid(report) and report["status"] == "PASS"
        and isinstance(report.get("root"), Mapping)
        and report["root"].get("thread_id") == record["governed_thread_id"]
        for row in report["workers"]
        if isinstance(row, Mapping) and isinstance(row.get("thread_id"), str)
        and row["thread_id"] in workers
        and (row.get("archived") is True or row.get("closed_natively") is True)
    }
    # Archive ends a worker task but does not release its parent's native
    # spawn slot. A later root close, joined to both hooks, settles that slot.
    # Keep the original transition reports immutable and project newer proof
    # into this report instead of repeating an old close in the next summary.
    for worker, row in settled_before.items():
        if worker in observed.closed_workers:
            row["closed_natively"] = True
    # Earlier revisions already proved these exact owned tasks settled. Their
    # immutable cleanup reports remain in the record; never archive them twice.
    workers -= settled_before.keys()
    result = task_cleanup.settle_owned_tasks(
        connection, root_thread_id=record["governed_thread_id"], root_turn_id=record["turn_id"],
        worker_thread_ids=sorted(workers), closed_worker_ids=sorted(observed.closed_workers & workers),
        interrupt_root=interrupt_root, connect=connect, socket_path=socket_path,
        wait_seconds=WORKER_SETTLE_SECONDS,
    )
    if settled_before:
        rows = sorted([*result["workers"], *settled_before.values()], key=lambda row: row["thread_id"])
        closed = [row["thread_id"] for row in rows if row.get("closed_natively") is True]
        result = task_cleanup.sealed({
            **result, "workers": rows, "owned_worker_thread_ids": [row["thread_id"] for row in rows],
            "closed_worker_thread_ids": closed, "workers_closed_natively": len(closed),
            "own_workers_confirmed_ended": all(row["turns_confirmed_ended"] for row in rows),
            "own_workers_archived": all(row["archived"] is True or row["closed_natively"] for row in rows),
            "counters": {**result["counters"], "owned_worker_threads": len(rows),
                         "worker_threads_closed_natively": len(closed)},
        }, "report_sha256")
    if evidence_issue:
        result = task_cleanup.sealed({**result, "status": "BLOCKED",
                                      "issues": [*result["issues"], evidence_issue]}, "report_sha256")
    pending_slots = sorted(worker for worker, row in settled_before.items()
                           if row.get("closed_natively") is not True)
    if pending_slots and not transition:
        result = task_cleanup.sealed({
            **result, "status": "BLOCKED",
            "issues": [*result["issues"], "governed_run:cleanup_unconfirmed"],
            "remaining": [*result["remaining"], *(
                {"role": "worker", "thread_id": worker, "reason": "native_slot_not_closed"}
                for worker in pending_slots
            )],
        }, "report_sha256")
    return result


def activate_revision(
    session: RunControlSession, accepted: Mapping[str, Any], *, records: Path, data_root: Path,
) -> dict[str, Any]:
    """Activate an already frozen, admitted revision after the old tasks ended."""
    record = session.record
    frozen = accepted["frozen"]
    project = read_enrollment(records, Path(record["project_root"]))
    if project["record_sha256"] != session.project["record_sha256"]:
        raise WatcherError("governed_run:enrollment_changed")
    summary = frozen["summary"]
    lanes = accepted["lanes"]
    revision = frozen["revision"]
    binding = policy.seal_binding({
        **session.binding, "revision": revision, "round": 1, "workers": len(lanes),
        "status": "ACTIVE", "summary_sha256": policy.sha256(summary), "continuations": [],
        "grants": [policy.spawn_grant(policy.revision_grant_id("lane:" + lane["id"], revision), lane["spawn"])
                   for lane in summary["lanes"]], "bound_at": utc_now(),
        "lane_writes": {policy.revision_grant_id("lane:" + lane["id"], revision): list(lane["writes"])
                        for lane in lanes if lane.get("writes")},
    })
    if policy.binding_issues(binding, session_id=record["governed_thread_id"]):
        raise WatcherError("governed_run:binding_failed", "revision permissions")
    with machine_lock(records):
        holder_path = records / "active" / (project_key(Path(record["project_root"])) + ".json")
        holder = read_json(holder_path)
        if holder.get("run_id") != record["run_id"] or not holder_alive(holder):
            raise WatcherError("governed_run:revision_owner_lost")
        write_json(holder_path, {**holder, "workers": len(lanes)})
        write_json(policy.binding_path(data_root, record["governed_thread_id"]), binding)
    entries = [_lane_entry(lane) for lane in lanes]
    for lane in entries:
        lane["grant_id"] = policy.revision_grant_id("lane:" + lane["id"], revision)
    record.update(
        revision=revision, plan_sha256=frozen["plan"]["plan_sha256"],
        admission_sha256=frozen["admission"]["admission_sha256"], summary_sha256=policy.sha256(summary),
        binding_sha256=binding["binding_sha256"], lanes=entries, revision_offer=None,
        worker_model=accepted["request"]["worker_model"], worker_effort=accepted["request"]["worker_effort"],
        turn_id=None, turn_status=None, cross_check=None, checks=[], changed_check_files=[],
    )
    return binding


def _finish_round(
    connection: app_server.AppServerConnection,
    record: dict[str, Any],
    data_root: Path,
    run_dir: Path,
    *,
    root: Path,
    binding: Mapping[str, Any],
    lanes: Sequence[Mapping[str, Any]],
    observed: OwnerObservations,
    until_ns: int | None,
    after_ns: int | None = None,
) -> str | None:
    """Cross-check one round once its binding ended; a refusal when the hooks changed."""

    if observed.controls is not None:
        read = connection.request("thread/read", {"threadId": record["governed_thread_id"], "includeTurns": True})
        observed.controls.reconcile_messages((read or {}).get("thread") or {}, observed)
    if lanes or any(row["workers"] for row in record["rounds"]):
        earlier = record["rounds"]
        workers = finish_lane_round(
            connection, record, data_root, run_dir, binding=binding, observed=observed,
            after_ns=after_ns, until_ns=until_ns,
            earlier_turns=[row["turn_id"] for row in earlier],
            earlier_workers=[worker["thread_id"] for row in earlier for worker in row["workers"]],
        )
        repair = record["repair"] if binding["round"] == 2 else None
        entries = [repair] if repair is not None else record["lanes"]
        for worker in workers:
            for entry in entries:
                if entry["grant_id"] == worker["grant_id"]:
                    entry.update(worker_thread_id=worker["thread_id"], worker_status=worker["status"],
                                 worker_closed=worker["closed"], observed_model=worker.get("observed_model"))
        refused = set((record["cross_check"] or {}).get("spawns_codex_refused") or [])
        for entry in entries:
            if entry["grant_id"] in refused:
                entry["worker_status"] = "spawn_refused"
    else:
        finish_observation(connection, record, data_root, run_dir, ended_at_ns=until_ns,
                           earlier_turns=[row["turn_id"] for row in record["rounds"]], after_ns=after_ns)
    try:
        changed = hook_definition(root) != binding["hook_definition_sha256"]
    except OSError:
        changed = True
    return "governed_run:hooks_changed_during_run" if changed else None


def _round_agreed(record: Mapping[str, Any]) -> bool:
    """Whether the round's turn ended and its hooks and owner record agreed."""

    return (
        record["turn_status"] == "completed"
        and record["interruption"] is None
        and (record["cross_check"] or {}).get("status") == "AGREED"
    )


def _run_round_checks(
    record: dict[str, Any], project: Mapping[str, Any], lanes: Sequence[Mapping[str, Any]],
    project_root: Path, run_dir: Path, *, tree: Mapping[str, str | None], connection: Any = None,
    observed: OwnerObservations | None = None,
) -> str | None:
    """Run each lane's checks, then the project's checks on the joined tree.

    A run that changed an enrolled check's files, a lane's acceptance test
    or the test tree pinned when it started is refused before any check
    runs; a stop ends the running check.
    """

    pins = dict(project["pinned_files"])
    for lane in lanes:
        pins.update(lane["pins"])
    record["changed_check_files"] = sorted(
        set(changed_check_files(project_root, pins)) | set(changed_test_tree(project_root, tree))
    )
    if record["changed_check_files"]:
        return "governed_run:check_changed"
    _status(run_dir, record["run_id"], "CHECKING", governed_thread_id=record["governed_thread_id"])
    scoped = [(check, "lane:" + lane["id"]) for lane in lanes for check in lane["checks"]]
    scoped += [(check, "joined" if lanes else "project") for check in project["checks"]]
    def stopped() -> bool:
        if connection is not None and observed is not None:
            _drain(connection, record, observed)
            if observed.controls is not None and record["interruption"] is None:
                try:
                    observed.controls.poll(connection, observed, can_forward=False)
                except (WatcherError, *_TRANSPORT_ERRORS) as error:
                    record["interruption"] = record["interruption"] or (
                        error.reason if isinstance(error, WatcherError) else "governed_run:owner_connection_lost"
                    )
        return bool(stop_requested(run_dir) or record["interruption"] or
                    (observed is not None and observed.controls and observed.controls.accepted))

    for check, scope in scoped:
        if stopped():
            if stop_requested(run_dir):
                record["stop"] = observed_stop(run_dir, "during_checks")
            break
        row = run_check(check, project_root, stop=stopped)
        record["checks"].append({**row, "scope": scope})
        stop_now = stopped()
        if stop_requested(run_dir):
            record["stop"] = observed_stop(run_dir, "during_checks")
        if row["stopped"] or stop_now:
            break
    return None


def _judge_lanes(record: dict[str, Any], *, after_repair: bool) -> None:
    """Each lane's checks result for the round that just ran its checks.

    After the lane round a lane also records whether its worker reported
    completion that its checks did not bear out; after the repair round only
    its checks' new result is added, so the lane round's own facts stay.
    """

    for lane in record["lanes"]:
        rows = [row for row in record["checks"] if row.get("scope") == "lane:" + lane["id"]]
        passed = all(row["passed"] for row in rows) if len(rows) == len(lane["checks"]) else None
        if after_repair:
            lane["checks_passed_after_repair"] = passed
            continue
        lane["checks_passed"] = passed
        lane["overclaim"] = None if passed is None else lane["worker_status"] == "completed" and not passed


def _repair_due(record: Mapping[str, Any]) -> bool:
    """A lane run's first round ran every check and at least one failed."""

    return (
        record["repair"] is None
        and record["stop"] is None
        and bool(record["checks"])
        and not all(row["passed"] for row in record["checks"])
    )


def _close_round(record: dict[str, Any]) -> None:
    """Keep the facts of the round that just ended in the record's rounds."""

    repair = record["repair"] or {}
    entries = [repair] if repair.get("turn_id") and repair["turn_id"] == record["turn_id"] else record["lanes"]
    record["rounds"].append({
        "round": len(record["rounds"]) + 1,
        "revision": record["revision"], "plan_sha256": record["plan_sha256"],
        "turn_id": record["turn_id"],
        "turn_status": record["turn_status"],
        "workers": [
            {"grant_id": entry["grant_id"], "thread_id": entry["worker_thread_id"],
             "status": entry["worker_status"], "closed": entry["worker_closed"]}
            for entry in entries if entry.get("worker_thread_id")
        ],
        "cross_check": record["cross_check"],
        "changed_check_files": list(record["changed_check_files"]),
        "checks": [dict(row) for row in record["checks"]],
    })


def _repair_round(
    connection: app_server.AppServerConnection,
    record: dict[str, Any],
    request: Mapping[str, Any],
    summary: Mapping[str, Any],
    data_root: Path,
    run_dir: Path,
    *,
    root: Path,
    binding: Mapping[str, Any],
    project: Mapping[str, Any],
    lanes: Sequence[Mapping[str, Any]],
    project_root: Path,
    observed: OwnerObservations,
    tree: Mapping[str, str | None],
) -> str | None:
    """The run's one repair round, then every check again.

    The governed task spawns one repair worker with the message the watcher
    computed from the failed checks, under a binding that holds only that
    worker's permission; the round is cross-checked like the first before
    the checks run on the repaired tree.
    """

    if stop_requested(run_dir):
        record["stop"] = observed_stop(run_dir, "before_repair")
        return None
    failed = [row for row in record["checks"] if not row["passed"]]
    arguments = spawn_arguments(repair_message(summary["goal"], failed), request["worker_model"],
                                request["worker_effort"])
    repair_id = policy.revision_grant_id(policy.REPAIR_GRANT, record["revision"])
    grant = policy.spawn_grant(repair_id, arguments)
    _close_round(record)
    record["repair"] = {
        "failed_checks": [row["id"] for row in failed], "grant_id": repair_id,
        "message_sha256": grant["message_sha256"], "turn_id": None,
        "worker_thread_id": None, "worker_status": None, "worker_closed": None,
    }
    open_workers = [lane["worker_thread_id"] for lane in record["lanes"]
                    if lane["worker_thread_id"] and not lane["worker_closed"]]
    record.update(turn_id=None, turn_status=None, cross_check=None, changed_check_files=[], checks=[])
    after_ns = time.time_ns()
    binding = bind_repair_round(data_root, binding, grant)
    if observed.controls is not None:
        observed.controls.binding = binding
    _status(run_dir, record["run_id"], "RUNNING", governed_thread_id=record["governed_thread_id"],
            location=record["location"], round=2)
    try:
        observe(connection, record, request, repair_text(record["run_id"], arguments, open_workers),
                run_dir=run_dir, on_unstarted=lambda _thread: None, observed=observed)
        if record["turn_status"] is not None:
            settle_workers(connection, record, observed)
    except WatcherError as error:
        if error.reason == "governed_run:task_start_failed":
            raise WatcherError("governed_run:repair_start_failed", error.detail) from error
        raise
    finally:
        record["repair"]["turn_id"] = record["turn_id"]
        until_ns = time.time_ns()
        try:
            binding = end_binding(data_root, binding)
            if observed.controls is not None:
                observed.controls.binding = binding
            record["cleanup"]["binding_status"] = binding["status"]
        except (OSError, ValueError):
            record["cleanup"]["binding_status"] = "UNKNOWN"
    refusal = _finish_round(connection, record, data_root, run_dir, root=root, binding=binding, lanes=lanes,
                            observed=observed, after_ns=after_ns, until_ns=until_ns)
    if refusal is None:
        await_revision_answer(connection, record, observed, run_dir=run_dir, request=request)
    if (refusal is None and _round_agreed(record)
            and not (observed.controls and observed.controls.accepted)):
        refusal = _run_round_checks(record, project, lanes, project_root, run_dir, tree=tree,
                                    connection=connection, observed=observed)
        _judge_lanes(record, after_repair=True)
    return refusal


def run_cost_summary(
    record: Mapping[str, Any], project: Mapping[str, Any], claim: Mapping[str, Any],
    observed: OwnerObservations,
) -> dict[str, Any]:
    """The run's cost summary from the token counts its owner connection saw.

    The frontier model it estimates against is the model the user chats
    with; the governed task plans a run with lanes and writes the code of a
    run without, and every lane or repair worker writes code.
    """

    threads = []
    if record["governed_thread_id"]:
        threads.append({"thread_id": record["governed_thread_id"], "model": record["model"],
                        "role": "planner" if record["lanes"] else "implementer"})
    workers = [(lane["id"], lane["worker_thread_id"]) for lane in record["lanes"]]
    workers += [(worker["grant_id"].split("lane:", 1)[-1] if "lane:" in worker["grant_id"] else "repair",
                 worker["thread_id"]) for row in record["rounds"]
                for worker in row["workers"]]
    if record["repair"]:
        workers.append(("repair", record["repair"]["worker_thread_id"]))
    threads.extend(
        {"thread_id": thread_id, "model": record["worker_model"], "role": "implementer", "lane": lane_id}
        for thread_id, lane_id in dict((thread_id, lane_id) for lane_id, thread_id in workers if thread_id).items()
    )
    authority = project.get("standing_authority") if isinstance(project, Mapping) else None
    models = project.get("models") if isinstance(project, Mapping) else None
    decision = claim.get("admission") if isinstance(claim, Mapping) else None
    return run_cost.cost_summary(
        threads=threads,
        usage=observed.usage,
        frontier_model=models.get("chat_model") if isinstance(models, Mapping) else None,
        budget_cents=decision.get("budget_cents") if isinstance(decision, Mapping) else None,
        daily_cents=authority.get("daily_cost_cents") if isinstance(authority, Mapping) else None,
        run_workers=len(record["lanes"]),
        machine_workers=MACHINE_WORKERS,
    )


def _record_notification(message: Mapping[str, Any], record: Mapping[str, Any], observed: OwnerObservations) -> None:
    """Keep what one notification says about token usage and the run's workers.

    The run's workers are the threads the governed task's own spawn items
    name; turns and items of other threads are kept but never acted on.
    """

    params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
    thread = params.get("threadId")
    method = message.get("method")
    if not isinstance(thread, str):
        return
    if method == "thread/tokenUsage/updated":
        totals = run_cost.thread_totals(params.get("tokenUsage"))
        if totals is not None:
            observed.usage[thread] = totals
        return
    item = params.get("item") if isinstance(params.get("item"), Mapping) else None
    if thread == record["governed_thread_id"]:
        if method == "item/completed" and item is not None and item.get("type") == "userMessage":
            if observed.controls is not None:
                observed.controls.user_message(item, params.get("turnId"), observed)
        if (
            method == "item/completed" and item is not None
            and item.get("type") == "collabAgentToolCall" and item.get("tool") == "spawnAgent"
        ):
            observed.workers.update(
                value for value in item.get("receiverThreadIds") or [] if isinstance(value, str)
            )
        elif (method == "item/completed" and item is not None and item.get("type") == "collabAgentToolCall"
              and item.get("tool") == "closeAgent" and item.get("status") == "completed"):
            observed.closed_workers.update(
                worker for worker in item.get("receiverThreadIds") or [] if worker in observed.workers
            )
        return
    turn = params.get("turn") if isinstance(params.get("turn"), Mapping) else {}
    if method == "turn/started" and isinstance(turn.get("id"), str):
        observed.worker_turns.setdefault(thread, {}).setdefault(turn["id"], None)
    elif method == "turn/completed" and isinstance(turn.get("id"), str):
        observed.worker_turns.setdefault(thread, {})[turn["id"]] = str(turn.get("status") or "unknown")
    elif method == "item/completed" and item is not None:
        row = _item_row(params.get("turnId"), item)
        if row is not None:
            observed.items.setdefault(thread, {})[str(row["id"])] = row


def _running_workers(observed: OwnerObservations) -> list[tuple[str, str]]:
    """The turns of the run's own workers that started and have not ended."""

    return [
        (worker, turn) for worker, turns in observed.worker_turns.items()
        if worker in observed.workers
        for turn, status in turns.items() if status is None
    ]


def _interrupt_workers(connection: app_server.AppServerConnection, record: dict[str, Any],
                       observed: OwnerObservations) -> int:
    """Interrupt every worker turn seen to start and not end; how many were sent."""

    sent = 0
    for worker, turn in _running_workers(observed):
        try:
            connection.request("turn/interrupt", {"threadId": worker, "turnId": turn}, timeout=15)
            sent += 1
        except _TRANSPORT_ERRORS:
            pass
    record["cleanup"]["worker_turns_interrupted"] = record["cleanup"].get("worker_turns_interrupted", 0) + sent
    return sent


def _decline_or_record(connection: app_server.AppServerConnection, record: dict[str, Any],
                     observed: OwnerObservations, message: Mapping[str, Any]) -> None:
    if "id" in message and "method" in message:
        connection.respond_error(message["id"], "Orch Dork governed run declines server requests")
        record["server_requests_declined"] += 1
    else:
        _record_notification(message, record, observed)


def observe(
    connection: app_server.AppServerConnection,
    record: dict[str, Any],
    request: Mapping[str, Any],
    turn_text: str,
    *,
    run_dir: Path,
    on_unstarted: Callable[[str], None],
    observed: OwnerObservations,
) -> None:
    """Start one turn and follow it to its end on the starting connection.

    A stop request interrupts the turn and every worker turn it started on
    this connection and gives them a bounded time to end before the watcher
    cleans up anyway; a turn that has not ended by then is recorded as not
    confirmed.  Token usage and the turns and items of the workers the turn
    starts are kept as they arrive.
    """

    thread_id = record["governed_thread_id"]
    client_id = "orch-dork-initial-" + secrets.token_hex(16)
    if observed.controls is not None:
        observed.controls.initial_messages.add(client_id)
    try:
        turn = connection.request("turn/start", {
            "threadId": thread_id,
            "input": [{"type": "text", "text": turn_text}],
            "clientUserMessageId": client_id,
        })
        turn_id = turn["turn"]["id"]
    except (KeyError, TypeError, *_TRANSPORT_ERRORS) as error:
        on_unstarted(thread_id)
        raise WatcherError("governed_run:task_start_failed", str(error)) from error
    record["turn_id"] = turn_id
    if observed.controls is not None:
        observed.controls.progress()
    deadline = time.monotonic() + int(request["turn_seconds"])
    revision_interrupt_sent = False
    while True:
        if observed.controls is not None:
            observed.controls.poll(connection, observed)
            if observed.controls.accepted is not None and not revision_interrupt_sent:
                connection.request("turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=15)
                _interrupt_workers(connection, record, observed)
                revision_interrupt_sent = True
                deadline = min(deadline, time.monotonic() + STOP_GRACE_SECONDS)
        if record["stop"] is None and stop_requested(run_dir):
            record["stop"] = observed_stop(run_dir, "during_turn")
            try:
                connection.request("turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=15)
                record["stop"]["interrupt_sent"] = True
            except _TRANSPORT_ERRORS:
                pass
            _interrupt_workers(connection, record, observed)
            deadline = min(deadline, time.monotonic() + STOP_GRACE_SECONDS)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if record["stop"] is not None:
                record["stop"]["turn_ended"] = False
                return
            record["interruption"] = "governed_run:turn_timeout"
            try:
                connection.request("turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=15)
            except _TRANSPORT_ERRORS:
                pass
            _interrupt_workers(connection, record, observed)
            return
        try:
            message = connection.next_message(min(remaining, POLL_SECONDS))
        except (OSError, ConnectionError, ValueError) as error:
            record["interruption"] = "governed_run:owner_connection_lost"
            raise WatcherError("governed_run:owner_connection_lost", str(error)) from error
        if message is None:
            continue
        _decline_or_record(connection, record, observed, message)
        params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
        value = params.get("turn") if isinstance(params.get("turn"), Mapping) else {}
        if message.get("method") == "turn/completed" and value.get("id") == turn_id:
            record["turn_status"] = value.get("status")
            if record["stop"] is not None:
                record["stop"]["turn_ended"] = True
            return


def settle_workers(connection: app_server.AppServerConnection, record: dict[str, Any],
                   observed: OwnerObservations, *, wait_seconds: float | None = None) -> None:
    """Interrupt any worker still running once its round's governed turn ended.

    Each interrupt gets a bounded time to be confirmed, so no worker goes on
    changing the tree while Orch Dork checks it; a worker whose thread still
    shows a running turn afterwards leaves the run not verified.
    """

    if not _interrupt_workers(connection, record, observed):
        return
    deadline = time.monotonic() + (WORKER_SETTLE_SECONDS if wait_seconds is None else wait_seconds)
    while _running_workers(observed) and time.monotonic() < deadline:
        try:
            message = connection.next_message(max(0.0, min(POLL_SECONDS, deadline - time.monotonic())))
        except (OSError, ConnectionError, ValueError) as error:
            record["interruption"] = record["interruption"] or "governed_run:owner_connection_lost"
            raise WatcherError("governed_run:owner_connection_lost", str(error)) from error
        if message is not None:
            _decline_or_record(connection, record, observed, message)


def _drain(connection: app_server.AppServerConnection, record: dict[str, Any],
           observed: OwnerObservations, *, limit: int = 256) -> None:
    """Keep the usage and worker facts already queued on the owner connection."""

    for _ in range(limit):
        try:
            message = connection.next_message(0.05)
            if message is None:
                return
            _decline_or_record(connection, record, observed, message)
        except (OSError, ConnectionError, ValueError):
            record["interruption"] = record["interruption"] or "governed_run:owner_connection_lost"
            return


def finish_observation(
    connection: app_server.AppServerConnection,
    record: dict[str, Any],
    data_root: Path,
    run_dir: Path,
    *,
    ended_at_ns: int | None,
    earlier_turns: Sequence[str] = (),
    after_ns: int | None = None,
) -> None:
    """Read the owner rail and the hooks' records once the binding has ended."""

    thread = connection.request("thread/read", {
        "threadId": record["governed_thread_id"], "includeTurns": True,
    })
    items = owner_items((thread or {}).get("thread") or {})
    suffix = "" if record["revision"] == 1 else "-revision-" + str(record["revision"])
    write_json(run_dir / ("owner-items" + suffix + ".json"), items)
    try:
        events = policy.read_events(data_root, record["run_id"])
    except (OSError, ValueError) as error:
        raise WatcherError("governed_run:hook_records_unavailable", str(error)) from error
    write_json(run_dir / "hook-events.json", events)
    if earlier_turns:
        items = [item for item in items if item.get("turn_id") not in earlier_turns]
        events = [event for event in events if (
            event.get("hook_event_name") == "SessionStart" and event.get("agent_id") is None
        ) or (event.get("turn_id") not in earlier_turns
              and (after_ns is None or int(event.get("observed_at_ns") or 0) > after_ns))]
    record["cross_check"] = cross_check(items, events, turn_id=record["turn_id"], ended_at_ns=ended_at_ns)


def _joined_native_closes(
    root_items: Sequence[Mapping[str, Any]], events: Sequence[Mapping[str, Any]],
    owned_workers: set[str],
) -> set[str]:
    """Native closes whose owner item and successful hook return agree.

    Codex's close item reports the worker's previous status. Closing an
    already archived, known worker can therefore have status failed (not
    found) while the handler succeeds and releases the parent's spawn slot.
    A PostToolUse record proves that successful return; a failed item alone
    does not. Neither an unknown target nor an unmatched hook proves a close.
    """
    closed = set()
    for item in root_items:
        receivers = item.get("receivers")
        if (item.get("type") != "collabAgentToolCall" or item.get("tool") != "closeAgent"
                or item.get("status") not in {"completed", "failed"}
                or not isinstance(receivers, list) or len(receivers) != 1
                or receivers[0] not in owned_workers):
            continue
        matching = [row for row in events
                    if row.get("agent_id") is None and row.get("turn_id") == item.get("turn_id")
                    and row.get("tool_use_id") == item.get("id")
                    and policy.canonical_tool_name(row.get("tool_name")) == "close_agent"]
        pre = [row for row in matching if row.get("hook_event_name") == "PreToolUse"]
        post = [row for row in matching if row.get("hook_event_name") == "PostToolUse"]
        if (len(pre) == len(post) == 1 and pre[0].get("decision") == "ALLOW"
                and post[0].get("decision") == "OBSERVED" and not post[0].get("reasons")
                and pre[0].get("tool_input_sha256") == post[0].get("tool_input_sha256")
                == policy.sha256({"target": receivers[0]})):
            closed.add(receivers[0])
    return closed


def finish_lane_round(
    connection: app_server.AppServerConnection,
    record: dict[str, Any],
    data_root: Path,
    run_dir: Path,
    *,
    binding: Mapping[str, Any],
    observed: OwnerObservations,
    after_ns: int | None,
    until_ns: int | None,
    earlier_turns: Sequence[str],
    earlier_workers: Sequence[str],
) -> list[dict[str, Any]]:
    """Read the root's and each bound worker's thread once a lane round's
    binding ended, join them to that round's hook records, and return the
    round's workers with the status of each one's last turn and whether the
    governed task closed it in this round.

    A worker whose thread cannot be read is joined through the items its
    turns reported on the owner connection; a worker still running leaves
    the run not verified.
    """

    thread = connection.request("thread/read", {
        "threadId": record["governed_thread_id"], "includeTurns": True,
    })
    root_items = owner_items((thread or {}).get("thread") or {})
    closed = {
        receiver for item in root_items
        if item.get("turn_id") == record["turn_id"] and item.get("type") == "collabAgentToolCall"
        and item.get("tool") == "closeAgent" and item.get("status") == "completed"
        for receiver in item.get("receivers") or []
    }
    try:
        grant_state = policy.read_grant_state(data_root, record["run_id"])
        events = policy.read_events(data_root, record["run_id"])
    except (OSError, ValueError) as error:
        raise WatcherError("governed_run:hook_records_unavailable", str(error)) from error
    joined_closed = _joined_native_closes(root_items, events,
                                          policy.round_workers(binding, grant_state) | set(earlier_workers))
    observed.closed_workers.update(joined_closed)
    closed.update(joined_closed)
    facts: dict[str, dict[str, Any]] = {}
    workers = []
    for grant in binding["grants"]:
        agent = ((grant_state.get(grant["grant_id"]) or {}).get("outcome") or {}).get("agent_id")
        if not isinstance(agent, str) or agent in facts:
            continue
        try:
            read = connection.request("thread/read", {"threadId": agent, "includeTurns": True})
            value = (read or {}).get("thread") or {}
            facts[agent] = {"source": "thread_read", "turns": thread_turns(value), "items": owner_items(value)}
        except _TRANSPORT_ERRORS:
            reported = observed.items.get(agent)
            facts[agent] = {
                "source": "notifications",
                "turns": [{"id": turn, "status": status}
                          for turn, status in (observed.worker_turns.get(agent) or {}).items()],
                "items": list(reported.values()) if reported else None,
            }
        turns = facts[agent]["turns"]
        status = turns[-1]["status"] if turns else None
        if status in (None, "inProgress"):
            record["interruption"] = record["interruption"] or "governed_run:worker_not_stopped"
        spawns = [item for item in root_items
                  if item.get("turn_id") == record["turn_id"] and item.get("tool") == "spawnAgent"
                  and item.get("receivers") == [agent] and item.get("status") == "completed"]
        model = spawns[0].get("model") if len(spawns) == 1 else None
        workers.append({"grant_id": grant["grant_id"], "thread_id": agent, "status": status,
                        "closed": agent in closed,
                        "observed_model": model if isinstance(model, str) and model else None})
    revision = policy.binding_revision(binding)
    suffix = ("" if revision == 1 else "-revision-" + str(revision))
    suffix += "" if binding["round"] == 1 else "-round-" + str(binding["round"])
    write_json(run_dir / ("owner-items" + suffix + ".json"), {"root": root_items, "workers": facts})
    write_json(run_dir / "hook-events.json", events)
    write_json(run_dir / "grant-state.json", grant_state)
    record["cross_check"] = lane_cross_check(
        root_items, facts, events, turn_id=record["turn_id"], round_number=binding["round"],
        grants=binding["grants"], grant_state=grant_state, earlier_turns=earlier_turns,
        continuations=binding.get("continuations", []),
        earlier_workers=earlier_workers, after_ns=after_ns, until_ns=until_ns,
    )
    return workers


# ---------------------------------------------------------------- status and entry


def read_status(run_id: str, records: Path | None = None) -> dict[str, Any]:
    run_dir = run_directory(records or records_root(), run_id)
    record_path = run_dir / "record.json"
    if record_path.is_file():
        record = read_json(record_path)
        if seal_valid(record, "record_sha256"):
            return {"state": "TERMINAL", "record": record}
        return {"state": "UNREADABLE", "record_path": str(record_path)}
    status_path = run_dir / "status.json"
    if status_path.is_file():
        status = read_json(status_path)
        progress_path = run_dir / "progress.json"
        progress = read_json(progress_path) if progress_path.is_file() else None
        if progress is not None and (not seal_valid(progress, "progress_sha256")
                                     or progress.get("run_id") != run_id):
            return {"state": "UNREADABLE", "record_path": str(progress_path)}
        return {"state": status.get("state"), "status": status, "progress": progress}
    return {"state": "UNKNOWN", "run_id": run_id}


def spawn_watcher(
    request: Mapping[str, Any], *, records: Path | None = None, codex_executable: str | None = None,
    onboarding_root: Any = None,
) -> dict[str, Any]:
    """Start one detached watcher for a validated request.

    A short-lived trampoline starts the watcher in its own session and exits,
    so the watcher outlives the caller and leaves it no child to reap.  The
    Codex the caller runs under is handed down, because the detached watcher
    no longer has that app server as its parent, and so is the onboarding
    store the run was admitted against.
    """

    request = validate_request(request)
    records = records or records_root()
    run_dir = run_directory(records, request["run_id"])
    _private_directory(run_dir)
    request_path = run_dir / "request.pending.json"
    write_json(request_path, request, create_only=True)
    environment = dict(os.environ)
    environment[RECORDS_ENV] = str(records)
    environment[CODEX_ENV] = codex_executable or resolve_codex_executable()
    if onboarding_root is not None:
        environment[onboarded.STORE_ENV] = str(onboarded.store_root(onboarding_root))
    trampoline = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve()), "detach", "--request", str(request_path)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False,
        cwd=str(run_dir), env=environment,
    )
    if trampoline.returncode != 0:
        raise WatcherError("governed_run:watcher_start_failed",
                           (trampoline.stderr or trampoline.stdout)[-400:])
    return {"run_id": request["run_id"], "run_dir": str(run_dir)}


def _detach(request_path: Path) -> int:
    run_dir = request_path.parent
    log = open(run_dir / "watcher.log", "ab")
    try:
        subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__).resolve()), "run", "--request", str(request_path)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True,
            close_fds=True, cwd=str(run_dir),
        )
    finally:
        log.close()
    return 0


def verdict_summary(record: Mapping[str, Any]) -> dict[str, Any]:
    """What the requesting task receives once a run has ended."""

    verdict = record["verdict"]
    repair = record.get("repair")
    return {
        "verdict": verdict["label"],
        "reason": verdict["reason"],
        "message": verdict.get("message"),
        "advisory_offer": verdict.get("advisory_offer"),
        "steered_by_you": verdict["steered_by_you"],
        "checks": [
            {
                "id": row.get("id"),
                "scope": row.get("scope"),
                "passed": row.get("passed"),
                "exit_code": row.get("exit_code"),
                "timed_out": row.get("timed_out"),
            }
            for row in record.get("checks") or []
        ],
        "lanes": [
            {key: lane.get(key) for key in ("id", "worker_status", "checks_passed", "overclaim",
                                            "checks_passed_after_repair")}
            for lane in record.get("lanes") or []
        ],
        "repair": None if not repair else {
            "failed_checks": repair.get("failed_checks"), "worker_status": repair.get("worker_status"),
        },
        "rounds": len(record.get("rounds") or []),
        "steers": record.get("steers", []), "revision": record.get("revision", 1),
        "control_results": record.get("control_results", []),
        "revisions": record.get("revisions", []), "revision_offer": record.get("revision_offer"),
        "cross_check": (record.get("cross_check") or {}).get("status"),
        "governed_thread_id": record.get("governed_thread_id"),
        "record_path": record.get("record_path"),
        "enforcement_scope": ENFORCEMENT_SCOPE,
        "cost": record.get("cost") or {"billing": "unknown"},
    }


def _report(schema: str, **values: Any) -> dict[str, Any]:
    return sealed({"schema": schema, **values, "provider_free_entry": True}, "report_sha256")


def start_from_task(
    arguments: Mapping[str, Any],
    *,
    requesting_thread_id: str | None,
    records: Path | None = None,
    onboarding_root: Any = None,
    wait_seconds: float = START_WAIT_SECONDS,
    spawn: Callable[..., Mapping[str, Any]] = spawn_watcher,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The requesting task's entry: admit the frozen plan, then start or ask.

    Within the project's standing authority the watcher starts at once and
    the report carries the notice and the plan diagram; a plan beyond any
    limit is not started and the report names each limit and the plan digest
    the user approves; below two onboarded models it is refused with the
    profiles' reasons.  Approving a plan is passing its digest back.  A run
    with lanes names its workers' model, and their effort unless it is the
    governed task's; a repository with a live run or a machine whose runs
    hold the workers the plan needs is refused before anything is claimed.
    """

    records = records or records_root()
    try:
        import orch_dork_project_improvements as project_improvements
        if "intake_sha256" not in arguments:
            arguments, _ = project_improvements.apply_defaults(arguments, records=records)
        budget = arguments.get("cost_budget_usd")
        lanes_requested = arguments.get("lanes") or ()
        request = build_request(
            project_root=str(arguments.get("project_root")),
            goal=arguments.get("goal"),
            model=arguments.get("model"),
            effort=arguments.get("effort"),
            requesting_thread_id=requesting_thread_id,
            cost_budget_cents=None if budget is None else admission.cents(budget, field="cost_budget_usd"),
            lanes=lanes_requested,
            worker_model=arguments.get("worker_model"),
            worker_effort=arguments.get("worker_effort") or (arguments.get("effort") if lanes_requested else None),
        )
        approval = arguments.get("approve_plan_sha256")
        if approval is not None and (not isinstance(approval, str) or not re.fullmatch(r"[0-9a-f]{64}", approval)):
            raise WatcherError("governed_run:request_invalid", "approve_plan_sha256")
        enrollment, plan, decision = admit_request(
            request, records=records, onboarding_root=onboarding_root,
            approved_plan_sha256=approval, now=now,
        )
        lanes = resolve_lanes(request, enrollment) if request["lanes"] else []
        intake = work_intake.bind(arguments, request, enrollment, records=records)
        diagram = admission.plan_diagram(plan, enrollment["checks"], lanes)
        if decision["decision"] == "REFUSED":
            return _report(
                START_SCHEMA, status="REFUSED", run_id=None, reason="governed_run:onboarding_required",
                message=admission.refusal_text(decision), refusals=decision["refusals"], started=False,
                plan_sha256=plan["plan_sha256"], advisory_offer=advisory_offer("governed_run:onboarding_required"),
            )
        if decision["decision"] == "ASK":
            write_ask(records, request, decision, plan=plan)
            return _report(
                START_SCHEMA, status="APPROVAL_REQUIRED", run_id=None, started=False,
                plan_sha256=plan["plan_sha256"], exceeded=decision["exceeded"],
                question=admission.ask_text(decision), diagram=diagram,
            )
        reserve_start(records, request, plan, decision, now=now)
        try:
            project_improvements.bind_canary_run(arguments, request, plan, records=records)
        except (ValueError, OSError, KeyError, TypeError, WatcherError):
            run_dir = run_directory(records, request["run_id"])
            with machine_lock(records):
                os.rename(claim_path(run_dir), run_dir / "refused-admission.json")
                if decision.get("approved"):
                    _return_question(records, request, plan["plan_sha256"], run_dir)
            raise
        if intake is not None:
            write_json(run_directory(records, request["run_id"]) / "intake.json", intake, create_only=True)
        spawn(request, records=records, onboarding_root=onboarding_root)
    except admission.AdmissionError as error:
        return _report(
            START_SCHEMA, status="REFUSED", run_id=None, reason="governed_run:request_invalid",
            message=message_for("governed_run:request_invalid") + " (" + str(error) + ")", started=False,
        )
    except WatcherError as error:
        return _report(
            START_SCHEMA, status="REFUSED", run_id=None, reason=error.reason,
            message=message_for(error.reason) or error.reason, started=False,
        )
    except (ValueError, OSError, KeyError, TypeError) as error:
        return _report(START_SCHEMA, status="REFUSED", run_id=None, reason="governed_run:request_invalid",
                       message=str(error), started=False)
    run_id = request["run_id"]
    deadline = time.monotonic() + max(0.0, wait_seconds)
    state: Mapping[str, Any] = {"state": "STARTING"}
    while True:
        state = read_status(run_id, records)
        if state.get("state") == "TERMINAL":
            return _report(START_SCHEMA, status="TERMINAL", run_id=run_id, started=True,
                           diagram=diagram, **verdict_summary(state["record"]))
        if state.get("state") in {"RUNNING", "CHECKING"} or time.monotonic() >= deadline:
            break
        time.sleep(0.25)
    status = state.get("status") if isinstance(state.get("status"), Mapping) else {}
    return _report(
        START_SCHEMA,
        status="STARTED",
        run_id=run_id,
        started=True,
        state=state.get("state"),
        governed_thread_id=status.get("governed_thread_id"),
        plan_sha256=plan["plan_sha256"],
        diagram=diagram,
        notice=(
            "Governed run " + run_id + " is running in its own task, \"Orch Dork "
            "governed run " + run_id + "\", with "
            + (str(len(lanes)) + " lane workers. When they finish, Orch Dork runs each lane's "
               "checks and then the project's checks on the joined result itself, with one repair "
               "round if a check fails" if lanes else
               "zero workers. Orch Dork will run the project's checks itself when the task stops")
            + "; call read_governed_run for the verdict, or stop_governed_run to stop it. "
            + admission.start_text(decision, enrollment["standing_authority"])
        ),
    )


def read_from_task(
    arguments: Mapping[str, Any],
    *,
    records: Path | None = None,
) -> dict[str, Any]:
    """Wait a bounded time for a run to end; return its status or verdict."""

    records = records or records_root()
    run_id = arguments.get("run_id")
    wait = arguments.get("wait_seconds", DEFAULT_READ_WAIT_SECONDS)
    if (
        not isinstance(run_id, str)
        or not _RUN_ID.fullmatch(run_id)
        or type(wait) is not int
        or not 0 <= wait <= MAX_READ_WAIT_SECONDS
    ):
        return _report(READ_SCHEMA, status="REFUSED", run_id=None, reason="governed_run:request_invalid")
    deadline = time.monotonic() + wait
    while True:
        state = read_status(run_id, records)
        if state.get("state") == "TERMINAL":
            return _report(READ_SCHEMA, status="TERMINAL", run_id=run_id,
                           **verdict_summary(state["record"]))
        if time.monotonic() >= deadline:
            status = state.get("status") if isinstance(state.get("status"), Mapping) else {}
            return _report(READ_SCHEMA, status=str(state.get("state")), run_id=run_id,
                           governed_thread_id=status.get("governed_thread_id"), progress=state.get("progress"))
        time.sleep(0.5)


def _control_from_task(
    arguments: Mapping[str, Any], *, kind: str, requesting_thread_id: str | None,
    requesting_turn_id: str | None, records: Path | None, wait_seconds: float,
) -> dict[str, Any]:
    schema = STEER_REPORT_SCHEMA if kind == "steer" else REVISION_REPORT_SCHEMA
    records = records or records_root()
    run_id = arguments.get("run_id")
    try:
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise WatcherError("governed_run:request_invalid", "run_id")
        allowed = {"run_id", "text"} if kind == "steer" else {
            "run_id", "offer_sha256", "accept", "goal", "lanes", "approve_plan_sha256",
        }
        if set(arguments) - allowed:
            raise WatcherError("governed_run:request_invalid", "unknown control fields")
        run_dir = run_directory(records, run_id)
        state = read_status(run_id, records)
        if state.get("state") not in {"RUNNING", "CHECKING", "AWAITING_REVISION"}:
            raise WatcherError("governed_run:control_not_running")
        original = read_json(run_dir / "request.json")
        root_id = (state.get("status") or {}).get("governed_thread_id")
        if not requesting_thread_id or requesting_thread_id not in {original["requesting_thread_id"], root_id}:
            raise WatcherError("governed_run:control_source_mismatch")
        fields = {"text": arguments.get("text")} if kind == "steer" else {
            "offer_sha256": arguments.get("offer_sha256"), "accept": arguments.get("accept"),
            "goal": arguments.get("goal"), "lanes": arguments.get("lanes", []) if arguments.get("accept") is True else None,
            "approve_plan_sha256": arguments.get("approve_plan_sha256"),
        }
        request = controls.write_request(run_dir, run_id=run_id, kind=kind,
                                         source_thread_id=requesting_thread_id,
                                         source_turn_id=requesting_turn_id, **fields)
        deadline = time.monotonic() + max(0.0, min(5.0, wait_seconds))
        while True:
            result = controls.result(run_dir, request["control_id"])
            if result is not None:
                return _report(schema, run_id=run_id, control_id=request["control_id"],
                               status=result["status"], result=result)
            if time.monotonic() >= deadline:
                return _report(schema, run_id=run_id, control_id=request["control_id"], status="QUEUED",
                               notice="The watcher will record this control; read_governed_run shows its result.")
            time.sleep(0.05)
    except (WatcherError, OSError, ValueError, KeyError, TypeError) as error:
        return _report(schema, status="REFUSED", run_id=run_id,
                       reason=error.reason if isinstance(error, WatcherError) else "governed_run:request_invalid")


def steer_from_task(
    arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
    requesting_turn_id: str | None = None, records: Path | None = None, wait_seconds: float = 2.0,
) -> dict[str, Any]:
    """Queue one exact steer from this run's requesting or governed task."""
    return _control_from_task(arguments, kind="steer", requesting_thread_id=requesting_thread_id,
                              requesting_turn_id=requesting_turn_id, records=records, wait_seconds=wait_seconds)


def revise_from_task(
    arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
    requesting_turn_id: str | None = None, records: Path | None = None, wait_seconds: float = 2.0,
) -> dict[str, Any]:
    """Answer a specific revision offer; acceptance still requires admission."""
    return _control_from_task(arguments, kind="revision", requesting_thread_id=requesting_thread_id,
                              requesting_turn_id=requesting_turn_id, records=records, wait_seconds=wait_seconds)


def stop_from_task(
    arguments: Mapping[str, Any],
    *,
    requesting_thread_id: str | None,
    records: Path | None = None,
    wait_seconds: float = STOP_WAIT_SECONDS,
) -> dict[str, Any]:
    """Ask the watcher to stop a run; report its verdict once it has one."""

    records = records or records_root()
    run_id = arguments.get("run_id")
    try:
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise WatcherError("governed_run:request_invalid", "run_id")
        state = read_status(run_id, records)
        if state.get("state") == "TERMINAL":
            return _report(STOP_REPORT_SCHEMA, status="TERMINAL", run_id=run_id, stop_requested=False,
                           **verdict_summary(state["record"]))
        request_stop(records, run_id, requesting_thread_id)
    except WatcherError as error:
        return _report(STOP_REPORT_SCHEMA, status="REFUSED", run_id=None, reason=error.reason,
                       message=message_for(error.reason) or error.reason, stop_requested=False)
    deadline = time.monotonic() + max(0.0, wait_seconds)
    while True:
        state = read_status(run_id, records)
        if state.get("state") == "TERMINAL":
            return _report(STOP_REPORT_SCHEMA, status="TERMINAL", run_id=run_id, stop_requested=True,
                           **verdict_summary(state["record"]))
        if time.monotonic() >= deadline:
            return _report(STOP_REPORT_SCHEMA, status="STOP_REQUESTED", run_id=run_id, stop_requested=True,
                           notice="Orch Dork asked the governed task to stop; call read_governed_run "
                           "for the Stopped by you verdict.")
        time.sleep(0.25)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Orch Dork governed-run watcher (Issues 193 and 194).")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run one governed task to its verdict")
    run.add_argument("--request", required=True)
    admit = commands.add_parser("admit", help="admit a request against the project's standing authority")
    admit.add_argument("--request", required=True)
    admit.add_argument("--approve", help="the plan digest the user approved")
    detach = commands.add_parser("detach", help="start the run in its own session and return")
    detach.add_argument("--request", required=True)
    status = commands.add_parser("status", help="read one run's status or record")
    status.add_argument("--run-id", required=True)
    stop = commands.add_parser("stop", help="ask the watcher to stop a run")
    stop.add_argument("--run-id", required=True)
    commands.add_parser("active", help="list governed runs whose watcher is alive")
    args = parser.parse_args(argv)
    if args.command == "run":
        request = json.loads(Path(args.request).read_text(encoding="utf-8"))
        record = run_governed_task(request)
        print(json.dumps({"run_id": record["run_id"], "verdict": record["verdict"],
                          "record_path": record["record_path"]}, ensure_ascii=False))
        return 0
    if args.command == "admit":
        request = validate_request(json.loads(Path(args.request).read_text(encoding="utf-8")))
        records = records_root()
        _enrollment, plan, decision = admit_request(request, records=records, approved_plan_sha256=args.approve)
        if decision["decision"] == "START":
            reserve_start(records, request, plan, decision)
        print(json.dumps(decision, ensure_ascii=False))
        return 0 if decision["decision"] == "START" else 1
    if args.command == "detach":
        return _detach(Path(args.request))
    if args.command == "status":
        print(json.dumps(read_status(args.run_id), ensure_ascii=False))
        return 0
    if args.command == "stop":
        print(json.dumps(stop_from_task({"run_id": args.run_id}, requesting_thread_id=None), ensure_ascii=False))
        return 0
    print(json.dumps({"active": active_runs()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
