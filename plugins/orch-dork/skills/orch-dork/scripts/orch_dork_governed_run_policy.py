#!/usr/bin/env python3
"""Hook policy for one watcher-started governed task and its lane workers.

Issue 193 (ADR 0011, FR69, Owner decision D2 of 2026-10-03).  The governed-run
watcher binds a governed task's thread id before the task's first turn by
writing one sealed binding under the plugin data root.  For that task alone
the plugin hooks apply this policy; every task no binding names passes
through unchanged.

A zero-worker run's task may call only a closed set of tools: its shell,
apply_patch and view_image, whose calls the owner rail shows as items the
watcher joins by tool-use id, and a few quiet tools that show none.  Every
other call is refused: no worker may be spawned, messaged or act, no MCP tool
may run (one could start another governed run or agent), and the hook refuses
the paths it can see but cannot govern (input to an already running process,
background children) and any call that names Orch Dork's own records.

A run with lanes (Issue 195, Owner decision 2026-10-03) binds its native
actions here rather than through the governed native controller, which stays
the qualification path.  The binding carries one spawn permission per lane
of the current round, compiled from the admitted plan: the exact message,
model and effort of that lane's worker.  A spawn is allowed only when it
matches a permission no earlier spawn claimed, and the claim is written
create-only before the call runs, so a permission is used at most once; the
spawn's result binds the worker's thread id, and a worker no result bound yet
is refused.  Waits and closes may name only those workers, and a repair
round may also close a worker the first round left open; every other message
to a worker is refused, the task's own shell and apply_patch calls are
refused, and each worker may call only the zero-worker task's closed set of
tools and never a collaboration or MCP tool.

A steer (Issue 196) reaches a running worker the same way.  The binding
carries one continue permission per steer, each naming the worker it may
reach, the exact message, the turn that may send it and whether it interrupts.
A send_input call is allowed only when it matches a permission no earlier call
claimed and names a worker this round's spawn result bound, and its claim is
written create-only before the call runs, so a steer is delivered at most
once; its result binds that worker and the submission the call returned.  A
permission names a worker rather than a turn of its life, so a completed
close call marks its worker closed in the same store and every later steer of
that worker is refused: an event keeps a call's digest, not its target, so the
marker is the only record that can answer this afterwards.  A
revision, 1 to 3, names the plan a binding's spawn permissions came from, so
a revised plan's permissions cannot be claimed under the plan it replaced.

A lane may own paths (Issue 247, Owner decision 2026-10-15).  The v4 binding
carries each lane permission's paths for the first round, and the repair
round owns none.  A worker is refused a write to a path another lane owns: an
apply_patch file header, resolved against the call's folder and any linked
folders, or, on a best-effort basis, a shell command part that names the path
and writes it in a recognized form.  Reading another lane's files is allowed,
and a path no lane owns stays writable by every worker.

Every decision is written create-only for the watcher's owner-connection
cross-check.  A missing, malformed, ended or foreign binding, a hook
generation that changed under the run, or a record that cannot be written
fails closed.  Stop is never blocked: the model's stop claims nothing,
because the watcher is the run's external completion controller and computes
the verdict from the checks it runs itself.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import tempfile
import time
from typing import Any, Mapping


BINDING_SCHEMA = "orch-dork/governed-run-binding/v4"
V3_BINDING_SCHEMA = "orch-dork/governed-run-binding/v3"
LEGACY_BINDING_SCHEMA = "orch-dork/governed-run-binding/v2"
EVENT_SCHEMA = "orch-dork/governed-run-hook-event/v1"
GRANT_CLAIM_SCHEMA = "orch-dork/governed-run-grant-claim/v1"
GRANT_OUTCOME_SCHEMA = "orch-dork/governed-run-grant-outcome/v1"
GRANT_CLOSE_SCHEMA = "orch-dork/governed-run-grant-close/v1"
BINDING_STATUSES = frozenset({"ACTIVE", "TERMINAL"})
LEGACY_BINDING_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "thread_id",
        "project_root",
        "workers",
        "round",
        "grants",
        "status",
        "summary_sha256",
        "hook_definition_sha256",
        "protected_paths",
        "bound_at",
        "binding_sha256",
    }
)
V3_BINDING_FIELDS = LEGACY_BINDING_FIELDS | {"revision", "continuations"}
BINDING_FIELDS = V3_BINDING_FIELDS | {"lane_writes"}
# Each schema's exact fields; v3 and v2 bindings read as owning no paths.
_BINDING_SHAPES = {
    BINDING_SCHEMA: BINDING_FIELDS, V3_BINDING_SCHEMA: V3_BINDING_FIELDS,
    LEGACY_BINDING_SCHEMA: LEGACY_BINDING_FIELDS,
}
GRANT_FIELDS = frozenset({"grant_id", "message_sha256", "model", "reasoning_effort"})
CONTINUATION_FIELDS = frozenset(
    {"grant_id", "target", "message_sha256", "turn_id", "interrupt"}
)
CLAIM_FIELDS = frozenset(
    {
        "schema", "run_id", "grant_id", "round", "tool_use_id", "turn_id",
        "tool_input_sha256", "claimed_at_ns", "record_sha256",
    }
)
OUTCOME_FIELDS = frozenset(
    {
        "schema", "run_id", "grant_id", "tool_use_id", "agent_id", "result_sha256",
        "observed_at_ns", "record_sha256",
    }
)
CLOSE_FIELDS = frozenset(
    {
        "schema", "run_id", "grant_id", "agent_id", "tool_use_id", "result_sha256",
        "observed_at_ns", "record_sha256",
    }
)
MAX_WORKERS = 8
MAX_REVISION = 3
MAX_CONTINUATIONS = 128
MAX_LANE_WRITES = 128
MAX_WRITE_PATH = 4096
REPAIR_GRANT = "repair"
EVENT_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "session_id",
        "turn_id",
        "hook_event_name",
        "source",
        "tool_name",
        "tool_use_id",
        "agent_id",
        "decision",
        "reasons",
        "tool_input_sha256",
        "observed_at_ns",
        "record_sha256",
    }
)
DECISIONS = frozenset(
    {"HEALTHY", "READ_ONLY", "ALLOW", "DENY", "OBSERVED", "STOP_ALLOWED"}
)
MAX_BINDING_BYTES = 65_536
MAX_EVENT_BYTES = 65_536
_RUN_ID = re.compile(r"\A[a-z0-9][a-z0-9-]{7,63}\Z")
_THREAD_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_BASE_GRANT_ID = re.compile(r"\A(?:lane:[a-z][a-z0-9-]{0,31}|repair)\Z")
_GRANT_ID = re.compile(r"\A(?:r[23]:)?(?:lane:[a-z][a-z0-9-]{0,31}|repair)\Z")
_CONTINUATION_ID = re.compile(r"\Acontinue:[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_LANE_GRANT_ID = re.compile(r"\A(?:r[23]:)?lane:[a-z][a-z0-9-]{0,31}\Z")
_SPAWN_FIELDS = frozenset({"message", "model", "reasoning_effort", "fork_context"})
_CONTINUE_FIELDS = frozenset({"target", "message", "interrupt"})
# Every spelling Codex 0.160.0 gives a collaboration tool in a hook payload
# (racetrack/codex-facts/hooks-0.160.0.json): spawn_agent and
# multi_agent_v1send_input on V1, collaborationspawn_agent on V2, and the
# direct multi_agent_v1__ namespace.
_COLLABORATION_PREFIXES = (
    "multi_agent_v1__",
    "multi_agent_v2__",
    "collaboration__",
    "multi_agent_v1",
    "multi_agent_v2",
    "collaboration",
)
COLLABORATION_TOOLS = frozenset(
    {
        "spawn_agent",
        "send_input",
        "send_message",
        "wait_agent",
        "close_agent",
        "resume_agent",
        "followup_task",
        "list_agents",
        "interrupt_agent",
        "assign_task",
    }
)
# The tools a zero-worker governed task may call, by the owner-rail item each
# call shows on Codex 0.160.0 (racetrack/codex-facts/governed-task-0.160.0.json:
# a shell call is reported as Bash and shows a commandExecution item, an
# apply_patch call a fileChange item, each with the hook's tool_use_id).
ITEM_TOOLS = {
    "bash": "commandExecution",
    "exec_command": "commandExecution",
    "shell": "commandExecution",
    "apply_patch": "fileChange",
    "view_image": "imageView",
}
# Tools that show no item of their own; write_stdin only as an empty poll.
QUIET_TOOLS = frozenset(
    {"write_stdin", "clock__curr_time", "get_goal", "create_goal", "update_goal"}
)
_BACKGROUND = re.compile(r"(?:^|[\s;|])(?:&(?!&)|nohup|setsid|disown)(?:\s|$)")
# Issue 247: how a call writes a path.  apply_patch names each file it adds,
# updates, deletes or moves to; a shell command is read best-effort.
_PATCH_TARGET = re.compile(r"^\*\*\* (?:Add File|Update File|Delete File|Move to):[ \t]*(.*?)[ \t]*$", re.M)
SHELL_TOOLS = frozenset({"bash", "exec_command", "shell"})
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
_COMMAND_WRAPPERS = frozenset({"sudo", "env", "command", "builtin", "exec", "nohup", "setsid", "time", "nice", "xargs"})
# Wrapper flags that consume a value, including attached short/long values.
_WRAPPER_VALUES = {
    "sudo": {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from",
             "-T", "--command-timeout", "-R", "--chroot", "-D", "--chdir", "-r", "--role", "-t", "--type"},
    "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string", "--argv0"},
    "nice": {"-n", "--adjustment"},
    "exec": {"-a"},
    "time": {"-f", "--format", "-o", "--output"},
    "xargs": {"-a", "--arg-file", "-d", "--delimiter", "-E", "-I", "-L", "--max-lines", "-n", "--max-args",
              "-P", "--max-procs", "-s", "--max-chars", "--process-slot-var"},
}


def _unwrap_command(words: list[str]) -> tuple[list[str], list[str]]:
    """Return the command and wrapper output paths; consume flag values exactly."""

    outputs: list[str] = []
    while words:
        if _ASSIGNMENT.fullmatch(words[0]):
            words = words[1:]
            continue
        wrapper = os.path.basename(words[0])
        if wrapper not in _COMMAND_WRAPPERS:
            break
        values = _WRAPPER_VALUES.get(wrapper, set())
        index = 1
        while index < len(words) and words[index].startswith("-"):
            option = words[index]
            index += 1
            if option == "--":
                break
            if wrapper == "command" and option in {"-v", "-V"}:
                return [], outputs
            value = None
            flag = option.split("=", 1)[0]
            if option in values and index < len(words):
                value = words[index]
                index += 1
            elif option.startswith("--") and "=" in option:
                value = option.split("=", 1)[1]
            elif not option.startswith("--"):
                for offset, short in enumerate(option[1:], 2):
                    if "-" + short in values:
                        flag = "-" + short
                        value = option[offset:]
                        if not value and index < len(words):
                            value = words[index]
                            index += 1
                        break
            if wrapper == "time" and flag in {"-o", "--output"} and value:
                outputs.append(value)
            if wrapper == "env" and flag in {"-S", "--split-string"} and value:
                try:
                    words = words[:index] + shlex.split(value) + words[index:]
                except ValueError:
                    return [], outputs
                break
        words = words[index:]
    return words, outputs


# Commands that write the paths they name; a copier writes only its target.
_SHELL_WRITERS = frozenset(
    {"tee", "mv", "rm", "rmdir", "touch", "truncate", "dd", "mkdir", "chmod", "chown", "patch", "unlink", "shred"}
)
_SHELL_COPIERS = frozenset({"cp", "install", "rsync", "ln", "scp"})
_IN_PLACE = re.compile(r"-[A-Za-z]*i.*|--in-place(?:=.*)?")
_GIT_WRITERS = frozenset(
    {"checkout", "restore", "rm", "mv", "apply", "am", "stash", "reset", "clean", "switch", "merge", "pull",
     "revert", "cherry-pick"}
)
# Git's options that take the next word as their value, before the subcommand.
_GIT_VALUED_OPTIONS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})
_INTERPRETER = re.compile(r"python[0-9.]*|node|nodejs|perl|ruby|bash|sh|zsh|dash|deno|bun")
_INLINE_SCRIPT = re.compile(r"-[A-Za-z]{0,3}[ce]")
# A short reason a refused worker can act on, after the reason's code.
REASON_HINTS = {
    "governed_run:path_owned_by_other_lane": (
        "another lane owns a path this call writes; change only your own lane's paths, and read the rest"
    ),
}
STOP_MESSAGE = (
    "Orch Dork now runs the enrolled project's checks itself; the verdict "
    "comes from their observed results, not from this task's report."
)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def session_key(session_id: Any) -> str:
    return hashlib.sha256(str(session_id or "missing").encode("utf-8")).hexdigest()


def bindings_root(data_root: Path) -> Path:
    return Path(data_root) / "governed-runs" / "bindings"


def binding_path(data_root: Path, session_id: Any) -> Path:
    return bindings_root(data_root) / (session_key(session_id) + ".json")


def events_root(data_root: Path, run_id: str) -> Path:
    return Path(data_root) / "governed-runs" / "events" / run_id


def grants_root(data_root: Path, run_id: str) -> Path:
    return Path(data_root) / "governed-runs" / "grants" / run_id


def _grant_path(data_root: Path, run_id: str, grant_id: str, kind: str) -> Path:
    return grants_root(data_root, run_id) / (grant_id.replace(":", "-") + "." + kind + ".json")


def close_key(agent_id: Any) -> str:
    """The permission-store key one worker's close marker uses.

    A worker's thread id is as long as a thread id may be, so the marker is
    named for its digest and keeps the id itself in the record.
    """

    return "closed:" + hashlib.sha256(str(agent_id).encode("utf-8")).hexdigest()


def message_digest(message: Any) -> str | None:
    """The digest a spawn permission binds: the message's words.

    Each run of whitespace reads as one space, so a copy of the planned
    message that wraps its lines differently still matches it.
    """

    if not isinstance(message, str):
        return None
    return hashlib.sha256(" ".join(message.split()).encode("utf-8")).hexdigest()


def spawn_grant(grant_id: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """One spawn permission from the spawn_agent arguments the plan gives a worker."""

    return {
        "grant_id": grant_id,
        "message_sha256": message_digest(arguments.get("message")),
        "model": arguments.get("model"),
        "reasoning_effort": arguments.get("reasoning_effort"),
    }


def continuation_grant(
    grant_id: str, target: str, message: str, *, turn_id: str, interrupt: bool = True,
) -> dict[str, Any]:
    """One continue permission: the single steer a worker may be sent.

    It names the worker the steer may reach, the message's words, the turn
    that may send it and whether the call interrupts the worker's current
    turn.  A send_input call that omits interrupt reads as False, so a
    permission for such a call must say so.
    """

    return {
        "grant_id": grant_id,
        "target": target,
        "message_sha256": message_digest(message),
        "turn_id": turn_id,
        "interrupt": interrupt,
    }


def _revision_prefix(revision: Any) -> str:
    return "" if revision == 1 else "r%d:" % int(revision)


def revision_grant_id(base: str, revision: Any) -> str:
    """The spawn permission id one revision's lane or repair worker uses.

    Revision 1 keeps the historical ids, so a binding written before plan
    revisions existed names its permissions exactly as it always did.
    """

    if not isinstance(base, str) or not _BASE_GRANT_ID.fullmatch(base):
        raise ValueError("governed_run:grant_id_invalid")
    if type(revision) is not int or not 1 <= revision <= MAX_REVISION:
        raise ValueError("governed_run:revision_invalid")
    return _revision_prefix(revision) + base


def binding_revision(binding: Mapping[str, Any]) -> int:
    """The revision a binding names; a historical v2 binding is revision 1."""

    revision = binding.get("revision")
    return revision if type(revision) is int else 1


def _grant_valid(value: Any) -> bool:
    return bool(
        isinstance(value, Mapping)
        and set(value) == GRANT_FIELDS
        and isinstance(value.get("grant_id"), str)
        and _GRANT_ID.fullmatch(value["grant_id"])
        and isinstance(value.get("message_sha256"), str)
        and _SHA256.fullmatch(value["message_sha256"])
        and isinstance(value.get("model"), str)
        and 0 < len(value["model"]) <= 256
        and isinstance(value.get("reasoning_effort"), str)
        and 0 < len(value["reasoning_effort"]) <= 32
    )


def _continuation_valid(value: Any) -> bool:
    return bool(
        isinstance(value, Mapping)
        and set(value) == CONTINUATION_FIELDS
        and isinstance(value.get("grant_id"), str)
        and _CONTINUATION_ID.fullmatch(value["grant_id"])
        and isinstance(value.get("target"), str)
        and _THREAD_ID.fullmatch(value["target"])
        and isinstance(value.get("message_sha256"), str)
        and _SHA256.fullmatch(value["message_sha256"])
        and isinstance(value.get("turn_id"), str)
        and _THREAD_ID.fullmatch(value["turn_id"])
        and type(value.get("interrupt")) is bool
    )


def _continuation_by_id(binding: Mapping[str, Any], grant_id: Any) -> Mapping[str, Any] | None:
    for grant in binding.get("continuations") or []:
        if isinstance(grant, Mapping) and grant.get("grant_id") == grant_id:
            return grant
    return None


def _is_continuation_id(grant_id: Any) -> bool:
    return isinstance(grant_id, str) and grant_id.startswith("continue:")


def seal_binding(core: Mapping[str, Any]) -> dict[str, Any]:
    """Seal one binding, giving this version's fields their quiet defaults.

    A core that names this schema and no revision or continue permission is
    the first revision of a run that steers nobody, so a caller written
    before Issue 196 still seals a valid binding.  A historical v2 core is
    sealed exactly as it was.
    """

    value = {key: item for key, item in core.items() if key != "binding_sha256"}
    if value.get("schema") in (BINDING_SCHEMA, V3_BINDING_SCHEMA):
        value.setdefault("revision", 1)
        value.setdefault("continuations", [])
    if value.get("schema") == BINDING_SCHEMA:
        value.setdefault("lane_writes", {})
    return {**value, "binding_sha256": sha256(value)}


def binding_issues(value: Any, *, session_id: Any = None) -> list[str]:
    """Closed validation of one binding; an empty list means valid.

    A binding carries exactly this version's fields, a v3 binding's, which
    reads as owning no paths, or a historical v2 binding's, which also reads
    as revision 1 holding no continue permission.
    """

    shape = next(
        (schema for schema, fields in _BINDING_SHAPES.items()
         if isinstance(value, Mapping) and set(value) == set(fields)), None,
    )
    if shape is None:
        return ["governed_run:binding_invalid"]
    legacy = shape == LEGACY_BINDING_SCHEMA
    issues: list[str] = []
    if value.get("schema") != shape:
        issues.append("governed_run:binding_schema_invalid")
    if not isinstance(value.get("run_id"), str) or not _RUN_ID.fullmatch(value["run_id"]):
        issues.append("governed_run:binding_run_id_invalid")
    thread = value.get("thread_id")
    if not isinstance(thread, str) or not _THREAD_ID.fullmatch(thread):
        issues.append("governed_run:binding_thread_invalid")
    elif session_id is not None and thread != session_id:
        issues.append("governed_run:binding_thread_mismatch")
    root = value.get("project_root")
    if not isinstance(root, str) or not Path(root).is_absolute():
        issues.append("governed_run:binding_project_root_invalid")
    workers = value.get("workers")
    if type(workers) is not int or not 0 <= workers <= MAX_WORKERS:
        issues.append("governed_run:binding_workers_invalid")
        workers = None
    revision: Any = 1 if legacy else value.get("revision")
    if type(revision) is not int or not 1 <= revision <= MAX_REVISION:
        issues.append("governed_run:binding_revision_invalid")
        revision = None
    round_number = value.get("round")
    if round_number not in (1, 2) or (workers == 0 and round_number != 1):
        issues.append("governed_run:binding_round_invalid")
    grants = value.get("grants")
    grant_ids: set[str] = set()
    if (
        not isinstance(grants, list)
        or any(not _grant_valid(grant) for grant in grants)
        or len({grant["grant_id"] for grant in grants}) != len(grants)
    ):
        issues.append("governed_run:binding_grants_invalid")
    else:
        grant_ids = {grant["grant_id"] for grant in grants}
        if workers is not None and revision is not None and not _grants_fit_round(
            grants, workers, round_number, revision
        ):
            issues.append("governed_run:binding_grants_invalid")
    continuations = [] if legacy else value.get("continuations")
    if (
        not isinstance(continuations, list)
        or len(continuations) > MAX_CONTINUATIONS
        or any(not _continuation_valid(grant) for grant in continuations)
        or len({grant["grant_id"] for grant in continuations}) != len(continuations)
        or (workers == 0 and continuations)
    ):
        issues.append("governed_run:binding_continuations_invalid")
    if not _lane_writes_valid(value.get("lane_writes") if shape == BINDING_SCHEMA else {}, grant_ids):
        issues.append("governed_run:binding_lane_writes_invalid")
    if value.get("status") not in BINDING_STATUSES:
        issues.append("governed_run:binding_status_invalid")
    for field in ("summary_sha256", "hook_definition_sha256", "binding_sha256"):
        if not isinstance(value.get(field), str) or not _SHA256.fullmatch(value[field]):
            issues.append("governed_run:binding_" + field + "_invalid")
    protected = value.get("protected_paths")
    if (
        not isinstance(protected, list)
        or not protected
        or any(not isinstance(item, str) or not Path(item).is_absolute() for item in protected)
    ):
        issues.append("governed_run:binding_protected_paths_invalid")
    if not isinstance(value.get("bound_at"), str) or not value["bound_at"]:
        issues.append("governed_run:binding_bound_at_invalid")
    if not issues and len(canonical(value)) > MAX_BINDING_BYTES:
        issues.append("governed_run:binding_too_large")
    if not issues and value.get("binding_sha256") != sha256(
        {key: item for key, item in value.items() if key != "binding_sha256"}
    ):
        issues.append("governed_run:binding_seal_invalid")
    return issues


def write_path_valid(value: Any) -> bool:
    """A path a lane may own: canonical, relative to the project, and never
    through a parent, .git or .orch-dork."""

    if not isinstance(value, str) or not 0 < len(value) <= MAX_WRITE_PATH or "\x00" in value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and bool(path.parts)
        and value != "."
        and all(part.casefold() not in {"..", ".git", ".orch-dork"} for part in path.parts)
    )


def writes_overlap(first: str, second: str) -> bool:
    """Whether two owned paths are one, or one holds the other."""

    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


def _lane_writes_valid(value: Any, grant_ids: set[str]) -> bool:
    """Each owning lane permission is one of this round's, and no two lanes'
    paths overlap."""

    if not isinstance(value, Mapping):
        return False
    claimed: list[str] = []
    for grant_id, paths in value.items():
        if (
            not isinstance(grant_id, str)
            or not _LANE_GRANT_ID.fullmatch(grant_id)
            or grant_id not in grant_ids
            or not isinstance(paths, list)
            or not 1 <= len(paths) <= MAX_LANE_WRITES
            or not all(write_path_valid(path) for path in paths)
            or len(set(paths)) != len(paths)
            or any(writes_overlap(path, other) for path in paths for other in claimed)
        ):
            return False
        claimed.extend(paths)
    return True


def _grants_fit_round(
    grants: list[Mapping[str, Any]], workers: int, round_number: Any, revision: Any,
) -> bool:
    """A run without lanes holds no permission; a run with lanes holds one per
    lane in its first round and only the repair worker's in its second, each
    named for the revision whose plan admitted it."""

    ids = [grant["grant_id"] for grant in grants]
    prefix = _revision_prefix(revision)
    if workers == 0:
        return not ids
    if round_number == 1:
        return len(ids) == workers and all(
            grant_id.startswith(prefix + "lane:") for grant_id in ids
        )
    return ids == [prefix + REPAIR_GRANT]


def read_binding(path: Path) -> Mapping[str, Any]:
    """Read one owner-only, non-symlink binding file or raise."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not (info.st_mode & 0o170000 == 0o100000)
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            or info.st_mode & 0o022
            or info.st_size > MAX_BINDING_BYTES
        ):
            raise ValueError("governed_run:binding_file_unsafe")
        raw = os.read(descriptor, MAX_BINDING_BYTES + 1)
    finally:
        os.close(descriptor)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("governed_run:binding_invalid")
    return value


def canonical_tool_name(value: Any) -> str:
    name = str(value or "").strip().lower()
    for prefix in _COLLABORATION_PREFIXES:
        if name.startswith(prefix) and name[len(prefix):] in COLLABORATION_TOOLS:
            return name[len(prefix):]
    return name


def is_collaboration_tool(value: Any) -> bool:
    return canonical_tool_name(value) in COLLABORATION_TOOLS


def item_type_for_tool(value: Any) -> str | None:
    """The owner-rail item an allowed call of this tool shows, if any."""

    return ITEM_TOOLS.get(canonical_tool_name(value))


def quiet_tool(value: Any) -> bool:
    return canonical_tool_name(value) in QUIET_TOOLS


def _command_text(tool_input: Any) -> str | None:
    if not isinstance(tool_input, Mapping):
        return None
    for key in ("command", "cmd"):
        command = tool_input.get(key)
        if isinstance(command, str):
            return command
        if isinstance(command, list) and all(isinstance(part, str) for part in command):
            return " ".join(command)
    return None


def _names_protected_path(tool_input: Any, protected: list[str]) -> str | None:
    try:
        text = canonical(tool_input).decode("utf-8")
    except (TypeError, ValueError):
        return "unserializable"
    for path in protected:
        if path and path.rstrip("/") in text:
            return path
    return None


def _within(root: str, cwd: Any) -> bool:
    if not isinstance(cwd, str) or not cwd:
        return False
    try:
        Path(os.path.realpath(cwd)).relative_to(Path(os.path.realpath(root)))
    except ValueError:
        return False
    return True


def decide(
    binding: Mapping[str, Any] | None,
    hook_input: Mapping[str, Any],
    *,
    binding_problems: list[str],
    observed_hook_definition_sha256: str | None,
    grant_state: Mapping[str, Any] | None = None,
) -> tuple[str, list[str]]:
    """Return the closed decision and its reasons for one hook event.

    grant_state is the run's permission claims and outcomes so far, which a
    run with lanes decides its collaboration calls against.
    """

    event = hook_input.get("hook_event_name")
    reasons = list(binding_problems)
    if not reasons and binding is not None:
        if observed_hook_definition_sha256 != binding.get("hook_definition_sha256"):
            reasons.append("governed_run:hook_generation_changed")
        if binding.get("status") == "TERMINAL":
            reasons.append("governed_run:ended")
    if event == "SessionStart":
        if not reasons and binding is not None and not _within(
            str(binding.get("project_root")), hook_input.get("cwd")
        ):
            reasons.append("governed_run:cwd_outside_project")
        return ("READ_ONLY" if reasons else "HEALTHY"), reasons
    if event == "PreToolUse":
        if not reasons and binding is not None:
            if binding.get("workers") or (
                hook_input.get("agent_id") is None
                and canonical_tool_name(hook_input.get("tool_name")) == "close_agent"
                and earlier_workers(binding, grant_state or {})
            ):
                reasons.extend(_lane_call_reasons(binding, hook_input, grant_state or {}))
            elif hook_input.get("agent_id") is not None or is_collaboration_tool(hook_input.get("tool_name")):
                reasons.append("governed_run:zero_workers")
            else:
                reasons.extend(_own_call_reasons(binding, hook_input))
        return ("DENY" if reasons else "ALLOW"), reasons
    if event in {"Stop", "SubagentStop"}:
        return ("STOP_ALLOWED" if event == "Stop" else "OBSERVED"), reasons
    return "OBSERVED", reasons


def _own_call_reasons(binding: Mapping[str, Any], hook_input: Mapping[str, Any]) -> list[str]:
    """The closed set of tools a zero-worker task or a lane worker may call."""

    tool_name = hook_input.get("tool_name")
    tool_input = hook_input.get("tool_input")
    if item_type_for_tool(tool_name) is None and not quiet_tool(tool_name):
        return ["governed_run:tool_outside_enforcement"]
    if canonical_tool_name(tool_name) == "write_stdin" and (
        not isinstance(tool_input, Mapping) or tool_input.get("chars") not in (None, "")
    ):
        return ["governed_run:write_stdin_outside_enforcement"]
    reasons = []
    command = _command_text(tool_input)
    if command is not None and _BACKGROUND.search(command):
        reasons.append("governed_run:background_process_outside_enforcement")
    if _names_protected_path(tool_input, list(binding.get("protected_paths") or [])) is not None:
        reasons.append("governed_run:protected_resource")
    return reasons


def _lane_call_reasons(
    binding: Mapping[str, Any], hook_input: Mapping[str, Any], grant_state: Mapping[str, Any],
) -> list[str]:
    """Why one call of a run with lanes is refused; empty when it is allowed."""

    tool_name = hook_input.get("tool_name")
    tool_input = hook_input.get("tool_input")
    name = canonical_tool_name(tool_name)
    workers = round_workers(binding, grant_state)
    agent = hook_input.get("agent_id")
    if agent is not None:
        if agent not in workers:
            return ["governed_run:unknown_worker"]
        if is_collaboration_tool(tool_name):
            return ["governed_run:worker_collaboration"]
        return _own_call_reasons(binding, hook_input) + _ownership_reasons(binding, hook_input, grant_state)
    if name == "spawn_agent":
        _grant, problem = spawn_permission(binding, tool_input, grant_state)
        return [problem] if problem else []
    if name == "send_input":
        grant_id, problem = continuation_permission(binding, tool_input, grant_state)
        if problem:
            return [problem]
        grant = _continuation_by_id(binding, grant_id)
        if grant is None or grant["turn_id"] != hook_input.get("turn_id"):
            return ["governed_run:continuation_turn_mismatch"]
        return []
    if name == "wait_agent":
        targets = tool_input.get("targets") if isinstance(tool_input, Mapping) else None
        allowed = (
            isinstance(tool_input, Mapping)
            and set(tool_input) <= {"targets", "timeout_ms"}
            and isinstance(targets, list)
            and bool(targets)
            and all(isinstance(target, str) and target in workers for target in targets)
        )
        return [] if allowed else ["governed_run:wait_outside_plan"]
    if name == "close_agent":
        allowed = (
            isinstance(tool_input, Mapping)
            and set(tool_input) == {"target"}
            and tool_input.get("target") in workers | earlier_workers(binding, grant_state)
        )
        return [] if allowed else ["governed_run:close_outside_plan"]
    if is_collaboration_tool(tool_name):
        return ["governed_run:message_outside_plan"]
    if quiet_tool(tool_name):
        return _own_call_reasons(binding, hook_input)
    if item_type_for_tool(tool_name) is not None:
        return ["governed_run:root_implementation"]
    return ["governed_run:tool_outside_enforcement"]


def _ownership_reasons(
    binding: Mapping[str, Any], hook_input: Mapping[str, Any], grant_state: Mapping[str, Any],
) -> list[str]:
    """Why a worker's call is refused for writing another lane's paths."""

    owned = binding.get("lane_writes") or {}
    if not owned:
        return []
    agent = hook_input.get("agent_id")
    own = {
        grant["grant_id"] for grant in binding.get("grants") or []
        if ((grant_state.get(grant["grant_id"]) or {}).get("outcome") or {}).get("agent_id") == agent
    }
    others = [path for grant_id, paths in sorted(owned.items()) if grant_id not in own for path in paths]
    if others and writes_owned_path(hook_input, str(binding.get("project_root")), others):
        return ["governed_run:path_owned_by_other_lane"]
    return []


def writes_owned_path(hook_input: Mapping[str, Any], project_root: str, owned: list[str]) -> bool:
    """Whether one call writes any of these project-relative paths.

    apply_patch is read exactly from its file headers.  A shell command is
    read best-effort: a part of it that names a path and writes it by a
    redirection, a writing command, an in-place edit, a Git command that
    rewrites files, an inline interpreter script or a heredoc.  A write
    through a script file, a variable or a changed folder is not seen.
    Issue 248 unwraps option-bearing commands, inspects find execution bodies,
    and resolves literal paths and existing file identities at this boundary.
    """

    name = canonical_tool_name(hook_input.get("tool_name"))
    tool_input = hook_input.get("tool_input")
    root = os.path.realpath(project_root)
    cwd = hook_input.get("cwd")
    if isinstance(tool_input, Mapping):
        cwd = tool_input.get("workdir", tool_input.get("cwd", cwd))
    cwd = cwd if isinstance(cwd, str) and os.path.isabs(cwd) else root
    if name == "apply_patch":
        patch = _patch_text(tool_input)
        if patch is None:
            return False
        targets = [target for target in _PATCH_TARGET.findall(patch) if target]
        if not targets:
            return any(_mentions(patch, root, path) for path in owned)
        return any(_path_owned(target, cwd, root, owned) for target in targets)
    if name in SHELL_TOOLS:
        command = _command_text(tool_input)
        return command is not None and _shell_writes(command, root, owned, cwd)
    return False


def _patch_text(tool_input: Any) -> str | None:
    if isinstance(tool_input, str):
        return tool_input
    if not isinstance(tool_input, Mapping):
        return None
    for key in ("command", "input", "patch"):
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, list) and all(isinstance(part, str) for part in value):
            return "\n".join(value)
    return None


def _project_path(target: str, cwd: Any, root: str) -> str | None:
    """A patch path as a project-relative path, through every linked folder."""

    path = Path(target)
    if not path.is_absolute():
        path = Path(cwd if isinstance(cwd, str) and os.path.isabs(cwd) else root) / path
    try:
        return Path(os.path.realpath(path)).relative_to(root).as_posix()
    except ValueError:
        return None


def _inside(relative: str | None, owned: list[str]) -> bool:
    return relative is not None and any(relative == path or relative.startswith(path + "/") for path in owned)


def _mentions(text: str, root: str, path: str) -> bool:
    """Whether text names a project path, relative or under the project root."""

    after = r"(?![\w.\-])"
    relative = r"(?:(?<![\w.\-/~$])|(?<=\./))" + re.escape(path) + after
    absolute = re.escape(root.rstrip("/") + "/" + path) + after
    return re.search(relative, text) is not None or re.search(absolute, text) is not None


def _path_owned(target: str, cwd: str, root: str, owned: list[str]) -> bool:
    """Check lexical ownership, resolved links, then hard-linked file identity.

    No directory is scanned for ordinary files. For a multiply-linked file,
    bounded scanning of owned trees refuses conservatively on unreadable or
    oversized trees; this is a pre-call check, not a filesystem sandbox.
    """

    if not target or '\x00' in target:
        return False
    path = Path(target) if os.path.isabs(target) else Path(cwd) / target
    try:
        lexical = Path(os.path.abspath(path)).relative_to(root).as_posix()
    except ValueError:
        lexical = None
    if _inside(lexical, owned) or _inside(_project_path(target, cwd, root), owned):
        return True
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink < 2:
            return False
    except (OSError, ValueError):
        return False
    identity = (info.st_dev, info.st_ino)
    remaining = 4096
    def unreadable(error: OSError) -> None:
        raise error
    try:
        for relative in owned:
            candidate = Path(root) / relative
            if candidate.is_file():
                other = candidate.stat()
                if (other.st_dev, other.st_ino) == identity:
                    return True
            elif candidate.is_dir():
                for folder, dirs, files in os.walk(candidate, followlinks=False, onerror=unreadable):
                    remaining -= len(dirs) + len(files) + 1
                    if remaining < 0:
                        return True
                    for name in files:
                        other = (Path(folder) / name).stat()
                        if (other.st_dev, other.st_ino) == identity:
                            return True
    except OSError:
        return True
    return False


def _word_names_owned(word: str, cwd: str, root: str, owned: list[str]) -> bool:
    if any(_mentions(word, root, path) for path in owned) or _path_owned(word, cwd, root, owned):
        return True
    # Inline code and dd's of=path still name literal paths. Do not evaluate code.
    candidates = re.findall(r"['\"]([^'\"]+)['\"]", word)
    if '=' in word:
        candidates.append(word.split('=', 1)[1])
    return any(_path_owned(value, cwd, root, owned) for value in candidates)


def _shell_writes(command: str, root: str, owned: list[str], cwd: str) -> bool:
    if "<<" in command and _word_names_owned(command, cwd, root, owned):
        return True
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = ""
        words = list(lexer)
    except ValueError:
        # Preserve the conservative check for unfinished heredocs/quoted scripts.
        return _word_names_owned(command, cwd, root, owned)
    part: list[str] = []
    in_find_action = False
    for word in words:
        if word in {"-exec", "-execdir", "-ok", "-okdir"}:
            in_find_action = True
        if in_find_action and word in {";", "+"}:
            part.append(word)
            in_find_action = False
        elif word in {";", "&&", "||", "|", "|&", "&"} or not word.strip("\n"):
            if _words_write(part, root, owned, cwd):
                return True
            part = []
        else:
            part.append(word)
    return _words_write(part, root, owned, cwd)


def _words_write(words: list[str], root: str, owned: list[str], cwd: str, *, depth: int = 0) -> bool:
    if depth > 8:
        return True
    def names(word: str) -> bool:
        return _word_names_owned(word, cwd, root, owned)

    if any(word in {">", ">>", ">|", "&>", "&>>"} and names(words[index + 1])
           for index, word in enumerate(words[:-1])):
        return True
    words, wrapper_outputs = _unwrap_command(words)
    if any(names(path) for path in wrapper_outputs):
        return True
    if not words:
        return False
    program, arguments = os.path.basename(words[0]), words[1:]
    if program == "find":
        return _find_writes(arguments, root, owned, cwd, depth)
    if program in _SHELL_COPIERS:
        operands, target, options = _copy_operands(program, arguments)
        directory = target is not None
        if target is None and operands:
            operands, target = operands[:-1], operands[-1]
        if target is None:
            return False
        if names(target):
            return True
        destination = Path(cwd) / target
        # rsync creates a trailing-slash destination as a directory, even when absent.
        directory = directory or destination.is_dir() or (program == "rsync" and target.endswith("/"))
        if directory and any(names(str(destination / Path(word).name)) for word in operands):
            return True
        creates_links, preserves_links = _copy_alias_modes(program, options)
        if creates_links:
            # Refuse creating aliases too: the later write may be in this same call.
            parent = str(destination if directory else destination.parent)
            if any(_link_source_owned(word, cwd, root, owned)
                   or _link_source_owned(word, parent, root, owned) for word in operands):
                return True
        if preserves_links and any(_copied_symlink_owned(word, destination, directory, program, cwd, root, owned)
                                   for word in operands):
            return True
        if program == "rsync":
            for option in options:
                if option.startswith("--link-dest=") and _link_source_owned(
                        option.split("=", 1)[1], str(destination), root, owned):
                    return True
        return False
    writes = program in _SHELL_WRITERS
    writes = writes or (program in ("sed", "perl") and any(_IN_PLACE.fullmatch(word) for word in arguments))
    writes = writes or (bool(_INTERPRETER.fullmatch(program)) and any(_INLINE_SCRIPT.fullmatch(word) for word in arguments))
    if program == "git":
        index = 0
        while index < len(arguments) and arguments[index].startswith("-"):
            index += 2 if arguments[index] in _GIT_VALUED_OPTIONS else 1
        writes = index < len(arguments) and arguments[index] in _GIT_WRITERS
    return writes and any(names(word) for word in arguments)


def _contains_owned_path(target: str, cwd: str, root: str, owned: list[str]) -> bool:
    """Include ancestors outside the project, such as a find root of '..'."""

    resolved = Path(os.path.realpath(Path(cwd) / target))
    return any((Path(root) / path).is_relative_to(resolved) for path in owned)


def _link_source_owned(target: str, cwd: str, root: str, owned: list[str]) -> bool:
    """A directory link can expose an owned descendant, including through aliases."""

    if _path_owned(target, cwd, root, owned):
        return True
    if _contains_owned_path(target, cwd, root, owned):
        return True
    if (Path(cwd) / target).is_dir():
        matches, _folders, complete = _find_scope([target], cwd, root, owned)
        return not complete or any(_path_owned(path, cwd, root, owned) for path in matches)
    return False


def _copy_alias_modes(program: str, options: list[str]) -> tuple[bool, bool]:
    """Distinguish new aliases from preservation of symbolic-link contents."""

    short = {char for word in options if word.startswith('-') and not word.startswith('--') for char in word[1:]}
    long = {word.split('=', 1)[0] for word in options if word.startswith('--')}
    if program == 'ln':
        return True, not ('s' in short or '--symbolic' in long)
    if program == 'cp':
        creates = bool(short & {'l', 's'} or long & {'--link', '--symbolic-link'})
        preserves = bool(short & {'P', 'd', 'a', 'r', 'R'} or long & {'--no-dereference', '--archive', '--recursive'})
        return creates, preserves
    if program == 'rsync':
        return False, bool(short & {'l', 'a'} or long & {'--links', '--archive'})
    return False, False


def _copied_symlink_owned(
    source: str, destination: Path, directory: bool, program: str, cwd: str, root: str, owned: list[str],
) -> bool:
    """Inspect preserved symlinks at their destination, without following source links.

    A relative link can change its target when copied. Ordinary files, including
    copies read from another lane, do not become aliases in this mode.
    """

    source_path = Path(cwd) / source
    target = destination / source_path.name if directory else destination
    if program == 'rsync' and source.endswith('/'):
        target = destination
    if program == 'cp' and os.path.basename(source.rstrip('/')) in {'.', '..'}:
        target = destination
    matches, _folders, complete = _find_scope([str(source_path)], cwd, root, owned, follow_links=False)
    if not complete:
        return True
    for name in matches:
        path = Path(name)
        try:
            if path.is_symlink():
                link_target = os.readlink(path)
                copied = target / path.relative_to(source_path)
                if _link_source_owned(link_target, str(copied.parent), root, owned):
                    return True
        except (OSError, ValueError):
            return True
    return False


def _copy_operands(program: str, arguments: list[str]) -> tuple[list[str], str | None, list[str]]:
    """Separate operands using the command's own option meanings, not another copier's.

    Keep only flag names in short clusters: letters in an attached option value
    must not become alias-creation flags. rsync's -t/-o/-g/-m/-S take no values.
    """

    operands: list[str] = []
    target = None
    options: list[str] = []
    index = 0
    values = {
        "cp": {"-t", "--target-directory", "-S", "--suffix"},
        "ln": {"-t", "--target-directory", "-S", "--suffix"},
        "install": {"-t", "--target-directory", "-m", "--mode", "-o", "--owner", "-g", "--group",
                    "-S", "--suffix", "--strip-program"},
        "rsync": {"--link-dest", "--copy-dest", "--compare-dest", "-e", "--rsh", "-f", "--filter",
                  "--exclude", "--include", "--exclude-from", "--include-from", "--files-from",
                  "--out-format", "--log-file", "--log-file-format", "--bwlimit", "--timeout",
                  "--rsync-path", "--chmod", "--chown", "--usermap", "--groupmap"},
        "scp": {"-c", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"},
    }.get(program, set())
    while index < len(arguments):
        word = arguments[index]
        index += 1
        if word == "--":
            operands.extend(arguments[index:])
            break
        if not word.startswith("-") or word == "-":
            operands.append(word)
            continue
        flag, value = word, None
        if word.startswith("--"):
            flag, separator, attached = word.partition("=")
            options.append(flag)
            if separator:
                value = attached
        else:
            for offset, short in enumerate(word[1:], 2):
                flag = "-" + short
                options.append(flag)
                if flag in values:
                    value = word[offset:] or None
                    break
        if flag in values:
            if value is None and index < len(arguments):
                value = arguments[index]
                index += 1
            if flag in {"-t", "--target-directory"}:
                target = value
            if flag == "--link-dest" and value is not None:
                options.append(flag + "=" + value)
    return operands, target, options


def _find_scope(
    roots: list[str], cwd: str, root: str, owned: list[str], *, follow_links: bool = True,
) -> tuple[set[str], set[str], bool]:
    """Bounded search scope; on an incomplete walk, assume owned paths are reachable.

    Follow linked directories conservatively even without -L: an execution body
    can follow them itself. Inode deduplication prevents directory-link cycles.
    Predicates are deliberately ignored, so a read-only body must still pass.
    """

    matches: set[str] = set()
    folders = {str((Path(cwd) / path).parent) for path in roots}
    visited: set[tuple[int, int]] = set()
    pending = [Path(cwd) / path for path in roots]
    remaining = 4096
    while pending:
        path = pending.pop()
        remaining -= 1
        if remaining < 0:
            return matches | {str(Path(root) / path) for path in owned}, folders, False
        matches.add(str(path))
        try:
            info = path.stat()
            if (stat.S_ISDIR(info.st_mode) and (follow_links or not path.is_symlink())
                    and (info.st_dev, info.st_ino) not in visited):
                visited.add((info.st_dev, info.st_ino))
                folders.add(str(path))
                with os.scandir(path) as entries:
                    for entry in entries:
                        if len(pending) > remaining:
                            return matches | {str(Path(root) / path) for path in owned}, folders, False
                        pending.append(Path(entry.path))
        except FileNotFoundError:
            continue
        except OSError:
            return matches | {str(Path(root) / path) for path in owned}, folders, False
    return matches, folders, True


def _find_writes(arguments: list[str], root: str, owned: list[str], cwd: str, depth: int) -> bool:
    """Inspect execution bodies over conservative search-root ownership intersections.

    Find predicates can narrow the search but never expand it, so inspect every
    literal path under the search roots, including aliases and transformed {}.
    Nothing is executed. Execdir additionally changes the body's directory.
    """

    if not any(word in {"-exec", "-execdir", "-ok", "-okdir"} for word in arguments):
        return False
    index = 0
    while index < len(arguments) and (arguments[index] in {"-H", "-L", "-P", "-D"}
                                     or arguments[index].startswith("-O")):
        index += 2 if arguments[index] == "-D" else 1
    roots = []
    while index < len(arguments) and not arguments[index].startswith("-") and arguments[index] not in {"(", "!"}:
        roots.append(arguments[index])
        index += 1
    roots = roots or ["."]
    matches, execution_folders, complete = _find_scope(roots, cwd, root, owned)
    for search in roots:
        resolved = os.path.realpath(Path(cwd) / search)
        for path in owned:
            if _contains_owned_path(search, cwd, root, [path]):
                matches.add(str(Path(root) / path))
            elif _path_owned(search, cwd, root, [path]):
                matches.add(resolved)
    while index < len(arguments):
        action = arguments[index]
        index += 1
        if action not in {"-exec", "-execdir", "-ok", "-okdir"}:
            continue
        end = index
        while end < len(arguments) and arguments[end] not in {";", "+"}:
            end += 1
        body = arguments[index:end]
        index = end + 1
        if _words_write(body, root, owned, cwd, depth=depth + 1):
            return True
        if action in {"-execdir", "-okdir"}:
            # Literal operands can escape a search root even when no owned path is in it.
            if any(_words_write(body, root, owned, folder, depth=depth + 1) for folder in execution_folders):
                return True
        if not complete:
            # Unknown matches or execution directories: refuse possible writers.
            possible_targets = [str(Path(root) / path) for path in owned]
            if (_words_write(body + possible_targets, root, owned, cwd, depth=depth + 1)
                    or any(word in {">", ">>", ">|", "&>"} for word in body)
                    or _unwrap_command(body)[1]):
                return True
        if not any("{}" in word for word in body):
            continue
        for match in sorted(matches):
            folders = [cwd]
            variants = {match}
            if action in {"-execdir", "-okdir"}:
                folders = [str(Path(match).parent)]
                if Path(match).is_dir():
                    folders.append(match)
                variants.update({Path(match).name, "./" + Path(match).name})
            else:
                try:
                    relative = Path(match).relative_to(cwd).as_posix()
                except ValueError:
                    relative = os.path.relpath(match, cwd)
                variants.update({relative, "./" + relative})
            for replacement in sorted(variants):
                expanded = [word.replace("{}", replacement) for word in body]
                if any(_words_write(expanded, root, owned, folder, depth=depth + 1) for folder in folders):
                    return True
    return False


def hook_output(event: Any, decision: str, reasons: list[str], *, workers: int = 0) -> dict[str, Any]:
    reason = "Orch Dork governed run: " + (
        "; ".join(item + (" (" + REASON_HINTS[item] + ")" if item in REASON_HINTS else "") for item in reasons)
        if reasons else "recorded"
    )
    if event == "PreToolUse":
        if decision == "DENY":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    if event == "SessionStart":
        if decision == "READ_ONLY":
            return {
                "continue": False,
                "stopReason": reason,
                "systemMessage": reason,
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": reason,
                },
            }
        return {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": (
                    (
                        "Orch Dork governed run: you coordinate this run's lane workers. "
                        "Spawn exactly the workers the user message lists, with exactly "
                        "the arguments it gives, then wait for them, close them and stop; "
                        "your own edits and any other spawn or message are refused. "
                        if workers else
                        "Orch Dork governed run: this task has zero workers. Do the "
                        "requested work yourself and do not spawn or message agents. "
                    )
                    + STOP_MESSAGE
                ),
            },
        }
    if event == "Stop":
        return {"continue": True, "systemMessage": STOP_MESSAGE}
    return {"continue": True}


def event_record(
    run_id: str,
    hook_input: Mapping[str, Any],
    decision: str,
    reasons: list[str],
    *,
    observed_at_ns: int,
) -> dict[str, Any]:
    tool_input = hook_input.get("tool_input")
    core = {
        "schema": EVENT_SCHEMA,
        "run_id": run_id,
        "session_id": hook_input.get("session_id"),
        "turn_id": hook_input.get("turn_id"),
        "hook_event_name": hook_input.get("hook_event_name"),
        "source": hook_input.get("source"),
        "tool_name": hook_input.get("tool_name"),
        "tool_use_id": hook_input.get("tool_use_id"),
        "agent_id": hook_input.get("agent_id"),
        "decision": decision,
        "reasons": list(reasons),
        "tool_input_sha256": sha256(tool_input) if tool_input is not None else None,
        "observed_at_ns": observed_at_ns,
    }
    return {**core, "record_sha256": sha256(core)}


def write_event(data_root: Path, record: Mapping[str, Any]) -> Path:
    """Create one event file; never overwrite, never follow a link."""

    directory = events_root(data_root, str(record["run_id"]))
    name = "%020d-%s.json" % (int(record["observed_at_ns"]), str(record["record_sha256"])[:16])
    path = directory / name
    _create_only(path, canonical(record) + b"\n")
    return path


def create_whole(path: Path, payload: bytes, *, staging: Path) -> None:
    """Create one owner-only file that must not exist yet, so that it appears only when complete (Issue 244).

    The bytes are written and synced under a temporary name in staging, a directory on the same filesystem, and
    then linked to path. A reader polling path's directory finds no file or the whole file, never an empty or
    partial one. Linking refuses an existing path, a symbolic link included, as O_CREAT | O_EXCL | O_NOFOLLOW
    did, so create-only callers still get FileExistsError. The temporary name starts with a dot, so staging may
    be path's own directory when its readers list only "*.json" names.
    """

    staging.mkdir(parents=True, exist_ok=True, mode=0o700)
    if staging.is_symlink() or not staging.is_dir():
        raise NotADirectoryError("unsafe staging directory: " + str(staging))
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=staging)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _create_only(path: Path, payload: bytes) -> None:
    """Write one owner-only file that must not exist yet; never follow a link.

    The watcher lists and reads these directories while the hook writes them, and refuses any file it does not
    expect there, so the bytes are staged in a hidden directory beside the run's directory.
    """

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    create_whole(path, payload, staging=path.parent.parent / ".staging")


def spawned_agent_id(tool_response: Any) -> str | None:
    """The worker thread id a spawn_agent result names, when it names exactly one.

    Codex 0.160.0 hands PostToolUse the result as a JSON string; a mapping, its
    structured content, or a text content item carrying that JSON is read alike.
    """

    candidates: list[Any] = []
    pending = [tool_response]
    while pending and len(candidates) < 16:
        value = pending.pop()
        if isinstance(value, str):
            try:
                pending.append(json.loads(value))
            except ValueError:
                continue
        elif isinstance(value, Mapping):
            if "agent_id" in value:
                candidates.append(value.get("agent_id"))
            for field in ("structuredContent", "structured_content", "result", "output"):
                if field in value:
                    pending.append(value[field])
            content = value.get("content")
            if isinstance(content, list):
                pending.extend(
                    child.get("text") for child in content
                    if isinstance(child, Mapping) and child.get("type") == "text"
                )
    if not candidates or any(not isinstance(candidate, str) for candidate in candidates) or len(set(candidates)) != 1:
        return None
    agent = candidates[0]
    return agent if _THREAD_ID.fullmatch(agent) else None


def _seal_record(core: Mapping[str, Any]) -> dict[str, Any]:
    return {**core, "record_sha256": sha256(core)}


def write_claim(
    data_root: Path, binding: Mapping[str, Any], grant_id: str, hook_input: Mapping[str, Any],
    *, observed_at_ns: int,
) -> dict[str, Any]:
    """Claim one spawn or continue permission for one call, create-only: it is
    used at most once."""

    record = _seal_record({
        "schema": GRANT_CLAIM_SCHEMA,
        "run_id": binding["run_id"],
        "grant_id": grant_id,
        "round": binding["round"],
        "tool_use_id": hook_input.get("tool_use_id"),
        "turn_id": hook_input.get("turn_id"),
        "tool_input_sha256": sha256(hook_input.get("tool_input")),
        "claimed_at_ns": observed_at_ns,
    })
    _create_only(_grant_path(data_root, binding["run_id"], grant_id, "claim"), canonical(record) + b"\n")
    return record


def write_outcome(
    data_root: Path, binding: Mapping[str, Any], grant_id: str, hook_input: Mapping[str, Any],
    *, observed_at_ns: int,
) -> dict[str, Any]:
    """Bind what a claimed permission did, create-only.

    A spawn's outcome binds the worker its result named.  A steer's result
    names no worker, so its outcome binds the worker the permission already
    named and the result's digest stands for the submission it returned.
    """

    response = hook_input.get("tool_response")
    continuation = _continuation_by_id(binding, grant_id)
    record = _seal_record({
        "schema": GRANT_OUTCOME_SCHEMA,
        "run_id": binding["run_id"],
        "grant_id": grant_id,
        "tool_use_id": hook_input.get("tool_use_id"),
        "agent_id": (
            continuation["target"] if continuation is not None else spawned_agent_id(response)
        ),
        "result_sha256": sha256(response) if response is not None else None,
        "observed_at_ns": observed_at_ns,
    })
    _create_only(_grant_path(data_root, binding["run_id"], grant_id, "outcome"), canonical(record) + b"\n")
    return record


def write_close(
    data_root: Path, binding: Mapping[str, Any], agent_id: str, hook_input: Mapping[str, Any],
    *, observed_at_ns: int,
) -> dict[str, Any]:
    """Mark one bound worker closed by its completed close call, create-only."""

    response = hook_input.get("tool_response")
    record = _seal_record({
        "schema": GRANT_CLOSE_SCHEMA,
        "run_id": binding["run_id"],
        "grant_id": close_key(agent_id),
        "agent_id": agent_id,
        "tool_use_id": hook_input.get("tool_use_id"),
        "result_sha256": sha256(response) if response is not None else None,
        "observed_at_ns": observed_at_ns,
    })
    _create_only(
        _grant_path(data_root, binding["run_id"], close_key(agent_id), "close"),
        canonical(record) + b"\n",
    )
    return record


def read_grant_state(data_root: Path, run_id: str) -> dict[str, dict[str, Any]]:
    """Every permission's claim and outcome so far, and every closed worker's
    marker, by store key."""

    directory = grants_root(data_root, run_id)
    state: dict[str, dict[str, Any]] = {}
    if not directory.is_dir() or directory.is_symlink():
        return state
    for path in sorted(directory.iterdir()):
        kind = (
            "claim" if path.name.endswith(".claim.json")
            else "outcome" if path.name.endswith(".outcome.json")
            else "close" if path.name.endswith(".close.json") else None
        )
        if kind is None or path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_EVENT_BYTES:
            raise ValueError("governed_run:grant_file_unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
        fields, schema = {
            "claim": (CLAIM_FIELDS, GRANT_CLAIM_SCHEMA),
            "outcome": (OUTCOME_FIELDS, GRANT_OUTCOME_SCHEMA),
            "close": (CLOSE_FIELDS, GRANT_CLOSE_SCHEMA),
        }[kind]
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or value.get("schema") != schema
            or value.get("run_id") != run_id
            or not isinstance(value.get("grant_id"), str)
            or path.name != value["grant_id"].replace(":", "-") + "." + kind + ".json"
            or value.get("record_sha256")
            != sha256({key: item for key, item in value.items() if key != "record_sha256"})
        ):
            raise ValueError("governed_run:grant_record_invalid")
        if kind == "close" and (
            not isinstance(value.get("agent_id"), str)
            or not _THREAD_ID.fullmatch(value["agent_id"])
            or value["grant_id"] != close_key(value["agent_id"])
        ):
            raise ValueError("governed_run:grant_record_invalid")
        state.setdefault(
            value["grant_id"], {"claim": None, "outcome": None, "close": None}
        )[kind] = value
    return state


def round_workers(binding: Mapping[str, Any], grant_state: Mapping[str, Any]) -> set[str]:
    """The worker ids the current round's spawn results bound."""

    workers: set[str] = set()
    for grant in binding.get("grants") or []:
        outcome = (grant_state.get(grant["grant_id"]) or {}).get("outcome")
        if isinstance(outcome, Mapping) and isinstance(outcome.get("agent_id"), str):
            workers.add(outcome["agent_id"])
    return workers


def earlier_workers(binding: Mapping[str, Any], grant_state: Mapping[str, Any]) -> set[str]:
    """The worker ids an earlier round's spawn results bound."""

    current = {grant["grant_id"] for grant in binding.get("grants") or []}
    return {
        entry["outcome"]["agent_id"] for grant_id, entry in grant_state.items()
        if grant_id not in current
        and _GRANT_ID.fullmatch(grant_id)
        and isinstance(entry.get("outcome"), Mapping)
        and isinstance(entry["outcome"].get("agent_id"), str)
    }


def closed_workers(grant_state: Mapping[str, Any]) -> set[str]:
    """The workers a completed close call already ended."""

    return {
        entry["close"]["agent_id"] for entry in grant_state.values()
        if isinstance(entry.get("close"), Mapping)
        and isinstance(entry["close"].get("agent_id"), str)
    }


def spawn_permission(
    binding: Mapping[str, Any], tool_input: Any, grant_state: Mapping[str, Any],
) -> tuple[str | None, str | None]:
    """The unused permission a spawn call matches, or why it matches none."""

    if (
        not isinstance(tool_input, Mapping)
        or set(tool_input) - _SPAWN_FIELDS
        or tool_input.get("fork_context") not in (None, False)
    ):
        return None, "governed_run:spawn_outside_plan"
    digest = message_digest(tool_input.get("message"))
    matched = [
        grant for grant in binding.get("grants") or []
        if grant["message_sha256"] == digest
        and grant["model"] == tool_input.get("model")
        and grant["reasoning_effort"] == tool_input.get("reasoning_effort")
    ]
    for grant in matched:
        if (grant_state.get(grant["grant_id"]) or {}).get("claim") is None:
            return grant["grant_id"], None
    return None, ("governed_run:spawn_permission_used" if matched else "governed_run:spawn_outside_plan")


def continuation_permission(
    binding: Mapping[str, Any], tool_input: Any, grant_state: Mapping[str, Any],
) -> tuple[str | None, str | None]:
    """The unused permission a steer matches, or why it matches none.

    Only a worker this round's spawn result bound may be steered, so a
    permission naming an earlier round's worker or an id no spawn bound
    reaches nobody, and neither does one naming a worker the root closed.
    """

    if (
        not isinstance(tool_input, Mapping)
        or set(tool_input) - _CONTINUE_FIELDS
        or not isinstance(tool_input.get("target"), str)
        or not isinstance(tool_input.get("message"), str)
        or ("interrupt" in tool_input and type(tool_input["interrupt"]) is not bool)
    ):
        return None, "governed_run:continuation_outside_plan"
    target = tool_input["target"]
    if target not in round_workers(binding, grant_state):
        return None, "governed_run:continuation_target_unbound"
    if target in closed_workers(grant_state):
        return None, "governed_run:continuation_target_closed"
    digest = message_digest(tool_input["message"])
    interrupt = bool(tool_input.get("interrupt", False))
    matched = [
        grant for grant in binding.get("continuations") or []
        if grant["target"] == target
        and grant["message_sha256"] == digest
        and grant["interrupt"] is interrupt
    ]
    for grant in matched:
        if (grant_state.get(grant["grant_id"]) or {}).get("claim") is None:
            return grant["grant_id"], None
    return None, (
        "governed_run:continuation_permission_used" if matched
        else "governed_run:continuation_outside_plan"
    )


def claim_for_call(binding: Mapping[str, Any], grant_state: Mapping[str, Any], tool_use_id: Any) -> str | None:
    """The permission this round's native call with this tool-use id claimed."""

    for grant in list(binding.get("grants") or []) + list(binding.get("continuations") or []):
        claim = (grant_state.get(grant["grant_id"]) or {}).get("claim")
        if isinstance(claim, Mapping) and claim.get("tool_use_id") == tool_use_id:
            return grant["grant_id"]
    return None


def read_events(data_root: Path, run_id: str) -> list[dict[str, Any]]:
    """Every sealed event of one run, in the order the hook observed them."""

    directory = events_root(data_root, run_id)
    if not directory.is_dir() or directory.is_symlink():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or not path.is_file() or path.suffix != ".json":
            raise ValueError("governed_run:event_file_unsafe")
        if path.stat().st_size > MAX_EVENT_BYTES:
            raise ValueError("governed_run:event_file_too_large")
        value = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != EVENT_FIELDS
            or value.get("schema") != EVENT_SCHEMA
            or value.get("run_id") != run_id
            or value.get("decision") not in DECISIONS
            or value.get("record_sha256")
            != sha256({key: item for key, item in value.items() if key != "record_sha256"})
        ):
            raise ValueError("governed_run:event_record_invalid")
        rows.append(value)
    return rows


def hook_decision(
    data_root: Path,
    hook_input: Mapping[str, Any],
    *,
    observed_hook_definition_sha256: str | None,
    now_ns: Any = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Decide and record one event of a bound task; any failure fails closed."""

    event = hook_input.get("hook_event_name")
    session_id = hook_input.get("session_id")
    binding: Mapping[str, Any] | None = None
    problems: list[str] = []
    try:
        binding = read_binding(binding_path(data_root, session_id))
        problems = binding_issues(binding, session_id=session_id)
    except (OSError, ValueError, UnicodeDecodeError):
        problems = ["governed_run:binding_unreadable"]
    grant_state: dict[str, dict[str, Any]] = {}
    tracks_grants = bool(binding is not None and not problems and (
        binding.get("workers") or binding.get("revision", 1) > 1
    ))
    if tracks_grants:
        try:
            grant_state = read_grant_state(data_root, str(binding["run_id"]))
        except (OSError, ValueError, UnicodeDecodeError):
            problems = ["governed_run:grant_state_unreadable"]
            tracks_grants = False
    decision, reasons = decide(
        binding if not problems else None,
        hook_input,
        binding_problems=problems,
        observed_hook_definition_sha256=observed_hook_definition_sha256,
        grant_state=grant_state,
    )
    clock = now_ns if callable(now_ns) else time.time_ns
    observed_at_ns = int(clock())
    native = canonical_tool_name(hook_input.get("tool_name"))
    if tracks_grants and hook_input.get("agent_id") is None:
        if native in {"spawn_agent", "send_input"}:
            decision, reasons = _settle_grant_call(
                data_root, binding, hook_input, grant_state, decision, reasons,
                observed_at_ns=observed_at_ns,
            )
        elif native == "close_agent":
            reasons = _settle_close(
                data_root, binding, hook_input, grant_state, reasons,
                observed_at_ns=observed_at_ns,
            )
    record = None
    if binding is not None and not problems:
        record = event_record(
            str(binding["run_id"]), hook_input, decision, reasons, observed_at_ns=observed_at_ns
        )
        try:
            write_event(data_root, record)
        except (OSError, ValueError):
            reasons = reasons + ["governed_run:record_unavailable"]
            if event == "PreToolUse":
                decision = "DENY"
            elif event == "SessionStart":
                decision = "READ_ONLY"
            record = None
    workers = int(binding.get("workers") or 0) if binding is not None and not problems else 0
    return hook_output(event, decision, reasons, workers=workers), record


def _settle_grant_call(
    data_root: Path, binding: Mapping[str, Any], hook_input: Mapping[str, Any],
    grant_state: Mapping[str, Any], decision: str, reasons: list[str], *, observed_at_ns: int,
) -> tuple[str, list[str]]:
    """Claim the permission an allowed spawn or steer uses, or bind what it did.

    The claim is written before the call runs and is create-only, so two
    calls racing for one permission leave exactly one allowed.
    A result whose call claimed nothing, or whose claim belongs to the other
    kind of permission, is recorded as unclaimed.
    """

    event = hook_input.get("hook_event_name")
    continuation = canonical_tool_name(hook_input.get("tool_name")) == "send_input"
    used = (
        "governed_run:continuation_permission_used" if continuation
        else "governed_run:spawn_permission_used"
    )
    unclaimed = (
        "governed_run:continuation_result_unclaimed" if continuation
        else "governed_run:spawn_result_unclaimed"
    )
    if event == "PreToolUse" and decision == "ALLOW":
        permission = continuation_permission if continuation else spawn_permission
        grant_id, _problem = permission(binding, hook_input.get("tool_input"), grant_state)
        try:
            write_claim(data_root, binding, str(grant_id), hook_input, observed_at_ns=observed_at_ns)
        except FileExistsError:
            return "DENY", reasons + [used]
        except (OSError, ValueError):
            return "DENY", reasons + ["governed_run:record_unavailable"]
    elif event == "PostToolUse":
        grant_id = claim_for_call(binding, grant_state, hook_input.get("tool_use_id"))
        if grant_id is None or _is_continuation_id(grant_id) is not continuation:
            return decision, reasons + [unclaimed]
        try:
            write_outcome(data_root, binding, grant_id, hook_input, observed_at_ns=observed_at_ns)
        except (OSError, ValueError):
            return decision, reasons + ["governed_run:record_unavailable"]
    return decision, reasons


def _settle_close(
    data_root: Path, binding: Mapping[str, Any], hook_input: Mapping[str, Any],
    grant_state: Mapping[str, Any], reasons: list[str], *, observed_at_ns: int,
) -> list[str]:
    """Mark the worker one completed close call ended.

    The marker is written create-only for a target this run's spawn results
    bound, so marking a worker twice says the same thing once and a close of
    anything else marks nothing.
    """

    if hook_input.get("hook_event_name") != "PostToolUse":
        return reasons
    tool_input = hook_input.get("tool_input")
    target = tool_input.get("target") if isinstance(tool_input, Mapping) else None
    bound = round_workers(binding, grant_state) | earlier_workers(binding, grant_state)
    if not isinstance(target, str) or target not in bound:
        return reasons
    try:
        write_close(data_root, binding, target, hook_input, observed_at_ns=observed_at_ns)
    except FileExistsError:
        return reasons
    except (OSError, ValueError):
        return reasons + ["governed_run:record_unavailable"]
    return reasons


__all__ = [
    "BINDING_FIELDS",
    "BINDING_SCHEMA",
    "CLOSE_FIELDS",
    "COLLABORATION_TOOLS",
    "CONTINUATION_FIELDS",
    "EVENT_FIELDS",
    "EVENT_SCHEMA",
    "GRANT_CLAIM_SCHEMA",
    "GRANT_CLOSE_SCHEMA",
    "GRANT_OUTCOME_SCHEMA",
    "LEGACY_BINDING_FIELDS",
    "LEGACY_BINDING_SCHEMA",
    "MAX_CONTINUATIONS",
    "MAX_REVISION",
    "REPAIR_GRANT",
    "binding_issues",
    "binding_path",
    "binding_revision",
    "canonical_tool_name",
    "claim_for_call",
    "close_key",
    "closed_workers",
    "continuation_grant",
    "continuation_permission",
    "decide",
    "earlier_workers",
    "event_record",
    "events_root",
    "grants_root",
    "hook_decision",
    "hook_output",
    "is_collaboration_tool",
    "item_type_for_tool",
    "message_digest",
    "quiet_tool",
    "read_binding",
    "read_events",
    "read_grant_state",
    "revision_grant_id",
    "round_workers",
    "seal_binding",
    "session_key",
    "sha256",
    "spawn_grant",
    "spawn_permission",
    "spawned_agent_id",
    "write_event",
    "write_close",
]
