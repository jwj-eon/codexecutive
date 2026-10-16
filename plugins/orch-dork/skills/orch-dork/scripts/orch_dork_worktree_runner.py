#!/usr/bin/env python3
"""Issue 79: the first component in this tree that mutates a filesystem.

Every other worker module is an evaluator. `orch_dork_worker_workspace` says so
in its own docstring: it "never invokes a command, resolves a checkout, or
changes a file". That made the whole worker seam safe by construction and left
one thing missing -- something that actually creates the disposable worktree a
bounded-coding run needs, and destroys it afterwards.

This module is that runner, and it is deliberately narrow. It creates a
server-owned disposable git worktree pinned to an exact revision, hands back a
record shaped for the existing evaluator, and destroys the worktree while
emitting a cleanup receipt. It does not invoke a model, run lane commands, or
apply a patch; those arrive in later tickets on top of this lifecycle.

Containment is the whole design, because a runner that mutates state cannot be
safe by construction the way an evaluator is:

* Worktrees are only ever created under a caller-supplied root, and that root
  must be an existing directory that is not inside the source repository. A
  harness that can write into the repository it is testing is a harness that
  can destroy your work.
* Destruction is by exact recorded path only. The runner refuses to remove a
  path it did not itself create in this process, refuses anything that is not
  under the run root, and refuses a root-level or home-level path outright.
* The base revision must be an exact resolved commit. `HEAD`, `main`, and
  friends are refused, because a worktree pinned to a moving reference cannot
  produce reproducible evidence.
* Every receipt is hash-bound: the cleanup receipt digests the worktree
  identity and observed end state, so a receipt cannot be transplanted onto a
  different run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import orch_dork_evidence_core as evidence_core

WORKTREE_SCHEMA = "orch-dork/worker-worktree/v1"
CLEANUP_RECEIPT_SCHEMA = "orch-dork/worktree-cleanup-receipt/v1"
RUN_RECORD_SCHEMA = "orch-dork/worktree-run-record/v1"

_FULL_SHA = re.compile(r"\A[0-9a-f]{40}\Z")
_UNPINNED = frozenset({"HEAD", "LATEST", "WORKTREE", "CURRENT", "MAIN", "MASTER"})
GIT_TIMEOUT_SECONDS = 120
PLANNED_WORKTREE_PATH_ESCAPE = "path_escape"
PLANNED_WORKTREE_PATH_COLLISION = "path_collision"


class WorktreeRunnerError(RuntimeError):
    """Raised for any containment, git, or lifecycle failure. Fails closed."""


class PlannedWorktreePathError(WorktreeRunnerError):
    """A planned creation path escapes its identity or is already occupied."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_sha256 = evidence_core.legacy_ascii_digest


def _git(repo: Path, *args: str) -> str:
    """Run one git command with no shell and a bounded timeout."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WorktreeRunnerError(f"git {args[0]} failed: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        raise WorktreeRunnerError(
            f"git {args[0]} exited {completed.returncode}: {detail[0] if detail else 'no output'}"
        )
    return completed.stdout.strip()


def resolve_revision(repo: Path, revision: str) -> str:
    """Resolve a reference to an exact commit, refusing moving references."""

    if not isinstance(revision, str) or not revision.strip():
        raise WorktreeRunnerError("revision must be non-empty text")
    resolved = _git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if not _FULL_SHA.match(resolved):
        raise WorktreeRunnerError(f"revision did not resolve to a full commit: {resolved!r}")
    return resolved


def _require_containment(run_root: Path, repo_root: Path) -> None:
    """Refuse any run root that could let a worker write into the repository."""

    if not run_root.is_dir():
        raise WorktreeRunnerError(f"run root does not exist: {run_root}")
    resolved_root = run_root.resolve()
    resolved_repo = repo_root.resolve()
    if resolved_root == resolved_repo or resolved_repo in resolved_root.parents:
        raise WorktreeRunnerError("run root must not be inside the source repository")
    if resolved_root == Path(resolved_root.anchor) or resolved_root == Path.home():
        raise WorktreeRunnerError("run root must not be a filesystem or home root")


_PLANNED_WORKTREE_ID_MAX_BYTES = 128
_PLANNED_WORKTREE_ID_BANNED_CHARS = frozenset({"/", "\\", chr(0)})


def validate_planned_worktree_id(value: str) -> str:
    """Require a safe basename of at most 128 UTF-8 bytes.

    Refuse whitespace, path separators, NUL, leading/trailing dots and any
    embedded ``..``. Exact ``.``/``..`` refusals precede the other dot rules.
    Physical aliases and collisions belong to the shared creation gate.
    """

    if not isinstance(value, str) or not value:
        raise WorktreeRunnerError("planned_worktree_id must be non-empty text")
    if value != value.strip() or any(ch.isspace() for ch in value):
        raise WorktreeRunnerError(
            f"planned_worktree_id must not contain whitespace: {value!r}"
        )
    if len(value.encode("utf-8")) > _PLANNED_WORKTREE_ID_MAX_BYTES:
        raise WorktreeRunnerError(
            f"planned_worktree_id exceeds {_PLANNED_WORKTREE_ID_MAX_BYTES} bytes: {value!r}"
        )
    if value in {".", ".."}:
        raise WorktreeRunnerError(f"planned_worktree_id may not be {value!r}")
    if ".." in value:
        raise WorktreeRunnerError(
            f"planned_worktree_id may not contain traversal sequence: {value!r}"
        )
    if value.startswith("."):
        raise WorktreeRunnerError(
            f"planned_worktree_id may not start with a dot: {value!r}"
        )
    if value.endswith("."):
        raise WorktreeRunnerError(
            f"planned_worktree_id may not end with a dot: {value!r}"
        )
    for ch in _PLANNED_WORKTREE_ID_BANNED_CHARS:
        if ch in value:
            raise WorktreeRunnerError(
                f"planned_worktree_id contains banned character {ch!r}: {value!r}"
            )
    return value


def require_planned_worktree_creation(run_root: Path, worktree_id: str) -> Path:
    """Return the exact absent run-root/id path, refusing aliases and adoption.

    The caller supplies its canonical run root. Escapes are checked before
    collisions, preserving the public distinction for outward symlinks. An
    in-root symlink is a collision even when its target is absent. This gate
    is only for registration/creation; retained history may have no worktree.
    """
    target = run_root / validate_planned_worktree_id(worktree_id)
    try:
        canonical = target.resolve()
    except (OSError, RuntimeError) as error:
        raise PlannedWorktreePathError(
            PLANNED_WORKTREE_PATH_ESCAPE, f"worktree path cannot bind run root: {target}") from error
    if (not run_root.is_absolute() or
            canonical != run_root and run_root not in canonical.parents):
        raise PlannedWorktreePathError(
            PLANNED_WORKTREE_PATH_ESCAPE, f"worktree path escapes run_root: {canonical}")
    if target.is_symlink() or target.exists():
        raise PlannedWorktreePathError(
            PLANNED_WORKTREE_PATH_COLLISION, f"worktree path already exists: {target}")
    if canonical != target or canonical.parent != run_root:
        raise PlannedWorktreePathError(
            PLANNED_WORKTREE_PATH_ESCAPE, f"worktree path differs from its planned identity: {target}")
    return target


class WorktreeSession:
    """One disposable worktree, from creation through a sealed cleanup receipt.

    The session records the exact path it created. Cleanup removes that path and
    nothing else, so a caller cannot redirect destruction by editing a record.
    """

    def __init__(self, repo_root: str | Path, run_root: str | Path, *,
                 worker_id: str | None = None,
                 worktree_id: str | None = None):
        self.repo_root = Path(repo_root).expanduser().resolve()
        self.run_root = Path(run_root).expanduser().resolve()
        _require_containment(self.run_root, self.repo_root)
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:12]}"
        if worktree_id is None:
            self.worktree_id = f"wt-{uuid.uuid4().hex[:12]}"
        else:
            self.worktree_id = validate_planned_worktree_id(worktree_id)
        self._path: Path | None = None
        self._base_revision: str | None = None
        self._created_at: str | None = None
        self._cleaned = False

    @property
    def path(self) -> Path | None:
        return self._path

    @property
    def base_revision(self) -> str | None:
        return self._base_revision

    def create(self, revision: str) -> dict[str, Any]:
        """Create the worktree pinned to an exact commit."""

        if self._path is not None:
            raise WorktreeRunnerError("worktree already created for this session")
        if isinstance(revision, str) and revision.strip().upper() in _UNPINNED:
            raise WorktreeRunnerError(f"base revision must be pinned, got {revision!r}")
        target = require_planned_worktree_creation(self.run_root, self.worktree_id)
        resolved = resolve_revision(self.repo_root, revision)
        _git(self.repo_root, "worktree", "add", "--detach", str(target), resolved)
        self._path = target
        self._base_revision = resolved
        self._created_at = _now()
        return self.record()

    def record(self) -> dict[str, Any]:
        """Return the worktree record the workspace evaluator expects."""

        if self._path is None or self._base_revision is None:
            raise WorktreeRunnerError("worktree has not been created")
        return {
            "schema": WORKTREE_SCHEMA,
            "worktree_id": self.worktree_id,
            "owner": "server",
            "kind": "disposable",
            "disposable": True,
            "base_revision": self._base_revision,
            "created_from_revision": self._base_revision,
            "status": "destroyed" if self._cleaned else "active",
            "symlinks": [],
        }

    def observe(self) -> dict[str, Any]:
        """Report whether the worktree drifted from its pinned baseline."""

        if self._path is None:
            raise WorktreeRunnerError("worktree has not been created")
        status = _git(self._path, "status", "--porcelain=v1")
        # Porcelain v1 lines are "XY <path>": two status columns, one space,
        # then the path. Slicing at 3 would eat the first character of the name.
        changed = sorted(line[2:].strip() for line in status.splitlines() if line.strip())
        return {
            "schema": "orch-dork/worker-workspace-observation/v1",
            "status": "clean" if not changed else "drift",
            "changed_paths": changed,
        }

    def cleanup(self) -> dict[str, Any]:
        """Destroy the worktree and return a hash-bound cleanup receipt."""

        if self._path is None:
            raise WorktreeRunnerError("worktree has not been created")
        if self._cleaned:
            raise WorktreeRunnerError("cleanup already performed for this session")

        # Destruction is by the exact path this session created, re-checked
        # against the run root. A record cannot redirect it.
        target = self._path.resolve()
        if target.parent != self.run_root:
            raise WorktreeRunnerError("refusing to remove a path outside the run root")
        if target == self.run_root or target == Path(target.anchor) or target == Path.home():
            raise WorktreeRunnerError("refusing to remove a run root, filesystem root, or home")

        removal_error: str | None = None
        try:
            _git(self.repo_root, "worktree", "remove", "--force", str(target))
        except WorktreeRunnerError as exc:
            removal_error = str(exc)
            shutil.rmtree(target, ignore_errors=True)
        _git(self.repo_root, "worktree", "prune")

        destroyed = not target.exists()
        self._cleaned = True
        observed_at = _now()
        evidence = {
            "schema": CLEANUP_RECEIPT_SCHEMA,
            "worktree_id": self.worktree_id,
            "worker_id": self.worker_id,
            "base_revision": self._base_revision,
            "created_at": self._created_at,
            "observed_at": observed_at,
            "path_exists_after": not destroyed,
            "removal_fallback_used": removal_error is not None,
            "registered_worktrees_after": self.registered_paths(),
        }
        # The workspace evaluator accepts an exact key set on a cleanup record:
        # {status, worktree, evidence, source_pointer, recovery_id}. A top-level
        # schema key reads as an unknown field, so the receipt carries its
        # schema inside the evidence it seals.
        receipt = {
            "status": "complete" if destroyed else "incomplete",
            "worktree": "destroyed" if destroyed else "unknown",
            "evidence": evidence,
            "recovery_id": None if destroyed else f"recover-{self.worktree_id}",
        }
        receipt["evidence"]["receipt_sha256"] = _sha256(evidence)
        if not destroyed:
            raise WorktreeRunnerError(
                f"worktree still present after cleanup: {target} ({removal_error or 'no git error'})"
            )
        return receipt

    def registered_paths(self) -> list[str]:
        """List worktree paths git still tracks for this repository."""

        listing = _git(self.repo_root, "worktree", "list", "--porcelain")
        return sorted(
            line.split(" ", 1)[1].strip()
            for line in listing.splitlines()
            if line.startswith("worktree ")
        )

    def __enter__(self) -> "WorktreeSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # A failed run must not leak a worktree. Cleanup here is best-effort by
        # design: the caller already has its own failure to report, and masking
        # it with a cleanup error would lose the original cause.
        if self._path is not None and not self._cleaned:
            try:
                self.cleanup()
            except WorktreeRunnerError:
                pass


def run_lifecycle(repo_root: str | Path, run_root: str | Path, revision: str) -> dict[str, Any]:
    """Create, observe, and destroy one worktree, returning a sealed record."""

    session = WorktreeSession(repo_root, run_root)
    worktree = session.create(revision)
    observation = session.observe()
    receipt = session.cleanup()
    record = {
        "schema": RUN_RECORD_SCHEMA,
        "worker_id": session.worker_id,
        "worktree": {**worktree, "status": "destroyed"},
        "workspace_observation": observation,
        "cleanup": receipt,
        "executed_commands": 0,
        "model_calls": 0,
        "hosted_calls": 0,
        "patch_applied": False,
    }
    record["record_sha256"] = _sha256(record)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_root", help="Path to the source repository")
    parser.add_argument("revision", help="Exact revision to pin the worktree to")
    parser.add_argument("--run-root", help="Directory to create worktrees under")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    temporary: str | None = None
    try:
        run_root = args.run_root
        if not run_root:
            temporary = tempfile.mkdtemp(prefix="orch-dork-worktrees-")
            run_root = temporary
        record = run_lifecycle(args.repo_root, run_root, args.revision)
    except WorktreeRunnerError as exc:
        print(json.dumps({"status": "REFUSE", "reason": str(exc)}, sort_keys=True))
        return 1
    finally:
        if temporary:
            shutil.rmtree(temporary, ignore_errors=True)

    print(json.dumps(record, sort_keys=True, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
