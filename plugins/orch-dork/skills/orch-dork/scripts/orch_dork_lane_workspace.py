#!/usr/bin/env python3
"""Issue 96: materialized lane workspaces with masking and release receipts.

The v3 plan model promises resource isolation, but shared-checkout execution
provides one filesystem plus a polite request.  This module closes that gap
for the read side the same way the worktree runner closed the write side:

* A lane workspace is a disposable git worktree pinned to an exact revision
  (delegated to `orch_dork_worktree_runner.WorktreeSession`, which owns
  containment, pinning, and cleanup receipts).
* Sibling-owned paths named by the frozen plan are *masked*: removed from the
  materialized tree before the lane ever runs, so a masked read is impossible
  rather than forbidden.  Because the worktree is pinned to the base
  revision, sibling *uncommitted* progress is invisible even when a path is
  not masked.
* Release is a filesystem event, not a sentence in a prompt: the coordinator
  copies exact released files from the released lane's tree into this
  workspace and gets back a hash-bound `lane-release-receipt/v1`.

Nothing here spawns a process or invokes a model.  All receipts are digest
bound so they cannot be transplanted onto another run.  Standard library
only.
"""

from __future__ import annotations

import hashlib
import shutil
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from orch_dork_worktree_runner import (
    WorktreeSession, PlannedWorktreePathError,
)
import orch_dork_evidence_core as evidence_core

MANIFEST_SCHEMA = "orch-dork/lane-workspace-manifest/v1"
RELEASE_SCHEMA = "orch-dork/lane-release-receipt/v1"

REASON_MASK_ESCAPES = "MASK_ESCAPES_WORKSPACE"
REASON_RELEASE_SOURCE_MISSING = "RELEASE_SOURCE_MISSING"
REASON_RELEASE_ESCAPES = "RELEASE_ESCAPES_WORKSPACE"
REASON_WORKSPACE_INACTIVE = "WORKSPACE_INACTIVE"
REASON_BAD_FIELD = "INVALID_FIELD"


class LaneWorkspaceError(RuntimeError):
    """Typed refusal carrying a stable machine-readable reason."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__("%s: %s" % (reason, detail) if detail else reason)
        self.reason = reason
        self.detail = detail


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_sha256_text = evidence_core.digest


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_inside(root: Path, raw: str, *, reason: str) -> Path:
    """Resolve raw as a relative path strictly inside root, or refuse."""
    if not isinstance(raw, str) or not raw or raw.startswith("/") or "\x00" in raw:
        raise LaneWorkspaceError(reason, "path must be a relative string: %r" % (raw,))
    candidate = (root / raw).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise LaneWorkspaceError(reason, raw)
    return candidate


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Recompute the manifest binding digest over every non-digest field."""
    body = {k: manifest[k] for k in manifest if k != "manifest_sha256"}
    return _sha256_text(body)


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    """Recompute the release-receipt binding digest."""
    body = {k: receipt[k] for k in receipt if k != "receipt_sha256"}
    return _sha256_text(body)


class LaneWorkspace:
    """One lane's materialized, masked, pinned execution tree."""

    def __init__(self, repo_root: str | Path, run_root: str | Path, *,
                 lane_id: str, owned_resources: Iterable[str] = (),
                 masked_resources: Iterable[str] = (),
                 planned_worktree_id: str | None = None):
        if not isinstance(lane_id, str) or not lane_id:
            raise LaneWorkspaceError(REASON_BAD_FIELD, "lane_id must be non-empty")
        self.lane_id = lane_id
        self.owned_resources = tuple(owned_resources)
        self.masked_resources = tuple(masked_resources)
        self._planned_worktree_id = planned_worktree_id
        self._session = WorktreeSession(
            repo_root, run_root,
            worker_id=lane_id,
            worktree_id=planned_worktree_id,
        )
        self._manifest: dict[str, Any] | None = None

    @property
    def active(self) -> bool:
        return self._manifest is not None

    @property
    def workspace(self) -> Path | None:
        return self._session.path

    @property
    def manifest(self) -> dict[str, Any] | None:
        """Return an isolated view of the live materialization binding."""

        return deepcopy(self._manifest) if self._manifest is not None else None

    def materialize(self, revision: str) -> dict[str, Any]:
        """Create the pinned worktree, apply masks, and bind the manifest.

        When ``planned_worktree_id`` was supplied, the worktree path is
        validated by the runner's shared creation gate before Git. The
        canonical path is recorded in the manifest for the supervisor's
        comparison before runtime dispatch.
        """

        try:
            self._session.create(revision)
        except PlannedWorktreePathError as error:
            raise LaneWorkspaceError(error.reason, 'planned ' + str(error)) from error
        root = self._session.path
        assert root is not None
        masked_rows: list[dict[str, Any]] = []
        try:
            for raw in self.masked_resources:
                target = _relative_inside(root, raw, reason=REASON_MASK_ESCAPES)
                existed = target.exists() or target.is_symlink()
                row: dict[str, Any] = {"path": raw, "existed": bool(existed)}
                if existed and target.is_file() and not target.is_symlink():
                    row["sha256"] = _sha256_file(target)
                if existed:
                    if target.is_dir() and not target.is_symlink():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                masked_rows.append(row)
        except LaneWorkspaceError:
            self._session.cleanup()
            raise
        manifest: dict[str, Any] = {
            "schema": MANIFEST_SCHEMA,
            "lane_id": self.lane_id,
            "workspace": str(root),
            "base_revision": self._session.base_revision,
            "owned": sorted(self.owned_resources),
            "masked": masked_rows,
            "created_at": _now(),
        }
        if self._planned_worktree_id is not None:
            manifest["planned_worktree_id"] = self._planned_worktree_id
            manifest["planned_worktree_canonical_path"] = str(
                self._session.run_root / self._session.worktree_id
            )
        manifest["manifest_sha256"] = manifest_digest(manifest)
        self._manifest = manifest
        return manifest

    def release_into(self, source_root: str | Path, paths: Iterable[str], *,
                     released_by: str) -> dict[str, Any]:
        """Copy exact released files into this workspace; bind a receipt."""
        if self._manifest is None:
            raise LaneWorkspaceError(
                REASON_WORKSPACE_INACTIVE, "materialize before release")
        if not isinstance(released_by, str) or not released_by:
            raise LaneWorkspaceError(REASON_BAD_FIELD, "released_by required")
        root = self._session.path
        assert root is not None
        source = Path(source_root)
        rows: list[dict[str, Any]] = []
        staged: list[tuple[Path, Path]] = []
        for raw in paths:
            src = _relative_inside(source, raw, reason=REASON_RELEASE_ESCAPES)
            dst = _relative_inside(root, raw, reason=REASON_RELEASE_ESCAPES)
            if not src.is_file():
                raise LaneWorkspaceError(REASON_RELEASE_SOURCE_MISSING, raw)
            staged.append((src, dst))
            rows.append({"path": raw, "sha256": _sha256_file(src)})
        for src, dst in staged:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        receipt: dict[str, Any] = {
            "schema": RELEASE_SCHEMA,
            "lane_id": self.lane_id,
            "released_by": released_by,
            "workspace_manifest_sha256": self._manifest["manifest_sha256"],
            "files": rows,
            "released_at": _now(),
        }
        receipt["receipt_sha256"] = receipt_digest(receipt)
        return receipt

    def cleanup(self) -> dict[str, Any]:
        """Destroy the workspace; return the runner's cleanup receipt."""
        receipt = self._session.cleanup()
        self._manifest = None
        return receipt

    def __enter__(self) -> "LaneWorkspace":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.active:
            self.cleanup()
