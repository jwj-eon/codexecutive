#!/usr/bin/env python3
"""Physically bind write-capable workers to one live lane worktree.

Native collaboration currently exposes no spawn-time working-directory field.
This boundary therefore permits native launches only for read-only analysis and
fails closed for writes before a model call.  The contained-process adapter is
the executable path: it re-derives a bubblewrap policy from the live
``LaneWorkspace`` object and launches with that exact disposable worktree as
both the only writable root and the enforced working directory.

The module owns launch binding, not worktree creation.  ``LaneWorkspace`` owns
materialization and cleanup; ``orch_dork_workspace_sandbox`` owns process and
filesystem enforcement.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import orch_dork_lane_workspace as lane_workspace
import orch_dork_evidence_core as evidence_core
import orch_dork_workspace_sandbox as sandbox


PLAN_SCHEMA = "orch-dork/workspace-launch-plan/v1"
RECEIPT_SCHEMA = "orch-dork/workspace-launch-receipt/v1"
NATIVE_ADAPTER_ID = "native-collaboration/read-only-v1"
CONTAINED_ADAPTER_ID = "contained-process/bwrap-v1"

REASON_OK = "OK"
REASON_NATIVE_CWD_BINDING_UNAVAILABLE = "NATIVE_CWD_BINDING_UNAVAILABLE"
REASON_WORKSPACE_INACTIVE = "WORKSPACE_INACTIVE"
REASON_WORKSPACE_STALE = "WORKSPACE_STALE"
REASON_WORKSPACE_PATH_MISMATCH = "WORKSPACE_PATH_MISMATCH"
REASON_LAUNCH_PLAN_FORGED = "LAUNCH_PLAN_FORGED"
REASON_NATIVE_CREATION_FAILED = "NATIVE_CREATION_FAILED"
REASON_NATIVE_CREATION_AMBIGUOUS = "NATIVE_CREATION_AMBIGUOUS"
REASON_INVALID_FIELD = "INVALID_FIELD"

_SHA256 = evidence_core.SHA256_PATTERN
_PLAN_FIELDS = {
    "schema",
    "adapter_id",
    "attempt_id",
    "lane_id",
    "workspace",
    "base_revision",
    "manifest_sha256",
    "command",
    "scratch_dir",
    "tmp_dir",
    "network_granted",
    "limits",
    "sandbox_policy_digest",
    "sandbox_argv",
    "plan_sha256",
}


_sha = evidence_core.digest


def _report(
    *,
    status: str,
    reason: str,
    adapter_id: str,
    lane_id: Any = None,
    manifest_sha256: Any = None,
    workspace: Any = None,
    binding_kind: str | None = None,
    binding_enforced: bool = False,
    launch_permitted: bool = False,
    execution: Mapping[str, Any] | None = None,
    worker_id: str | None = None,
    model_calls: int | None = 0,
    workers_created: int | None = 0,
    provider_free: bool = True,
) -> dict[str, Any]:
    core = {
        "schema": RECEIPT_SCHEMA,
        "status": status,
        "reason": reason,
        "adapter_id": adapter_id,
        "lane_id": lane_id,
        "manifest_sha256": manifest_sha256,
        "workspace": workspace,
        "enforced_cwd": workspace if binding_enforced else None,
        "binding_kind": binding_kind,
        "binding_enforced": binding_enforced,
        "launch_permitted": launch_permitted,
        "execution": dict(execution) if isinstance(execution, Mapping) else None,
        "worker_id": worker_id,
        "provider_free": provider_free,
        "model_calls": model_calls,
        "workers_created": workers_created,
    }
    return evidence_core.seal(core, "receipt_sha256")


def _execution_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project launch evidence without leaking argv or worker output."""

    stdout = value.get("stdout") if isinstance(value.get("stdout"), str) else ""
    stderr = value.get("stderr") if isinstance(value.get("stderr"), str) else ""
    argv = value.get("argv") if isinstance(value.get("argv"), list) else []
    return {
        "status": value.get("status"),
        "reason": value.get("reason"),
        "executed": value.get("executed"),
        "exit_code": value.get("exit_code"),
        "plan_digest": value.get("plan_digest"),
        "chdir": value.get("chdir"),
        "argv_sha256": evidence_core.digest(argv),
        "stdout_bytes": len(stdout.encode("utf-8")),
        "stdout_sha256": evidence_core.byte_digest(stdout.encode("utf-8")),
        "stderr_bytes": len(stderr.encode("utf-8")),
        "stderr_sha256": evidence_core.byte_digest(stderr.encode("utf-8")),
    }


def _live_binding(
    workspace: Any,
    expected_manifest_sha256: str,
) -> tuple[dict[str, Any] | None, str | None]:
    """Return the live manifest and real path, or one stable refusal code."""

    if not isinstance(expected_manifest_sha256, str) or _SHA256.fullmatch(
        expected_manifest_sha256
    ) is None:
        return None, REASON_INVALID_FIELD
    if workspace is None or getattr(workspace, "active", False) is not True:
        return None, REASON_WORKSPACE_INACTIVE
    manifest = getattr(workspace, "manifest", None)
    path = getattr(workspace, "workspace", None)
    if not isinstance(manifest, Mapping) or path is None:
        return None, REASON_WORKSPACE_INACTIVE
    manifest_value = dict(manifest)
    if (
        manifest_value.get("schema") != lane_workspace.MANIFEST_SCHEMA
        or lane_workspace.manifest_digest(manifest_value)
        != manifest_value.get("manifest_sha256")
        or manifest_value.get("manifest_sha256") != expected_manifest_sha256
    ):
        return None, REASON_WORKSPACE_STALE
    real = Path(path).resolve()
    if not real.is_dir() or manifest_value.get("workspace") != str(real):
        return None, REASON_WORKSPACE_PATH_MISMATCH
    manifest_value["_real_workspace"] = str(real)
    return manifest_value, None


class NativeCollaborationAdapter:
    """Authorize native collaboration only when no worker write is possible."""

    adapter_id = NATIVE_ADAPTER_ID

    def authorize(
        self,
        workspace: Any,
        *,
        expected_manifest_sha256: str,
        write_capable: bool,
    ) -> dict[str, Any]:
        manifest, reason = _live_binding(workspace, expected_manifest_sha256)
        if reason is not None:
            return _report(
                status="REFUSED",
                reason=reason,
                adapter_id=self.adapter_id,
            )
        assert manifest is not None
        lane_id = manifest.get("lane_id")
        real = manifest["_real_workspace"]
        if type(write_capable) is not bool:
            return _report(
                status="REFUSED",
                reason=REASON_INVALID_FIELD,
                adapter_id=self.adapter_id,
                lane_id=lane_id,
                manifest_sha256=expected_manifest_sha256,
                workspace=real,
            )
        if write_capable:
            return _report(
                status="REFUSED",
                reason=REASON_NATIVE_CWD_BINDING_UNAVAILABLE,
                adapter_id=self.adapter_id,
                lane_id=lane_id,
                manifest_sha256=expected_manifest_sha256,
                workspace=real,
                binding_kind="write_native_unbound",
            )
        return _report(
            status="PASS",
            reason=REASON_OK,
            adapter_id=self.adapter_id,
            lane_id=lane_id,
            manifest_sha256=expected_manifest_sha256,
            workspace=real,
            binding_kind="read_only_native_unbound",
            binding_enforced=False,
            launch_permitted=True,
        )

    def launch(
        self,
        workspace: Any,
        *,
        expected_manifest_sha256: str,
        write_capable: bool,
        worker_factory: Callable[[], Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Gate the native creation call itself, not only its prompt.

        ``worker_factory`` is invoked exactly once only after authorization.
        A write-capable request therefore returns the refusal receipt without
        entering the host task-creation seam or giving a worker a chance to
        make a model call.
        """

        authorization = self.authorize(
            workspace,
            expected_manifest_sha256=expected_manifest_sha256,
            write_capable=write_capable,
        )
        if authorization.get("status") != "PASS":
            return authorization
        if not callable(worker_factory):
            return _report(
                status="REFUSED",
                reason=REASON_INVALID_FIELD,
                adapter_id=self.adapter_id,
                lane_id=authorization.get("lane_id"),
                manifest_sha256=authorization.get("manifest_sha256"),
                workspace=authorization.get("workspace"),
                binding_kind=authorization.get("binding_kind"),
            )
        try:
            created = worker_factory()
        except Exception:
            return _report(
                status="AMBIGUOUS",
                reason=REASON_NATIVE_CREATION_AMBIGUOUS,
                adapter_id=self.adapter_id,
                lane_id=authorization.get("lane_id"),
                manifest_sha256=authorization.get("manifest_sha256"),
                workspace=authorization.get("workspace"),
                binding_kind=authorization.get("binding_kind"),
                provider_free=False,
                model_calls=None,
                workers_created=None,
            )
        worker_id = (
            created.get("worker_id") if isinstance(created, Mapping) else None
        )
        if (
            not isinstance(created, Mapping)
            or not isinstance(worker_id, str)
            or not worker_id.strip()
            or created.get("status") != "created"
        ):
            return _report(
                status="REFUSED",
                reason=REASON_NATIVE_CREATION_FAILED,
                adapter_id=self.adapter_id,
                lane_id=authorization.get("lane_id"),
                manifest_sha256=authorization.get("manifest_sha256"),
                workspace=authorization.get("workspace"),
                binding_kind=authorization.get("binding_kind"),
                provider_free=False,
                model_calls=None,
            )
        return _report(
            status="PASS",
            reason=REASON_OK,
            adapter_id=self.adapter_id,
            lane_id=authorization.get("lane_id"),
            manifest_sha256=authorization.get("manifest_sha256"),
            workspace=authorization.get("workspace"),
            binding_kind=authorization.get("binding_kind"),
            binding_enforced=False,
            launch_permitted=True,
            worker_id=worker_id,
            provider_free=False,
            model_calls=None,
            workers_created=1,
        )


class ContainedProcessAdapter:
    """Plan and execute one command in the exact live lane worktree."""

    adapter_id = CONTAINED_ADAPTER_ID

    def plan(
        self,
        workspace: Any,
        *,
        expected_manifest_sha256: str,
        attempt_id: str,
        command: Sequence[str],
        scratch_dir: str | Path,
        tmp_dir: str | Path,
        executor: Any = None,
        limits: sandbox.WorkspaceLimits | None = None,
        network_granted: bool = False,
    ) -> dict[str, Any]:
        manifest, reason = _live_binding(workspace, expected_manifest_sha256)
        if reason is not None:
            raise sandbox.SandboxPolicyError(reason)
        if not isinstance(attempt_id, str) or not attempt_id:
            raise sandbox.SandboxPolicyError(REASON_INVALID_FIELD)
        assert manifest is not None
        real = manifest["_real_workspace"]
        effective_limits = limits or sandbox.WorkspaceLimits()
        policy = sandbox.WorkspaceSandboxPolicy(
            attempt_id=attempt_id,
            lane_id=str(manifest.get("lane_id")),
            workspace=real,
            writable_roots=(real,),
            scratch_dir=scratch_dir,
            tmp_dir=tmp_dir,
            network_granted=network_granted,
            command=tuple(command),
            limits=effective_limits,
            working_directory=real,
            workspace_write_granted=True,
        )
        features = sandbox.detect_bwrap(executor=executor)
        sandbox_plan = sandbox.build_launch_plan(policy, features)
        core = {
            "schema": PLAN_SCHEMA,
            "adapter_id": self.adapter_id,
            "attempt_id": attempt_id,
            "lane_id": manifest.get("lane_id"),
            "workspace": real,
            "base_revision": manifest.get("base_revision"),
            "manifest_sha256": expected_manifest_sha256,
            "command": list(command),
            "scratch_dir": str(Path(scratch_dir).resolve()),
            "tmp_dir": str(Path(tmp_dir).resolve()),
            "network_granted": network_granted,
            "limits": effective_limits.as_dict(),
            "sandbox_policy_digest": sandbox_plan.policy_digest,
            "sandbox_argv": list(sandbox_plan.argv),
        }
        return evidence_core.seal(core, "plan_sha256")

    def launch(
        self,
        workspace: Any,
        plan: Any,
        *,
        executor: Any = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        value = dict(plan) if isinstance(plan, Mapping) else {}
        unsigned = dict(value)
        supplied_sha = unsigned.pop("plan_sha256", None)
        if (
            set(value) != _PLAN_FIELDS
            or value.get("schema") != PLAN_SCHEMA
            or value.get("adapter_id") != self.adapter_id
            or supplied_sha != _sha(unsigned)
        ):
            return _report(
                status="REFUSED",
                reason=REASON_LAUNCH_PLAN_FORGED,
                adapter_id=self.adapter_id,
            )
        manifest, reason = _live_binding(workspace, value["manifest_sha256"])
        if reason is not None:
            return _report(
                status="REFUSED",
                reason=reason,
                adapter_id=self.adapter_id,
            )
        assert manifest is not None
        real = manifest["_real_workspace"]
        if (
            value.get("workspace") != real
            or value.get("lane_id") != manifest.get("lane_id")
            or value.get("base_revision") != manifest.get("base_revision")
        ):
            return _report(
                status="REFUSED",
                reason=REASON_LAUNCH_PLAN_FORGED,
                adapter_id=self.adapter_id,
                lane_id=manifest.get("lane_id"),
                manifest_sha256=manifest.get("manifest_sha256"),
                workspace=real,
            )
        try:
            limits = sandbox.WorkspaceLimits(**value["limits"])
            policy = sandbox.WorkspaceSandboxPolicy(
                attempt_id=value["attempt_id"],
                lane_id=value["lane_id"],
                workspace=real,
                writable_roots=(real,),
                scratch_dir=value["scratch_dir"],
                tmp_dir=value["tmp_dir"],
                network_granted=value["network_granted"],
                command=tuple(value["command"]),
                limits=limits,
                working_directory=real,
                workspace_write_granted=True,
            )
            features = sandbox.detect_bwrap(executor=executor)
            expected = sandbox.build_launch_plan(policy, features)
            if (
                expected.policy_digest != value["sandbox_policy_digest"]
                or list(expected.argv) != value["sandbox_argv"]
                or expected.chdir != real
            ):
                return _report(
                    status="REFUSED",
                    reason=REASON_LAUNCH_PLAN_FORGED,
                    adapter_id=self.adapter_id,
                    lane_id=value.get("lane_id"),
                    manifest_sha256=value.get("manifest_sha256"),
                    workspace=real,
                )
            execution = sandbox.launch(
                policy,
                plan=expected,
                dry_run=dry_run,
                executor=executor,
            )
        except (KeyError, TypeError, ValueError, sandbox.SandboxPolicyError) as exc:
            reason = (
                exc.reason
                if isinstance(exc, sandbox.SandboxPolicyError)
                else REASON_LAUNCH_PLAN_FORGED
            )
            return _report(
                status="REFUSED",
                reason=reason,
                adapter_id=self.adapter_id,
                lane_id=value.get("lane_id"),
                manifest_sha256=value.get("manifest_sha256"),
                workspace=real,
            )
        successful = execution.get("status") == "EXECUTED"
        planned = execution.get("status") == "PLANNED"
        return _report(
            status="PASS" if successful else "PLANNED" if planned else "REFUSED",
            reason=str(execution.get("reason", REASON_INVALID_FIELD)),
            adapter_id=self.adapter_id,
            lane_id=value.get("lane_id"),
            manifest_sha256=value.get("manifest_sha256"),
            workspace=real,
            binding_kind="contained_process",
            binding_enforced=successful,
            launch_permitted=successful,
            execution=_execution_evidence(execution),
        )


__all__ = [
    "PLAN_SCHEMA",
    "RECEIPT_SCHEMA",
    "REASON_INVALID_FIELD",
    "REASON_LAUNCH_PLAN_FORGED",
    "REASON_NATIVE_CREATION_AMBIGUOUS",
    "REASON_NATIVE_CREATION_FAILED",
    "REASON_NATIVE_CWD_BINDING_UNAVAILABLE",
    "REASON_OK",
    "REASON_WORKSPACE_INACTIVE",
    "REASON_WORKSPACE_PATH_MISMATCH",
    "REASON_WORKSPACE_STALE",
    "ContainedProcessAdapter",
    "NativeCollaborationAdapter",
]
