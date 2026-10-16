#!/usr/bin/env python3
"""Close and settle one observed-complete spawn stall."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterator, Mapping


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_governed_native_controller as native_controller  # noqa: E402
import orch_dork_observer_authority as observer_authority  # noqa: E402
import orch_dork_observer_receipt as observer_receipt  # noqa: E402
import orch_dork_qualification_successor as successor  # noqa: E402


RECEIPT_SCHEMA = (
    "orch-dork/qualification-observed-spawn-stall-recovery-"
    "artifact-receipt/v2"
)
RECEIPT_KIND = "stage-l-predecessor-recovery"
MAX_ARTIFACT_BYTES = 4_194_304
MAX_STDOUT_BYTES = 4_096


class ObservedSpawnStallRecoveryDriverError(ValueError):
    """Stable local-driver refusal."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@contextmanager
def _bound_observer_authority(
    trust_store: Path,
    replay_db: Path,
) -> Iterator[None]:
    paths = (trust_store, replay_db)
    try:
        resolved = tuple(path.resolve(strict=True) for path in paths)
    except OSError as error:
        raise ObservedSpawnStallRecoveryDriverError(
            "observed_spawn_stall_recovery:"
            "observer_authority_path_invalid"
        ) from error
    if (
        any(not path.is_absolute() or path.is_symlink() for path in paths)
        or resolved != paths
        or trust_store.parent != replay_db.parent
        or trust_store.name != observer_authority.TRUST_STORE_FILENAME
        or replay_db.name != observer_authority.REPLAY_DB_FILENAME
        or any(not path.is_file() for path in paths)
    ):
        raise ObservedSpawnStallRecoveryDriverError(
            "observed_spawn_stall_recovery:"
            "observer_authority_path_invalid"
        )
    bindings = {
        observer_receipt.TRUST_STORE_ENV: str(trust_store),
        observer_receipt.REPLAY_DB_ENV: str(replay_db),
    }
    previous = {name: os.environ.get(name) for name in bindings}
    if any(
        value is not None and value != bindings[name]
        for name, value in previous.items()
    ):
        raise ObservedSpawnStallRecoveryDriverError(
            "observed_spawn_stall_recovery:"
            "observer_authority_environment_conflict"
        )
    try:
        os.environ.update(bindings)
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def recover_observed_spawn_stall(
    *,
    plugin_data: Path,
    source_root: Path,
    evidence_root: Path,
    terminal_snapshot: Path,
    terminal_snapshot_sha256: str,
    worker_rollout: Path,
    worker_rollout_sha256: str,
    historical_runtime_plugin_root: Path,
    historical_runtime_package_digest: str,
) -> dict[str, Any]:
    """Terminalize the sealed stall, then release every reserved lane."""

    hook_path = (
        historical_runtime_plugin_root / "hooks" / "project_ground_hook.py"
    )
    roots = {"evidence": evidence_root, "source": source_root}
    controller = native_controller.GovernedNativeController(
        plugin_data=plugin_data,
        hook_definition_path=hook_path,
        source_roots=roots,
    )
    try:
        authority = controller.grants.canonical_authority()
        owner = authority.get("owner")
        tip = authority.get("tip")
        if (
            not isinstance(owner, Mapping)
            or not isinstance(owner.get("controller_id"), str)
            or not isinstance(tip, Mapping)
        ):
            raise ObservedSpawnStallRecoveryDriverError(
                "observed_spawn_stall_recovery:controller_authority_invalid"
            )
        program = (
            native_controller
            .build_observed_spawn_stall_terminalization_program(
                controller_id=owner["controller_id"],
                expected_cursor=tip,
                terminal_snapshot_path=terminal_snapshot,
                expected_terminal_snapshot_artifact_sha256=(
                    terminal_snapshot_sha256
                ),
                worker_rollout_path=worker_rollout,
                expected_worker_rollout_artifact_sha256=(
                    worker_rollout_sha256
                ),
                historical_runtime_root=historical_runtime_plugin_root,
                expected_package_digest=(
                    historical_runtime_package_digest
                ),
            )
        )
        terminalized = controller.terminalize_observed_spawn_stall(program)
    finally:
        controller.store.close()
    if (
        terminalized.get("status") != "PASS"
        or terminalized.get("decision")
        != "OBSERVED_SPAWN_STALL_TERMINALIZED"
        or terminalized.get("issues") != []
    ):
        # Keep the controller's issues: a recovery that refuses before any
        # mutation must be diagnosable from its own output.
        raise ObservedSpawnStallRecoveryDriverError(
            "observed_spawn_stall_recovery:terminalization_refused:"
            + ",".join(str(issue) for issue in (terminalized.get("issues") or []))
        )
    # The settler is the single acceptor: it returns the whole report through
    # the strict artifact validator (which checks the seal), so the bytes this
    # driver persists are the ones every later consumer re-derives, and a
    # refused settlement surfaces as the settler's own named refusal.
    return successor.settle_observed_spawn_stall_capacity(
        plugin_data=plugin_data,
        hook_definition_path=hook_path,
        source_roots=roots,
    )


def recover_owner_closed_ack_stall(
    *, plugin_data: Path, source_root: Path, evidence_root: Path,
    program: Mapping[str, Any], historical_runtime_plugin_root: Path,
    historical_runtime_package_digest: str, now: datetime | None = None,
) -> dict[str, Any]:
    """Recover one exact unused continuation without resuming its closed owner."""

    if (
        program.get("historical_runtime_root") != str(historical_runtime_plugin_root)
        or program.get("historical_package_digest") != historical_runtime_package_digest
    ):
        raise ObservedSpawnStallRecoveryDriverError("owner_closed_ack_stall:historical_runtime_mismatch")
    hook_path = historical_runtime_plugin_root / "hooks/project_ground_hook.py"
    roots = {"evidence": evidence_root, "source": source_root}
    controller = native_controller.GovernedNativeController(
        plugin_data=plugin_data, hook_definition_path=hook_path, source_roots=roots,
    )
    try:
        terminalized = controller.terminalize_owner_closed_ack_stall(program)
    finally:
        controller.store.close()
    if terminalized.get("status") != "PASS" or terminalized.get("decision") != "OBSERVED_SPAWN_STALL_TERMINALIZED" or terminalized.get("issues") != []:
        raise ObservedSpawnStallRecoveryDriverError(
            "observed_spawn_stall_recovery:terminalization_refused:"
            + ",".join(str(issue) for issue in terminalized.get("issues", []))
        )
    return successor.settle_observed_spawn_stall_capacity(
        plugin_data=plugin_data, hook_definition_path=hook_path, source_roots=roots, now=now,
    )


def _prepare_artifact(report: Mapping[str, Any]) -> bytes:
    payload = _canonical(report) + b"\n"
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ObservedSpawnStallRecoveryDriverError(
            "observed_spawn_stall_recovery:artifact_too_large"
        )
    return payload


def _build_receipt(
    *,
    output: Path,
    report: Mapping[str, Any],
    payload: bytes,
    signer: observer_receipt.FileHostSigner,
    issued_at: datetime,
) -> bytes:
    predecessor = report.get("predecessor")
    if not isinstance(predecessor, Mapping):
        raise ObservedSpawnStallRecoveryDriverError(
            "observed_spawn_stall_recovery:predecessor_invalid"
        )
    core = {
        "schema": RECEIPT_SCHEMA,
        "status": "PASS",
        "decision": "OBSERVED_SPAWN_STALL_RECOVERED",
        "issues": [],
        "artifact_path": str(output),
        "artifact_size_bytes": len(payload),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": report["report_sha256"],
        "predecessor_controller_id": predecessor.get("controller_id"),
        "released_authority_lane_ids": report.get(
            "released_authority_lane_ids"
        ),
        "disposition": "READY_FOR_FRESH_SUCCESSOR_ACTIVATION",
    }
    signed = signer.issue(
        RECEIPT_KIND,
        core,
        issued_at=(issued_at - timedelta(seconds=1)).isoformat(),
        valid_until=(issued_at + timedelta(minutes=4)).isoformat(),
        nonce="stage-l-predecessor-recovery-"
        + core["artifact_sha256"][:24],
    )
    sealed = {**core, "host_recovery_receipt": signed}
    receipt = {
        **sealed,
        "receipt_sha256": hashlib.sha256(_canonical(sealed)).hexdigest(),
    }
    stdout = _canonical(receipt) + b"\n"
    if len(stdout) > MAX_STDOUT_BYTES:
        raise ObservedSpawnStallRecoveryDriverError(
            "observed_spawn_stall_recovery:receipt_too_large"
        )
    return stdout


def _write_create_only(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-data", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--terminal-snapshot", type=Path)
    parser.add_argument("--terminal-snapshot-sha256")
    parser.add_argument("--worker-rollout", type=Path)
    parser.add_argument("--worker-rollout-sha256")
    parser.add_argument("--owner-closed-ack-program", type=Path)
    parser.add_argument("--owner-closed-ack-program-sha256")
    parser.add_argument(
        "--historical-runtime-plugin-root", type=Path, required=True
    )
    parser.add_argument(
        "--historical-runtime-package-digest", required=True
    )
    parser.add_argument("--observer-trust-store", type=Path, required=True)
    parser.add_argument("--observer-replay-db", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    output_descriptor = None
    try:
        program = None
        old_inputs = (args.terminal_snapshot, args.terminal_snapshot_sha256, args.worker_rollout, args.worker_rollout_sha256)
        if args.owner_closed_ack_program is not None:
            if any(value is not None for value in old_inputs) or args.owner_closed_ack_program_sha256 is None:
                raise ObservedSpawnStallRecoveryDriverError("owner_closed_ack_stall:ambiguous_inputs")
            from orch_dork_owned_file import read_owned_bytes
            raw = read_owned_bytes(args.owner_closed_ack_program, max_bytes=65_536, required_mode=0o600)
            if hashlib.sha256(raw).hexdigest() != args.owner_closed_ack_program_sha256:
                raise ObservedSpawnStallRecoveryDriverError("owner_closed_ack_stall:program_changed")
            program = json.loads(raw.decode("utf-8"))
            if not args.output.is_absolute() or args.output.is_symlink():
                raise ObservedSpawnStallRecoveryDriverError("owner_closed_ack_stall:output_path_invalid")
            args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Reserve the create-only output before controller or capacity changes.
            output_descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
        elif not all(value is not None for value in old_inputs) or args.owner_closed_ack_program_sha256 is not None:
            raise ObservedSpawnStallRecoveryDriverError("observed_spawn_stall_recovery:inputs_incomplete")
        with _bound_observer_authority(
            args.observer_trust_store, args.observer_replay_db
        ):
            authority = observer_authority.inspect_authority(
                state_dir=args.observer_trust_store.parent
            )
            signer = observer_receipt.FileHostSigner.from_host_file(
                args.observer_trust_store.parent
                / observer_authority.SEED_FILENAME,
                key_id=authority["key_id"],
                host_id=authority["host_id"],
            )
            if program is not None:
                report = recover_owner_closed_ack_stall(
                    plugin_data=args.plugin_data, source_root=args.source_root,
                    evidence_root=args.evidence_root, program=program,
                    historical_runtime_plugin_root=args.historical_runtime_plugin_root,
                    historical_runtime_package_digest=args.historical_runtime_package_digest,
                )
            else:
                report = recover_observed_spawn_stall(
                plugin_data=args.plugin_data,
                source_root=args.source_root,
                evidence_root=args.evidence_root,
                terminal_snapshot=args.terminal_snapshot,
                terminal_snapshot_sha256=args.terminal_snapshot_sha256,
                worker_rollout=args.worker_rollout,
                worker_rollout_sha256=args.worker_rollout_sha256,
                historical_runtime_plugin_root=(
                    args.historical_runtime_plugin_root
                ),
                historical_runtime_package_digest=(
                    args.historical_runtime_package_digest
                ),
            )
            payload = _prepare_artifact(report)
            stdout = _build_receipt(
                output=args.output,
                report=report,
                payload=payload,
                signer=signer,
                issued_at=datetime.now(timezone.utc),
            )
        if output_descriptor is None:
            _write_create_only(args.output, payload)
        else:
            with os.fdopen(output_descriptor, "wb", closefd=True) as handle:
                output_descriptor = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
    except Exception as error:
        issue = (
            str(error)
            if isinstance(
                error,
                (
                    successor.QualificationSuccessorError,
                    ObservedSpawnStallRecoveryDriverError,
                ),
            )
            else "observed_spawn_stall_recovery:driver_failure"
        )
        print(
            json.dumps(
                {
                    "schema": (
                        successor
                        .OBSERVED_SPAWN_STALL_SETTLEMENT_REPORT_SCHEMA
                    ),
                    "status": "FAIL",
                    "decision": "REFUSED",
                    "issues": [issue],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    finally:
        if output_descriptor is not None:
            os.close(output_descriptor)
    sys.stdout.buffer.write(stdout)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
