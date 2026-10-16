#!/usr/bin/env python3
"""Recover a sealed profiled two-worker ACK bridge predecessor."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_observer_authority as observer_authority  # noqa: E402
import orch_dork_observer_receipt as observer_receipt  # noqa: E402
import orch_dork_qualification_successor as successor  # noqa: E402


RECEIPT_SCHEMA = (
    "orch-dork/qualification-post-ack-bridge-failure-recovery-"
    "artifact-receipt/v1"
)
MAX_ARTIFACT_BYTES = 4_194_304
MAX_STDOUT_BYTES = 4_096


class PostAckBridgeFailureRecoveryDriverError(ValueError):
    """Stable local-driver refusal."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _lane_pairs(values: list[str], *, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values:
        lane_id, separator, value = raw.partition("=")
        if (
            not separator
            or not lane_id.strip()
            or not value.strip()
            or lane_id in result
        ):
            raise PostAckBridgeFailureRecoveryDriverError(
                "post_ack_bridge_failure_recovery:" + label + "_invalid"
            )
        result[lane_id] = value
    if len(result) != 2:
        raise PostAckBridgeFailureRecoveryDriverError(
            "post_ack_bridge_failure_recovery:" + label + "_invalid"
        )
    return result


@contextmanager
def _bound_observer_authority(
    trust_store: Path,
    replay_db: Path,
):
    paths = (trust_store, replay_db)
    try:
        resolved = tuple(path.resolve(strict=True) for path in paths)
    except OSError as error:
        raise PostAckBridgeFailureRecoveryDriverError(
            "post_ack_bridge_failure_recovery:"
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
        raise PostAckBridgeFailureRecoveryDriverError(
            "post_ack_bridge_failure_recovery:"
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
        raise PostAckBridgeFailureRecoveryDriverError(
            "post_ack_bridge_failure_recovery:"
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


def _prepare_artifact(
    report: Mapping[str, Any],
) -> tuple[
    successor.QualificationPostAckBridgeFailureRecoveryArtifact,
    bytes,
]:
    artifact = (
        successor.QualificationPostAckBridgeFailureRecoveryArtifact.from_report(
            report
        )
    )
    payload = _canonical(artifact.report) + b"\n"
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise PostAckBridgeFailureRecoveryDriverError(
            "post_ack_bridge_failure_recovery:artifact_too_large"
        )
    return artifact, payload


def _build_receipt(
    *,
    output: Path,
    artifact: successor.QualificationPostAckBridgeFailureRecoveryArtifact,
    payload: bytes,
) -> tuple[dict[str, Any], bytes]:
    core = {
        "schema": RECEIPT_SCHEMA,
        "status": "PASS",
        "decision": "POST_ACK_BRIDGE_FAILURE_RECOVERED",
        "issues": [],
        "artifact_path": str(output),
        "artifact_size_bytes": len(payload),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": artifact.report_sha256,
        "predecessor_controller_id": artifact.predecessor_controller_id,
        "released_authority_lane_ids": artifact.released_authority_lane_ids,
        "disposition": "READY_FOR_FRESH_SUCCESSOR_ACTIVATION",
    }
    receipt = {
        **core,
        "receipt_sha256": hashlib.sha256(_canonical(core)).hexdigest(),
    }
    stdout = _canonical(receipt) + b"\n"
    if len(stdout) > MAX_STDOUT_BYTES:
        raise PostAckBridgeFailureRecoveryDriverError(
            "post_ack_bridge_failure_recovery:receipt_too_large"
        )
    return receipt, stdout


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
    parser.add_argument("--dedicated-run", type=Path, required=True)
    parser.add_argument("--dedicated-run-sha256", required=True)
    parser.add_argument("--attempt-envelope", type=Path, required=True)
    parser.add_argument("--attempt-envelope-sha256", required=True)
    parser.add_argument("--pre-turn-report", type=Path, required=True)
    parser.add_argument("--pre-turn-artifact-sha256", required=True)
    parser.add_argument("--root-rollout", type=Path, required=True)
    parser.add_argument("--root-rollout-sha256", required=True)
    parser.add_argument("--pretool-denial", type=Path)
    parser.add_argument("--pretool-denial-sha256")
    parser.add_argument(
        "--worker-rollout",
        action="append",
        default=[],
        metavar="LANE=PATH",
    )
    parser.add_argument(
        "--worker-rollout-sha256",
        action="append",
        default=[],
        metavar="LANE=SHA256",
    )
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
    try:
        worker_paths = {
            lane: Path(path)
            for lane, path in _lane_pairs(
                args.worker_rollout, label="worker_rollouts"
            ).items()
        }
        worker_hashes = _lane_pairs(
            args.worker_rollout_sha256,
            label="worker_rollout_hashes",
        )
        if set(worker_paths) != set(worker_hashes):
            raise PostAckBridgeFailureRecoveryDriverError(
                "post_ack_bridge_failure_recovery:"
                "worker_rollout_lanes_mismatch"
            )
        with _bound_observer_authority(
            args.observer_trust_store,
            args.observer_replay_db,
        ):
            report = successor.recover_issue94_post_ack_bridge_failure(
                plugin_data=args.plugin_data,
                source_roots={
                    "evidence": args.evidence_root,
                    "source": args.source_root,
                },
                dedicated_run_path=args.dedicated_run,
                expected_dedicated_run_artifact_sha256=(
                    args.dedicated_run_sha256
                ),
                attempt_envelope_path=args.attempt_envelope,
                expected_attempt_envelope_artifact_sha256=(
                    args.attempt_envelope_sha256
                ),
                pre_turn_report_path=args.pre_turn_report,
                expected_pre_turn_artifact_sha256=(
                    args.pre_turn_artifact_sha256
                ),
                root_rollout_path=args.root_rollout,
                expected_root_rollout_artifact_sha256=(
                    args.root_rollout_sha256
                ),
                worker_rollout_paths=worker_paths,
                expected_worker_rollout_artifact_sha256=worker_hashes,
                historical_runtime_plugin_root=(
                    args.historical_runtime_plugin_root
                ),
                expected_historical_package_digest=(
                    args.historical_runtime_package_digest
                ),
                pretool_denial_path=args.pretool_denial,
                expected_pretool_denial_artifact_sha256=(
                    args.pretool_denial_sha256
                ),
            )
        artifact, payload = _prepare_artifact(report)
        _receipt, stdout = _build_receipt(
            output=args.output,
            artifact=artifact,
            payload=payload,
        )
        _write_create_only(args.output, payload)
    except Exception as error:
        issue = (
            str(error)
            if isinstance(
                error,
                (
                    successor.QualificationSuccessorError,
                    PostAckBridgeFailureRecoveryDriverError,
                ),
            )
            else "post_ack_bridge_failure_recovery:driver_failure"
        )
        print(
            json.dumps(
                {
                    "schema": (
                        successor
                        .POST_ACK_BRIDGE_FAILURE_RECOVERY_REPORT_SCHEMA
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
    sys.stdout.buffer.write(stdout)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
