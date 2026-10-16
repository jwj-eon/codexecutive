#!/usr/bin/env python3
"""Recover one sealed Issue 94 partial-native predecessor before release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_qualification_successor as successor  # noqa: E402


RECEIPT_SCHEMA = (
    "orch-dork/qualification-partial-native-failure-recovery-"
    "artifact-receipt/v1"
)
MAX_ARTIFACT_BYTES = 4_194_305
MAX_STDOUT_BYTES = 4_096


class PartialNativeFailureRecoveryDriverError(ValueError):
    """Stable local-driver refusal."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _prepare_artifact(
    report: Mapping[str, Any],
) -> tuple[
    successor.QualificationPartialNativeFailureRecoveryArtifact,
    bytes,
]:
    artifact = (
        successor.QualificationPartialNativeFailureRecoveryArtifact.from_report(
            report
        )
    )
    payload = _canonical(artifact.report) + b"\n"
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise PartialNativeFailureRecoveryDriverError(
            "partial_native_failure_recovery:artifact_too_large"
        )
    return artifact, payload


def _build_receipt(
    *,
    output: Path,
    artifact: successor.QualificationPartialNativeFailureRecoveryArtifact,
    payload: bytes,
) -> tuple[dict[str, Any], bytes]:
    core = {
        "schema": RECEIPT_SCHEMA,
        "status": "PASS",
        "decision": "PARTIAL_NATIVE_FAILURE_RECOVERED",
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
        raise PartialNativeFailureRecoveryDriverError(
            "partial_native_failure_recovery:receipt_too_large"
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
    parser.add_argument("--terminal-snapshot", type=Path, required=True)
    parser.add_argument("--terminal-snapshot-sha256", required=True)
    parser.add_argument("--worker-state", type=Path, required=True)
    parser.add_argument("--worker-state-sha256", required=True)
    parser.add_argument("--worker-rollout", type=Path, required=True)
    parser.add_argument("--worker-rollout-sha256", required=True)
    parser.add_argument("--historical-runtime-plugin-root", type=Path, required=True)
    parser.add_argument("--historical-runtime-package-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = successor.recover_issue94_partial_native_failure(
            plugin_data=args.plugin_data,
            source_roots={
                "evidence": args.evidence_root,
                "source": args.source_root,
            },
            terminal_snapshot_path=args.terminal_snapshot,
            expected_terminal_snapshot_artifact_sha256=(
                args.terminal_snapshot_sha256
            ),
            worker_state_path=args.worker_state,
            expected_worker_state_artifact_sha256=args.worker_state_sha256,
            worker_rollout_path=args.worker_rollout,
            expected_worker_rollout_artifact_sha256=args.worker_rollout_sha256,
            historical_runtime_plugin_root=(
                args.historical_runtime_plugin_root
            ),
            expected_historical_package_digest=(
                args.historical_runtime_package_digest
            ),
        )
        artifact, payload = _prepare_artifact(report)
        receipt, stdout = _build_receipt(
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
                    PartialNativeFailureRecoveryDriverError,
                ),
            )
            else "partial_native_failure_recovery:driver_failure"
        )
        print(
            json.dumps(
                {
                    "schema": successor.PARTIAL_NATIVE_FAILURE_RECOVERY_REPORT_SCHEMA,
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
