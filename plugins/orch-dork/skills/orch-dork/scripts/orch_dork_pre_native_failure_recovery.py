#!/usr/bin/env python3
"""Close and settle one predecessor whose root turn failed before any native
action.

Generation v51 ended this way: the qualification owner started the fresh
task's first root turn, the app server reported the turn failed (a 429 on
the account), the owner refused ``issue170_owner:turn_reported_failed`` and
closed its host, and the governed controller stayed in its pristine waiting
state with zero lanes reserved.  ``terminalize_pre_native_failure`` is the
sanctioned closer for that controller state, but until this driver existed
the only attestation it accepted was the Issue 163 interrupted-turn packet,
and Stage L accepted no receipt for the closure.

This driver builds the owner-terminal failure report from the owner's FAIL
terminal and the root thread rollout, snapshots the waiting authority, runs
the existing terminal predecessor settlement (which terminalizes through the
controller and emits the ``TERMINALIZED`` capacity-settlement artifact), and
signs a host recovery receipt that
``lifecycle_conformance.action_host`` accepts as the predecessor binding for
the successor generation.  No lane is released because none was reserved.

The settlement artifact goes to ``--output``, which must be an absolute path
that does not exist yet: the file is created before the controller is
touched, so the one irreversible step can never leave its artifact
unwritable.  The signed receipt is printed on stdout; the caller captures it
to an owned file and passes that path to Stage L as
``predecessor_pre_native_receipt``.  Both evidence artifacts under
``--evidence-root`` are written only after the predecessor is confirmed
waiting, and an evidence root that already holds one refuses by name.
"""

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
    "orch-dork/qualification-pre-native-failure-recovery-"
    "artifact-receipt/v1"
)
RECEIPT_DECISION = "PRE_NATIVE_FAILURE_RECOVERED"
# The same signing kind as the observed-spawn-stall receipt: Stage L verifies
# kind and payload together, and the payload names this schema and decision.
RECEIPT_KIND = "stage-l-predecessor-recovery"
FAILURE_REPORT_NAME = "pre-native-failure-report.json"
AUTHORITY_SNAPSHOT_NAME = "predecessor-authority.json"
MAX_ARTIFACT_BYTES = 4_194_304
MAX_STDOUT_BYTES = 4_096


class PreNativeFailureRecoveryDriverError(ValueError):
    """Stable local-driver refusal."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sealed(report: Mapping[str, Any]) -> bool:
    digest = report.get("report_sha256")
    core = {
        key: value for key, value in report.items() if key != "report_sha256"
    }
    return (
        isinstance(digest, str)
        and len(digest) == 64
        and hashlib.sha256(_canonical(core)).hexdigest() == digest
    )


@contextmanager
def _bound_observer_authority(
    trust_store: Path,
    replay_db: Path,
) -> Iterator[None]:
    paths = (trust_store, replay_db)
    try:
        resolved = tuple(path.resolve(strict=True) for path in paths)
    except OSError as error:
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:observer_authority_path_invalid"
        ) from error
    if (
        any(not path.is_absolute() or path.is_symlink() for path in paths)
        or resolved != paths
        or trust_store.parent != replay_db.parent
        or trust_store.name != observer_authority.TRUST_STORE_FILENAME
        or replay_db.name != observer_authority.REPLAY_DB_FILENAME
        or any(not path.is_file() for path in paths)
    ):
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:observer_authority_path_invalid"
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
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:observer_authority_environment_conflict"
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


def _write_create_only(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = _create_only_descriptor(path)
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


def _create_only_descriptor(path: Path) -> int:
    try:
        return os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except FileExistsError as error:
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:artifact_exists:" + path.name
        ) from error


def _write_descriptor(descriptor: int, payload: bytes) -> None:
    """Write the settlement artifact into the pre-created output file.

    Takes ownership of the descriptor.  This runs after the controller has
    been terminalized, so a failure here is named rather than folded into a
    generic driver failure, and the caller keeps whatever was written.
    """

    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:artifact_write_failed"
        ) from error


def _persist_canonical(path: Path, value: Mapping[str, Any]) -> str:
    payload = _canonical(value) + b"\n"
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:artifact_too_large"
        )
    _write_create_only(path, payload)
    return hashlib.sha256(payload).hexdigest()


def _waiting_authority_snapshot(
    *,
    plugin_data: Path,
    hook_path: Path,
    roots: Mapping[str, Path],
) -> dict[str, Any]:
    """Read the canonical authority the terminalizer will compare against.

    The controller refuses unless the snapshot equals the authority it reads
    under its own lock, so this is only a faithful copy of a waiting
    predecessor, never a claim about it.
    """

    controller = native_controller.GovernedNativeController(
        plugin_data=plugin_data,
        hook_definition_path=hook_path,
        source_roots=roots,
    )
    try:
        authority = controller.grants.canonical_authority()
    finally:
        controller.store.close()
    owner = authority.get("owner")
    lifecycle = authority.get("lifecycle")
    if (
        authority.get("status") != "VERIFIED"
        or not isinstance(owner, Mapping)
        or not isinstance(owner.get("controller_id"), str)
        or not isinstance(lifecycle, Mapping)
        or lifecycle.get("expected_binding_status") != "WAITING"
        or lifecycle.get("terminal") is not False
        or lifecycle.get("pending_intent") is not False
        or lifecycle.get("cleanup_required") is not False
    ):
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:waiting_predecessor_required"
        )
    return dict(authority)


def recover_pre_native_failure(
    *,
    plugin_data: Path,
    source_root: Path,
    evidence_root: Path,
    owner_terminal: Path,
    owner_terminal_sha256: str,
    root_rollout: Path,
    root_rollout_sha256: str,
    historical_runtime_plugin_root: Path,
    historical_runtime_package_digest: str,
) -> dict[str, Any]:
    """Terminalize the owner-refused root turn and settle its (empty)
    capacity through the existing predecessor settlement."""

    hook_path = (
        historical_runtime_plugin_root / "hooks" / "project_ground_hook.py"
    )
    roots = {"evidence": evidence_root, "source": source_root}
    if not evidence_root.is_absolute():
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:evidence_root_relative"
        )
    # Derive both inputs before persisting either, so a refusal on either
    # leaves the evidence root untouched and a corrected re-run is possible.
    try:
        failure_report = (
            native_controller.build_owner_terminal_pre_native_failure_report(
                owner_terminal_path=owner_terminal,
                expected_owner_terminal_sha256=owner_terminal_sha256,
                root_rollout_path=root_rollout,
                expected_root_rollout_sha256=root_rollout_sha256,
            )
        )
    except ValueError as error:
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:failure_report_refused:" + str(error)
        ) from error
    authority = _waiting_authority_snapshot(
        plugin_data=plugin_data, hook_path=hook_path, roots=roots
    )
    report_path = evidence_root / FAILURE_REPORT_NAME
    authority_path = evidence_root / AUTHORITY_SNAPSHOT_NAME
    if report_path.exists() or authority_path.exists():
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:evidence_root_not_fresh"
        )
    report_sha256 = _persist_canonical(report_path, failure_report)
    authority_sha256 = _persist_canonical(authority_path, authority)
    settled = successor.settle_issue94_terminal_predecessor_capacity(
        plugin_data=plugin_data,
        hook_definition_path=hook_path,
        source_roots=roots,
        pre_native_failure_report_path=report_path,
        expected_pre_native_failure_artifact_sha256=report_sha256,
        predecessor_authority_path=authority_path,
        expected_predecessor_authority_artifact_sha256=authority_sha256,
        historical_runtime_plugin_root=historical_runtime_plugin_root,
        expected_historical_package_digest=historical_runtime_package_digest,
    )
    after = settled.get("capacity_authority_after")
    after_state = after.get("state") if isinstance(after, Mapping) else None
    if (
        settled.get("schema") != successor.PREDECESSOR_SETTLEMENT_REPORT_SCHEMA
        or settled.get("status") != "PASS"
        or settled.get("decision") != "TERMINALIZED"
        or settled.get("issues") != []
        or settled.get("released_authority_lane_ids") != []
        or not isinstance(after_state, Mapping)
        or after_state.get("active_lane_ids") != []
        or not _sealed(settled)
    ):
        issues = settled.get("issues")
        detail = (
            ":" + ",".join(str(issue) for issue in issues)
            if isinstance(issues, list) and issues
            else ""
        )
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:settlement_refused" + detail
        )
    return settled


def _prepare_artifact(report: Mapping[str, Any]) -> bytes:
    payload = _canonical(report) + b"\n"
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:artifact_too_large"
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
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:predecessor_invalid"
        )
    core = {
        "schema": RECEIPT_SCHEMA,
        "status": "PASS",
        "decision": RECEIPT_DECISION,
        "issues": [],
        "artifact_path": str(output),
        "artifact_size_bytes": len(payload),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": report["report_sha256"],
        "predecessor_controller_id": predecessor.get("controller_id"),
        "released_authority_lane_ids": [],
        "disposition": "READY_FOR_FRESH_SUCCESSOR_ACTIVATION",
    }
    signed = signer.issue(
        RECEIPT_KIND,
        core,
        issued_at=(issued_at - timedelta(seconds=1)).isoformat(),
        valid_until=(issued_at + timedelta(minutes=4)).isoformat(),
        nonce="stage-l-pre-native-recovery-" + core["artifact_sha256"][:24],
    )
    sealed = {**core, "host_recovery_receipt": signed}
    receipt = {
        **sealed,
        "receipt_sha256": hashlib.sha256(_canonical(sealed)).hexdigest(),
    }
    stdout = _canonical(receipt) + b"\n"
    if len(stdout) > MAX_STDOUT_BYTES:
        raise PreNativeFailureRecoveryDriverError(
            "pre_native_failure_recovery:receipt_too_large"
        )
    return stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--plugin-data", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--owner-terminal", type=Path, required=True)
    parser.add_argument("--owner-terminal-sha256", required=True)
    parser.add_argument("--root-rollout", type=Path, required=True)
    parser.add_argument("--root-rollout-sha256", required=True)
    parser.add_argument(
        "--historical-runtime-plugin-root", type=Path, required=True
    )
    parser.add_argument("--historical-runtime-package-digest", required=True)
    parser.add_argument("--observer-trust-store", type=Path, required=True)
    parser.add_argument("--observer-replay-db", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    output_descriptor: int | None = None
    output_created = False
    report: dict[str, Any] | None = None
    try:
        # The receipt names --output verbatim and Stage L compares it with
        # the artifact's absolute path, so a relative path would bind a
        # closure that can never be accepted.  Create the file before the
        # controller is touched: the one irreversible step must not be able
        # to outrun its own artifact.
        if not args.output.is_absolute():
            raise PreNativeFailureRecoveryDriverError(
                "pre_native_failure_recovery:output_path_relative"
            )
        args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        output_descriptor = _create_only_descriptor(args.output)
        output_created = True
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
            report = recover_pre_native_failure(
                plugin_data=args.plugin_data,
                source_root=args.source_root,
                evidence_root=args.evidence_root,
                owner_terminal=args.owner_terminal,
                owner_terminal_sha256=args.owner_terminal_sha256,
                root_rollout=args.root_rollout,
                root_rollout_sha256=args.root_rollout_sha256,
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
        descriptor, output_descriptor = output_descriptor, None
        _write_descriptor(descriptor, payload)
    except Exception as error:
        if output_descriptor is not None:
            os.close(output_descriptor)
        if output_created and report is None:
            # Nothing irreversible happened; leave no empty artifact behind.
            # After the controller has been terminalized the file stays,
            # whatever it holds, as the record of what was written.
            try:
                args.output.unlink()
            except OSError:
                pass
        issue = (
            str(error)
            if isinstance(
                error,
                (
                    successor.QualificationSuccessorError,
                    PreNativeFailureRecoveryDriverError,
                ),
            )
            else "pre_native_failure_recovery:driver_failure"
        )
        print(
            json.dumps(
                {
                    "schema": successor.PREDECESSOR_SETTLEMENT_REPORT_SCHEMA,
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
