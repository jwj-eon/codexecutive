"""Close one controller stranded in an activated-but-never-dispatched state.

Canonical state cannot distinguish a stranded activation from a healthy one:
at sequence one they are identical by construction. Closure therefore rests on
a host-signed abandonment receipt verified against the trust root the host
fixes at controller construction, and on the retiring runtime's own admitting
signature. Every security decision belongs to the controller's
terminalize_activation_only_failure seam; this driver only binds inputs and
preserves a receipt.

The controller is constructed against the HISTORICAL runtime root, exactly as
the pre-native sibling does, because _hook_runtime_matches pins the sealed
installed_plugin_version. A stranded controller can only ever be closed by the
runtime generation that admitted it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_governed_native_controller as native_controller  # noqa: E402
import orch_dork_owned_file as owned_file  # noqa: E402

SCHEMA = "orch-dork/activation-only-failure-recovery/v1"
MAX_REPORT_BYTES = 1_000_000
MAX_STDOUT_BYTES = 4_096


class ActivationOnlyFailureRecoveryError(RuntimeError):
    """Refusal raised before any controller mutation is attempted."""


def _root(value: Any, *, label: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise ActivationOnlyFailureRecoveryError(label + ":reference_invalid")
    try:
        return candidate.resolve(strict=True)
    except OSError as error:
        raise ActivationOnlyFailureRecoveryError(
            label + ":unavailable"
        ) from error


def _owned_json(
    path: Any, *, expected_sha256: str, label: str
) -> dict[str, Any]:
    target = _root(path, label=label)
    try:
        raw = owned_file.read_owned_bytes(
            target, max_bytes=MAX_REPORT_BYTES, required_mode=0o600
        )
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ActivationOnlyFailureRecoveryError(
            label + ":unavailable"
        ) from error
    if hashlib.sha256(raw).hexdigest() != expected_sha256 or not isinstance(
        value, Mapping
    ):
        raise ActivationOnlyFailureRecoveryError(label + ":reference_invalid")
    return dict(value)


def recover_issue170_activation_only_failure(
    *,
    plugin_data: str | Path,
    source_roots: Mapping[str, str | Path],
    abandonment_receipt_path: str | Path,
    expected_receipt_artifact_sha256: str,
    admitting_report_path: str | Path,
    expected_admitting_report_sha256: str,
    historical_runtime_plugin_root: str | Path,
    expected_historical_package_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Terminalize one abandoned activation, or refuse without mutating."""

    data = _root(plugin_data, label="activation_only_recovery:plugin_data")
    historical = _root(
        historical_runtime_plugin_root,
        label="activation_only_recovery:historical_runtime",
    )
    if not isinstance(source_roots, Mapping) or set(source_roots) != {
        "evidence",
        "source",
    }:
        raise ActivationOnlyFailureRecoveryError(
            "activation_only_recovery:source_roots_invalid"
        )
    roots = {
        name: _root(path, label="activation_only_recovery:" + name + "_root")
        for name, path in source_roots.items()
    }
    admitting = _owned_json(
        admitting_report_path,
        expected_sha256=expected_admitting_report_sha256,
        label="activation_only_recovery:admitting_report",
    )
    evaluation_time = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    try:
        controller = native_controller.GovernedNativeController(
            plugin_data=data,
            hook_definition_path=(
                historical / "hooks" / "project_ground_hook.py"
            ),
            source_roots=roots,
            now=evaluation_time,
        )
    except (OSError, TypeError, ValueError) as error:
        raise ActivationOnlyFailureRecoveryError(
            "activation_only_recovery:controller_unavailable"
        ) from error
    authority = controller.grants.canonical_authority()
    owner = authority.get("owner") if isinstance(authority, Mapping) else None
    if authority.get("status") != "VERIFIED" or not isinstance(owner, Mapping):
        raise ActivationOnlyFailureRecoveryError(
            "activation_only_recovery:authority_unavailable"
        )
    try:
        build = (
            native_controller.build_activation_only_failure_terminalization_program
        )
        program = build(
            controller_id=str(owner["controller_id"]),
            expected_cursor=authority["tip"],
            abandonment_receipt_path=abandonment_receipt_path,
            expected_receipt_artifact_sha256=expected_receipt_artifact_sha256,
            hook_trust_verification_report=admitting,
            historical_runtime_root=historical,
            expected_package_digest=expected_historical_package_digest,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ActivationOnlyFailureRecoveryError(
            "activation_only_recovery:program_invalid"
        ) from error
    result = controller.terminalize_activation_only_failure(program)
    if result.get("status") != "PASS":
        # The seam refuses by returning BLOCKED rather than raising. Sealing
        # that as a receipt would report the likeliest operator error -- a
        # wrong historical runtime root yielding historical_runtime_not_active
        # -- as success, and burn the create-only output path doing it.
        raise ActivationOnlyFailureRecoveryError(
            "activation_only_recovery:terminalization_refused:"
            + ",".join(str(issue) for issue in (result.get("issues") or []))
        )
    core = {
        "schema": SCHEMA,
        "status": result.get("status"),
        "decision": result.get("decision"),
        "issues": list(result.get("issues") or []),
        "controller_id": owner.get("controller_id"),
        "controller_run_id": owner.get("controller_run_id"),
        "activation_sha256": owner.get("activation_sha256"),
        "historical_package_digest": expected_historical_package_digest,
        "controller_report": result,
        "terminal_claim_permitted": False,
        "qualification_claim_permitted": False,
        "provider_free": True,
        "model_calls": 0,
    }
    return {**core, "report_sha256": native_controller._sha(core)}


def _write_create_only(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
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
    parser.add_argument("--abandonment-receipt", type=Path, required=True)
    parser.add_argument("--abandonment-receipt-sha256", required=True)
    parser.add_argument("--admitting-report", type=Path, required=True)
    parser.add_argument("--admitting-report-sha256", required=True)
    parser.add_argument(
        "--historical-runtime-plugin-root", type=Path, required=True
    )
    parser.add_argument("--historical-runtime-package-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    committed = False
    try:
        report = recover_issue170_activation_only_failure(
            plugin_data=args.plugin_data,
            source_roots={
                "evidence": args.evidence_root,
                "source": args.source_root,
            },
            abandonment_receipt_path=args.abandonment_receipt,
            expected_receipt_artifact_sha256=args.abandonment_receipt_sha256,
            admitting_report_path=args.admitting_report,
            expected_admitting_report_sha256=args.admitting_report_sha256,
            historical_runtime_plugin_root=(
                args.historical_runtime_plugin_root
            ),
            expected_historical_package_digest=(
                args.historical_runtime_package_digest
            ),
        )
        committed = True
        payload = native_controller._canonical(report) + b"\n"
        _write_create_only(args.output, payload)
    except Exception as error:
        issue = (
            str(error)
            if isinstance(error, ActivationOnlyFailureRecoveryError)
            else "activation_only_recovery:driver_failure"
        )
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "status": "FAIL",
                    # Once the seam has committed, the controller is terminal
                    # whatever happens next. Reporting REFUSED here would tell
                    # an operator the opposite of the truth.
                    "decision": (
                        "COMMITTED_RECEIPT_UNAVAILABLE" if committed else "REFUSED"
                    ),
                    "issues": [issue],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    sys.stdout.buffer.write(payload[:MAX_STDOUT_BYTES])
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
