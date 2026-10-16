"""Process-local Issue 170 authority for one release/install action.

Durable consumption proves that an attempt was spent; it does not prove that
the campaign or a physical action passed.  This module joins those boundaries:
it retains the original in-process gate inputs, re-runs the fixed completion
gate with the original host witnesses, validates the distinct candidate tree,
and persists the release/install claim before returning authority to act.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import weakref

from lifecycle_conformance import (
    candidate_identity,
    completion_gate,
    consumption,
    host_attestation,
    reference_values as rv,
    source_scope_closure,
)
from lifecycle_conformance.values import LifecycleContractError


RELEASE_RECEIPT_SCHEMA = "orch-dork/issue170-release-install-physical-receipt/v1"
STAGE_L_EVIDENCE_SCHEMA = "orch-dork/stage-l-campaign-evidence/v1"
STAGE_L_REPORT_SCHEMA = "orch-dork/stage-l-campaign/v1"
_PROFILES = ("campaign", "focused", "rehearsal", "full_suite")
_REQUIRED_STAGE_L_FACTS = frozenset({
    "host_attestation_valid", "runtime_identity_attested",
    "source_custody_complete", "output_custody_complete",
    "exit_custody_complete", "cleanup_custody_complete",
    "focused_tests_same_runtime", "rehearsal_same_runtime",
    "full_suite_same_runtime",
})
_AUTHORITY = object()
_ISSUED: dict[int, tuple[weakref.ReferenceType[object], int, tuple[object, ...]]] = {}
_OPERATIONS: dict[int, dict] = {}
_OPERATION_LOCK = threading.RLock()


def _require(condition: bool, reason: str) -> None:
    if condition is not True:
        raise LifecycleContractError("action_authority:" + reason)


def _same_path(left: str | Path, right: str | Path) -> bool:
    try:
        return Path(left).resolve(strict=True) == Path(right).resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def _stage_l_originals(evidence, host_runs):
    _require(
        type(evidence) is dict
        and set(evidence) == {"schema", "runtime", "components", "consumption"}
        and evidence["schema"] == STAGE_L_EVIDENCE_SCHEMA
        and type(evidence["components"]) is list,
        "stage_l_evidence",
    )
    rows = [
        row for row in evidence["components"]
        if type(row) is dict and row.get("kind") == "manifest_host_campaign"
    ]
    _require(len(rows) == 1, "stage_l_campaign_originals")
    originals = rows[0].get("originals")
    _require(
        type(originals) is dict
        and set(originals) == {
            "source_root", "runs", "attestations", "test_set"
        }
        and type(originals["runs"]) is dict
        and set(originals["runs"]) == set(_PROFILES)
        and type(originals["attestations"]) is dict
        and set(originals["attestations"]) == set(_PROFILES)
        and type(host_runs) is dict,
        "stage_l_campaign_originals",
    )
    return originals


def _stage_l_candidate(
    evidence, consumption_anchor, *, source_root, sources, runtime
):
    rows = [
        row for row in evidence["components"]
        if type(row) is dict and row.get("kind") == "candidate_identity_transition"
    ]
    _require(len(rows) <= 1, "candidate_component_count")
    if not rows:
        _require(
            consumption_anchor is None
            and evidence["consumption"] == {
                "candidate": None, "release_install": None, "live_attempt": None,
            },
            "pre_candidate_consumption",
        )
        return None
    _require(type(consumption_anchor) is dict, "candidate_anchor_required")
    row = rows[0]
    originals = row.get("originals")
    _require(
        set(row) == {"schema", "kind", "case_id", "material", "originals"}
        and row["schema"] == completion_gate.COMPONENT_SCHEMA
        and type(originals) is dict
        and set(originals) == {
            "report", "original_root", "candidate_root", "generation"
        },
        "candidate_originals",
    )
    original_root = originals.get("original_root")
    candidate_root = originals.get("candidate_root")
    transition = originals.get("report")
    _require(type(transition) is rv.FrozenValue, "candidate_transition_original")
    generation = originals["generation"]
    _require(
        generation == {
            "sources": sources,
            "runtime": runtime,
            "registry_components": {},
        }
        and row["material"] == {
            "report_sha256": transition.digest(),
            "generation_sha256": rv.freeze(generation).digest(),
        }
        and row["case_id"] == completion_gate.case_identity(
            "candidate_identity_transition", row["material"]
        )
        and _same_path(original_root, source_root),
        "candidate_generation_binding",
    )
    candidate_identity.validate_cachebuster_identity_transition(
        original_root, candidate_root, transition
    )
    transition_data = transition.to_plain()
    pre = transition_data["original"]["project_runtime_source_report"]
    _require(
        pre["package_digest"] == runtime["package_digest_before_cachebuster"]
        and pre["version"] == runtime["version_before_cachebuster"]
        and {
            row["path"]: row["sha256"]
            for row in transition_data["original"]["inventory"]
        } == runtime["runtime_entry_hashes"],
        "candidate_pre_runtime_binding",
    )
    _require(
        set(consumption_anchor) == {
            "root", "initial_receipt", "latest_receipt", "campaign_receipt_json"
        }
        and type(consumption_anchor["initial_receipt"]) is rv.FrozenValue
        and type(consumption_anchor["latest_receipt"]) is rv.FrozenValue,
        "candidate_anchor",
    )
    latest = consumption_anchor["latest_receipt"]
    plain = latest.to_plain()
    _require(
        plain["phase"] == "candidate"
        and plain["status"] == "SUCCEEDED"
        and evidence["consumption"] == {
            "candidate": plain, "release_install": None, "live_attempt": None,
        },
        "candidate_consumption",
    )
    consumption.read_store(
        consumption_anchor["root"], latest, expected_binding=plain["binding"]
    )
    return {
        "transition_sha256": transition.digest(),
        "original_root": str(Path(original_root).resolve(strict=True)),
        "candidate_root": str(Path(candidate_root).resolve(strict=True)),
    }


def build_stage_l_campaign_report(
    evidence, *, sources, host_runs, consumption_anchor=None
):
    """Re-read the four manifest profiles and mint Stage L gate authority."""

    originals = _stage_l_originals(evidence, host_runs)
    source_root = Path(originals["source_root"]).resolve(strict=True)
    _require(
        source_root == Path(source_scope_closure._ROOT).resolve(strict=True),
        "stage_l_source_root",
    )
    snapshot = source_scope_closure.read_source_snapshot()
    _require(
        snapshot["sources"] == sources and snapshot["runtime"] == evidence["runtime"],
        "stage_l_source_scope",
    )
    reread = {}
    profile_material = {}
    runtime = evidence["runtime"]
    expected_runtime = {
        key: value for key, value in runtime.items()
        if key != "python_source_hashes"
    }
    for profile in _PROFILES:
        run = originals["runs"][profile]
        attestation = originals["attestations"][profile]
        _require(
            type(run) is host_attestation.HostRun
            and type(attestation) is host_attestation.ValidatedAttestation
            and host_runs.get(run.witness.invocation_id) is run,
            "stage_l_host_run:" + profile,
        )
        checked = host_attestation.readback(
            source_root=source_root,
            artifact_root=run.artifact_root,
            witness=run.witness,
            expected_invocation_id=run.witness.invocation_id,
        )
        _require(
            checked.report == attestation.report
            and checked.report.to_plain()["profile"] == profile,
            "stage_l_attestation:" + profile,
        )
        _require(
            checked.report.to_plain()["runtime_identity"] == expected_runtime,
            "stage_l_profile_runtime:" + profile,
        )
        reread[profile] = checked
        profile_material[profile] = {
            "invocation_id": checked.report.to_plain()["invocation_id"],
            "report_sha256": checked.report.digest(),
        }
    facts = list(host_attestation.completion_facts(reread["campaign"]))
    test_set = host_attestation.validate_test_run_set({
        profile: reread[profile]
        for profile in ("focused", "rehearsal", "full_suite")
    })
    _require(test_set == originals["test_set"], "stage_l_test_set")
    test_data = test_set.to_plain()
    facts.extend(test_data["facts"])
    campaign_data = reread["campaign"].report.to_plain()
    _require(
        test_data["runtime_identity"] == expected_runtime
        and test_data["source_generation_sha256"]
        == campaign_data["source_generation_sha256"],
        "stage_l_profile_set_binding",
    )
    manifest = host_attestation.release_manifest_identity(
        source_root=source_root
    ).to_plain()
    candidate = _stage_l_candidate(
        evidence,
        consumption_anchor,
        source_root=source_root,
        sources=sources,
        runtime=runtime,
    )
    authorized = set(facts) == _REQUIRED_STAGE_L_FACTS
    _require(authorized, "stage_l_required_facts")
    source_hashes = {
        path: hashlib.sha256(text.encode("utf-8")).hexdigest()
        for path, text in sorted(sources.items())
    }
    material = {
        "manifest": manifest,
        "profiles": profile_material,
        "test_set_sha256": test_set.digest(),
        "candidate": candidate,
        "consumption": evidence["consumption"],
    }
    return rv.freeze({
        "schema": STAGE_L_REPORT_SCHEMA,
        "status": "PASS" if authorized else "BLOCKED",
        "source_inventory_hashes": source_hashes,
        "runtime_identity": {"phase": "pre_cachebuster", **runtime},
        "release_manifest": manifest,
        "profiles": profile_material,
        "facts": facts,
        "campaign_authorized": authorized,
        "candidate_authorized": authorized,
        "release_authorized": candidate is not None,
        "live_attempt_authorized": False,
        "qualification_authorized": False,
        "promotion_authorized": False,
        "candidate_transition_sha256": (
            candidate["transition_sha256"] if candidate is not None else None
        ),
        "evidence_sha256": rv.freeze(material).digest(),
    })


def validate_stage_l_campaign_report(
    report, evidence, *, sources, host_runs, consumption_anchor=None
):
    _require(type(report) is rv.FrozenValue, "stage_l_report_original")
    rebuilt = build_stage_l_campaign_report(
        evidence,
        sources=sources,
        host_runs=host_runs,
        consumption_anchor=consumption_anchor,
    )
    _require(report == rebuilt, "stage_l_report_binding")
    return report


@dataclass(frozen=True, init=False)
class ReleaseActionInputs:
    """Original objects retained by the action-host process."""

    report: rv.FrozenValue
    evidence: dict
    sources: dict
    registry_components: dict
    host_runs: dict
    consumption_anchor: dict
    original_root: Path
    candidate_root: Path

    def __init__(self, authority, **values):
        _require(authority is _AUTHORITY, "inputs_factory_required")
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, values[name])


@dataclass(frozen=True, init=False)
class ReleaseInstallClaim:
    """Opaque same-process proof that the durable claim precedes effects."""

    inputs: ReleaseActionInputs
    receipt: rv.FrozenValue
    release_root: Path
    _authority: object

    def __init__(self, authority, *, inputs, receipt, release_root):
        _require(authority is _AUTHORITY, "claim_factory_required")
        object.__setattr__(self, "inputs", inputs)
        object.__setattr__(self, "receipt", receipt)
        object.__setattr__(self, "release_root", release_root)
        object.__setattr__(self, "_authority", authority)


@dataclass(frozen=True, init=False)
class ReleaseOperationInvocation:
    """Opaque invocation token retained only while one public effect runs."""

    claim: ReleaseInstallClaim
    operation: str
    nonce: str
    invocation_sha256: str
    _authority: object

    def __init__(self, authority, *, claim, operation, nonce, invocation_sha256):
        _require(authority is _AUTHORITY, "operation_factory_required")
        object.__setattr__(self, "claim", claim)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(self, "invocation_sha256", invocation_sha256)
        object.__setattr__(self, "_authority", authority)


def _fingerprint(value):
    if type(value) is ReleaseActionInputs:
        return (
            value.report.digest(),
            id(value.evidence),
            id(value.sources),
            id(value.registry_components),
            id(value.host_runs),
            id(value.consumption_anchor),
            str(value.original_root),
            str(value.candidate_root),
        )
    if type(value) is ReleaseInstallClaim:
        return (
            id(value.inputs),
            value.receipt.digest(),
            str(value.release_root),
            id(value._authority),
        )
    if type(value) is ReleaseOperationInvocation:
        return (
            id(value.claim),
            value.operation,
            value.nonce,
            value.invocation_sha256,
            id(value._authority),
        )
    return None


def _issue(value):
    identity = id(value)
    _ISSUED[identity] = (
        weakref.ref(value, lambda _: _ISSUED.pop(identity, None)),
        os.getpid(),
        _fingerprint(value),
    )
    return value


def _issued(value) -> None:
    record = _ISSUED.get(id(value))
    _require(
        record is not None
        and record[0]() is value
        and record[1] == os.getpid()
        and record[2] == _fingerprint(value),
        "issued_object_binding",
    )


def _clear_process_authority() -> None:
    _ISSUED.clear()
    _OPERATIONS.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_clear_process_authority)


def prepare_release_action(
    report,
    evidence,
    *,
    sources,
    registry_components,
    host_runs,
    consumption_anchor,
    original_root,
    candidate_root,
):
    """Retain exact originals; validation and consumption occur at action time."""

    _require(type(report) is rv.FrozenValue, "report_original_required")
    _require(type(evidence) is dict, "evidence_original_required")
    _require(type(sources) is dict, "sources_original_required")
    _require(type(registry_components) is dict, "registries_original_required")
    _require(type(host_runs) is dict, "host_runs_original_required")
    _require(type(consumption_anchor) is dict, "consumption_anchor_original_required")
    return _issue(
        ReleaseActionInputs(
            _AUTHORITY,
            report=report,
            evidence=evidence,
            sources=sources,
            registry_components=registry_components,
            host_runs=host_runs,
            consumption_anchor=consumption_anchor,
            original_root=Path(original_root),
            candidate_root=Path(candidate_root),
        )
    )


def _candidate_original(inputs: ReleaseActionInputs):
    records = [
        row
        for row in inputs.evidence.get("components", ())
        if type(row) is dict and row.get("kind") == "candidate_identity_transition"
    ]
    _require(len(records) == 1, "candidate_component_required")
    originals = records[0].get("originals")
    _require(type(originals) is dict, "candidate_originals")
    return originals


def _frozen(value):
    return value if type(value) is rv.FrozenValue else rv.freeze(value)


def claim_release_install(inputs, *, source_root, release_root) -> ReleaseInstallClaim:
    """Revalidate all physical originals, then consume before the first effect."""

    _require(type(inputs) is ReleaseActionInputs, "inputs_type")
    _issued(inputs)
    _require(_same_path(source_root, inputs.candidate_root), "candidate_action_root")
    _require(not _same_path(inputs.original_root, inputs.candidate_root), "distinct_roots_required")
    target = Path(release_root).absolute()
    _require(not target.is_symlink() and not target.exists(), "release_root_not_create_only")
    validate_stage_l_campaign_report(
        inputs.report,
        inputs.evidence,
        sources=inputs.sources,
        host_runs=inputs.host_runs,
        consumption_anchor=inputs.consumption_anchor,
    )
    report = inputs.report.to_plain()
    _require(
        report["status"] == "PASS"
        and report["campaign_authorized"] is True
        and report["release_authorized"] is True,
        "release_not_authorized",
    )
    original = _candidate_original(inputs)
    _require(
        _same_path(original.get("original_root"), inputs.original_root)
        and _same_path(original.get("candidate_root"), inputs.candidate_root),
        "candidate_root_binding",
    )
    transition = _frozen(original.get("report"))
    candidate_identity.validate_cachebuster_identity_transition(
        inputs.original_root,
        inputs.candidate_root,
        transition,
    )
    anchor = inputs.consumption_anchor
    _require(
        set(anchor) == {"root", "initial_receipt", "latest_receipt", "campaign_receipt_json"}
        and type(anchor["initial_receipt"]) is rv.FrozenValue
        and type(anchor["latest_receipt"]) is rv.FrozenValue,
        "consumption_anchor",
    )
    latest = anchor["latest_receipt"]
    latest_plain = latest.to_plain()
    _require(
        latest_plain["phase"] == "candidate" and latest_plain["status"] == "SUCCEEDED",
        "candidate_outcome_required",
    )
    _require(
        inputs.evidence.get("consumption")
        == {"candidate": latest_plain, "release_install": None, "live_attempt": None},
        "candidate_consumption_binding",
    )
    claim = consumption.claim_phase(
        anchor["root"],
        latest,
        phase="release_install",
        expected_binding=latest_plain["binding"],
    )
    anchor["latest_receipt"] = claim
    issued = _issue(
        ReleaseInstallClaim(
            _AUTHORITY,
            inputs=inputs,
            receipt=claim,
            release_root=target,
        )
    )
    _OPERATIONS[id(issued)] = {
        "claim": weakref.ref(issued),
        "pid": os.getpid(),
        "state": "HOST_READY",
        "active": None,
        "host_output": None,
        "build_output": None,
        "install_output": None,
        "host_output_sha256": None,
        "build_output_sha256": None,
        "install_output_sha256": None,
        # This is populated only after all three original operation outputs
        # are bound.  It stays separate from the durable outcome: a physical
        # reader must accept this exact report before _record can write
        # release_install/SUCCEEDED.
        "report": None,
        "report_sha256": None,
    }
    return issued


def require_release_install_claim(
    claim,
    *,
    source_root=None,
    release_root,
) -> ReleaseInstallClaim:
    """Re-read a current issued claim at every public effectful entrypoint."""

    _require(type(claim) is ReleaseInstallClaim, "claim_type")
    _issued(claim)
    _require(Path(release_root).absolute() == claim.release_root, "release_root_binding")
    if source_root is not None:
        _require(_same_path(source_root, claim.inputs.candidate_root), "candidate_action_root")
    original = _candidate_original(claim.inputs)
    candidate_identity.validate_cachebuster_identity_transition(
        claim.inputs.original_root,
        claim.inputs.candidate_root,
        _frozen(original.get("report")),
    )
    plain = claim.receipt.to_plain()
    _require(
        plain["phase"] == "release_install" and plain["status"] == "CLAIMED",
        "release_claim_state",
    )
    consumption.read_store(
        claim.inputs.consumption_anchor["root"],
        claim.receipt,
        expected_binding=plain["binding"],
    )
    return claim


def _operation_record(claim: ReleaseInstallClaim) -> dict:
    record = _OPERATIONS.get(id(claim))
    _require(
        record is not None
        and record["claim"]() is claim
        and record["pid"] == os.getpid(),
        "operation_claim_binding",
    )
    return record


def _canonical_sha256(value) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LifecycleContractError("action_authority:operation_invocation") from exc
    return hashlib.sha256(encoded).hexdigest()


def _begin_release_operation(
    claim,
    operation,
    *,
    source_root=None,
    release_root,
    invocation,
) -> ReleaseOperationInvocation:
    """Consume the next in-process operation slot before its first effect."""

    _require(operation in {"host", "build", "install"}, "operation_name")
    with _OPERATION_LOCK:
        require_release_install_claim(
            claim, source_root=source_root, release_root=release_root
        )
        record = _operation_record(claim)
        expected = {
            "host": "HOST_READY",
            "build": "BUILD_READY",
            "install": "INSTALL_READY",
        }[operation]
        _require(record["state"] == expected, "operation_out_of_order")
        token = _issue(
            ReleaseOperationInvocation(
                _AUTHORITY,
                claim=claim,
                operation=operation,
                nonce=secrets.token_hex(32),
                invocation_sha256=_canonical_sha256(invocation),
            )
        )
        record["state"] = operation.upper() + "_ACTIVE"
        record["active"] = token
        return token


def _complete_release_operation(token, output):
    """Bind the exact output returned by the active public operation."""

    _require(type(token) is ReleaseOperationInvocation, "operation_token_type")
    _issued(token)
    _require(type(output) is dict, "operation_output")
    expected_schema = {
        "host": "orch-dork/release-host-check/v1",
        "build": "orch-dork/release-marketplace/v1",
        "install": "orch-dork/release-install/v1",
    }[token.operation]
    _require(
        output.get("schema") == expected_schema and output.get("status") == "PASS",
        "operation_output",
    )
    with _OPERATION_LOCK:
        record = _operation_record(token.claim)
        _require(
            record["state"] == token.operation.upper() + "_EFFECT"
            and record["active"] is token,
            "operation_token_binding",
        )
        record[token.operation + "_output"] = output
        record[token.operation + "_output_sha256"] = _canonical_sha256(output)
        record["active"] = None
        record["state"] = {
            "host": "BUILD_READY",
            "build": "INSTALL_READY",
            "install": "COMPLETE",
        }[token.operation]
    return output


def _enter_release_operation_effect(
    token,
    operation,
    *,
    source_root=None,
    release_root,
    invocation,
) -> ReleaseOperationInvocation:
    """Atomically consume the active token before the lower-level effect."""

    _require(type(token) is ReleaseOperationInvocation, "operation_token_type")
    _issued(token)
    _require(token.operation == operation, "operation_token_binding")
    _require(token.invocation_sha256 == _canonical_sha256(invocation), "operation_invocation_binding")
    with _OPERATION_LOCK:
        require_release_install_claim(
            token.claim, source_root=source_root, release_root=release_root
        )
        record = _operation_record(token.claim)
        _require(
            record["state"] == operation.upper() + "_ACTIVE"
            and record["active"] is token,
            "operation_token_binding",
        )
        record["state"] = operation.upper() + "_EFFECT"
    return token


def _fail_release_operation(token, error) -> None:
    """Make a started operation terminal; failure never restores a slot."""

    _require(type(token) is ReleaseOperationInvocation, "operation_token_type")
    _issued(token)
    with _OPERATION_LOCK:
        record = _operation_record(token.claim)
        started = {
            token.operation.upper() + "_ACTIVE": False,
            token.operation.upper() + "_EFFECT": True,
        }
        _require(
            record["state"] in started and record["active"] is token,
            "operation_token_binding",
        )
        entered = started[record["state"]]
        record["active"] = None
        record["state"] = "FAILED"
        record["failure_phase"] = token.operation
        record["failure_effect_entered"] = entered
        record["failure_error"] = error
        record["failure"] = _error_receipt(error, token.operation, entered)


def _error_receipt(error, phase, effect_entered) -> dict:
    return {
        "phase": phase,
        "effect_entered": effect_entered,
        "error_type": type(error).__name__,
        "error_sha256": hashlib.sha256(
            str(error).encode("utf-8", errors="replace")
        ).hexdigest(),
    }


def _outcome_bytes(claim, outcome: str, receipt: dict) -> bytes:
    physical = {
        "schema": RELEASE_RECEIPT_SCHEMA,
        "outcome": outcome,
        "receipt": receipt,
    }
    transport = {
        "schema": consumption.TRANSPORT_SCHEMA,
        "status": "VALIDATED",
        "original_receipt_json": json.dumps(
            physical, sort_keys=True, separators=(",", ":"), allow_nan=False
        ),
    }
    value = {
        "schema": consumption.OUTCOME_SCHEMA,
        "phase": "release_install",
        "claim_sha256": claim.receipt.digest(),
        "outcome": outcome,
        "transport": transport,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _release_install_report(claim: ReleaseInstallClaim) -> dict:
    """Return the one report assembled from the three retained outputs.

    This deliberately does not record a durable success.  The marketplace
    retains this exact object in its physical original, and the release reader
    later proves that the same object still binds the same host, build, and
    install observations.
    """

    _require(type(claim) is ReleaseInstallClaim, "claim_type")
    _issued(claim)
    record = _operation_record(claim)
    _require(record["state"] == "COMPLETE", "operations_not_complete")
    _require(
        type(record["host_output"]) is dict
        and type(record["build_output"]) is dict
        and type(record["install_output"]) is dict
        and record["host_output"].get("schema") == "orch-dork/release-host-check/v1"
        and record["host_output"].get("status") == "PASS"
        and record["build_output"].get("package")
        == record["install_output"].get("package")
        and _canonical_sha256(record["host_output"])
        == record["host_output_sha256"]
        and _canonical_sha256(record["build_output"])
        == record["build_output_sha256"]
        and _canonical_sha256(record["install_output"])
        == record["install_output_sha256"],
        "operation_output_binding",
    )
    report = record["report"]
    if report is None:
        report = {
            **record["build_output"],
            "schema": "orch-dork/release/v1",
            "marketplace_build_schema": "orch-dork/release-marketplace/v1",
            "installation": record["install_output"],
            "release_host_check": record["host_output"],
        }
        record["report"] = report
        record["report_sha256"] = _canonical_sha256(report)
    _require(
        type(report) is dict
        and report.get("schema") == "orch-dork/release/v1"
        and report.get("installation") is record["install_output"]
        and report.get("release_host_check") is record["host_output"]
        and _canonical_sha256(report) == record["report_sha256"],
        "operation_report_binding",
    )
    return report


def _fail_release_install_terminal_validation(claim, error) -> None:
    """Close a completed effect when its independent physical reader refuses.

    The output originals stay retained for failure custody, but the operation
    can never return to COMPLETE or launch a replacement release.
    """

    _require(type(claim) is ReleaseInstallClaim, "claim_type")
    _issued(claim)
    record = _operation_record(claim)
    _require(record.get("outcome_recorded") is not True, "outcome_already_recorded")
    _require(record["state"] in {"HOST_READY", "COMPLETE"}, "operations_not_complete")
    record["state"] = "FAILED"
    record["failure_phase"] = "terminal_validation"
    record["failure_effect_entered"] = record["host_output"] is not None
    record["failure_error"] = error
    record["failure"] = _error_receipt(
        error, "terminal_validation", record["failure_effect_entered"]
    )


def record_release_install_success(claim, execution):
    """Persist success only after the fixed release reader accepts custody.

    ``execution`` must be the exact same-process ReleaseExecution that called
    the fixed marketplace entry point.  The lazy import avoids a module-import
    cycle while keeping the authority decision inside the source-owned reader.
    """

    _require(type(claim) is ReleaseInstallClaim, "claim_type")
    _issued(claim)
    record = _operation_record(claim)
    _require(record.get("outcome_recorded") is not True, "outcome_already_recorded")
    _require(record["state"] == "COMPLETE", "operations_not_complete")
    from lifecycle_conformance import release_execution

    # A caller that merely has a completed claim has not supplied a reader
    # result at all.  That misuse is refused before changing the claim state;
    # a later genuine reader may still inspect the retained originals.
    _require(
        type(execution) is release_execution.ReleaseExecution,
        "reader_execution_required",
    )
    try:
        physical = release_execution._validate_durable_release_execution(
            execution, claim
        )
        report = _release_install_report(claim)
        _require(
            physical.report is report,
            "reader_report_identity",
        )
    except BaseException as error:
        # A post-effect refusal is terminal and must be durably visible.  The
        # exact raised object is retained so a caller cannot substitute an
        # equal-looking error when attempting to record the failure.
        if record.get("outcome_recorded") is not True and record["state"] == "COMPLETE":
            _fail_release_install_terminal_validation(claim, error)
            record_release_install_failure(claim, error)
        raise
    latest = _record(claim, "SUCCEEDED", report)
    return report, latest


def record_release_install_failure(claim, error):
    """Persist terminal failure without creating retry or replacement authority."""

    _require(type(claim) is ReleaseInstallClaim, "claim_type")
    _issued(claim)
    record = _operation_record(claim)
    _require(record.get("outcome_recorded") is not True, "outcome_already_recorded")
    _require(
        record["state"] == "FAILED"
        and record.get("failure_error") is error
        and record.get("failure")
        == _error_receipt(
            error,
            record.get("failure_phase"),
            record.get("failure_effect_entered"),
        ),
        "failure_error_binding",
    )
    return _record(claim, "FAILED", record["failure"])


def _record(claim, outcome, receipt):
    record = _operation_record(claim)
    _require(record.get("outcome_recorded") is not True, "outcome_already_recorded")
    plain = claim.receipt.to_plain()
    latest = consumption.record_outcome(
        claim.inputs.consumption_anchor["root"],
        claim.receipt,
        outcome_receipt=_outcome_bytes(claim, outcome, receipt),
        expected_binding=plain["binding"],
    )
    record["outcome_recorded"] = True
    claim.inputs.consumption_anchor["latest_receipt"] = latest
    return latest


__all__ = [
    "RELEASE_RECEIPT_SCHEMA", "STAGE_L_EVIDENCE_SCHEMA", "STAGE_L_REPORT_SCHEMA",
    "ReleaseActionInputs",
    "ReleaseInstallClaim",
    "build_stage_l_campaign_report",
    "validate_stage_l_campaign_report",
    "prepare_release_action",
    "claim_release_install",
    "require_release_install_claim",
    "record_release_install_success",
    "record_release_install_failure",
]
