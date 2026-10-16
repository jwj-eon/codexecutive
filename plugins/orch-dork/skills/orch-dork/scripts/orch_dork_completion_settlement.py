"""Host-only completion proof to signed capacity settlement, without qualification.

The caller retains the original process handle and a private evidence root.
Each capture gets one create-only attempt directory. Signed evidence is fsynced
before dispatch; exceptions preserve partial receipts and never trigger retry.
No live producer selects this API. Source/result JSON alone cannot authorize it.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
import os
from pathlib import Path
import stat
from typing import Any

import orch_dork_completion_process as process
import orch_dork_governed_attempt as attempt
import orch_dork_governed_native_controller as native
import orch_dork_observer_receipt as observer_receipt
import orch_dork_qualification_activation as activation
import orch_dork_shared_capacity as capacity
from orch_dork_governed_native_reports import completion_waiting_authority, _json

SCHEMA = "orch-dork/completion-capacity-settlement/v1"
CLEANUP_SETTLEMENT_SCHEMA = "orch-dork/cleanup-capacity-settlement/v1"
HOST_CLEANUP_SCHEMA = "orch-dork/qualification-host-cleanup/v1"


def _require(condition: bool, issue: str = "binding_invalid") -> None:
    if not condition:
        raise ValueError("completion_settlement:" + issue)


def _same(left: Any, right: Any) -> bool:
    return native._canonical(left) == native._canonical(right)


def _read_capacity(controller) -> dict:
    """Use the same adapter protocol as the governed capacity evaluator."""
    authority = controller.capacity_authority
    reader = getattr(authority, "read", None)
    if not callable(reader):
        reader = getattr(authority, "read_shared_capacity_authority", None)
    _require(callable(reader), "capacity_adapter_required")
    return deepcopy(reader())


def _snapshot(controller, capture: dict) -> tuple[dict, dict]:
    authority = controller.grants.canonical_authority()
    completion_waiting_authority(authority)
    _require(_same(authority, capture["authority_after"]), "owner_changed")
    state, rows = controller._state(authority["owner"]["controller_run_id"], recover_provisional=False)
    bound = state["activation"]["identity"]
    _require(authority["owner"]["activation_sha256"] == native._sha(state["activation"]))
    _require(_same(native._cursor(rows), authority["tip"]))
    _require(all(_same(authority["identity"][key], bound[key]) for key in (
        "root_thread_id", "root_session_id", "root_model", "hook_definition_sha256", "hook_registration_sha256")))
    _require(state["action"] is None and state["pending_intent"] is None and state["grant_state"] is None
        and state["terminal"] is False and state["cleanup_required"] is False and state["action_outcome"] == "completed")
    _require(_same(state["stage_report"], capture["controller_report"]["stage_report"]))
    _require(_same([row for row in state["action_evidence"] if row["action"]["kind"] == "stop"], capture["action_evidence"]))
    _require(_same(state["last_batch_result"], capture["batch_result"]))
    _require(_same(state.get("checkpoint_sources"), capture["checkpoint_sources"]))
    _require(state["stage_report"]["receipt"]["bindings"]["review_context"]["owner_hook_inventory_report"]["report_sha256"]
        == state["activation"]["hook_trust"]["hook_inventory_report_sha256"])
    _require(controller._hook_runtime_matches(bound) and controller._retained_hook_evidence_valid(state), "hooks_changed")
    identity = {key: bound[source] for key, source in (
        ("run_id", "run_id"), ("attempt_id", "attempt_id"), ("root_task_id", "root_thread_id"),
        ("root_model", "root_model"), ("root_effort", "root_effort"), ("source_version", "source_version"),
        ("installed_version", "installed_plugin_version"), ("task_loaded_version", "task_loaded_version"), ("fresh_task", "fresh_task"))}
    return deepcopy(state), identity


def _capacity_read(read: dict, capture: dict, identity: dict) -> None:
    stage = capture["controller_report"]["stage_report"]["receipt"]
    bindings = stage["bindings"]
    _json(read)
    _require(_same(read, capacity.authority_read_report(read["state"], store_id=read["store_id"])))
    _require(read["status"] == "VERIFIED" and read["continuity_verified"] is True)
    _require(read["store_id"] == bindings["capacity_authority_store_id"]
        and read["state_sha256"] == bindings["capacity_authority_state_sha256"], "capacity_changed")
    checked = capacity.validate_authority_state(read["state"])
    lanes = bindings["capacity_authority_lane_ids"]
    _require(lanes == [identity["run_id"] + ":" + lane for lane in ("spec", "standards")])
    _require(set(lanes) <= checked["active_lane_ids"])
    _require(checked["runs"][identity["run_id"]]["root_thread_id"] == identity["root_task_id"])
    _require(all(checked["ledger"]["bindings"][lane] == {"run_id": identity["run_id"], "route": "native_luna"} for lane in lanes))


def _claim_directory(root: Any, capture: dict) -> int:
    path = Path(root)
    _require(path.is_absolute() and path.resolve(strict=True) == path, "evidence_root_invalid")
    parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(parent)
        _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0, "evidence_root_invalid")
        name = "completion-settlement-" + capture["report_sha256"]
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
        except FileExistsError as error:
            raise ValueError("completion_settlement:attempt_already_claimed") from error
        os.fsync(parent)
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)


def _keep(directory: int, name: str, value: dict) -> None:
    raw = native._canonical(value) + b"\n"
    _require(len(raw) <= 8 * native.MAX_PROGRAM_BYTES, "evidence_too_large")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.fsync(directory)


def _report(*, capture, observation, before, status, releases=(), native_result=None, after=None, authority_after=None, issues=()):
    core = deepcopy({"schema": SCHEMA, "status": status, "issues": list(issues),
        "completion_capture": capture, "process_observation": observation, "capacity_before": before,
        "release_receipts": list(releases), "native_result": native_result, "capacity_after": after,
        "authority_after": authority_after,
        "scope": "owned_completion_capacity", "resource_release_proven": status == "PASS",
        "terminal_claim_permitted": False, "model_calls": 0, "native_calls": 0, "cost_usd": None})
    return {**core, "report_sha256": native._sha(core)}


def validate_completed_capacity_settlement(report: Any) -> dict:
    """Validate a successful transport join, not the origin of supplied JSON.

    Signature authority and replay checks belong to the actual capacity commit.
    This pure validator cannot turn an arbitrary report into host authority.
    """
    try:
        _json(report)
        _require(len(native._canonical(report)) <= 8 * native.MAX_PROGRAM_BYTES)
        capture, observation = report["completion_capture"], report["process_observation"]
        _require(process.validate_completion_process_observation(observation, capture)["valid"] and observation["status"] == "OBSERVED")
        result, releases = report["native_result"], report["release_receipts"]
        _require(native.validate_governed_native_controller_report(result)["valid"] and result["status"] == "PASS")
        _require(result["controller_id"] == capture["controller_report"]["controller_id"] and result["action"] is None)
        _require(result["controller_state"]["terminal"] is False and result["controller_state"]["cleanup_required"] is False)
        prior = capture["controller_report"]["stage_report"]["receipt"]
        settled = result["stage_report"]["receipt"]
        _require(result["stage_report"]["disposition"] == "CAPACITY_RELEASED")
        _require(settled["predecessor_receipt_sha256"] == prior["receipt_sha256"])
        _require(result["next_stage_action"] in {"final_qualification", "failure_closure"})
        authority = report["authority_after"]
        completion_waiting_authority(authority)
        _require(_same(authority["owner"], capture["authority_after"]["owner"]))
        _require(_same(authority["identity"], capture["authority_after"]["identity"]))
        _require(_same(authority["tip"], result["cursor"]))
        prior_cursor = capture["controller_report"]["cursor"]
        _require(result["cursor"]["run_id"] == prior_cursor["run_id"] and result["cursor"]["seq"] > prior_cursor["seq"])
        before, after = report["capacity_before"], report["capacity_after"]
        identity = {"run_id": prior["run_id"], "root_task_id": prior["root_task_id"]}
        _capacity_read(before, capture, identity)
        lanes = prior["bindings"]["capacity_authority_lane_ids"]
        _require(type(releases) is list and len(releases) == len(lanes))
        for lane, release in zip(lanes, releases):
            _require(capacity.validate_release_receipt(release, lane_id=lane, run_id=prior["run_id"], route="native_luna", terminal_state="completed"))
            _require(release["terminal_evidence_sha256"] == observation["report_sha256"])
            payload = capacity.cleanup_observer_payload(lane_id=lane, run_id=prior["run_id"], route="native_luna",
                terminal_state="completed", cleanup_status="complete", owned_descendants=0,
                terminal_evidence_sha256=observation["report_sha256"])
            _require(_same(release["cleanup_observer_receipt"]["payload"], payload))
        _require(_same(after, capacity.authority_read_report(after["state"], store_id=before["store_id"])))
        _require(after["status"] == "VERIFIED" and after["state_sha256"] == settled["bindings"]["capacity_authority_state_sha256"])
        _require(not set(lanes) & set(after["state"]["active_lane_ids"]))
        expected_capacity = capacity._next_authority_state(before["state"],
            active_lane_ids=sorted(set(before["state"]["active_lane_ids"]) - set(lanes)))
        _require(_same(after["state"], expected_capacity))
        expected_bindings = {**deepcopy(prior["bindings"]), "capacity_authority_lane_ids": [],
            "current_wave_logical_lane_ids": [], "completed_logical_lane_ids": ["spec", "standards"],
            "capacity_authority_state_sha256": after["state_sha256"]}
        _require(_same(settled["bindings"], expected_bindings))
        _require(_same(report, _report(capture=capture, observation=observation, before=before, releases=releases,
            native_result=result, after=after, authority_after=authority, status="PASS")))
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return {"valid": False, "issues": ["completion_settlement:transport_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def settle_verified_completion(controller, bound_process: process.BoundCompletionProcess, completion_capture: Any, *, evidence_root: Any) -> dict:
    """Sign once after observed cleanup, then submit one exact native stage.

    Read-only refusal raises before authority/key access. Once the create-only
    directory is claimed, every failure is final for that evidence root/capture.
    A REFUSED result may follow a physical commit; retained native/readback
    evidence must be reconciled, never treated as proof of rollback.
    """
    _require(type(bound_process) is process.BoundCompletionProcess, "original_process_handle_required")
    capture = deepcopy(completion_capture)
    _require(native.validate_verified_completion_source_capture(capture)["valid"] and capture["status"] == "OBSERVED")
    observation = bound_process.observe_cleanup()
    _require(process.validate_completion_process_observation(observation, capture)["valid"])
    _require(observation["status"] == "OBSERVED", "process_unobserved")
    state, identity = _snapshot(controller, capture)
    before = _read_capacity(controller)
    _capacity_read(before, capture, identity)
    now = controller._evaluation_time()
    directory = _claim_directory(evidence_root, capture)
    releases, native_result, after, authority_after = [], None, None, None
    try:
        _keep(directory, "intent.json", _report(capture=capture, observation=observation, before=before, status="STARTED"))
        try:
            # Bracket initial observations and artifact creation before key access.
            _require(_same(_snapshot(controller, capture)[0], state))
            _require(_same(_read_capacity(controller), before), "capacity_changed")
            _, signer, _ = activation._authority()
            for index, lane in enumerate(capture["controller_report"]["stage_report"]["receipt"]["bindings"]["capacity_authority_lane_ids"]):
                payload = capacity.cleanup_observer_payload(lane_id=lane, run_id=identity["run_id"], route="native_luna",
                    terminal_state="completed", cleanup_status="complete", owned_descendants=0,
                    terminal_evidence_sha256=observation["report_sha256"])
                signed = signer.issue("lane-cleanup-observation", payload, issued_at=(now-timedelta(seconds=1)).isoformat(),
                    valid_until=(now+timedelta(minutes=4)).isoformat(), nonce="completion-" + native._sha(payload)[:32])
                _keep(directory, f"signed-{index}.json", signed)
                release = capacity.release({"lane_id": lane, "run_id": identity["run_id"], "route": "native_luna",
                    "state": "completed", "cleanup_status": "complete", "terminal_evidence_sha256": observation["report_sha256"],
                    "cleanup_evidence_sha256": native._sha(signed), "cleanup_observer_receipt": signed}, 0)
                _keep(directory, f"release-{index}.json", release)
                releases.append(release)
            stage = attempt.build_capacity_settlement_program(identity, state["stage_report"], releases)
            program = native.build_governed_native_stage_program(controller_id=capture["controller_report"]["controller_id"],
                expected_cursor=capture["controller_report"]["cursor"], stage_program=stage, proposed_action=None)
            _require(controller._stage_continuity_issues(stage, state) == [])
            _require(_same(_snapshot(controller, capture)[0], state))
            _require(_same(_read_capacity(controller), before), "capacity_changed")
            _keep(directory, "dispatch.json", program)
            native_result = controller.advance(program)
            _keep(directory, "native-result.json", native_result)
            after = _read_capacity(controller)
            authority_after = controller.grants.canonical_authority()
            latest, rows = controller._state(capture["authority_after"]["owner"]["controller_run_id"], recover_provisional=False)
            _require(_same(native._cursor(rows), native_result["cursor"]))
            _require(_same(latest["stage_report"], native_result["stage_report"]))
            _require(_same(latest.get("checkpoint_sources"), capture["checkpoint_sources"]))
            _require(controller._hook_runtime_matches(latest["activation"]["identity"])
                and controller._retained_hook_evidence_valid(latest))
            result = _report(capture=capture, observation=observation, before=before, releases=releases,
                native_result=native_result, after=after, authority_after=authority_after, status="PASS")
            _require(validate_completed_capacity_settlement(result)["valid"], "settlement_unconfirmed")
        except Exception as error:
            # Never copy arbitrary signer/provider error text into host evidence.
            result = _report(capture=capture, observation=observation, before=before, releases=releases,
                native_result=native_result, after=after, authority_after=authority_after, status="REFUSED",
                issues=["completion_settlement:" + type(error).__name__])
        _keep(directory, "result.json", result)
        return result
    finally:
        os.close(directory)


def _verified_host_cleanup(value: Any) -> dict:
    cleanup = deepcopy(value)
    _json(cleanup)
    core = {
        key: child for key, child in cleanup.items() if key != "report_sha256"
    }
    _require(
        cleanup.get("schema") == HOST_CLEANUP_SCHEMA
        and cleanup.get("status") == "PASS"
        and cleanup.get("disposition") == "QUALIFICATION_HOST_CLOSED"
        and cleanup.get("issues") == []
        and cleanup.get("process_reaped") is True
        and cleanup.get("process_group_absent") is True
        and cleanup.get("descendants_absent") is True
        and cleanup.get("owner_socket_absent") is True
        and cleanup.get("output_monitor_closed") is True
        and cleanup.get("host_closed") is True
        and cleanup.get("report_sha256") == native._sha(core),
        "host_cleanup_invalid",
    )
    return cleanup


def _cleanup_snapshot(controller) -> tuple[dict, dict, dict, dict]:
    authority = controller.grants.canonical_authority()
    completion_waiting_authority(authority)
    state, rows = controller._state(
        authority["owner"]["controller_run_id"], recover_provisional=False
    )
    cursor = native._cursor(rows)
    identity_source = state["activation"]["identity"]
    _require(authority["owner"]["activation_sha256"] == native._sha(state["activation"]))
    _require(_same(cursor, authority["tip"]))
    _require(
        state["action"] is None
        and state["pending_intent"] is None
        and state["grant_state"] is None
        and state["terminal"] is False
        and state["cleanup_required"] is False
        and state["action_outcome"] == "completed",
        "controller_not_clean",
    )
    _require(
        isinstance(state.get("last_batch_result"), dict)
        and state["last_batch_result"].get("kind") == "stop"
        and native.native_result.stop_result_binding(
            state["last_batch_result"].get("result_binding"),
            state["last_batch_result"].get("lane_ids"),
        )
        == state["last_batch_result"].get("result_binding"),
        "workers_not_closed",
    )
    _require(controller._retained_hook_evidence_valid(state), "action_evidence_changed")
    identity = {
        key: identity_source[source]
        for key, source in (
            ("run_id", "run_id"),
            ("attempt_id", "attempt_id"),
            ("root_task_id", "root_thread_id"),
            ("root_model", "root_model"),
            ("root_effort", "root_effort"),
            ("source_version", "source_version"),
            ("installed_version", "installed_plugin_version"),
            ("task_loaded_version", "task_loaded_version"),
            ("fresh_task", "fresh_task"),
        )
    }
    controller_before = controller._base_report(
        controller_id=authority["owner"]["controller_id"],
        status="PASS",
        decision="WAITING_FOR_STAGE",
        issues=[],
        cursor=cursor,
        state=state,
    )
    return deepcopy(state), identity, deepcopy(authority), controller_before


def _cleanup_capacity_read(read: dict, state: dict, identity: dict) -> list[str]:
    receipt = state["stage_report"]["receipt"]
    bindings = receipt["bindings"]
    _json(read)
    _require(
        _same(
            read,
            capacity.authority_read_report(
                read["state"], store_id=read["store_id"]
            ),
        )
    )
    _require(read["status"] == "VERIFIED" and read["continuity_verified"] is True)
    _require(
        read["store_id"] == bindings["capacity_authority_store_id"]
        and read["state_sha256"]
        == bindings["capacity_authority_state_sha256"],
        "capacity_changed",
    )
    checked = capacity.validate_authority_state(read["state"])
    lanes = list(bindings["capacity_authority_lane_ids"])
    _require(set(lanes) <= set(checked["active_lane_ids"]))
    _require(
        checked["runs"][identity["run_id"]]["root_thread_id"]
        == identity["root_task_id"]
    )
    return lanes


def _cleanup_settlement_report(
    *,
    status: str,
    cleanup: dict,
    authority_before: dict,
    controller_before: dict,
    capacity_before: dict,
    releases=(),
    native_result=None,
    capacity_after=None,
    authority_after=None,
    issues=(),
) -> dict:
    core = {
        "schema": CLEANUP_SETTLEMENT_SCHEMA,
        "status": status,
        "issues": list(issues),
        "host_cleanup": cleanup,
        "authority_before": authority_before,
        "controller_before": controller_before,
        "capacity_before": capacity_before,
        "release_receipts": list(releases),
        "native_result": native_result,
        "capacity_after": capacity_after,
        "authority_after": authority_after,
        "resource_release_proven": status == "PASS",
        "provider_free": True,
        "model_calls": 0,
        "native_calls": 0,
    }
    return {**core, "report_sha256": native._sha(core)}


def validate_cleanup_capacity_settlement(report: Any) -> dict:
    try:
        _json(report)
        _require(len(native._canonical(report)) <= 4 * native.MAX_PROGRAM_BYTES, "report_too_large")
        cleanup = _verified_host_cleanup(report["host_cleanup"])
        before_report = report["controller_before"]
        result = report["native_result"]
        releases = report["release_receipts"]
        before = report["capacity_before"]
        after = report["capacity_after"]
        _require(
            native.validate_governed_native_controller_report(before_report)[
                "valid"
            ]
            and before_report["status"] == "PASS"
            and before_report["decision"] == "WAITING_FOR_STAGE"
            and before_report["action"] is None,
            "controller_before_invalid",
        )
        _require(
            native.validate_governed_native_controller_report(result)["valid"]
            and result["status"] == "PASS"
            and result["action"] is None
            and result["stage_report"]["disposition"] == "CAPACITY_RELEASED"
            # A rejected review settles to failure_closure (rehearsals 21-22);
            # the route is the one the governed attempt derived.
            and result["next_stage_action"] in {"final_qualification", "failure_closure"}
            and result["next_stage_action"]
            == result["stage_report"]["receipt"]["next_action"],
            "native_result_invalid",
        )
        prior = before_report["stage_report"]["receipt"]
        settled = result["stage_report"]["receipt"]
        _require(
            settled["predecessor_receipt_sha256"] == prior["receipt_sha256"],
            "settled_predecessor_mismatch",
        )
        identity = {
            "run_id": prior["run_id"],
            "root_task_id": prior["root_task_id"],
        }
        lanes = _cleanup_capacity_read(before, {
            "stage_report": before_report["stage_report"]
        }, identity)
        _require(type(releases) is list and len(releases) == len(lanes), "release_count_invalid")
        for lane, release in zip(lanes, releases):
            _require(
                capacity.validate_release_receipt(
                    release,
                    lane_id=lane,
                    run_id=prior["run_id"],
                    route="native_luna",
                    terminal_state="completed",
                ),
                "release_receipt_invalid",
            )
            _require(
                release["terminal_evidence_sha256"]
                == cleanup["report_sha256"],
                "release_evidence_mismatch",
            )
        _require(
            _same(
                after,
                capacity.authority_read_report(
                    after["state"], store_id=before["store_id"]
                ),
            )
            and after["status"] == "VERIFIED"
            and after["state"]["active_lane_ids"] == []
            and settled["bindings"]["capacity_authority_lane_ids"] == []
            and settled["bindings"]["capacity_authority_state_sha256"]
            == after["state_sha256"],
            "capacity_after_invalid",
        )
        authority_after = report["authority_after"]
        completion_waiting_authority(authority_after)
        _require(_same(authority_after["tip"], result["cursor"]), "authority_tip_mismatch")
        expected = _cleanup_settlement_report(
            status="PASS",
            cleanup=cleanup,
            authority_before=report["authority_before"],
            controller_before=before_report,
            capacity_before=before,
            releases=releases,
            native_result=result,
            capacity_after=after,
            authority_after=authority_after,
        )
        _require(_same(report, expected), "report_not_canonical")
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
        # Name the failing check (rehearsal run 21 reported only ValueError).
        detail = str(error)
        return {
            "valid": False,
            "issues": [
                "completion_settlement:cleanup_transport_invalid",
                detail
                if detail.startswith("completion_settlement:")
                else "completion_settlement:" + type(error).__name__,
            ],
            "scope": "canonical_transport",
        }
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def settle_cleanup_observed_completion(controller, host_cleanup: Any) -> dict:
    """Release capacity after physical cleanup, without source/process proofs."""

    cleanup = _verified_host_cleanup(host_cleanup)
    state, identity, authority_before, controller_before = _cleanup_snapshot(
        controller
    )
    before = _read_capacity(controller)
    lanes = _cleanup_capacity_read(before, state, identity)
    now = controller._evaluation_time()
    releases: list[dict] = []
    native_result = None
    after = None
    authority_after = None
    try:
        _, signer, _ = activation._authority()
        for lane in lanes:
            payload = capacity.cleanup_observer_payload(
                lane_id=lane,
                run_id=identity["run_id"],
                route="native_luna",
                terminal_state="completed",
                cleanup_status="complete",
                owned_descendants=0,
                terminal_evidence_sha256=cleanup["report_sha256"],
            )
            signed = signer.issue(
                "lane-cleanup-observation",
                payload,
                issued_at=(now - timedelta(seconds=1)).isoformat(),
                valid_until=(now + timedelta(minutes=4)).isoformat(),
                nonce="cleanup-" + native._sha(payload)[:32],
            )
            releases.append(
                capacity.release(
                    {
                        "lane_id": lane,
                        "run_id": identity["run_id"],
                        "route": "native_luna",
                        "state": "completed",
                        "cleanup_status": "complete",
                        "terminal_evidence_sha256": cleanup["report_sha256"],
                        "cleanup_evidence_sha256": native._sha(signed),
                        "cleanup_observer_receipt": signed,
                    },
                    0,
                )
            )
        stage = attempt.build_capacity_settlement_program(
            identity, state["stage_report"], releases
        )
        program = native.build_governed_native_stage_program(
            controller_id=authority_before["owner"]["controller_id"],
            expected_cursor=controller_before["cursor"],
            stage_program=stage,
            proposed_action=None,
        )
        native_result = controller.advance(program)
        after = _read_capacity(controller)
        authority_after = controller.grants.canonical_authority()
        report = _cleanup_settlement_report(
            status="PASS",
            cleanup=cleanup,
            authority_before=authority_before,
            controller_before=controller_before,
            capacity_before=before,
            releases=releases,
            native_result=native_result,
            capacity_after=after,
            authority_after=authority_after,
        )
        validation = validate_cleanup_capacity_settlement(report)
        _require(
            validation["valid"],
            "cleanup_settlement_unconfirmed:"
            + ",".join(str(issue) for issue in validation["issues"][1:]),
        )
        return report
    except Exception as error:
        detail = str(error)
        return _cleanup_settlement_report(
            status="REFUSED",
            cleanup=cleanup,
            authority_before=authority_before,
            controller_before=controller_before,
            capacity_before=before,
            releases=releases,
            native_result=native_result,
            capacity_after=after,
            authority_after=authority_after,
            issues=["completion_settlement:" + type(error).__name__]
            + ([detail[:300]] if detail.startswith("completion_settlement:") else []),
        )


def _settled_snapshot(controller, report: dict) -> dict:
    """Read current resource/owner authority; never recover or advance a grant."""
    authority = controller.grants.canonical_authority()
    completion_waiting_authority(authority)
    _require(_same(authority, report["authority_after"]), "owner_changed")
    state, rows = controller._state(authority["owner"]["controller_run_id"], recover_provisional=False)
    capture = report["completion_capture"]
    _require(authority["owner"]["activation_sha256"] == native._sha(state["activation"]))
    _require(_same(native._cursor(rows), report["native_result"]["cursor"]))
    _require(_same(state["stage_report"], report["native_result"]["stage_report"]))
    _require(state["action"] is None and state["pending_intent"] is None and state["grant_state"] is None
        and state["terminal"] is False and state["cleanup_required"] is False and state["action_outcome"] is None)
    _require(_same([row for row in state["action_evidence"] if row["action"]["kind"] == "stop"], capture["action_evidence"]))
    _require(_same(state["last_batch_result"], capture["batch_result"]))
    _require(_same(state.get("checkpoint_sources"), capture["checkpoint_sources"]))
    _require(controller._hook_runtime_matches(state["activation"]["identity"])
        and controller._retained_hook_evidence_valid(state), "hooks_changed")
    current_capacity = _read_capacity(controller)
    _require(_same(current_capacity, report["capacity_after"]), "capacity_changed")
    return deepcopy({"authority": authority, "capacity": current_capacity, "state": state, "rows": rows})


def observe_current_completion_settlement(controller, settlement_report: Any) -> dict:
    """Authenticate saved capture/process proof and compare current owned state.

    Unlike the pure transport validator, this host observer verifies both
    signatures against one public trust-store snapshot and the host replay guard.
    It uses the controller's trusted clock and the existing host environment
    bindings; input JSON supplies no trust path, key or evaluation time. Replay
    bookkeeping may write its own database. No signing key, owner RPC, native
    action, controller journal, grant or capacity mutation is performed here.
    Final gates must invoke this observer, not trust a saved OBSERVED JSON value.
    """
    report = deepcopy(settlement_report)
    before, after, signatures, issues = None, None, [], []
    try:
        _require(validate_completed_capacity_settlement(report)["valid"], "transport_invalid")
        before = _settled_snapshot(controller, report)
        now = controller._evaluation_time()
        trust, replay, dependency_issue = observer_receipt._host_dependencies(None, None, os.environ)
        _require(dependency_issue is None, "observer_authority_unavailable")
        for release in report["release_receipts"]:
            payload = capacity.cleanup_observer_payload(lane_id=release["lane_id"], run_id=release["run_id"],
                route=release["route"], terminal_state="completed", cleanup_status="complete", owned_descendants=0,
                terminal_evidence_sha256=report["process_observation"]["report_sha256"])
            verified = observer_receipt.verify_signed_receipt(release["cleanup_observer_receipt"],
                expected_kind="lane-cleanup-observation", expected_payload=payload, evaluation_time=now,
                trust_store=trust, replay_guard=replay)
            signatures.append(verified)
            _require(verified["status"] == "PASS" and verified["signed_receipt_sha256"] == release["cleanup_evidence_sha256"],
                "signature_unverified")
        after = _settled_snapshot(controller, report)
        _require(_same(before, after), "state_changed")
    except Exception as error:
        # Retain structured signature failures; avoid copying arbitrary adapter errors.
        issues = ["completion_settlement:observation_" + type(error).__name__]
    core = {"schema": "orch-dork/current-completion-settlement-observation/v1",
        "status": "REFUSED" if issues else "OBSERVED", "issues": issues,
        "settlement_report_sha256": report.get("report_sha256") if type(report) is dict and capacity._digest(report.get("report_sha256")) else None,
        "authority_before": before["authority"] if before else None,
        "authority_after": after["authority"] if after else None,
        "capacity_before": before["capacity"] if before else None,
        "capacity_after": after["capacity"] if after else None,
        "signature_reports": signatures, "scope": "current_owned_completion_settlement",
        "resource_release_proven": not issues, "terminal_claim_permitted": False,
        "model_calls": 0, "native_calls": 0, "signing_key_reads": 0}
    return {**core, "report_sha256": native._sha(core)}


def _admitted_program(snapshot: dict, program: Any) -> dict:
    """Select a unique successful historical pre-spawn from the verified journal.

    This helper checks transport relationships; only its caller's current host
    snapshot authenticates where those rows came from. Never rerun old preflight
    inputs or turn their receipt into new admission authority.
    """
    _json(program)
    _require(len(native._canonical(program)) <= native.MAX_PROGRAM_BYTES, "admission_program_bounds")
    issues = []
    identity = attempt._validate_identity(program.get("identity"), issues)
    _require(not issues and set(program) == attempt._PROGRAM_FIELDS
        and program["schema"] in {attempt.PROGRAM_SCHEMA, attempt.CHECKPOINT_PROGRAM_SCHEMA}
        and program["operation"] == "pre_spawn" and program["predecessor_receipt"] is None, "admission_program_invalid")
    rows, state = snapshot["rows"], snapshot["state"]
    native.run_engine.verify_event_chain(rows)
    _require(all(row["run_id"] == snapshot["authority"]["owner"]["controller_run_id"] for row in rows)
        and _same(native._cursor(rows), snapshot["authority"]["tip"]), "admission_journal_mismatch")
    events = native._controller_events(rows)
    reduced = native._reduce(events)
    _require(_same(reduced, {key: value for key, value in state.items() if key not in {"grant", "grant_state"}}),
        "admission_reduction_mismatch")
    current = attempt._post_batch_predecessor_report(identity, state["stage_report"], issues)
    _require(not issues and current["stage"] == "capacity_settlement", "admission_identity_mismatch")
    positions = [i for i, event in enumerate(events) if event["event_type"] == "stage_intent"
        and event["payload"].get("operation") == "pre_spawn"]
    _require(len(positions) == 1, "admission_not_unique")
    index = positions[0]
    intent = events[index]
    _require(intent["payload"].get("stage_program_sha256") == native._sha(program)
        and index + 1 < len(events) and events[index+1]["event_type"] == "stage_result", "admission_intent_mismatch")
    result = events[index+1]
    report = result["payload"]["stage_report"]
    receipt = attempt._validate_receipt(report.get("receipt"), identity, issues,
        allowed_stages={"pre_spawn"}, allowed_actions={"capacity_admission"})
    _require(not issues and receipt["status"] == "READY" and receipt["predecessor_receipt_sha256"] is None
        and receipt["plan_sha256"] == current["plan_sha256"] and report["schema"] == attempt.REPORT_SCHEMA
        and report["operation"] == "pre_spawn" and report["status"] == "PASS"
        and report["disposition"] == "SHARED_CAPACITY_ADMISSION_REQUIRED" and report["next_action"] == "capacity_admission"
        and all(report[key] == identity[key] for key in ("run_id", "attempt_id", "root_task_id"))
        and _same(report, attempt._report(operation="pre_spawn", identity=identity, status="PASS",
            disposition="SHARED_CAPACITY_ADMISSION_REQUIRED", issues=[], stages=report["stages"], receipt=receipt)),
        "admission_not_successful")
    # The exact original bytes, rather than the later checkpoint budget receipt,
    # identify the frozen input. Progress legitimately replaces that receipt.
    return deepcopy({"intent": intent, "result": result, "stage_report": report,
        "journal_sha256": native._sha(rows), "journal_tip": snapshot["authority"]["tip"]})


def _admitted_capacity(snapshot: dict, program: dict, admission: dict, source: dict) -> dict:
    """Bind one historical capacity admission to this wave's settled slots.

    Inventory describes allocated slots for this attempt, not a retrospective
    native-capacity measurement. Other runs may have changed the global ledger;
    the initial authority hash is provenance, never assumed equal to today's.
    """
    events = native._controller_events(snapshot["rows"])
    positions = [i for i,event in enumerate(events) if event["event_type"] == "stage_intent"
        and event["payload"].get("operation") == "capacity_admission"]
    _require(len(positions) == 1, "capacity_admission_not_unique")
    index = positions[0]
    expected = attempt.build_capacity_admission_program(program, admission["stage_report"])
    _require(index > events.index(admission["result"]) and index+1 < len(events)
        and events[index+1]["event_type"] == "stage_result"
        and events[index]["payload"].get("stage_program_sha256") == native._sha(expected), "capacity_admission_input_mismatch")
    report = events[index+1]["payload"]["stage_report"]
    issues = []
    receipt = attempt._validate_receipt(report.get("receipt"), program["identity"], issues,
        allowed_stages={"capacity_admission"}, allowed_actions={"spawn"})
    prior = admission["stage_report"]["receipt"]
    _require(not issues and receipt["status"] == "AUTHORIZED" and receipt["plan_sha256"] == prior["plan_sha256"]
        and receipt["predecessor_receipt_sha256"] == prior["receipt_sha256"]
        and _same(report, attempt._report(operation="capacity_admission", identity=program["identity"], status="PASS",
            disposition="SPAWN_AUTHORIZED", issues=[], stages=report["stages"], receipt=receipt)), "capacity_admission_not_successful")
    bindings = receipt["bindings"]
    retained = source["completion_capture"]["controller_report"]["stage_report"]["receipt"]["bindings"]
    lanes = bindings["capacity_authority_lane_ids"]
    _require(type(bindings["capacity_wave_index"]) is int and bindings["capacity_wave_index"] == 1
        and bindings["current_wave_logical_lane_ids"] == ["spec", "standards"]
        and _same(lanes, retained["capacity_authority_lane_ids"])
        and _same(bindings["task_specs"], retained["task_specs"])
        and _same(bindings["all_task_specs"], retained["all_task_specs"])
        and bindings["capacity_authority_store_id"] == source["capacity_before"]["store_id"], "capacity_admission_wave_mismatch")
    admitted_at = observer_receipt.evidence.instant(events[index]["payload"]["evaluation_time"])
    _require(admitted_at >= observer_receipt.evidence.instant(admission["intent"]["payload"]["evaluation_time"]),
        "capacity_admission_clock_invalid")
    return deepcopy({"intent":events[index], "result":events[index+1], "stage_report":report,
        "inventory_scope":"admitted_current_wave_slots", "inventory":{
            "schema":"orch-dork/collaboration-inventory/v1", "root_thread_id":program["identity"]["root_task_id"],
            "capacity":len(lanes), "retirement_supported":False, "workers":[]},
        "slot_ids":lanes, "logical_lane_ids":bindings["current_wave_logical_lane_ids"],
        "initial_authority_sha256":bindings["capacity_authority_state_sha256"],
        "pre_release_authority_sha256":source["capacity_before"]["state_sha256"],
        "journal_sha256":admission["journal_sha256"], "journal_tip":admission["journal_tip"]})


def observe_completion_admission_context(controller, settlement_report: Any, pre_spawn_program: Any) -> dict:
    """Bind the admitted program, current signed settlement and trusted host time.

    No JSON observation can substitute for this host call. The production chain
    reader and current owner/capacity bracket history and signature verification.
    This does not advance the controller or confer final/continuation authority.
    Public signature verification may update its existing replay database.
    """
    report, program = deepcopy(settlement_report), deepcopy(pre_spawn_program)
    before, after, admission, allocated, observed, now, issues = None, None, None, None, None, None, []
    try:
        _require(validate_completed_capacity_settlement(report)["valid"], "transport_invalid")
        before = _settled_snapshot(controller, report)
        admission = _admitted_program(before, program)
        allocated = _admitted_capacity(before, program, admission, report)
        observed = observe_current_completion_settlement(controller, report)
        _require(observed["status"] == "OBSERVED", "current_settlement_unobserved")
        now = controller._evaluation_time()
        _require(now >= observer_receipt.evidence.instant(allocated["intent"]["payload"]["evaluation_time"]),
            "admission_clock_regressed")
        # A signature can expire while the host finishes the remaining reads.
        for release in report["release_receipts"]:
            signed = release["cleanup_observer_receipt"]
            _require(observer_receipt.evidence.instant(signed["issued_at"]) <= now
                <= observer_receipt.evidence.instant(signed["valid_until"]), "admission_signature_expired")
        after = _settled_snapshot(controller, report)
        _require(_same(before, after), "admission_state_changed")
    except Exception as error:
        issues = ["completion_settlement:admission_observation_" + type(error).__name__]
    core = {"schema": "orch-dork/completion-admission-context/v1", "status": "REFUSED" if issues else "OBSERVED",
        "issues": issues, "scope": "current_host_admission_and_settlement",
        "settlement_report_sha256": report.get("report_sha256") if type(report) is dict and capacity._digest(report.get("report_sha256")) else None,
        "pre_spawn_program_sha256": native._sha(program) if admission else None,
        "admission": admission, "capacity_admission": allocated, "settlement_observation": observed,
        "authority_before": before["authority"] if before else None,
        "authority_after": after["authority"] if after else None,
        "observed_at": now.isoformat() if now else None,
        "terminal_claim_permitted": False, "continuation_permitted": False,
        "model_calls": 0, "native_calls": 0, "signing_key_reads": 0}
    return {**core, "report_sha256": native._sha(core)}


__all__ = [
    "CLEANUP_SETTLEMENT_SCHEMA",
    "settle_cleanup_observed_completion",
    "settle_verified_completion",
    "validate_cleanup_capacity_settlement",
    "validate_completed_capacity_settlement",
    "observe_current_completion_settlement",
    "observe_completion_admission_context",
]
