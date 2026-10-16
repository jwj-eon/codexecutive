"""Execute and refine the fixed Issue 170 production-readiness slice.

Importing this module is runtime-only.  The complete-source execution fixture is
loaded only by :func:`execute_readiness_case`, from one fixed repository path.
The resulting report deliberately carries no campaign or qualification authority
until the production-execution issued-object API is frozen and integrated.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType

from lifecycle_conformance import cartesian, reference_model as model
from lifecycle_conformance import reference_values as rv, values
import orch_dork_execution_readiness as execution_readiness
import orch_dork_adaptive_contracts as contracts
import orch_dork_qualification_bootstrap as bootstrap


SCHEMA = "orch-dork/production-readiness-execution/v1"
STATUS = "PASS_ZERO_AUTHORITY_API_PENDING"
_FIXTURE_RELATIVE = Path("tests/lifecycle_conformance/production_readiness_fixture.py")
_FIXTURE_SHA256 = "12ca5b71d4fe6f6f8f476d22b72eb686b90068ed4cc061393d59450a99c63624"
_EXPECTED = {
    "context170-8a27b8e93bb8a9e456883eecfd2fe5cea00894f89e9c1b035f40950758615efc": (
        "08a430d248b4d3df50dee0f4f4a73e7539247565c6bccf90ce21da532e9b1db9",
        "a43e2c6d565a4889985b70fee6781595a9a3ec685fab54338087457d5d68f92e",
        "production-family:1caeed3f4238c734de5db1dd1f65470aea4c288a3ac13ce66e01bb39485c8cfb",
    ),
    "context170-943c443fad4f124e42cd3f23daff13ab7578546b96afb82a73278f3725567ea6": (
        "0f9d3106caf8bbdbb4ff29fdcf81a25b23e92d050df6e6ca04d328a4a6b246cb",
        "fe1c7362226c3867c135a3bbd2962bcf18a756ba0964deb1cc687e5829ca2e80",
        "production-family:39f4f34345583b9a3a5ab3e40131483251b7407a90ecd276b0089b3e38d3db0b",
    ),
    "context170-c2142c1e1e3649e79c918f8d718c741eff3cf69de0c73945fbba50ec8ef7a014": (
        "7550d9b4d3023d60522c55f066678d29a0cef216773a47568e18434013dfc8e8",
        "efd2d861dbe3e4c0edb331ff47cc53d1650e7f983ab5118a0a2d6026eabd330a",
        "production-family:861530d39c7145a6ba2966675f69b52a4b9bec4cb2ca66f97c14519d7897c265",
    ),
    "context170-bfabc933d6ad104dc9fefdf5d4284426c7e78580f9a84cfdad17f06e7fe1ce09": (
        "e7397eb2167af7b5c328d3d9257dfab4f4955a2f4328224cf31892fefa5904a0",
        "9a447d20dc8551c78ef9082a80cd19cc91ed5e6a48b3981a31d79f8975451861",
        "production-family:39f4f34345583b9a3a5ab3e40131483251b7407a90ecd276b0089b3e38d3db0b",
    ),
    "context170-4295282ac569804a19b4adf3c71105ddb962ef88041580036002b71deb9a0f0a": (
        "30efcd9896712b1897abb8035a7f2684ae05bf83b5adb627e3031a8690054d12",
        "628a2c31aa7626250bed31a2d476580105491fa71a60ef4f9aa4c290ff7ec4ba",
        "production-family:861530d39c7145a6ba2966675f69b52a4b9bec4cb2ca66f97c14519d7897c265",
    ),
}


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("production_readiness:" + reason)


def _load_fixed_driver() -> ModuleType:
    root = Path(__file__).resolve().parents[4]
    fixture = root / _FIXTURE_RELATIVE
    try:
        fixture_bytes = fixture.read_bytes()
        if (fixture.is_symlink() or not fixture.is_file() or fixture.resolve(strict=True) != fixture
                or hashlib.sha256(fixture_bytes).hexdigest() != _FIXTURE_SHA256):
            _refuse("fixture_origin")
    except OSError:
        _refuse("fixture_unavailable")
    spec = importlib.util.spec_from_file_location(
        "_orch_dork_fixed_production_readiness_fixture", fixture)
    if spec is None or spec.loader is None or spec.origin != str(fixture):
        _refuse("fixture_origin")
    module = importlib.util.module_from_spec(spec)
    exec(compile(fixture_bytes, str(fixture), "exec"), module.__dict__)
    driver = getattr(module, "execute_fixed_readiness", None)
    if not callable(driver) or getattr(driver, "__module__", None) != module.__name__:
        _refuse("fixture_entrypoint")
    return module


def _context_paths():
    """Yield the five exact contexts in both legal lane orders."""
    initial = model.initial_state("graph-166")
    shared_event = model.outgoing_stimuli(initial).to_plain()[0]
    shared = cartesian.context_for(initial, shared_event)
    after_shared = rv.freeze(model.reduce(initial, shared_event).to_plain()["successor"])
    outgoing = {row["target"]: row for row in model.outgoing_stimuli(after_shared).to_plain()}
    paths = []
    for first, second in (("spec", "standards"), ("standards", "spec")):
        first_event = deepcopy(outgoing[first])
        first_context = cartesian.context_for(after_shared, first_event)
        after_first = rv.freeze(model.reduce(after_shared, first_event).to_plain()["successor"])
        second_event = next(row for row in model.outgoing_stimuli(after_first).to_plain()
                            if row["target"] == second)
        second_context = cartesian.context_for(after_first, second_event)
        paths.append((shared, first_context, second_context))
    return paths


def _production_inputs(seed) -> tuple[dict, dict]:
    """Validate the live seed and retain exact public readiness inputs."""
    if getattr(seed, "mode", None) != "fresh-bootstrap":
        _refuse("seed_mode")
    artifact = getattr(seed, "bootstrap_artifact", None)
    inputs = getattr(seed, "pre_turn_inputs", None)
    if not isinstance(artifact, bootstrap.Issue94ControllerBootstrapArtifact) or type(inputs) is not dict:
        _refuse("seed_shape")
    roots = artifact.source_roots
    validated = bootstrap.Issue94ControllerBootstrapArtifact.from_report(
        artifact.report, roots["source"], roots["evidence"],
        inputs["enrollment_registry_root"])
    if validated.report_sha256 != artifact.report_sha256:
        _refuse("bootstrap_binding")
    pre = validated.pre_spawn_artifact
    binding = execution_readiness.validate_readiness_binding(
        pre.execution_readiness_program, pre.execution_readiness_report)
    if binding.get("valid") is not True or pre.execution_readiness_report.get("status") != "READY_FOR_AUTHORITY":
        _refuse("shared_readiness")
    task_specs = pre.qualification_report.get("qualification_payload", {}).get("task_specs")
    if type(task_specs) is not list or len(task_specs) != 2:
        _refuse("lane_inventory")
    lanes = {row.get("logical_worker_id"): row for row in task_specs if type(row) is dict}
    if set(lanes) != {"spec", "standards"}:
        _refuse("lane_inventory")
    for lane, row in lanes.items():
        validation = contracts.validate_task_spec(row.get("task_spec"))
        if (validation.get("valid") is not True or validation.get("digest") != row.get("task_spec_sha256")
                or validation.get("normalized", {}).get("id") != lane):
            _refuse("lane_input")
    claims = pre.governed_inputs_report.get("research_manifest", {}).get("claims")
    if type(claims) is not list:
        _refuse("lane_sources")
    claim_ids = {row.get("claim_id") for row in claims if type(row) is dict}
    if not {"issue94-spec-research-scope", "issue94-standards-research-scope"} <= claim_ids:
        _refuse("lane_sources")
    whole = {
        "bootstrap_report": artifact.report,
        "qualification_report": pre.qualification_report,
        "governed_inputs_report": pre.governed_inputs_report,
        "execution_readiness_program": pre.execution_readiness_program,
        "execution_readiness_report": pre.execution_readiness_report,
        "source_roots": roots,
    }
    return whole, {"production_case_id": artifact.report["case_id"],
        "shared_program": pre.execution_readiness_program,
        "shared_original": pre.execution_readiness_report,
        "lanes": lanes, "whole_output_sha256": values.canonical_digest(whole)}


def _execute_boundary(inputs: dict, target: str) -> tuple[dict, dict, dict]:
    """Call the actual public producer/validator and one real refusal branch."""
    if target == "shared":
        original_input = inputs["shared_program"]
        produced = execution_readiness.evaluate_execution_readiness(original_input)
        binding = execution_readiness.validate_readiness_binding(original_input, produced)
        if (produced != inputs["shared_original"] or produced.get("status") != "READY_FOR_AUTHORITY"
                or binding.get("valid") is not True):
            _refuse("shared_output")
        accepted = {"producer_output": produced, "validation": binding}
        counterfeit = deepcopy(produced)
        counterfeit["receipt_sha256"] = "0" * 64
        refused = execution_readiness.validate_readiness_binding(original_input, counterfeit)
        if refused.get("valid") is not False or refused.get("status") != "FAIL":
            _refuse("shared_counterfeit_accepted")
    else:
        wrapper = inputs["lanes"][target]
        original_input = wrapper["task_spec"]
        accepted = contracts.validate_task_spec(original_input)
        if (accepted.get("valid") is not True or accepted.get("digest") != wrapper["task_spec_sha256"]
                or accepted.get("normalized", {}).get("id") != target):
            _refuse("lane_output")
        counterfeit = deepcopy(original_input)
        counterfeit["schema"] = "orch-dork/counterfeit-task-spec/v2"
        refused = contracts.validate_task_spec(counterfeit)
        if refused.get("valid") is not False or refused.get("status") != "FAIL":
            _refuse("lane_counterfeit_accepted")
    return accepted, refused, {"input_sha256": values.canonical_digest(original_input),
        "counterfeit_input_sha256": values.canonical_digest(counterfeit)}


def _effect_snapshot(seed) -> dict:
    """Observe the production state that pure readiness checks must preserve."""
    process = getattr(seed, "owner_process", None)
    clock = getattr(seed, "fixture_clock", None)
    return {
        "authority_sha256": values.canonical_digest({
            "preparation": getattr(seed, "preparation_report", None),
            "first_action": getattr(seed, "first_action_report", None),
        }),
        "grants_sha256": values.canonical_digest(
            getattr(seed, "first_action_report", {}).get("action")),
        "owner_sha256": values.canonical_digest({
            "observation": getattr(seed, "owner_observation", None),
            "custody": getattr(seed, "owner_custody", None),
            "pid": None if process is None else process.pid,
            "returncode": None if process is None else process.poll(),
        }),
        "clock": None if clock is None else clock.instant.isoformat(),
        "resources_sha256": values.canonical_digest({
            "bootstrap": seed.bootstrap_artifact.report,
            "roots": seed.bootstrap_artifact.source_roots,
            "process_alive": process is not None and process.poll() is None,
        }),
    }


def _execute_live_seed(seed) -> rv.FrozenValue:
    """Fixed callback used only by the repository-owned complete-source driver."""
    whole, inputs = _production_inputs(seed)
    original_digest = values.canonical_digest(whole)
    effects_before = _effect_snapshot(seed)
    accepted, refused, seen = [], [], set()
    order_receipts = []
    shared, *_ = _context_paths()[0]
    paths = [(shared,), *_context_paths()]
    for path_index, path in enumerate(paths):
        order = []
        for context in path if path_index == 0 else path[1:]:
            data = context.to_plain()
            if data["id"] in seen:
                _refuse("duplicate_context_execution")
            seen.add(data["id"])
            expected = _EXPECTED.get(data["id"])
            if expected is None or (context.digest(), values.canonical_digest(data["event"])) != expected[:2]:
                _refuse("context_binding")
            before = rv.freeze(data["state"])
            before_digest = before.digest()
            target = data["event"]["target"]
            actual, actual_refusal, input_binding = _execute_boundary(inputs, target)
            reduced = model.reduce(before, data["event"]).to_plain()
            if before.digest() != before_digest or reduced["transition_id"] != data["event"]["transition"]:
                _refuse("model_refinement")
            accepted.append({"context_id": data["id"], "context_sha256": context.digest(),
                "family_id": expected[2], "transition_id": reduced["transition_id"],
                "event_sha256": expected[1], "before_state_sha256": before_digest,
                "after_state_sha256": rv.freeze(reduced["successor"]).digest(),
                "directive_sha256": values.canonical_digest(reduced["directive"]),
                "production_target": target, **input_binding,
                "production_output_sha256": values.canonical_digest(actual),
                "whole_output_sha256": inputs["whole_output_sha256"], "status": "PASS"})

            invalid_event = deepcopy(data["event"])
            invalid_event["generation"] += 1
            try:
                model.reduce(before, invalid_event)
            except values.LifecycleContractError as error:
                model_reason = error.reason
            else:
                _refuse("invalid_model_event_accepted")
            if before.digest() != before_digest or values.canonical_digest(whole) != original_digest:
                _refuse("refusal_mutated_original")
            refused.append({"context_id": data["id"], "context_sha256": context.digest(),
                "counterfeit_change": ("readiness receipt_sha256 replaced" if target == "shared"
                                        else "task_spec schema replaced"),
                "production_refusal_sha256": values.canonical_digest(actual_refusal),
                "production_refusal_status": actual_refusal.get("status"),
                "invalid_event_change": "generation + 1",
                "model_reason": model_reason, "source_state_unchanged": True,
                "whole_original_unchanged": True, "status": "REFUSED"})
            order.append({"target": target,
                "input_sha256": input_binding["input_sha256"],
                "output_sha256": values.canonical_digest(actual)})
        order_receipts.append(order)
    if set(seen) != set(_EXPECTED) or len(accepted) != 5 or len(refused) != 5:
        _refuse("context_union")
    lane_orders = order_receipts[1:]
    by_lane = [{row["target"]: row for row in order} for order in lane_orders]
    if (len(lane_orders) != 2 or [row["target"] for row in lane_orders[0]] != ["spec", "standards"]
            or [row["target"] for row in lane_orders[1]] != ["standards", "spec"]
            or any(by_lane[0][lane] != by_lane[1][lane] for lane in ("spec", "standards"))
            or values.canonical_digest(whole) != original_digest):
        _refuse("lane_commutation")
    effects_after = _effect_snapshot(seed)
    if effects_after != effects_before:
        _refuse("readiness_effect")
    validator_sources = {}
    root = Path(__file__).resolve().parents[4]
    for name, module in (("shared", execution_readiness), ("lane", contracts)):
        path = Path(module.__file__).resolve(strict=True)
        try:
            relative = path.relative_to(root)
        except ValueError:
            _refuse("validator_origin")
        validator_sources[name] = {"path": str(relative),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    report = {"schema": SCHEMA, "status": STATUS,
        "production_case_id": inputs["production_case_id"],
        "whole_output_sha256": inputs["whole_output_sha256"],
        "accepted_contexts": sorted(accepted, key=lambda row: row["context_id"]),
        "refused_contexts": sorted(refused, key=lambda row: row["context_id"]),
        "commutation": {"orders": lane_orders, "whole_outputs_equal_by_lane": True,
            "source_inputs_unchanged": True, "effects_before": effects_before,
            "effects_after": effects_after, "authority_delta": 0, "grant_delta": 0,
            "owner_delta": 0, "clock_delta": 0, "resource_delta": 0,
            "validator_sources": validator_sources},
        "counts": {"candidate_families": 3, "contexts": 5, "accepted": 5,
                   "refused": 5, "injections": 0, "credited_contexts": 0},
        "issued_api_integrated": False, "production_execution_attested": False,
        "qualification_authorized": False, "campaign_credit_permitted": False}
    report["report_sha256"] = values.canonical_digest(report)
    return rv.freeze(report)


def execute_readiness_case() -> rv.FrozenValue:
    """Run the sole fixed complete-source readiness case; accepts no callback."""
    result = _load_fixed_driver().execute_fixed_readiness()
    if type(result) is not rv.FrozenValue or result.to_plain().get("schema") != SCHEMA:
        _refuse("driver_result")
    return result


def validate_readiness_report(report: rv.FrozenValue) -> None:
    """Validate reporting identity only; this never upgrades execution credit."""
    if type(report) is not rv.FrozenValue:
        _refuse("report_type")
    data = report.to_plain()
    seal = data.pop("report_sha256", None)
    if (data.get("schema") != SCHEMA or data.get("status") != STATUS
            or seal != values.canonical_digest(data)
            or data.get("campaign_credit_permitted") is not False
            or data.get("counts") != {"candidate_families": 3, "contexts": 5,
                "accepted": 5, "refused": 5, "injections": 0, "credited_contexts": 0}
            or len(data.get("accepted_contexts", [])) != 5
            or len(data.get("refused_contexts", [])) != 5):
        _refuse("report_binding")


__all__ = ["SCHEMA", "STATUS", "execute_readiness_case", "validate_readiness_report"]
