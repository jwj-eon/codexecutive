"""Host-local project evidence and improvement adoption (Issue 199).

Ordinary watcher runs lack some measurements required by the historical
factored-route schema. Project evidence retains the same role attribution
grammar without inventing those measurements. Context is frozen before a
model turn; history derives outcomes from the stored host terminal record.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

import orch_dork_champion_challenger as cc
import orch_dork_model_profile_registry as registry
import orch_dork_onboarded_profiles as onboarded
import orch_dork_route_learning as learning
import orch_dork_runtime_package as runtime_package
import orch_dork_project_proposals as proposals
import orch_dork_project_promotion as promotion


CONTEXT_SCHEMA = "orch-dork/project-run-context/v1"
FACTORS_SCHEMA = "orch-dork/project-run-factors/v1"
HISTORY_SCHEMA = "orch-dork/project-improvement-history/v1"
REPORT_SCHEMA = "orch-dork/project-improvement-report/v1"
PROPOSE_INPUT_SCHEMA = "orch-dork/project-improvement-propose-input/v1"
READ_INPUT_SCHEMA = "orch-dork/project-improvement-read-input/v1"
DECISION_INPUT_SCHEMA = "orch-dork/project-improvement-decision-input/v1"
CANARY_INPUT_SCHEMA = "orch-dork/project-canary-approval-input/v1"
ADOPT_INPUT_SCHEMA = "orch-dork/project-improvement-adopt-input/v1"
STORED_SCHEMA = "orch-dork/project-improvement-stored/v1"
DECISION_SCHEMA = "orch-dork/project-improvement-decision/v1"
PREFERENCES_SCHEMA = "orch-dork/project-preferences/v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
STAGE_SCHEMA = "orch-dork/project-promotion-stage/v1"
CANARY_INTENT_SCHEMA = "orch-dork/project-canary-intent/v1"
OBSERVATION_SCHEMA = "orch-dork/project-evaluation-observation/v1"
FEEDBACK_SCHEMA = "orch-dork/project-human-review/v1"
COST_SCHEMA = "orch-dork/project-cost-observation/v1"
FIXTURE_SCHEMA = "orch-dork/project-evaluation-fixture/v1"


def _watcher():
    import orch_dork_governed_run_watcher
    return orch_dork_governed_run_watcher


def freeze_context(request: Mapping[str, Any], plan: Mapping[str, Any],
                   admission: Mapping[str, Any], *, source_root: Path,
                   run_dir: Path, onboarding_root: Any = None, records: Path | None = None,
                   role_guidance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Retain the exact model profiles and configuration before model dispatch.

    Recheck cached guidance against its packaged source before freezing.
    The prompt identity includes the consumed block's source label and
    digest as well as its planner body. Zero-worker runs retain the
    watcher-only prompt identity; history reads its retained context.
    """

    watcher = _watcher()
    models = {row["model"]: row["profile_sha256"] for row in admission["models"]}
    workers = plan["workers"]
    actors = [("planner" if workers else "implementer", request["model"], request["effort"],
               "root_labor", ["root"])]
    if workers:
        actors.append(("implementer", request["worker_model"], request["worker_effort"],
                       "native_subagent", sorted(lane["id"] for lane in request["lanes"])))
    assignments = []
    identities = []
    profiles = []
    for role, model, effort, adapter, nodes in actors:
        observed = onboarded.onboarded(model, onboarding_root)
        if observed is None or observed["profile_sha256"] != models.get(model):
            raise watcher.WatcherError("governed_run:request_invalid", "onboarding profile changed before evidence freeze")
        profile = {"role": role, "model": model, "effort": effort, "adapter": adapter,
                   "onboarded_profile": observed}
        profiles.append(profile)
        assignments.append({"role": role, "profile_id": registry.onboarded_profile_id(role, model, effort),
                            "profile_sha256": watcher.policy.sha256(profile), "model": model,
                            "effort": effort, "adapter": adapter, "node_ids": nodes})
        identities.append({"role": role, "model_id": model,
                           "runtime_id": "codex/" + observed["codex_version"].removeprefix("codex-cli "),
                           "checkpoint_sha256": observed["profile_sha256"]})
    settings = {"workflow_profile": plan["workflow_profile"], "worker_count": workers,
                "models": {role: model for role, model, _, _, _ in actors},
                "efforts": {role: effort for role, _, effort, _, _ in actors}}
    choice_sha = watcher.policy.sha256(settings)
    catalog = registry.registry()
    role_guidance_bytes = b""
    role_guidance_sha256: str | None = None
    consumed_role_section: str | None = None
    planner_bytes = 0
    if role_guidance is not None:
        current_guidance = watcher.required_role_guidance(source_root)
        if current_guidance != role_guidance:
            raise watcher.WatcherError(watcher.ROLE_GUIDANCE_INVALID,
                                       "packaged role guidance changed before evidence freeze")
        consumed_role_section, planner_body = watcher.planner_role_guidance(current_guidance)
        role_guidance_sha256 = current_guidance["digest"]
        planner_bytes = len(planner_body.encode("utf-8"))
        role_guidance_bytes = watcher.role_guidance_block(
            consumed_role_section, planner_body, role_guidance_sha256).encode("utf-8")
    compiler_inputs = {}
    for name in runtime_package.RUNTIME_ALLOWLIST:
        try:
            data = (source_root / name).read_bytes()
        except FileNotFoundError:
            if name not in runtime_package.RUNTIME_OPTIONAL_PATHS:
                raise
            compiler_inputs[name] = None
        else:
            compiler_inputs[name] = hashlib.sha256(data).hexdigest()
    compiler = watcher.policy.sha256(compiler_inputs)
    if role_guidance_sha256 is not None and compiler_inputs.get(
            watcher.ROLE_GUIDANCE_PACKAGED_PATH) != role_guidance_sha256:
        raise watcher.WatcherError(watcher.ROLE_GUIDANCE_INVALID,
                                   "packaged role guidance changed during evidence freeze")
    watcher_prompts = (source_root / "skills/orch-dork/scripts/orch_dork_governed_run_watcher.py").read_bytes()
    prompts = hashlib.sha256(watcher_prompts + role_guidance_bytes).hexdigest()
    program = {"schema": cc.PROGRAM_SCHEMA, "action": "seal_configuration", "request": {
        "configuration": {"schema": cc.CONFIGURATION_DRAFT_SCHEMA_V3,
            "configuration_id": "project-choice-" + choice_sha[:24], "role": "champion",
            "profile_registry_sha256": catalog["registry_sha256"],
            "registry_generation": catalog["generation"], "routing_policy_sha256": choice_sha,
            "role_default": None, "compiler_sha256": compiler,
            "prompt_bundle_sha256": prompts, "routing_rules_sha256": choice_sha,
            "model_runtime_identities": identities,
            "context_policy": {"policy_id": "watcher-summary/v1", "policy_sha256": compiler},
            "budgets": {"token_limit": None, "cost_limit_micros": plan["budget_cents"] * 10000,
                        "latency_limit_ms": request["turn_seconds"] * 1000,
                        "sol_ingress_limit_tokens": None, "repair_limit": 1},
            "verification_policy": {"policy_id": "enrolled-checks/v1",
                                    "policy_sha256": plan["enrollment_sha256"]}}}}
    configuration = cc.evaluate(program)
    if configuration["status"] != "PASS":
        raise watcher.WatcherError("governed_run:request_invalid", str(configuration["issues"]))
    context = watcher.sealed({"schema": CONTEXT_SCHEMA, "run_id": request["run_id"],
        "frozen_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "project_id": watcher.project_key(Path(request["project_root"])),
        "request_sha256": watcher.policy.sha256(dict(request)), "plan_sha256": plan["plan_sha256"],
        "settings": settings, "policy_sha256": choice_sha, "profiles": profiles,
        "role_factors": {"registry_generation": catalog["generation"],
                         "registry_sha256": catalog["registry_sha256"],
                         "routing_policy_sha256": choice_sha,
                         "assignments": sorted(assignments, key=lambda row: (row["role"], row["profile_id"]))},
        "role_guidance": {"sha256": role_guidance_sha256,
                          "consumed_section": consumed_role_section,
                          "bytes": planner_bytes},
        "configuration": configuration["configuration"]}, "context_sha256")
    active = preferences(Path(request["project_root"]), records=records)
    context = watcher.sealed({**context, "preferences_sha256": active["preferences_sha256"]
        if active and active["state"] == "active" and active["settings"] == settings else None}, "context_sha256")
    watcher.write_json(run_dir / "project-context.json", context, create_only=True)
    canary_path = run_dir / "project-canary.json"
    if canary_path.exists():
        canary = _artifact(canary_path, "orch-dork/project-canary-run/v1", "claim_sha256")
        _require(context["configuration"] == _champion(canary["configuration"]),
                 "canary source, onboarding, budgets or verification differ from the frozen configuration")
    return context


def _project_factors(record: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    watcher = _watcher()
    known, unknown = learning.known_factor, learning.unknown_factor
    rows = []
    for actor in context["role_factors"]["assignments"]:
        rows.append({"role": actor["role"], "profile_id": actor["profile_id"],
                     "acceptance": known("accepted" if record["verdict"]["label"] == watcher.VERIFIED else "rejected")
                     if actor["role"] == "implementer" and record["verdict"]["label"] in
                     {watcher.VERIFIED, watcher.FAILED_CHECKS}
                     else unknown("not_attributable"),
                     "repair_passes": known(1 if actor["role"] == "implementer" and record.get("repair") else 0),
                     "elapsed_ms": unknown("not_observed"), "cost": unknown("cost_unpriced"),
                     "escalations": unknown("not_attributable"),
                     "human_disposition": unknown("not_observed")})
    validation = learning.validate_role_attribution(context["role_factors"], rows)
    if validation["status"] != "PASS":
        raise ValueError(str(validation["issues"]))
    start, end = (datetime.fromisoformat(record[key].replace("Z", "+00:00"))
                  for key in ("started_at", "ended_at"))
    elapsed = int((end - start).total_seconds() * 1000)
    measured = record.get("elapsed_ms")
    if measured is not None:
        _require(type(measured) is int and measured > 0, "invalid host latency observation")
        elapsed = measured
    if (record.get("cleanup") or {}).get("reaped"):
        elapsed = None  # Neither this process's clock nor reaping time measured the lost run.
    return watcher.sealed({"schema": FACTORS_SCHEMA, "run_id": record["run_id"],
        "project_id": context["project_id"], "terminal_record_sha256": record["record_sha256"],
        "policy_sha256": context["policy_sha256"], "settings": context["settings"],
        "role_factors": context["role_factors"],
        "role_outcome_factors": rows, "verdict": record["verdict"]["label"],
        "elapsed_ms": elapsed if elapsed is not None and elapsed > 0 else None}, "evidence_sha256")


def read_history(project_root: Path, *, records: Path | None = None) -> dict[str, Any]:
    """Read only this project's host terminal records and frozen contexts."""

    watcher = _watcher()
    records = records or watcher.records_root()
    key = watcher.project_key(project_root)
    history, excluded, ordering = [], [], {}
    directory = records / "runs"
    for run_dir in sorted(directory.iterdir()) if directory.is_dir() else ():
        if not run_dir.is_dir() or run_dir.is_symlink():
            continue
        try:
            if not (run_dir / "record.json").exists():
                continue
            record = watcher.read_json(run_dir / "record.json")
            if watcher.project_key(Path(record["project_root"])) != key:
                continue
            context = watcher.read_json(run_dir / "project-context.json")
            if context.get("project_id") != key:
                continue
            request = watcher.read_json(run_dir / "request.json")
            claim = watcher.read_json(run_dir / "admission.json")
            if watcher.record_verdict(record, None)["label"] != record["verdict"]["label"]:
                raise ValueError("terminal verdict disagrees with host checks and observation")
            settings = context["settings"]
            plan = claim["plan"]
            models = ({"planner": request["model"], "implementer": request["worker_model"]}
                      if plan["workers"] else {"implementer": request["model"]})
            efforts = ({"planner": request["effort"], "implementer": request["worker_effort"]}
                       if plan["workers"] else {"implementer": request["effort"]})
            expected_settings = {"workflow_profile": plan["workflow_profile"],
                                 "worker_count": plan["workers"], "models": models, "efforts": efforts}
            if (settings != expected_settings or
                    context["policy_sha256"] != watcher.policy.sha256(settings) or
                    context["configuration"]["routing_policy_sha256"] != context["policy_sha256"] or
                    context["configuration"]["routing_rules_sha256"] != context["policy_sha256"]):
                raise ValueError("workflow settings disagree with admitted plan")
            expected_assignments, expected_identities = [], []
            for profile in context["profiles"]:
                observed = profile["onboarded_profile"]
                role = profile["role"]
                root_labor = role == "planner" or not plan["workers"]
                _require(not onboarded.validate_profile(observed) and observed["model"] == profile["model"] == models[role] and
                         profile["effort"] == efforts[role] and profile["adapter"] == ("root_labor" if root_labor else "native_subagent"),
                         "retained model profile disagrees with the admitted actor")
                expected_assignments.append({"role": role,
                    "profile_id": registry.onboarded_profile_id(role, profile["model"], profile["effort"]),
                    "profile_sha256": watcher.policy.sha256(profile), "model": profile["model"], "effort": profile["effort"],
                    "adapter": profile["adapter"], "node_ids": ["root"] if root_labor else sorted(lane["id"] for lane in request["lanes"])})
                expected_identities.append({"role": role, "model_id": profile["model"],
                    "runtime_id": "codex/" + observed["codex_version"].removeprefix("codex-cli "),
                    "checkpoint_sha256": observed["profile_sha256"]})
            _require(context["role_factors"]["assignments"] == sorted(expected_assignments, key=lambda row: (row["role"], row["profile_id"])) and
                     sorted(context["configuration"]["model_runtime_identities"], key=lambda row: row["role"]) ==
                     sorted(expected_identities, key=lambda row: row["role"]) and
                     context["role_factors"]["registry_sha256"] == context["configuration"]["profile_registry_sha256"] and
                     context["role_factors"]["registry_generation"] == context["configuration"]["registry_generation"],
                     "role attribution disagrees with retained profiles")
            if not (watcher.seal_valid(context, "context_sha256") and
                    watcher.seal_valid(record, "record_sha256") and
                    watcher.seal_valid(claim, "claim_sha256") and
                    context["run_id"] == record["run_id"] == request["run_id"] == run_dir.name and
                    context["request_sha256"] == claim["request_sha256"] == watcher.policy.sha256(request) and
                    context["plan_sha256"] == record["plan_sha256"] == claim["plan"]["plan_sha256"] and
                    key == watcher.project_key(Path(record["project_root"])) == claim["project_key"] and
                    cc.validate_configuration(context["configuration"])["status"] == "PASS"):
                raise ValueError("project evidence provenance mismatch")
            factors = _project_factors(record, context)
            history.append({"run_id": record["run_id"], "project_id": key,
                            "settings": context["settings"], "configuration": context["configuration"],
                            "factored_record": factors})
            ordering[record["run_id"]] = (record["ended_at"], record["run_id"])
        except (OSError, ValueError, KeyError, TypeError, watcher.WatcherError) as error:
            excluded.append({"run_id": run_dir.name, "reason": str(error)[:200]})
    return {"schema": HISTORY_SCHEMA, "status": "PASS", "project_id": key,
            "history": sorted(history, key=lambda row: ordering[row["run_id"]]), "excluded": excluded, "provider_free": True}


def _require(condition: Any, detail: str) -> None:
    if not condition:
        raise ValueError(detail)


def _report(status: str, **values: Any) -> dict[str, Any]:
    return _watcher().sealed({"schema": REPORT_SCHEMA, "status": status,
        "provider_free": True, "model_calls": 0, "hosted_calls": 0, **values}, "report_sha256")


def _refused(error: Exception, *, mutation_performed: bool = False) -> dict[str, Any]:
    return _report("REFUSED", reason="project_improvement:request_invalid", message=str(error),
                   mutation_performed=mutation_performed)


def _task(task: Any) -> str:
    _require(isinstance(task, str) and 0 < len(task.encode("utf-8")) <= 256 and
             all(ord(char) >= 32 for char in task), "requesting task required")
    return hashlib.sha256(task.encode("utf-8")).hexdigest()


def _project(arguments: Mapping[str, Any], records: Path) -> tuple[Path, str, Path]:
    _require(isinstance(arguments.get("project_root"), str), "project_root required")
    root = Path(os.path.realpath(arguments["project_root"]))
    _watcher().read_enrollment(records, root)
    key = _watcher().project_key(root)
    return root, key, records / "project-improvements" / key


def _artifact(path: Path, schema: str, field: str) -> dict[str, Any]:
    value = _watcher().read_json(path)
    _require(value.get("schema") == schema and _watcher().seal_valid(value, field),
             "invalid project artifact")
    return value


def _digest(value: Any) -> str:
    _require(isinstance(value, str) and _SHA.fullmatch(value), "invalid proposal digest")
    return value


def preferences(project_root: Path, *, records: Path | None = None) -> dict[str, Any] | None:
    """Forward-only local defaults; absence is distinct from an observed baseline."""
    records = records or _watcher().records_root()
    path = records / "project-improvements" / _watcher().project_key(project_root) / "preferences.json"
    if not path.exists():
        return None
    value = _artifact(path, PREFERENCES_SCHEMA, "preferences_sha256")
    _require(value["project_id"] == _watcher().project_key(project_root), "foreign project preferences")
    _require(value["state"] in {"active", "suspended"} and type(value["version"]) is int and value["version"] > 0,
             "invalid preference state")
    settings = value["settings"]
    _require(set(settings) == {"workflow_profile", "worker_count", "models", "efforts"} and
             type(settings["worker_count"]) is int and 0 <= settings["worker_count"] <= _watcher().admission.MAX_WORKERS and
             settings["workflow_profile"] == _watcher().admission.workflow_profile_for(settings["worker_count"]),
             "invalid preference workflow")
    roles = {"planner", "implementer"} if settings["worker_count"] else {"implementer"}
    _require(set(settings["models"]) == set(settings["efforts"]) == roles and
             all(isinstance(model, str) and _watcher()._MODEL.fullmatch(model) for model in settings["models"].values()) and
             all(isinstance(effort, str) and _watcher()._EFFORT.fullmatch(effort)
                 for effort in settings["efforts"].values()), "invalid preference roles")
    _require(cc.validate_configuration(value["configuration"])["status"] == "PASS" and
             value["configuration"]["routing_policy_sha256"] == _watcher().policy.sha256(settings),
             "preference configuration disagrees")
    return value


def apply_defaults(arguments: Mapping[str, Any], *, records: Path) -> tuple[dict[str, Any], str | None]:
    """Use adopted settings only for omitted choices in a fresh work draft."""
    watcher = _watcher()
    root = Path(os.path.realpath(str(arguments.get("project_root"))))
    active = suspend_on_regression(root, records=records)
    result = dict(arguments)
    digest = (active or {}).get("preferences_sha256")
    if active is None or active["state"] != "active":
        return result, digest
    settings = active["settings"]
    if "lanes" not in result and "tickets" not in result and settings["worker_count"]:
        _require(settings["worker_count"] == 1, "draft the adopted number of disjoint lanes before preparation")
        project = watcher.read_enrollment(records, root)
        result["lanes"] = [{"id": "implementation", "goal": result["goal"],
                            "checks": [{"check": row["id"]} for row in project["checks"]]}]
    workers = bool(result.get("lanes"))
    role = "planner" if workers else "implementer"
    if role in settings["models"]:
        result.setdefault("model", settings["models"][role])
        result.setdefault("effort", settings["efforts"][role])
    if workers:
        result.setdefault("worker_model", settings["models"]["implementer"])
        result.setdefault("worker_effort", settings["efforts"]["implementer"])
    return result, digest


def suspend_on_regression(root: Path, *, records: Path) -> dict[str, Any] | None:
    """A fresh host intake suspends a regressed default without rewriting any run."""
    watcher = _watcher()
    with watcher.machine_lock(records):
        active = preferences(root, records=records)
        if active is None or active["state"] != "active" or watcher.project_key(root) in watcher.machine_runs(records)["projects"]:
            return active
        for row in read_history(root, records=records)["history"]:
            if row["factored_record"]["verdict"] != watcher.FAILED_CHECKS:
                continue
            context = watcher.read_json(watcher.run_directory(records, row["run_id"]) / "project-context.json")
            if context.get("preferences_sha256") != active["preferences_sha256"]:
                continue
            updated = watcher.sealed({**active, "state": "suspended", "version": active["version"] + 1,
                "prior_preferences_sha256": active["preferences_sha256"],
                "suspension": {"reason": "failed_checks", "run_id": row["run_id"],
                    "terminal_record_sha256": row["factored_record"]["terminal_record_sha256"],
                    "observed_at": watcher.utc_now()}}, "preferences_sha256")
            base = records / "project-improvements" / watcher.project_key(root)
            watcher.write_json(base / "suspensions" / (active["preferences_sha256"] + ".json"), updated, create_only=True)
            watcher.write_json(base / "preferences.json", updated)
            return updated
        return active


def _inactive(records: Path, key: str) -> None:
    _require(key not in _watcher().machine_runs(records)["projects"], "project has an active or starting run")


def _stored(base: Path, task: str, digest: Any) -> tuple[Path, dict[str, Any]]:
    path = base / "proposals" / _task(task) / (_digest(digest) + ".json")
    value = _artifact(path, STORED_SCHEMA, "stored_sha256")
    _require(value["requesting_thread_id"] == task and value["proposal"]["proposal_sha256"] == digest,
             "proposal belongs to another task")
    replay = proposals.evaluate(value["evaluation_input"])
    _require(replay["status"] == "PASS" and value["proposal"] in replay["proposals"] and
             replay.get("fixture_only") is False, "proposal no longer replays under production floors")
    return path, value


def _unchanged(value: Mapping[str, Any], root: Path, records: Path) -> None:
    current = preferences(root, records=records)
    _require((current or {}).get("preferences_sha256") == value["prior_preferences_sha256"],
             "project defaults changed; propose again")
    _require(_watcher().policy.sha256(_watcher().read_enrollment(records, root)) == value["enrollment_sha256"],
             "enrollment changed; propose again")


def propose(arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
            records: Path | None = None) -> dict[str, Any]:
    """Project history creates advisory Challengers, never a policy change."""
    watcher = _watcher()
    records = records or watcher.records_root()
    try:
        _task(requesting_thread_id)
        _require(isinstance(arguments, Mapping) and set(arguments) <= {"project_root", "baseline_run_id"},
                 "proposal fields")
        root, key, base = _project(arguments, records)
        with watcher.machine_lock(records):
            evidence = read_history(root, records=records)
            all_rows = evidence["history"]
            rows = all_rows[-256:]
            window = {"selection": "latest_terminal_time_then_run_id", "maximum_runs": 256,
                      "retained_eligible_runs": len(all_rows), "selected_runs": len(rows),
                      "omitted_run_ids_sha256": watcher.policy.sha256([row["run_id"] for row in all_rows[:-256]])}
            evidence = {**evidence, "history": rows}
            if len(rows) < proposals.PRODUCTION_FLOORS["min_eligible_project_runs"]:
                return _report("INSUFFICIENT_EVIDENCE", floors=dict(proposals.PRODUCTION_FLOORS),
                    eligible_run_count=len(rows), excluded=evidence["excluded"], proposals=[], evidence_window=window,
                    mutation_performed=False)
            active = preferences(root, records=records)
            baseline = next((row for row in rows if row["run_id"] == arguments.get("baseline_run_id")), None)
            if active and active["state"] == "active" and "baseline_run_id" not in arguments:
                current = {"settings": active["settings"], "configuration": active["configuration"]}
            elif baseline is not None:
                current = {"settings": baseline["settings"], "configuration": baseline["configuration"]}
            else:
                return _report("BASELINE_REQUIRED", run_ids=[row["run_id"] for row in rows],
                    message="Choose the observed run to compare against; no adopted defaults exist.", mutation_performed=False)
            candidates, seen = [], set()
            candidate_settings = {}
            for row in rows:
                settings = row["settings"]
                variants = [("workflow_profile", {"workflow_profile": settings["workflow_profile"]}),
                            ("worker_count", {"worker_count": settings["worker_count"]})]
                variants += [("role_model", {"role": role, "model": model}) for role, model in settings["models"].items()]
                for dimension, choice in variants:
                    identity = watcher.policy.sha256({"dimension": dimension, "choice": choice,
                        "configuration": row["configuration"]["configuration_sha256"]})
                    if identity in seen:
                        continue
                    seen.add(identity)
                    candidates.append({"schema": proposals.CANDIDATE_SCHEMA, "candidate_id": "observed-" + identity[:24],
                        "dimension": dimension, "choice": choice, "configuration": row["configuration"]})
                    candidate_settings[row["configuration"]["configuration_sha256"]] = settings
            summaries = []
            evaluated_at = watcher.utc_now()
            for offset in range(0, len(candidates), proposals.MAX_CANDIDATES):
                evaluation_input = {"schema": proposals.REQUEST_SCHEMA, "project_id": key,
                    "evaluated_at": evaluated_at, "current": current,
                    "candidates": candidates[offset:offset + proposals.MAX_CANDIDATES], "history": evidence}
                report = proposals.evaluate(evaluation_input)
                _require(report["status"] == "PASS", str(report["issues"]))
                for proposal in report["proposals"]:
                    digest = proposal["proposal_sha256"]
                    original_sha = proposal["candidate"]["observed_configuration_sha256"]
                    value = watcher.sealed({"schema": STORED_SCHEMA, "project_root": str(root), "project_id": key,
                        "requesting_thread_id": requesting_thread_id, "proposal": proposal,
                        "evaluation_input": evaluation_input, "evidence_window": window,
                        "candidate_settings": candidate_settings[original_sha],
                        "prior_preferences_sha256": (active or {}).get("preferences_sha256"),
                        "enrollment_sha256": watcher.policy.sha256(watcher.read_enrollment(records, root))}, "stored_sha256")
                    path = base / "proposals" / _task(requesting_thread_id) / (digest + ".json")
                    if not path.exists():
                        watcher.write_json(path, value, create_only=True)
                    summaries.append({"proposal_sha256": digest, "dimension": proposal["dimension"],
                        "baseline": proposal["baseline"]["choice"], "candidate": proposal["candidate"]["choice"],
                        "promotion_gaps": proposal["promotion_gaps"],
                        "supporting_run_count": len(proposal["support"]["supporting_runs"]),
                        "contradicting_run_count": len(proposal["support"]["contradicting_runs"])})
            return _report("PROPOSALS_RECORDED" if summaries else "NO_IMPROVEMENT", proposals=summaries,
                floors=report["floors"], eligible_run_count=report["evidence"]["eligible_run_count"],
                evidence_window=window,
                instruction="Read each exact proposal and its evidence before asking for approval; approval alone does not activate it.",
                mutation_performed=False)
    except (OSError, ValueError, KeyError, TypeError, watcher.WatcherError) as error:
        return _refused(error)


def read(arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
         records: Path | None = None) -> dict[str, Any]:
    records = records or _watcher().records_root()
    try:
        _require(set(arguments) == {"project_root", "proposal_sha256"}, "read fields")
        _, _, base = _project(arguments, records)
        path, value = _stored(base, requesting_thread_id, arguments["proposal_sha256"])
        decision = path.with_name(path.stem + ".decision.json")
        intent = path.with_name(path.stem + ".canary-intent.json")
        stages = {stage: _artifact(_stage_path(path, stage), STAGE_SCHEMA, "stage_sha256")["stage_sha256"]
                  for stage in promotion.STAGE_ORDER if _stage_path(path, stage).exists()}
        return _report("PROPOSAL", proposal=value["proposal"], proposed_settings=value["candidate_settings"],
            evidence_window=value["evidence_window"],
            decision=_artifact(decision, DECISION_SCHEMA, "decision_sha256") if decision.exists() else None,
            recorded_stages=stages,
            canary=_artifact(intent, CANARY_INTENT_SCHEMA, "intent_sha256") if intent.exists() else None,
            mutation_performed=False)
    except (OSError, ValueError, KeyError, TypeError, _watcher().WatcherError) as error:
        return _refused(error)


def decide(arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
           records: Path | None = None) -> dict[str, Any]:
    """Record one explicit user approval/rejection; standing authority is neither."""
    watcher = _watcher()
    records = records or watcher.records_root()
    try:
        _require(set(arguments) == {"project_root", "confirm_proposal_sha256", "decision"} and
                 arguments["decision"] in {"approve", "reject"}, "decision fields")
        root, key, base = _project(arguments, records)
        with watcher.machine_lock(records):
            _inactive(records, key)
            path, value = _stored(base, requesting_thread_id, arguments["confirm_proposal_sha256"])
            _unchanged(value, root, records)
            decision = watcher.sealed({"schema": DECISION_SCHEMA, "project_id": key,
                "proposal_sha256": value["proposal"]["proposal_sha256"], "requesting_thread_id": requesting_thread_id,
                "decision": arguments["decision"], "decided_at": watcher.utc_now()}, "decision_sha256")
            watcher.write_json(path.with_name(path.stem + ".decision.json"), decision, create_only=True)
        return _report("APPROVED" if decision["decision"] == "approve" else "REJECTED",
            decision=decision, activation_permitted=False, mutation_performed=False)
    except (OSError, ValueError, KeyError, TypeError, watcher.WatcherError) as error:
        return _refused(error)


def _champion(configuration: Mapping[str, Any]) -> dict[str, Any]:
    return _watcher().sealed({**configuration, "role": "champion"}, "configuration_sha256")


def _approved(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    decision = _artifact(path.with_name(path.stem + ".decision.json"), DECISION_SCHEMA, "decision_sha256")
    _require(decision["decision"] == "approve" and decision["proposal_sha256"] == value["proposal"]["proposal_sha256"] and
             decision["requesting_thread_id"] == value["requesting_thread_id"], "explicit user approval missing")
    return decision


def _stage_path(path: Path, stage: str) -> Path:
    _require(stage in promotion.STAGE_ORDER, "unknown evaluation stage")
    return path.with_name(path.stem + "." + stage + ".json")


def _stage(path: Path, stage: str, value: Mapping[str, Any]) -> dict[str, Any]:
    stored = _artifact(_stage_path(path, stage), STAGE_SCHEMA, "stage_sha256")
    request = stored["evaluation_input"]
    _require(stored["stage"] == stage and stored["proposal_sha256"] == value["proposal"]["proposal_sha256"] and
             request["champion"] == _champion(value["proposal"]["baseline"]["configuration"]) and
             request["challenger"] == value["proposal"]["candidate"]["configuration"], "stage configuration changed")
    replay = cc.evaluate({"schema": cc.PROGRAM_SCHEMA, "action": "evaluate_offline", "request": request})
    _require(replay["status"] == "PASS" and replay["evaluation"]["decision"] == "OFFLINE_CHALLENGER_RETAINED",
             "stage does not pass Champion/Challenger gates: " + str(replay.get("issues")))
    return stored


def _blob(base: Path, digest: str) -> dict[str, Any]:
    raw = (base / "evidence" / (_digest(digest) + ".json"))
    value = _watcher().read_json(raw)
    _require(hashlib.sha256(raw.read_bytes()).hexdigest() == digest, "evaluation evidence bytes changed")
    return value


def _retain_blob(base: Path, value: Mapping[str, Any]) -> str:
    raw = _watcher().policy.canonical(value) + b"\n"
    digest = hashlib.sha256(raw).hexdigest()
    target = base / "evidence" / (digest + ".json")
    if target.exists():
        _require(target.read_bytes() == raw, "evaluation evidence digest collision")
    else:
        _watcher().write_json(target, value, create_only=True)
    return digest


def capture_result(project_root: Path, *, run_id: str, stage: str, configuration: Mapping[str, Any],
                   corpus: Mapping[str, Any], fixture: Mapping[str, Any], feedback: Mapping[str, Any],
                   cost: Mapping[str, Any], records: Path | None = None) -> dict[str, Any]:
    """Operator tooling: derive a CC result from a local terminal and explicit human/cost observations.

    No MCP tool accepts these measurements. Unknown billing or missing human
    review produces no result. Canary observations additionally require the
    host's authorization claim written before that run's first model turn.
    """
    watcher = _watcher()
    records = records or watcher.records_root()
    _, key, base = _project({"project_root": str(project_root)}, records)
    _require(stage in promotion.STAGE_ORDER and cc.validate_configuration(configuration)["status"] == "PASS" and
             cc.validate_corpus(corpus)["status"] == "PASS", "evaluation configuration/corpus invalid")
    _require(set(fixture) == {"schema", "project_id", "fixture_id", "goal", "lanes", "partition", "lineage_sha256"} and
             fixture["schema"] == FIXTURE_SCHEMA and fixture["project_id"] == key and
             fixture["partition"] in cc.PARTITIONS, "invalid frozen evaluation fixture")
    fixture_sha = _retain_blob(base, fixture)
    _require(fixture_sha in corpus["partitions"][fixture["partition"]], "fixture not in frozen corpus")
    run_dir = watcher.run_directory(records, run_id)
    context = _artifact(run_dir / "project-context.json", CONTEXT_SCHEMA, "context_sha256")
    record = _artifact(run_dir / "record.json", watcher.RECORD_SCHEMA, "record_sha256")
    request = watcher.read_json(run_dir / "request.json")
    rows = read_history(project_root, records=records)["history"]
    _require(any(row["run_id"] == run_id for row in rows) and context["configuration"] == _champion(configuration) and
             request["goal"] == fixture["goal"] and request["lanes"] == watcher._lane_requests(
                 fixture["lanes"][configuration["role"]]),
             "terminal does not bind the frozen configuration and fixture")
    _require(record.get("revision", 1) == 1 and record["cross_check"]["status"] == "AGREED" and
             record["verdict"]["label"] in {watcher.VERIFIED, watcher.FAILED_CHECKS}, "terminal conformance not observed")
    _require(datetime.fromisoformat(corpus["created_at"].replace("Z", "+00:00")) <=
             datetime.fromisoformat(context["frozen_at"].replace("Z", "+00:00")) <=
             datetime.fromisoformat(corpus["valid_until"].replace("Z", "+00:00")),
             "evaluation corpus was not frozen before the run")
    _require(set(feedback) == {"schema", "project_id", "run_id", "reviewer", "reviewed_at", "human_usefulness_bps"} and
             feedback["schema"] == FEEDBACK_SCHEMA and feedback["project_id"] == key and feedback["run_id"] == run_id and
             isinstance(feedback["reviewer"], str) and bool(feedback["reviewer"].strip()) and
             type(feedback["human_usefulness_bps"]) is int and 0 <= feedback["human_usefulness_bps"] <= 10000,
             "explicit human review required")
    _require(set(cost) == {"schema", "project_id", "run_id", "currency", "micros", "source", "observed_at"} and
             cost["schema"] == COST_SCHEMA and cost["project_id"] == key and cost["run_id"] == run_id and
             cost["currency"] == "USD" and type(cost["micros"]) is int and cost["micros"] >= 0 and
             isinstance(cost["source"], str) and bool(cost["source"].strip()), "observed billing required; budgets are not cost")
    for observed in (feedback["reviewed_at"], cost["observed_at"]):
        _require(datetime.fromisoformat(observed.replace("Z", "+00:00")) >=
                 datetime.fromisoformat(record["ended_at"].replace("Z", "+00:00")), "observation predates terminal")
    elapsed = _project_factors(record, context)["elapsed_ms"]
    _require(type(elapsed) is int and elapsed > 0, "latency was not measured")
    canary = None
    if stage == "canary":
        canary = _artifact(run_dir / "project-canary.json", "orch-dork/project-canary-run/v1", "claim_sha256")
        _require(canary["project_id"] == key and canary["fixture_sha256"] == fixture_sha and
                 canary["corpus_sha256"] == corpus["corpus_sha256"] and canary["configuration_sha256"] == configuration["configuration_sha256"] and
                 canary["request_sha256"] == watcher.policy.sha256(request), "canary was not authorized before its run")
    observation = watcher.sealed({"schema": OBSERVATION_SCHEMA, "project_id": key, "run_id": run_id,
        "stage": stage, "configuration_sha256": configuration["configuration_sha256"], "fixture_sha256": fixture_sha,
        "corpus_sha256": corpus["corpus_sha256"], "terminal_record_sha256": record["record_sha256"],
        "human_review_sha256": _retain_blob(base, feedback), "cost_observation_sha256": _retain_blob(base, cost),
        "canary_claim_sha256": (canary or {}).get("claim_sha256"),
        "safety": "PASS", "privacy": "PASS", "authority": "PASS",
        "correctness": "PASS" if record["verdict"]["label"] == watcher.VERIFIED else "FAIL",
        "human_usefulness_bps": feedback["human_usefulness_bps"], "cost_micros": cost["micros"],
        "latency_ms": elapsed}, "observation_sha256")
    result = cc.evaluate({"schema": cc.PROGRAM_SCHEMA, "action": "seal_result", "request": {"result": {
        "schema": cc.RESULT_DRAFT_SCHEMA, "configuration_sha256": configuration["configuration_sha256"],
        "fixture_sha256": fixture_sha, "partition": fixture["partition"], "lineage_sha256": fixture["lineage_sha256"],
        **{field: observation[field] for field in ("safety", "privacy", "authority", "correctness", "human_usefulness_bps", "cost_micros", "latency_ms")},
        "human_review_sha256": observation["human_review_sha256"], "evidence_sha256": _retain_blob(base, observation)}}})
    _require(result["status"] == "PASS", str(result["issues"]))
    return result["result"]


def _check_observations(base: Path, stage: str, request: Mapping[str, Any], root: Path, records: Path) -> None:
    """Re-derive every stored result from its retained local originals."""
    used = set()
    for role in ("champion", "challenger"):
        for result in request[role + "_results"]:
            observation = _blob(base, result["evidence_sha256"])
            _require(observation.get("schema") == OBSERVATION_SCHEMA and observation["stage"] == stage,
                     "stage observation missing")
            _require(observation["run_id"] not in used, "one terminal reused for several evaluation cases")
            used.add(observation["run_id"])
            derived = capture_result(root, run_id=observation["run_id"], stage=stage,
                configuration=request[role], corpus=request["corpus"], fixture=_blob(base, result["fixture_sha256"]),
                feedback=_blob(base, result["human_review_sha256"]),
                cost=_blob(base, observation["cost_observation_sha256"]), records=records)
            _require(derived == result, "result disagrees with host observation")


def record_stage(arguments: Mapping[str, Any], evaluation_input: Mapping[str, Any], *,
                 requesting_thread_id: str, stage: str, records: Path | None = None) -> dict[str, Any]:
    """Local operator seam, outside MCP: retain one stage only after replaying originals."""
    watcher = _watcher()
    records = records or watcher.records_root()
    root, key, base = _project(arguments, records)
    with watcher.machine_lock(records):
        _inactive(records, key)
        path, value = _stored(base, requesting_thread_id, arguments["proposal_sha256"])
        _unchanged(value, root, records)
        _approved(path, value)
        _check_observations(base, stage, evaluation_input, root, records)
        stored = watcher.sealed({"schema": STAGE_SCHEMA, "stage": stage,
            "proposal_sha256": arguments["proposal_sha256"], "evaluation_input": evaluation_input,
            "recorded_at": watcher.utc_now()}, "stage_sha256")
        # Validate before the create-only write, then recheck the persisted bytes.
        replay = cc.evaluate({"schema": cc.PROGRAM_SCHEMA, "action": "evaluate_offline", "request": evaluation_input})
        _require(replay["status"] == "PASS" and replay["evaluation"]["decision"] == "OFFLINE_CHALLENGER_RETAINED",
                 "stage gates refused: " + str(replay.get("issues")))
        _require(evaluation_input["champion"] == _champion(value["proposal"]["baseline"]["configuration"]) and
                 evaluation_input["challenger"] == value["proposal"]["candidate"]["configuration"], "stage configurations differ")
        index = promotion.STAGE_ORDER.index(stage)
        for predecessor in promotion.STAGE_ORDER[:index]:
            previous = _stage(path, predecessor, value)["evaluation_input"]
            _require(previous["evaluated_at"] < evaluation_input["evaluated_at"], "stage time did not advance")
        watcher.write_json(_stage_path(path, stage), stored, create_only=True)
    return _report("STAGE_RECORDED", stage=stage, stage_sha256=stored["stage_sha256"], mutation_performed=False)


def prepare_canary(arguments: Mapping[str, Any], corpus: Mapping[str, Any], fixtures: list[Mapping[str, Any]], *,
                   requesting_thread_id: str, records: Path | None = None) -> dict[str, Any]:
    """Local operator freezes the next evaluation cases; this grants no run authority."""
    watcher = _watcher()
    records = records or watcher.records_root()
    root, key, base = _project(arguments, records)
    with watcher.machine_lock(records):
        _inactive(records, key)
        path, value = _stored(base, requesting_thread_id, arguments["proposal_sha256"])
        _unchanged(value, root, records)
        _approved(path, value)
        for predecessor in ("offline", "shadow"):
            _stage(path, predecessor, value)
        _require(cc.validate_corpus(corpus)["status"] == "PASS", "canary corpus invalid")
        fixture_ids = [_retain_blob(base, fixture) for fixture in fixtures]
        expected = [digest for partition in cc.PARTITIONS for digest in corpus["partitions"][partition]]
        _require(len(fixture_ids) == len(set(fixture_ids)) and set(fixture_ids) == set(expected) and
                 all(fixture["project_id"] == key and fixture["schema"] == FIXTURE_SCHEMA for fixture in fixtures),
                 "canary cases do not match the frozen project corpus")
        champion = _champion(value["proposal"]["baseline"]["configuration"])
        challenger = value["proposal"]["candidate"]["configuration"]
        intent = watcher.sealed({"schema": CANARY_INTENT_SCHEMA, "proposal_sha256": arguments["proposal_sha256"],
            "project_id": key, "requesting_thread_id": requesting_thread_id, "champion": champion,
            "challenger": challenger, "corpus": corpus, "fixtures": fixtures,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "case_count": len(fixtures) * 2,
            "maximum_cost_micros": len(fixtures) * sum(config["budgets"]["cost_limit_micros"] for config in (champion, challenger))},
            "intent_sha256")
        target = path.with_name(path.stem + ".canary-intent.json")
        watcher.write_json(target, intent, create_only=True)
    return _report("CANARY_APPROVAL_REQUIRED", canary=intent, mutation_performed=False)


def authorize_canary(arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
                     records: Path | None = None) -> dict[str, Any]:
    """One separate explicit user decision binds the frozen canary cases, not standing run authority."""
    watcher = _watcher()
    records = records or watcher.records_root()
    try:
        _require(set(arguments) == {"project_root", "proposal_sha256", "confirm_canary_sha256"}, "canary approval fields")
        root, key, base = _project(arguments, records)
        with watcher.machine_lock(records):
            _inactive(records, key)
            path, value = _stored(base, requesting_thread_id, arguments["proposal_sha256"])
            _approved(path, value)
            _unchanged(value, root, records)
            shadow = _stage(path, "shadow", value)
            intent = _artifact(path.with_name(path.stem + ".canary-intent.json"), CANARY_INTENT_SCHEMA, "intent_sha256")
            _require(intent["intent_sha256"] == arguments["confirm_canary_sha256"], "canary confirmation differs from shown cases")
            now = datetime.now(timezone.utc)
            _require(now > datetime.fromisoformat(shadow["evaluation_input"]["evaluated_at"].replace("Z", "+00:00")),
                     "canary approval must follow shadow observation")
            authority = promotion.seal_canary_authority({
                "schema": promotion.CANARY_AUTHORITY_SCHEMA,
                "proposal_sha256": arguments["proposal_sha256"], "project_id": key,
                "requesting_thread_id": requesting_thread_id,
                "champion_sha256": intent["champion"]["configuration_sha256"],
                "challenger_sha256": intent["challenger"]["configuration_sha256"],
                "canary_corpus_sha256": intent["corpus"]["corpus_sha256"],
                "approved_at": now.isoformat().replace("+00:00", "Z"),
                "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")})
            _require(promotion.validate_canary_authority(authority)["status"] == "PASS", "invalid canary authority")
            watcher.write_json(path.with_name(path.stem + ".canary-authority.json"), authority, create_only=True)
        return _report("CANARY_AUTHORIZED", canary_authority=authority, canary=intent,
            instruction="Run only these frozen cases through ordinary governed admission. This approval changes no defaults.",
            mutation_performed=False)
    except (OSError, ValueError, KeyError, TypeError, watcher.WatcherError) as error:
        return _refused(error)


def bind_canary_run(arguments: Mapping[str, Any], request: Mapping[str, Any], plan: Mapping[str, Any], *, records: Path) -> None:
    """Claim one approved evaluation case before its first model turn."""
    if "project_canary" not in arguments:
        return
    watcher = _watcher()
    case = arguments["project_canary"]
    _require(isinstance(case, Mapping) and set(case) == {"proposal_sha256", "intent_sha256", "fixture_sha256", "role"} and
             case["role"] in {"champion", "challenger"}, "canary case fields")
    root, key, base = _project(arguments, records)
    with watcher.machine_lock(records):
        path, value = _stored(base, request["requesting_thread_id"], case["proposal_sha256"])
        _approved(path, value)
        _unchanged(value, root, records)
        intent = _artifact(path.with_name(path.stem + ".canary-intent.json"), CANARY_INTENT_SCHEMA, "intent_sha256")
        authority = _artifact(path.with_name(path.stem + ".canary-authority.json"), promotion.CANARY_AUTHORITY_SCHEMA, "authority_sha256")
        _require(promotion.validate_canary_authority(authority)["status"] == "PASS" and
                 intent["intent_sha256"] == case["intent_sha256"] and
                 datetime.now(timezone.utc) <= datetime.fromisoformat(authority["expires_at"].replace("Z", "+00:00")),
                 "canary approval missing, stale or changed")
        fixture = _blob(base, case["fixture_sha256"])
        _require(fixture in intent["fixtures"] and request["goal"] == fixture["goal"] and
                 request["lanes"] == watcher._lane_requests(fixture["lanes"][case["role"]]), "canary work differs from the approved fixture")
        configuration = intent[case["role"]]
        choice = value["candidate_settings"] if case["role"] == "challenger" else value["proposal"]["baseline"]["settings"]
        actual = {"workflow_profile": plan["workflow_profile"], "worker_count": plan["workers"],
                  "models": {"planner": request["model"], "implementer": request["worker_model"]} if plan["workers"] else {"implementer": request["model"]},
                  "efforts": {"planner": request["effort"], "implementer": request["worker_effort"]} if plan["workers"] else {"implementer": request["effort"]}}
        _require(actual == choice, "canary model, effort or workflow differs from the approved configuration")
        claim = watcher.sealed({"schema": "orch-dork/project-canary-run/v1", "project_id": key,
            "run_id": request["run_id"], "proposal_sha256": case["proposal_sha256"], "intent_sha256": case["intent_sha256"],
            "authority_sha256": authority["authority_sha256"], "fixture_sha256": case["fixture_sha256"],
            "corpus_sha256": intent["corpus"]["corpus_sha256"], "configuration": configuration,
            "configuration_sha256": configuration["configuration_sha256"], "request_sha256": watcher.policy.sha256(request),
            "claimed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}, "claim_sha256")
        marker = path.with_name(path.stem + ".canary-" + case["role"] + "-" + case["fixture_sha256"] + ".claimed.json")
        watcher.write_json(marker, claim, create_only=True)
        watcher.write_json(watcher.run_directory(records, request["run_id"]) / "project-canary.json", claim, create_only=True)


def adopt(arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
          records: Path | None = None) -> dict[str, Any]:
    """Replay complete promotion and consume exact adoption confirmation between runs."""
    watcher = _watcher()
    records = records or watcher.records_root()
    performed = False
    try:
        _require(set(arguments) == {"project_root", "confirm_proposal_sha256"}, "adoption fields")
        root, key, base = _project(arguments, records)
        with watcher.machine_lock(records):
            _inactive(records, key)
            path, value = _stored(base, requesting_thread_id, arguments["confirm_proposal_sha256"])
            _approved(path, value)
            _unchanged(value, root, records)
            stages = {stage: _stage(path, stage, value)["evaluation_input"] for stage in promotion.STAGE_ORDER}
            for stage, stage_request in stages.items():
                _check_observations(base, stage, stage_request, root, records)
            authority = _artifact(path.with_name(path.stem + ".canary-authority.json"), promotion.CANARY_AUTHORITY_SCHEMA, "authority_sha256")
            bundle = {"schema": promotion.BUNDLE_SCHEMA, "proposal_sha256": arguments["confirm_proposal_sha256"],
                "project_id": key, "requesting_thread_id": requesting_thread_id,
                "champion": stages["offline"]["champion"], "challenger": stages["offline"]["challenger"],
                "stages": stages, "canary_authority": authority,
                "evaluated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
            result = promotion.evaluate(bundle)
            _require(promotion.validate_report(result)["status"] == "PASS" and result["status"] == "READY" and
                     result["forward_activation_eligible"] is True, "promotion incomplete: " + str(result["issues"]))
            prior = preferences(root, records=records)
            active = watcher.sealed({"schema": PREFERENCES_SCHEMA, "project_id": key, "state": "active",
                "version": (prior or {}).get("version", 0) + 1, "settings": value["candidate_settings"],
                "configuration": _champion(stages["offline"]["challenger"]),
                "proposal_sha256": arguments["confirm_proposal_sha256"], "promotion_sha256": result["report_sha256"],
                "prior_preferences_sha256": (prior or {}).get("preferences_sha256"),
                "activated_at": watcher.utc_now()}, "preferences_sha256")
            watcher.write_json(path.with_name(path.stem + ".promotion.json"),
                watcher.sealed({"schema": "orch-dork/project-promotion-retained/v1", "bundle": bundle,
                    "report": result}, "retained_sha256"), create_only=True)
            watcher.write_json(path.with_name(path.stem + ".adoption-consumed.json"), active, create_only=True)
            watcher.write_json(base / "preferences.json", active)
            performed = True
            preferences(root, records=records)
        return _report("ADOPTED", preferences=active, promotion=result, mutation_performed=True,
            applies_to="future_runs_only")
    except (OSError, ValueError, KeyError, TypeError, watcher.WatcherError) as error:
        return _refused(error, mutation_performed=performed)


def main(argv: list[str] | None = None) -> int:
    """Operator-only evidence tooling; no MCP input imports histories or measurements."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture-result", "record-stage", "prepare-canary"))
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--requesting-thread-id", required=True)
    parser.add_argument("--proposal-sha256", required=True)
    parser.add_argument("--input-json", type=Path, required=True)
    parser.add_argument("--stage", choices=promotion.STAGE_ORDER)
    options = parser.parse_args(argv)
    try:
        value = _watcher().read_json(options.input_json)
        arguments = {"project_root": str(options.project_root), "proposal_sha256": options.proposal_sha256}
        if options.action == "capture-result":
            _require(set(value) == {"run_id", "configuration", "corpus", "fixture", "feedback", "cost"} and
                     options.stage is not None, "capture-result input fields and stage required")
            result = capture_result(options.project_root, stage=options.stage, **value)
            result = _report("RESULT_RECORDED", result=result, mutation_performed=False)
        elif options.action == "record-stage":
            _require(options.stage is not None, "stage required")
            result = record_stage(arguments, value, requesting_thread_id=options.requesting_thread_id, stage=options.stage)
        else:
            _require(set(value) == {"corpus", "fixtures"}, "prepare-canary input fields")
            result = prepare_canary(arguments, value["corpus"], value["fixtures"],
                                    requesting_thread_id=options.requesting_thread_id)
    except (OSError, ValueError, KeyError, TypeError, _watcher().WatcherError) as error:
        result = _refused(error)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False, allow_nan=False))
    return 1 if result["status"] == "REFUSED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
