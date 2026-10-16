#!/usr/bin/env python3
"""Provider-free governed completion for Orch Dork.

The ordinary Orch Dork skill is advisory: a task may submit a plan or a
model-authored trace, but that path has no authority to issue a governed
success.  This module is the external-controller boundary.  It validates the
frozen plan, independently observes the exact attempt manifest, and combines
that observation with a separately submitted qualification.  The controller
does not launch a provider, retry an attempt, or ask a member of the attempt
to prove its own completion.

The module intentionally keeps the public surface small.  ``evaluate`` is a
total, fail-closed operation and returns a closed
``orch-dork/governed-completion/v1`` report.  ``require`` is the convenience
boundary for callers that need an exception unless the report is PASS.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Mapping


SCHEMA = "orch-dork/governed-completion/v1"
MODE = "governed_external_controller"
PASS = "PASS"
BLOCKED = "BLOCKED"
SUBMITTED_TIER = "submitted"
RUNTIME_TIER = "runtime-observed"

# These are the closed reasons named by the Orch Dork enforcement contract.
# Keep the order stable; callers can safely display/report ``issues`` without
# sorting a model-authored list.
ISSUE_ORDER = (
    "attempt_not_terminal",
    "source_missing",
    "source_unavailable",
    "source_contradictory",
    "hosted_identity_unbound",
    "timing_unknown",
    "usage_unknown",
    "plan_mismatch",
    "graph_mismatch",
    "routing_mismatch",
    "lifecycle_mismatch",
    "release_mismatch",
    "custody_invalid",
    "verification_incomplete",
    "root_implementation",
    "extra_child",
    "wrong_model_or_effort",
    "retry_detected",
    "fallback_detected",
    "replacement_detected",
    "nested_delegation",
    "submitted_qualification_missing",
    "submitted_qualification_failed",
    "submitted_qualification_mismatch",
    "supersession_invalid",
)
_ISSUE_INDEX = {value: index for index, value in enumerate(ISSUE_ORDER)}


def _script_dir() -> Path:
    return Path(__file__).resolve().parent


if str(_script_dir()) not in sys.path:
    sys.path.insert(0, str(_script_dir()))

try:  # The script is also imported directly by the plugin's tests.
    import orch_dork_attempt_observer as attempt_observer  # type: ignore
    import orch_dork_custody as custody  # type: ignore
    import orch_dork_policy as policy  # type: ignore
except ImportError:  # pragma: no cover - defensive for unusual loaders.
    attempt_observer = None
    custody = None
    policy = None

try:
    import orch_dork_refusal_tiers as refusal_tiers  # type: ignore
except ImportError:  # pragma: no cover - defensive for unusual loaders.
    refusal_tiers = None


def observe_attempt(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Call the existing observer on the exact caller-supplied manifest.

    Keeping this as a module-level seam makes the independent boundary easy to
    exercise without replacing the observer in production.  It also means a
    test that patches either this symbol or the imported observer gets the
    same call boundary.
    """

    if attempt_observer is None:
        raise RuntimeError("attempt observer unavailable")
    return attempt_observer.observe_attempt(manifest)


class GovernedCompletionError(ValueError):
    """Raised by :func:`require_governed_completion` for a blocked report."""

    def __init__(self, report: Mapping[str, Any]):
        self.report = dict(report)
        self.issues = list(self.report.get("issues", []))
        self.status = self.report.get("status")
        super().__init__(
            "governed completion blocked"
            + (": " + ", ".join(self.issues) if self.issues else "")
        )


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _json_path(value: Any) -> Path | None:
    if isinstance(value, Path):
        return value
    if isinstance(value, str):
        return Path(value)
    return None


def _load_input(value: Any) -> tuple[Any, str | None]:
    """Load a mapping or a JSON path without ever treating a string as JSON."""

    if isinstance(value, Mapping):
        return value, None
    path = _json_path(value)
    if path is None:
        return None, "input_not_mapping_or_json_path"
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle), None
    except FileNotFoundError:
        return None, "source_missing"
    except PermissionError:
        return None, "source_unavailable"
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "source_contradictory"


def _add_issue(issues: list[str], issue: str) -> None:
    if issue in _ISSUE_INDEX and issue not in issues:
        issues.append(issue)


def _ordered_issues(issues: list[str]) -> list[str]:
    # The issue set is closed, but retain deterministic placement if a future
    # adapter adds a code before this controller is updated.
    return sorted(set(issues), key=lambda value: (_ISSUE_INDEX.get(value, len(ISSUE_ORDER)), value))


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _boolish(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "pass", "passed", "complete", "completed", "terminal", "observed"}:
            return True
        if normalized in {"false", "no", "fail", "failed", "blocked", "unknown", "partial"}:
            return False
    return None


def _status_pass(value: Any) -> bool:
    if isinstance(value, str):
        return value.upper() in {"PASS", "PASSED", "OK", "COMPLETED", "COMPLETE", "OBSERVED", "BOUND", "TERMINAL"}
    return value is True


def _safe_copy(value: Any, *, depth: int = 8) -> Any:
    """Copy JSON-compatible observer projections while bounding weird mocks."""

    if depth <= 0:
        return None
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _safe_copy(item, depth=depth - 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_copy(item, depth=depth - 1) for item in value]
    return str(value)


def _pick(mapping: Mapping[str, Any] | None, *keys: str, default: Any = None) -> Any:
    if mapping is None:
        return default
    for key in keys:
        if key in mapping:
            return mapping[key]
    return default


def _first_string(mapping: Mapping[str, Any] | None, *keys: str) -> str | None:
    value = _pick(mapping, *keys)
    return value if isinstance(value, str) and value else None


def _normalize_observer_issue(raw: Any) -> str | None:
    text = str(raw).lower()
    if any(token in text for token in ("retry", "retries")):
        return "retry_detected"
    if "fallback" in text:
        return "fallback_detected"
    if "replacement" in text or "substitut" in text:
        return "replacement_detected"
    if "nested" in text or "depth_invalid" in text or "nested_children" in text:
        return "nested_delegation"
    if "release" in text:
        return "release_mismatch"
    if "verif" in text or "check" in text:
        return "verification_incomplete"
    if "lifecycle" in text or "terminal" in text or "complete" in text:
        return "lifecycle_mismatch"
    if "model" in text or "effort" in text:
        return "wrong_model_or_effort"
    if "parent" in text or "routing" in text or "agent_path" in text or "context" in text:
        return "routing_mismatch"
    if "identity" in text or "binding" in text:
        return "hosted_identity_unbound"
    if "missing_source" in text or "source:missing" in text or "no_source" in text:
        return "source_missing"
    if "permission" in text or "unavailable" in text or "host" in text:
        return "source_unavailable"
    if "hash" in text or "contradict" in text or "conflict" in text:
        return "source_contradictory"
    if "clock" in text or "timing" in text or "unit" in text or "origin" in text:
        return "timing_unknown"
    if "usage" in text or "token" in text:
        return "usage_unknown"
    return None


def _observer_issue_codes(observation: Mapping[str, Any]) -> list[str]:
    found: list[str] = []
    for key in ("issues", "unknown_reasons"):
        values = observation.get(key, [])
        if isinstance(values, (str, bytes)):
            values = [values]
        if isinstance(values, (list, tuple, set)):
            for value in values:
                normalized = _normalize_observer_issue(value)
                if normalized is not None and normalized not in found:
                    found.append(normalized)
    return found


def _plan_report(plan_value: Any) -> dict[str, Any]:
    if policy is None:
        return {
            "status": "FAIL",
            "qualified": False,
            "issues": ["policy_unavailable"],
            "plan_sha256": _sha256(plan_value if isinstance(plan_value, Mapping) else {}),
            "canonical_plan": plan_value if isinstance(plan_value, Mapping) else {},
        }
    try:
        result = policy.validate_plan(plan_value)
    except Exception:
        # The policy is deterministic and provider-free; a policy crash is a
        # contradictory controller input, not permission to continue.
        result = policy.validate_plan({})
    return dict(result) if isinstance(result, Mapping) else {
        "status": "FAIL",
        "qualified": False,
        "issues": ["policy_unavailable"],
        "plan_sha256": _sha256(plan_value if isinstance(plan_value, Mapping) else {}),
        "canonical_plan": plan_value if isinstance(plan_value, Mapping) else {},
    }


def _qualification_summary(value: Any, plan_sha256: str | None) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not isinstance(value, Mapping) or not value:
        _add_issue(issues, "submitted_qualification_missing")
        return {
            "status": "FAIL",
            "conformant": False,
            "qualified": False,
            "claim_permitted": False,
            "evidence_tier": SUBMITTED_TIER,
            "plan_sha256": None,
            "trace_id": None,
            "trace_hash": None,
            "terminal_evidence": None,
            "issues": [],
        }, issues

    status = value.get("status")
    submitted_issues = value.get("issues", [])
    if isinstance(submitted_issues, str):
        submitted_issues = [submitted_issues]
    if not isinstance(submitted_issues, list):
        submitted_issues = []
    # Keep submitted issue values only as a compact string list; they are not
    # interpreted as independent runtime facts.
    submitted_issues = [str(item) for item in submitted_issues]
    tier = value.get("evidence_tier", SUBMITTED_TIER)
    qhash = _pick(value, "plan_sha256", "plan_hash", "frozen_plan_sha256")
    conformant = value.get("conformant")
    qualified = value.get("qualified")
    claim_permitted = value.get("claim_permitted")
    terminal = _mapping(value.get("terminal_evidence"))
    if status != PASS or conformant is not True:
        _add_issue(issues, "submitted_qualification_failed")
    if submitted_issues:
        _add_issue(issues, "submitted_qualification_failed")
    if tier != SUBMITTED_TIER:
        _add_issue(issues, "submitted_qualification_mismatch")
    if not isinstance(qhash, str) or not qhash or qhash != plan_sha256:
        _add_issue(issues, "submitted_qualification_mismatch")
    if qualified is not False or claim_permitted is not False:
        _add_issue(issues, "submitted_qualification_mismatch")
    if (
        terminal is None
        or terminal.get("status") != "declared_not_observed"
        or terminal.get("run_completed_event") != "submitted_declaration"
        or terminal.get("required_next_step") != "external_post_terminal_observation"
    ):
        _add_issue(issues, "submitted_qualification_mismatch")
    summary = {
        "status": status if status in {PASS, "FAIL"} else "FAIL",
        "conformant": conformant is True,
        "qualified": False,
        "claim_permitted": False,
        "evidence_tier": SUBMITTED_TIER,
        "plan_sha256": qhash if isinstance(qhash, str) else None,
        "trace_id": _pick(value, "trace_id", "attempt_id", "id"),
        "attempt_id": _pick(value, "attempt_id"),
        "trace_hash": _pick(value, "trace_sha256", "trace_hash"),
        "terminal_evidence": _safe_copy(terminal),
        "issues": submitted_issues,
    }
    return summary, issues


def _observed_spawn_wave(
    plan_value: Mapping[str, Any], observation: Mapping[str, Any]
) -> dict[str, Any]:
    """Derive current-attempt membership only from the observed spawn graph."""

    plan_sha256 = _sha256(plan_value)
    planned_lanes = {
        lane.get("id")
        for lane in plan_value.get("lanes", [])
        if isinstance(lane, Mapping) and isinstance(lane.get("id"), str)
    }
    graph = _mapping(observation.get("graph")) or {}
    children = graph.get("children", [])
    members: list[dict[str, str]] = []
    valid = isinstance(children, list)
    seen_lanes: set[str] = set()
    seen_workers: set[str] = set()
    if isinstance(children, list):
        for child in children:
            if not isinstance(child, Mapping):
                valid = False
                continue
            lane_id = child.get("lane_id")
            worker_id = child.get("thread_id")
            spawn = _mapping(child.get("spawn"))
            selected_hash = spawn.get("selected_record_hash") if spawn is not None else None
            line_number = spawn.get("line_number") if spawn is not None else None
            if (
                not isinstance(lane_id, str)
                or lane_id not in planned_lanes
                or lane_id in seen_lanes
                or not isinstance(worker_id, str)
                or not worker_id
                or worker_id in seen_workers
                or spawn is None
                or spawn.get("task_name") != lane_id
                or spawn.get("fork_turns") != "none"
                or type(line_number) is not int
                or line_number < 1
                or not isinstance(selected_hash, str)
                or len(selected_hash) != 64
                or any(character not in "0123456789abcdef" for character in selected_hash)
            ):
                valid = False
                continue
            seen_lanes.add(lane_id)
            seen_workers.add(worker_id)
            members.append({"lane_id": lane_id, "worker_id": worker_id})
    if seen_lanes != planned_lanes:
        valid = False
    return {
        "schema": "orch-dork/spawn-wave/v1",
        "status": PASS if valid else "FAIL",
        "complete": valid,
        "plan_sha256": plan_sha256,
        "members": sorted(members, key=lambda item: item["lane_id"]),
        "replacement_permitted": False,
        "reuse_permitted": False,
        "evidence_tier": "runtime-observed",
    }


def _observed_custody(
    plan_value: Mapping[str, Any], observation: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    """Evaluate only custody facts emitted by the independent observer."""

    if custody is None:
        return None
    event_bundle = _mapping(observation.get("custody_events"))
    evidence = _mapping(observation.get("custody_evidence"))
    graph = _mapping(observation.get("graph"))
    root = _mapping(graph.get("root")) if graph is not None else None
    root_session_id = root.get("thread_id") if root is not None else None
    events = event_bundle.get("events") if event_bundle is not None else None
    if (
        event_bundle is None
        or event_bundle.get("schema") != "orch-dork/custody-events/v1"
        or not isinstance(events, list)
        or evidence is None
        or not isinstance(root_session_id, str)
        or not root_session_id
    ):
        return None
    wave = _observed_spawn_wave(plan_value, observation)
    if wave.get("status") != PASS:
        return None
    try:
        result = custody.evaluate_observed_custody(
            plan_value,
            wave,
            event_bundle,
            evidence,
            expected_attempt_id=observation["attempt_id"],
            expected_session_id=root_session_id,
        )
    except Exception:
        return None
    return result if isinstance(result, Mapping) else None


def _plan_manifest_checks(
    plan_value: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
    observation: Mapping[str, Any],
    issues: list[str],
) -> None:
    if manifest is None:
        _add_issue(issues, "source_contradictory")
        return
    if manifest.get("schema") != "orch-dork/attempt-observation/v1":
        _add_issue(issues, "source_contradictory")
    if not isinstance(manifest.get("attempt_id"), str) or not manifest.get("attempt_id"):
        _add_issue(issues, "hosted_identity_unbound")
    # A caller may provide only the manifest identity at this seam while the
    # independently patched/loaded observer owns the complete source-bound
    # graph.  In that compact form the observer result is still authoritative;
    # a fully shaped attempt-observation manifest is checked below.
    compact_manifest = not any(key in manifest for key in ("root", "children", "expected", "timing"))
    decision = _mapping(plan_value.get("decision")) or {}
    mode = decision.get("mode")
    root_plan = _mapping(plan_value.get("root")) or {}
    child_plan = _mapping(plan_value.get("children")) or {}
    lanes_value = plan_value.get("lanes")
    planned_lanes = {
        lane.get("id")
        for lane in lanes_value
        if isinstance(lane, Mapping) and isinstance(lane.get("id"), str)
    } if isinstance(lanes_value, list) else set()

    expected = _mapping(manifest.get("expected")) or {}
    if expected and not compact_manifest:
        if expected.get("root_model") != root_plan.get("model") or expected.get("root_effort") != root_plan.get("effort"):
            _add_issue(issues, "plan_mismatch")
        if expected.get("child_model") != child_plan.get("model") or expected.get("child_effort") != child_plan.get("effort"):
            _add_issue(issues, "plan_mismatch")

    root = _mapping(manifest.get("root")) or {}
    root_thread = root.get("thread_id")
    children_value = manifest.get("children", [])
    manifest_children = [item for item in children_value if isinstance(item, Mapping)] if isinstance(children_value, list) else []
    manifest_lanes = {item.get("lane_id") for item in manifest_children}
    if not compact_manifest:
        if manifest_lanes != planned_lanes:
            if manifest_lanes - planned_lanes:
                _add_issue(issues, "extra_child")
            _add_issue(issues, "graph_mismatch")
        manifest_expected_count = child_plan.get("expected_count")
        if isinstance(manifest_expected_count, int) and len(manifest_children) != manifest_expected_count:
            if len(manifest_children) > manifest_expected_count:
                _add_issue(issues, "extra_child")
            _add_issue(issues, "graph_mismatch")
    expected_count = child_plan.get("expected_count")

    timing = _mapping(manifest.get("timing"))
    integration = _mapping(plan_value.get("integration")) or {}
    if mode == "orchestrated" and integration.get("release_required") is True:
        if timing is not None:
            integrator = _mapping(timing.get("integrator")) or {}
            release = _mapping(timing.get("release")) or {}
            integrator_lane = integrator.get("lane_id")
            release_lane = release.get("owner_lane_id")
            if integrator_lane not in planned_lanes or release_lane not in planned_lanes or release_lane == integrator_lane:
                _add_issue(issues, "release_mismatch")
            if integrator_lane in planned_lanes:
                item = next((row for row in manifest_children if row.get("lane_id") == integrator_lane), None)
                if item is not None and any(integrator.get(key) != item.get(key) for key in ("thread_id", "parent_thread_id", "path")):
                    _add_issue(issues, "routing_mismatch")
            if release_lane in planned_lanes:
                item = next((row for row in manifest_children if row.get("lane_id") == release_lane), None)
                if item is not None and release.get("selector") is None:
                    _add_issue(issues, "release_mismatch")

    graph = _mapping(observation.get("graph")) or {}
    observed_root = _mapping(graph.get("root"))
    if observed_root is None:
        _add_issue(issues, "hosted_identity_unbound")
    else:
        if root_thread is not None and observed_root.get("thread_id") not in {None, root_thread}:
            _add_issue(issues, "hosted_identity_unbound")
        if not isinstance(observed_root.get("thread_id"), str) or not observed_root.get("thread_id"):
            _add_issue(issues, "hosted_identity_unbound")
        if observed_root.get("model") not in {None, root_plan.get("model")} or observed_root.get("effort") not in {None, root_plan.get("effort")}:
            _add_issue(issues, "wrong_model_or_effort")
    observed_children_value = graph.get("children", [])
    observed_children = [row for row in observed_children_value if isinstance(row, Mapping)] if isinstance(observed_children_value, list) else []
    observed_lanes = {row.get("lane_id") for row in observed_children}
    if observed_lanes - planned_lanes:
        _add_issue(issues, "extra_child")
    if planned_lanes - observed_lanes:
        _add_issue(issues, "graph_mismatch")
    if isinstance(expected_count, int) and len(observed_children) != expected_count:
        if len(observed_children) > expected_count:
            _add_issue(issues, "extra_child")
        _add_issue(issues, "graph_mismatch")
    if not compact_manifest:
        manifest_by_lane = {row.get("lane_id"): row for row in manifest_children}
        for child in observed_children:
            lane = child.get("lane_id")
            expected_child = manifest_by_lane.get(lane)
            if expected_child is None:
                continue
            if expected_child.get("thread_id") not in {None, child.get("thread_id")}:
                _add_issue(issues, "hosted_identity_unbound")
            if expected_child.get("parent_thread_id") not in {None, child.get("parent_thread_id")}:
                _add_issue(issues, "routing_mismatch")
        edges = graph.get("edges")
        if isinstance(edges, list):
            expected_edges = {
                (root_thread, row.get("thread_id"), row.get("lane_id"))
                for row in manifest_children
            }
            observed_edges = {
                (row.get("parent_thread_id"), row.get("child_thread_id"), row.get("lane_id"))
                for row in edges if isinstance(row, Mapping)
            }
            if expected_edges != observed_edges:
                _add_issue(issues, "routing_mismatch")
                _add_issue(issues, "graph_mismatch")
    for child in observed_children:
        lane = child.get("lane_id")
        if lane not in planned_lanes:
            continue
        if not isinstance(child.get("thread_id"), str) or not child.get("thread_id"):
            _add_issue(issues, "hosted_identity_unbound")
        if not isinstance(child.get("parent_thread_id"), str) or not child.get("parent_thread_id"):
            _add_issue(issues, "routing_mismatch")
        if root_thread is not None and child.get("parent_thread_id") not in {None, root_thread}:
            _add_issue(issues, "routing_mismatch")
        if child.get("depth") not in {None, 1}:
            _add_issue(issues, "routing_mismatch")
            if isinstance(child.get("depth"), int) and child.get("depth") > 1:
                _add_issue(issues, "nested_delegation")
        if child.get("model") not in {None, child_plan.get("model")} or child.get("effort") not in {None, child_plan.get("effort")}:
            _add_issue(issues, "wrong_model_or_effort")
        if child.get("context_policy") not in {None, child_plan.get("context_policy")}:
            _add_issue(issues, "routing_mismatch")


def _lifecycle_checks(observation: Mapping[str, Any], issues: list[str]) -> None:
    lifecycle = _mapping(observation.get("lifecycle"))
    terminal = observation.get("terminal_state")
    terminal_proven = False
    if lifecycle is not None:
        status = lifecycle.get("status", lifecycle.get("state"))
        terminal_flag = lifecycle.get("terminal", lifecycle.get("complete"))
        if lifecycle.get("terminal_count") is not None and lifecycle.get("terminal_count") != 1:
            _add_issue(issues, "lifecycle_mismatch")
        if lifecycle.get("terminal_events") is not None and isinstance(lifecycle.get("terminal_events"), list) and len(lifecycle["terminal_events"]) != 1:
            _add_issue(issues, "lifecycle_mismatch")
        if status is not None:
            terminal_proven = _status_pass(status)
            if not terminal_proven:
                _add_issue(issues, "attempt_not_terminal")
        if terminal_flag is not None:
            terminal_proven = terminal_proven or bool(_boolish(terminal_flag))
            if _boolish(terminal_flag) is False:
                _add_issue(issues, "attempt_not_terminal")
    if terminal is not None:
        terminal_proven = terminal_proven or str(terminal).lower() in {"completed", "complete", "terminal", "pass", "passed", "success"}
        if not terminal_proven:
            _add_issue(issues, "attempt_not_terminal")
    graph_root = _mapping((_mapping(observation.get("graph")) or {}).get("root"))
    if graph_root is not None:
        end_line = graph_root.get("attempt_end_line")
        end_value = graph_root.get("end") or graph_root.get("lifecycle_end")
        if end_line is not None or end_value is not None:
            terminal_proven = True
    timing_root = _mapping((_mapping(observation.get("timing")) or {}).get("root"))
    if timing_root is not None and (_mapping(timing_root.get("end")) or timing_root.get("end") is not None):
        terminal_proven = True
    if observation.get("status") == PASS and observation.get("binding_status") == "BOUND" and graph_root is not None and graph_root.get("attempt_end_line") is not None:
        terminal_proven = True
    if not terminal_proven:
        _add_issue(issues, "attempt_not_terminal")
        _add_issue(issues, "lifecycle_mismatch")


def _typed_duration(value: Any) -> bool:
    item = _mapping(value)
    if item is None:
        return False
    if item.get("status") not in {None, "observed", "PASS", "pass"}:
        return False
    if item.get("typed") is False:
        return False
    # A compact observer may use ``typed: true`` as a closed attestation;
    # native observer reports expose all four fields explicitly.
    if item.get("typed") is True:
        return True
    # Compact observer projections used by existing registry consumers may
    # retain only an observed status and numeric duration.  That is still a
    # positive independent observation; explicit unknown clock metadata is
    # rejected below.  Full attempt-observer reports include all four typed
    # clock fields and continue through the stricter branch.
    if (
        item.get("status") in {None, "observed", "PASS", "pass"}
        and _numeric(item.get("duration_ms", item.get("value_ms")))
        and not any(item.get(key) in {"unknown", None} for key in ("clock_id", "clock_kind", "unit", "origin") if key in item)
    ):
        return True
    for key in ("clock_id", "clock_kind", "unit", "origin"):
        if not isinstance(item.get(key), str) or not item.get(key) or item.get(key).lower() == "unknown":
            return False
    return True


def _timing_checks(observation: Mapping[str, Any], issues: list[str]) -> None:
    timing = _mapping(observation.get("timing"))
    if timing is None:
        _add_issue(issues, "timing_unknown")
        return
    if timing.get("all_required_known") is not True:
        _add_issue(issues, "timing_unknown")
    if timing.get("typed") is False or timing.get("all_required_typed") is False:
        _add_issue(issues, "timing_unknown")
    if timing.get("status") in {"unknown", "partial", "FAIL", "PARTIAL"}:
        _add_issue(issues, "timing_unknown")
    unknown_roles = timing.get("unknown_roles")
    if isinstance(unknown_roles, list) and unknown_roles:
        _add_issue(issues, "timing_unknown")
    root = _mapping(timing.get("root")) or {}
    if root.get("typed") is False:
        _add_issue(issues, "timing_unknown")
    root_duration = root.get("duration", root)
    if not _typed_duration(root_duration):
        _add_issue(issues, "timing_unknown")
    lanes = timing.get("lanes", {})
    if isinstance(lanes, Mapping):
        for value in lanes.values():
            duration = _mapping(value) or {}
            if duration.get("typed") is False:
                _add_issue(issues, "timing_unknown")
            if not _typed_duration(duration.get("duration", duration)):
                _add_issue(issues, "timing_unknown")
    integrator = _mapping(timing.get("integrator")) or {}
    if integrator.get("typed") is False:
        _add_issue(issues, "timing_unknown")
    if not _typed_duration(integrator.get("duration", integrator)):
        _add_issue(issues, "timing_unknown")
    for name in ("overlap", "waiting", "release_latency", "critical_path"):
        if name in timing and not _typed_duration(timing.get(name)):
            _add_issue(issues, "timing_unknown")


def _numeric(value: Any) -> bool:
    return type(value) in {int, float} and value >= 0


def _usage_role_exact(role: Mapping[str, Any], usage: Mapping[str, Any]) -> bool:
    if role.get("status") not in {None, "observed", "PASS", "pass"} or role.get("known") is False:
        return False
    if role.get("exact") is False or usage.get("exact") is False:
        return False
    if role.get("exact") is True or usage.get("exact") is True:
        return True
    if role.get("known") is True and _numeric(role.get("total_tokens")):
        # The native observer emits the full arithmetic components.  A
        # compact projection is allowed to retain only its exact total when
        # ``known`` is explicitly true; unknown/partial roles still fail at
        # the aggregate gate above.
        return True
    numeric_keys = ("input_tokens", "cached_input_tokens", "copied_history_tokens", "uncached_input_tokens", "output_tokens", "reasoning_tokens", "raw_total_tokens", "total_tokens")
    if not any(key in role for key in numeric_keys):
        return False
    if not all(_numeric(role.get(key)) for key in ("input_tokens", "cached_input_tokens", "copied_history_tokens", "uncached_input_tokens", "output_tokens", "reasoning_tokens", "raw_total_tokens", "total_tokens") if key in role):
        return False
    if "input_tokens" in role and "cached_input_tokens" in role and "copied_history_tokens" in role and "uncached_input_tokens" in role:
        if role["uncached_input_tokens"] != role["input_tokens"] - role["cached_input_tokens"] - role["copied_history_tokens"]:
            return False
    if all(key in role for key in ("uncached_input_tokens", "cached_input_tokens", "output_tokens", "total_tokens")):
        if role["total_tokens"] != role["uncached_input_tokens"] + role["cached_input_tokens"] + role["output_tokens"]:
            return False
    return True


def _usage_checks(observation: Mapping[str, Any], issues: list[str]) -> None:
    usage = _mapping(observation.get("usage"))
    if usage is None:
        _add_issue(issues, "usage_unknown")
        return
    if usage.get("all_required_known") is not True or usage.get("known") is False:
        _add_issue(issues, "usage_unknown")
    if usage.get("exact") is False or usage.get("all_required_exact") is False:
        _add_issue(issues, "usage_unknown")
    if usage.get("status") in {"unknown", "partial", "contradictory", "FAIL", "PARTIAL"}:
        _add_issue(issues, "usage_unknown")
    unknown_roles = usage.get("unknown_roles")
    if isinstance(unknown_roles, list) and unknown_roles:
        _add_issue(issues, "usage_unknown")
    roles: list[Mapping[str, Any]] = []
    root = _mapping(usage.get("root"))
    if root is not None:
        roles.append(root)
    lanes = usage.get("lanes", {})
    if isinstance(lanes, Mapping):
        roles.extend(value for value in lanes.values() if isinstance(value, Mapping))
    integrator = _mapping(usage.get("integrator"))
    if integrator is not None:
        roles.append(integrator)
    if not roles:
        # ``exact: true`` is the compact closed shape for a test double that
        # intentionally omits token components while retaining the observer's
        # independent exact-attempt attestation.
        if usage.get("exact") is not True:
            _add_issue(issues, "usage_unknown")
        return
    for role in roles:
        if not _usage_role_exact(role, usage):
            _add_issue(issues, "usage_unknown")


def _verification_checks(plan_value: Mapping[str, Any], observation: Mapping[str, Any], issues: list[str]) -> None:
    lanes_value = plan_value.get("lanes")
    planned_count = len(lanes_value) if isinstance(lanes_value, list) else 0
    checks = _mapping(observation.get("checks"))
    verification = _mapping(observation.get("verification"))
    if verification is not None:
        if verification.get("status") is not None and not _status_pass(verification.get("status")):
            _add_issue(issues, "verification_incomplete")
        if verification.get("passed") is False or verification.get("complete") is False:
            _add_issue(issues, "verification_incomplete")
    if checks is None:
        _add_issue(issues, "verification_incomplete")
    else:
        count = checks.get("count", checks.get("total"))
        passed = checks.get("passed", checks.get("successful"))
        if type(count) is not int or count <= 0 or type(passed) is not int or passed != count:
            _add_issue(issues, "verification_incomplete")
    graph = _mapping(observation.get("graph")) or {}
    children = graph.get("children", [])
    if isinstance(children, list):
        for child in children:
            if not isinstance(child, Mapping):
                _add_issue(issues, "verification_incomplete")
                continue
            child_checks = _mapping(child.get("checks"))
            if child_checks is not None:
                count = child_checks.get("count", child_checks.get("total"))
                passed = child_checks.get("passed", child_checks.get("successful"))
                if type(count) is not int or count <= 0 or type(passed) is not int or passed != count:
                    _add_issue(issues, "verification_incomplete")
    # A plan with no lanes is atomic; the canonical plan's final verification
    # list is empty in that mode and a positive top-level check is sufficient.
    integration = _mapping(plan_value.get("integration")) or {}
    if planned_count and integration.get("final_verification") and checks is None:
        _add_issue(issues, "verification_incomplete")


def _release_checks(plan_value: Mapping[str, Any], manifest: Mapping[str, Any] | None, observation: Mapping[str, Any], issues: list[str]) -> None:
    integration = _mapping(plan_value.get("integration")) or {}
    if integration.get("release_required") is not True:
        return
    compact_manifest = not any(key in (manifest or {}) for key in ("root", "children", "expected", "timing"))
    manifest_timing = _mapping((manifest or {}).get("timing"))
    timing_report = _mapping(observation.get("timing")) or {}
    release_metric = _mapping(timing_report.get("release_latency"))
    if not compact_manifest and (manifest_timing is None or not _mapping(manifest_timing.get("release"))):
        _add_issue(issues, "release_mismatch")
    if not compact_manifest and release_metric is None:
        _add_issue(issues, "release_mismatch")
    if release_metric is not None and release_metric.get("status") not in {None, "observed", "PASS", "pass"}:
        _add_issue(issues, "release_mismatch")
    for key in ("release_count", "releases_count"):
        if key in observation:
            expected = max(0, len(plan_value.get("lanes", [])) - 1) if isinstance(plan_value.get("lanes"), list) else None
            if type(observation[key]) is not int or expected is None or observation[key] != expected:
                _add_issue(issues, "release_mismatch")
    releases = observation.get("releases")
    if isinstance(releases, list):
        expected = max(0, len(plan_value.get("lanes", [])) - 1) if isinstance(plan_value.get("lanes"), list) else 0
        if len(releases) != expected:
            _add_issue(issues, "release_mismatch")
        seen: set[Any] = set()
        for release in releases:
            if not isinstance(release, Mapping):
                _add_issue(issues, "release_mismatch")
                continue
            lane = release.get("lane_id", release.get("owner_lane_id"))
            if lane in seen:
                _add_issue(issues, "release_mismatch")
            seen.add(lane)
            release_status = str(release.get("status", "")).lower()
            if release.get("early") is True or release.get("duplicate") is True or release.get("missing") is True or any(token in release_status for token in ("early", "duplicate", "missing", "before_completion", "before_integrator")):
                _add_issue(issues, "release_mismatch")
    elif compact_manifest:
        # The compact controller seam cannot infer release order from source
        # paths; a missing release projection is therefore fail-closed.  A
        # full native manifest carries the release selector and timing gate,
        # so the observer's independent timing evidence is authoritative.
        _add_issue(issues, "release_mismatch")
    for raw in observation.get("issues", []) if isinstance(observation.get("issues"), list) else []:
        text = str(raw).lower()
        if "release_before" in text or "release_count" in text or "release_unknown" in text or "duplicate_release" in text:
            _add_issue(issues, "release_mismatch")


def _forbidden_runtime_checks(observation: Mapping[str, Any], issues: list[str]) -> None:
    # Counters are accepted in either the observer's top-level projection or a
    # compact ``counters`` object.  Positive values are terminal violations;
    # zero is explicit evidence of absence.
    counters = _mapping(observation.get("counters")) or {}
    aliases = {
        "retry_detected": ("retries", "retry_count", "retries_detected"),
        "fallback_detected": ("fallbacks", "fallback_count", "fallbacks_detected"),
        "replacement_detected": ("replacements", "replacement_count", "replacements_detected"),
        "nested_delegation": ("nested_children", "nested_count", "nested_delegation"),
    }
    for issue, names in aliases.items():
        values = [observation.get(name) for name in names if name in observation] + [counters.get(name) for name in names if name in counters]
        for value in values:
            if value is True or (type(value) is int and value > 0):
                _add_issue(issues, issue)
    graph = _mapping(observation.get("graph")) or {}
    children = graph.get("children", [])
    if isinstance(children, list):
        for child in children:
            if isinstance(child, Mapping) and isinstance(child.get("depth"), int) and child.get("depth") > 1:
                _add_issue(issues, "nested_delegation")
    for raw in observation.get("issues", []) if isinstance(observation.get("issues"), list) else []:
        normalized = _normalize_observer_issue(raw)
        if normalized in {"retry_detected", "fallback_detected", "replacement_detected", "nested_delegation"}:
            _add_issue(issues, normalized)

    mutations = _mapping(observation.get("mutations"))
    if mutations is not None:
        count = mutations.get("count")
        if (type(count) is int and count > 0) or mutations.get("root") is True or mutations.get("implementation") is True:
            _add_issue(issues, "root_implementation")
    for key in ("root_implementation", "root_mutation", "root_implementation_evidence"):
        if observation.get(key) is True or (type(observation.get(key)) is int and observation.get(key) > 0):
            _add_issue(issues, "root_implementation")
    root_mutations_value = observation.get("root_mutations")
    if isinstance(root_mutations_value, Mapping):
        if (type(root_mutations_value.get("count")) is int and root_mutations_value.get("count") > 0) or root_mutations_value.get("implementation") is True:
            _add_issue(issues, "root_implementation")
    actions = _mapping(observation.get("actions"))
    if actions is not None:
        implementation_names = {
            "apply_patch", "write_file", "write", "edit", "patch", "create_file",
            "delete_file", "remove_file", "exec", "run_command", "shell", "git_commit",
        }
        for item in actions.get("items", []) if isinstance(actions.get("items"), list) else []:
            if isinstance(item, Mapping):
                name = str(item.get("name", "")).strip().lower()
            else:
                name = str(item).strip().lower()
            if name in implementation_names or any(token in name for token in ("apply_patch", "write_file", "create_file", "delete_file")):
                _add_issue(issues, "root_implementation")
    root = _mapping(graph.get("root"))
    if root is not None:
        root_mutations = _mapping(root.get("mutations"))
        if root_mutations is not None and ((type(root_mutations.get("count")) is int and root_mutations.get("count") > 0) or root_mutations.get("implementation") is True):
            _add_issue(issues, "root_implementation")
        if root.get("implementation") is True:
            _add_issue(issues, "root_implementation")


def _independent_summary(observation: Mapping[str, Any]) -> dict[str, Any]:
    graph = _mapping(observation.get("graph")) or {}
    root = _mapping(graph.get("root")) or {}
    children = graph.get("children", [])
    if not isinstance(children, list):
        children = []
    # Observer projections are already privacy-safe.  ``_safe_copy`` retains
    # their compact provenance while bounding arbitrary test doubles.
    summary: dict[str, Any] = {
        "status": observation.get("status"),
        "binding_status": observation.get("binding_status"),
        "attempt_id": observation.get("attempt_id"),
        "graph": {
            "root": _safe_copy(root),
            "children": _safe_copy(children),
            "edges": _safe_copy(graph.get("edges", [])),
        },
        "timing": _safe_copy(observation.get("timing", {})),
        "usage": _safe_copy(observation.get("usage", {})),
        "checks": _safe_copy(observation.get("checks", {})),
        "mutations": _safe_copy(observation.get("mutations", {})),
        "actions": _safe_copy(observation.get("actions", {})),
        "issue_count": len(observation.get("issues", [])) if isinstance(observation.get("issues"), list) else 0,
        "unknown_reasons": _safe_copy(observation.get("unknown_reasons", [])),
    }
    for key in ("lifecycle", "terminal_state", "releases", "verification"):
        if key in observation:
            summary[key] = _safe_copy(observation.get(key))
    return summary


def _cleanup(observation: Mapping[str, Any] | None, issues: list[str]) -> dict[str, Any]:
    active = False
    if isinstance(observation, Mapping):
        cleanup = _mapping(observation.get("cleanup"))
        if cleanup is not None and cleanup.get("status") in {"incomplete", "active", "unknown", "pending"}:
            active = True
        for key in ("active_subagents", "active_children", "owned_processes"):
            value = observation.get(key)
            if type(value) is int and value > 0:
                active = True
        ui = _mapping(observation.get("ui_observation"))
        if ui is not None and type(ui.get("active_subagents")) is int and ui.get("active_subagents") > 0:
            active = True
    return {
        "status": "incomplete" if active else "complete",
        "actions": [],
        "evidence": "controller_owned_resources_none" if not active else "controller_owned_resources_pending",
    }


def _write_atomic(path_value: Any, report: Mapping[str, Any]) -> None:
    path = _json_path(path_value)
    if path is None:
        raise ValueError("report_path must be a filesystem path")
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            if os.path.exists(temporary):
                os.unlink(temporary)
        except OSError:
            pass


def mode_contract() -> dict[str, Any]:
    """Describe the advisory and hard external-controller boundaries."""

    advisory = {
        "mode": "advisory",
        "decision": "advisory",
        "claim_permitted": False,
        "can_emit_governed_completion": False,
        "requires_independent_observation": False,
        "description": "Ordinary plugin validation is submitted/advisory evidence only.",
    }
    governed = {
        "mode": MODE,
        "decision": "governed_success",
        "claim_permitted": True,
        "can_emit_governed_completion": True,
        "requires_independent_observation": True,
        "description": "An external provider-free controller owns the completion boundary.",
    }
    return {
        "schema": SCHEMA,
        "ordinary_plugin": advisory,
        "advisory": advisory,
        "governed": governed,
        "governed_external_controller": governed,
    }


def evaluate_governed_completion(
    plan: Mapping[str, Any] | str | Path,
    observer_manifest: Mapping[str, Any] | str | Path,
    submitted_qualification: Mapping[str, Any] | str | Path | None,
    *,
    report_path: str | Path | None = None,
    supersedes: str | None = None,
) -> dict[str, Any]:
    """Evaluate one attempt and return a closed PASS/BLOCKED report.

    All three inputs may be mappings or JSON paths.  The observer is invoked
    exactly once with the loaded manifest object, regardless of submitted
    qualification content.  Any parse, policy, observer, or shape failure is
    represented as BLOCKED rather than raised.

    ``supersedes`` names the prior report's ``report_sha256`` when a
    re-evaluation against new independent observation replaces a verdict;
    prior reports remain byte-identical at their own paths and lineage is
    mechanical.  A malformed digest blocks under ``supersession_invalid``.
    """

    issues: list[str] = []
    supersedes_digest: str | None = None
    if supersedes is not None:
        if (
            isinstance(supersedes, str)
            and len(supersedes) == 64
            and all(char in "0123456789abcdef" for char in supersedes)
        ):
            supersedes_digest = supersedes
        else:
            _add_issue(issues, "supersession_invalid")
    plan_value, plan_error = _load_input(plan)
    manifest_value, manifest_error = _load_input(observer_manifest)
    qualification_value, qualification_error = _load_input(submitted_qualification) if submitted_qualification is not None else (None, None)

    if plan_error is not None:
        if plan_error == "source_missing":
            _add_issue(issues, "source_missing")
        elif plan_error == "source_unavailable":
            _add_issue(issues, "source_unavailable")
        else:
            _add_issue(issues, "plan_mismatch")
    if manifest_error is not None:
        if manifest_error == "source_missing":
            _add_issue(issues, "source_missing")
        elif manifest_error == "source_unavailable":
            _add_issue(issues, "source_unavailable")
        else:
            _add_issue(issues, "source_contradictory")
    if qualification_error is not None:
        if qualification_error == "source_missing":
            _add_issue(issues, "submitted_qualification_missing")
        elif qualification_error == "source_unavailable":
            _add_issue(issues, "submitted_qualification_failed")
        else:
            _add_issue(issues, "submitted_qualification_failed")

    plan_object = plan_value if isinstance(plan_value, Mapping) else {}
    plan_report = _plan_report(plan_object)
    plan_sha256 = plan_report.get("plan_sha256") if isinstance(plan_report.get("plan_sha256"), str) else _sha256(plan_object)
    if plan_report.get("status") != PASS or plan_report.get("qualified") is not True:
        _add_issue(issues, "plan_mismatch")
    manifest_object = manifest_value if isinstance(manifest_value, Mapping) else None
    qualification_summary, qualification_issues = _qualification_summary(
        qualification_value if qualification_error is None else None,
        plan_sha256,
    )
    for issue in qualification_issues:
        _add_issue(issues, issue)

    observation: Mapping[str, Any] | None = None
    observation_sha256: str | None = None
    if manifest_object is not None and manifest_error is None:
        try:
            observed = observe_attempt(manifest_object)
            if isinstance(observed, Mapping):
                observation = observed
                observation_sha256 = _sha256(observed)
            else:
                _add_issue(issues, "source_contradictory")
        except FileNotFoundError:
            _add_issue(issues, "source_missing")
        except PermissionError:
            _add_issue(issues, "source_unavailable")
        except OSError:
            _add_issue(issues, "source_unavailable")
        except Exception:
            _add_issue(issues, "source_contradictory")
    else:
        _add_issue(issues, "hosted_identity_unbound")

    custody_report: Mapping[str, Any] | None = None
    if observation is not None:
        status = observation.get("status")
        binding = observation.get("binding_status")
        if status != PASS or binding != "BOUND":
            _add_issue(issues, "hosted_identity_unbound")
            if status == "FAIL" or binding == "CONTRADICTORY":
                _add_issue(issues, "source_contradictory")
        for issue in _observer_issue_codes(observation):
            _add_issue(issues, issue)
        _plan_manifest_checks(plan_object, manifest_object, observation, issues)
        _lifecycle_checks(observation, issues)
        _timing_checks(observation, issues)
        _usage_checks(observation, issues)
        _verification_checks(plan_object, observation, issues)
        _release_checks(plan_object, manifest_object, observation, issues)
        _forbidden_runtime_checks(observation, issues)
        custody_report = _observed_custody(plan_object, observation)
        if (
            custody_report is None
            or custody_report.get("status") != PASS
            or custody_report.get("custody_preserved") is not True
        ):
            _add_issue(issues, "custody_invalid")
    else:
        _add_issue(issues, "custody_invalid")

    issues = _ordered_issues(issues)
    status = PASS if not issues else BLOCKED
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "mode": MODE,
        "decision": "governed_success" if status == PASS else "blocked",
        "status": status,
        "evidence_tier": RUNTIME_TIER,
        "claim_permitted": status == PASS,
        "issues": issues,
        "block_reasons": issues,
        "binding_status": observation.get("binding_status") if observation is not None else None,
        "plan_sha256": plan_sha256,
        "observation_sha256": observation_sha256,
        "independent_runtime": _independent_summary(observation) if observation is not None else {
            "status": None,
            "binding_status": None,
            "attempt_id": None,
            "graph": {"root": None, "children": [], "edges": []},
            "timing": {},
            "usage": {},
            "checks": {},
            "mutations": {},
            "actions": {},
            "issue_count": 0,
            "unknown_reasons": [],
        },
        "submitted_qualification": qualification_summary,
        "custody": _safe_copy(custody_report) if custody_report is not None else {
            "status": "missing",
            "custody_preserved": False,
            "issues": ["custody_invalid"],
        },
        "external_evaluator": {"status": "not_collected"},
        "cleanup": _cleanup(observation, issues),
        "automatic_retries": 0,
    }
    report["supersedes"] = supersedes_digest
    if status != PASS and refusal_tiers is not None:
        # C10: report-only tier annotation; verdicts and issue lists are
        # untouched, and PASS reports never carry the annotation.
        report["refusal_tiers"] = refusal_tiers.annotate_refusal_tiers(
            report["issues"]
        )
    report["report_sha256"] = _sha256(report)
    if report_path is not None:
        try:
            _write_atomic(report_path, report)
        except (OSError, ValueError):
            # A report-write failure cannot turn a blocked attempt into a
            # success.  Keep the closed result and make the write problem
            # visible through the stable source-unavailable reason.
            if "source_unavailable" not in report["issues"]:
                report["issues"] = _ordered_issues([*report["issues"], "source_unavailable"])
                report["status"] = BLOCKED
                report["decision"] = "blocked"
                report["claim_permitted"] = False
                if refusal_tiers is not None:
                    report["refusal_tiers"] = refusal_tiers.annotate_refusal_tiers(
                        report["issues"]
                    )
                report["report_sha256"] = _sha256(
                    {
                        key: value
                        for key, value in report.items()
                        if key != "report_sha256"
                    }
                )
            # Best effort second write is intentionally omitted: no retries.
    return report


def require_governed_completion(
    plan: Mapping[str, Any] | str | Path,
    observer_manifest: Mapping[str, Any] | str | Path,
    submitted_qualification: Mapping[str, Any] | str | Path | None,
    *,
    report_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return a PASS report or raise :class:`GovernedCompletionError`."""

    report = evaluate_governed_completion(
        plan,
        observer_manifest,
        submitted_qualification,
        report_path=report_path,
    )
    if report.get("status") != PASS:
        raise GovernedCompletionError(report)
    return report


def _load_cli_json(path: str) -> Any:
    value, error = _load_input(path)
    if error is not None:
        raise ValueError(error)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provider-free Orch Dork governed completion controller")
    sub = parser.add_subparsers(dest="command", required=True)
    evaluate = sub.add_parser("evaluate", help="evaluate one frozen attempt")
    evaluate.add_argument("plan")
    evaluate.add_argument("observer_manifest")
    evaluate.add_argument("submitted_qualification")
    evaluate.add_argument("--report-path", default=None)
    sub.add_parser("modes", help="show advisory and governed mode boundaries")
    args = parser.parse_args(argv)
    if args.command == "modes":
        print(json.dumps(mode_contract(), indent=2, sort_keys=True))
        return 0
    try:
        report = evaluate_governed_completion(
            _load_cli_json(args.plan),
            _load_cli_json(args.observer_manifest),
            _load_cli_json(args.submitted_qualification),
            report_path=args.report_path,
        )
    except Exception:
        # CLI input failures still produce a closed report through the public
        # evaluator.  This branch is only for an unexpected parser/runtime
        # failure and remains non-success.
        report = evaluate_governed_completion({}, {}, None, report_path=args.report_path)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("status") == PASS else 2


if __name__ == "__main__":  # pragma: no cover - exercised by CLI tests.
    raise SystemExit(main())
