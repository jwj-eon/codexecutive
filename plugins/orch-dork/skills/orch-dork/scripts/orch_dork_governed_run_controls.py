#!/usr/bin/env python3
"""Private, bounded user controls for a watcher-owned governed run.

Requests preserve the user's words and their source. They do not authorize
an action: the watcher consumes them on its existing owner connection, and
an accepted revision still needs fresh plan admission before it is frozen.
Progress is a projection, never a source of permission for a model or hook.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Any, Mapping

import orch_dork_governed_run_policy as policy


REQUEST_SCHEMA = "orch-dork/governed-run-control-request/v1"
PROGRESS_SCHEMA = "orch-dork/governed-run-control-progress/v2"
OFFER_SCHEMA = "orch-dork/governed-run-revision-offer/v1"
REVISION_SCHEMA = "orch-dork/governed-run-revision/v1"
MAX_STEERS = 16
MAX_REVISIONS = 3
MAX_REQUEST_BYTES = 256 * 1024
_ID = re.compile(r"\A[0-9a-f]{32}\Z")
_SHA = re.compile(r"\A[0-9a-f]{64}\Z")
_FIELDS = frozenset({
    "schema", "control_id", "run_id", "kind", "text", "offer_sha256", "accept",
    "goal", "lanes", "approve_plan_sha256", "source_thread_id", "source_turn_id", "requested_at", "request_sha256",
})


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sealed(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    core = {key: item for key, item in value.items() if key != field}
    return {**core, field: hashlib.sha256(canonical(core)).hexdigest()}


def seal_valid(value: Any, field: str) -> bool:
    return isinstance(value, Mapping) and value.get(field) == sealed(value, field)[field]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read(path: Path) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REQUEST_BYTES:
        raise ValueError("unsafe control file")
    return json.loads(path.read_text(encoding="utf-8"))


def _create(path: Path, value: Any) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("unsafe control directory")
    payload = canonical(value) + b"\n"
    if len(payload) > MAX_REQUEST_BYTES:
        raise ValueError("control too large")
    # The watcher and the sender poll these directories and refuse foreign files, so the bytes are staged beside
    # them and the file appears only when complete (Issue 244).
    policy.create_whole(path, payload, staging=parent.parent / ".staging")


def _source_valid(value: Any, *, nullable: bool = False) -> bool:
    return (value is None and nullable) or (
        isinstance(value, str) and bool(value) and len(value) <= 256
    )


def request_issues(value: Any, *, run_id: str) -> list[str]:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        return ["shape"]
    issues = []
    if value.get("schema") != REQUEST_SCHEMA or value.get("run_id") != run_id:
        issues.append("identity")
    if not isinstance(value.get("control_id"), str) or not _ID.fullmatch(value["control_id"]):
        issues.append("control_id")
    if not _source_valid(value.get("source_thread_id")) or not _source_valid(
        value.get("source_turn_id"), nullable=True
    ):
        issues.append("source")
    if value.get("kind") == "steer":
        if not isinstance(value.get("text"), str) or not value["text"].strip() or len(value["text"]) > 16_000:
            issues.append("text")
        if any(value.get(key) is not None for key in ("offer_sha256", "accept", "goal", "lanes", "approve_plan_sha256")):
            issues.append("steer_fields")
    elif value.get("kind") == "revision":
        offer = value.get("offer_sha256")
        if not isinstance(offer, str) or not _SHA.fullmatch(offer) or type(value.get("accept")) is not bool:
            issues.append("revision")
        if value.get("text") is not None:
            issues.append("revision_text")
        if value.get("accept") is True:
            goal = value.get("goal")
            if not isinstance(goal, str) or not goal.strip() or len(goal) > 16_000:
                issues.append("goal")
            if not isinstance(value.get("lanes"), list) or len(value["lanes"]) > 8:
                issues.append("lanes")
            approval = value.get("approve_plan_sha256")
            if approval is not None and (not isinstance(approval, str) or not _SHA.fullmatch(approval)):
                issues.append("approval")
        elif any(value.get(key) is not None for key in ("goal", "lanes", "approve_plan_sha256")):
            issues.append("decline_fields")
    else:
        issues.append("kind")
    if not isinstance(value.get("requested_at"), str) or not value["requested_at"]:
        issues.append("requested_at")
    if not seal_valid(value, "request_sha256"):
        issues.append("seal")
    return issues


def write_request(
    run_dir: Path, *, run_id: str, kind: str, source_thread_id: str,
    source_turn_id: str | None = None, text: str | None = None,
    offer_sha256: str | None = None, accept: bool | None = None,
    goal: str | None = None, lanes: list[dict[str, Any]] | None = None,
    approve_plan_sha256: str | None = None,
) -> dict[str, Any]:
    value = sealed({
        "schema": REQUEST_SCHEMA, "control_id": secrets.token_hex(16), "run_id": run_id,
        "kind": kind, "text": text, "offer_sha256": offer_sha256, "accept": accept,
        "goal": goal, "lanes": lanes, "approve_plan_sha256": approve_plan_sha256, "source_thread_id": source_thread_id,
        "source_turn_id": source_turn_id, "requested_at": now(),
    }, "request_sha256")
    issues = request_issues(value, run_id=run_id)
    if issues:
        raise ValueError("invalid control: " + ",".join(issues))
    _create(run_dir / "controls" / (value["control_id"] + ".json"), value)
    return value


def pending(run_dir: Path, *, run_id: str) -> list[dict[str, Any]]:
    directory = run_dir / "controls"
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("unsafe control directory")
    result = []
    for path in sorted(directory.iterdir(), key=lambda p: (p.stat().st_mtime_ns, p.name)):
        if not _ID.fullmatch(path.stem) or path.suffix != ".json":
            raise ValueError("foreign control file")
        if (run_dir / "control-results" / path.name).exists():
            continue
        value = _read(path)
        if request_issues(value, run_id=run_id) or value["control_id"] != path.stem:
            raise ValueError("invalid control record")
        result.append(value)
    return result


def record_result(run_dir: Path, control: Mapping[str, Any], **facts: Any) -> dict[str, Any]:
    value = sealed({
        "schema": "orch-dork/governed-run-control-result/v1",
        "control_id": control["control_id"], "run_id": control["run_id"],
        "request_sha256": control["request_sha256"], "observed_at": now(), **facts,
    }, "result_sha256")
    _create(run_dir / "control-results" / (control["control_id"] + ".json"), value)
    return value


def result(run_dir: Path, control_id: str) -> dict[str, Any] | None:
    if not isinstance(control_id, str) or not _ID.fullmatch(control_id):
        raise ValueError("invalid control id")
    path = run_dir / "control-results" / (control_id + ".json")
    if not path.exists():
        return None
    value = _read(path)
    if not seal_valid(value, "result_sha256") or value.get("control_id") != control_id:
        raise ValueError("invalid control result")
    return value


def results(run_dir: Path) -> list[dict[str, Any]]:
    directory = run_dir / "control-results"
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("unsafe control results directory")
    values = []
    for path in sorted(directory.iterdir()):
        if path.suffix != ".json" or not _ID.fullmatch(path.stem):
            raise ValueError("foreign control result")
        values.append(result(run_dir, path.stem))
    return values


def revision_offer(
    run_dir: Path, *, run_id: str, revision: int, parent_plan_sha256: str,
    steer_ids: list[str], refusal: Mapping[str, Any],
) -> dict[str, Any]:
    value = sealed({
        "schema": OFFER_SCHEMA, "run_id": run_id, "revision": revision + 1,
        "parent_revision": revision, "parent_plan_sha256": parent_plan_sha256,
        "steer_ids": list(steer_ids), "refused_action": dict(refusal), "offered_at": now(),
        "notice": "That action is outside the admitted plan and was refused. "
                  "Accept a revised goal and lanes to freeze the next plan, or decline to keep this plan. "
                  "The revised plan must pass the project's standing authority before it starts.",
    }, "offer_sha256")
    _create(run_dir / "revision-offers" / (str(revision + 1) + ".json"), value)
    return value


def revision_issues(value: Any) -> list[str]:
    fields = {"schema", "run_id", "revision", "parent_plan_sha256", "plan", "summary",
              "admission", "answer", "offer_sha256", "frozen_at", "revision_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        return ["shape"]
    issues = []
    revision = value.get("revision")
    if value.get("schema") != REVISION_SCHEMA or type(revision) is not int or not 2 <= revision <= MAX_REVISIONS:
        issues.append("identity")
    if not _source_valid(value.get("run_id")):
        issues.append("run_id")
    if any(not isinstance(value.get(key), str) or not _SHA.fullmatch(value[key])
           for key in ("parent_plan_sha256", "offer_sha256")):
        issues.append("predecessor")
    plan, decision, summary, answer = (value.get(key) for key in ("plan", "admission", "summary", "answer"))
    if not seal_valid(plan, "plan_sha256") or not seal_valid(decision, "admission_sha256"):
        issues.append("admission_seal")
    elif decision.get("decision") != "START" or decision.get("plan_sha256") != plan.get("plan_sha256"):
        issues.append("admission")
    if not isinstance(summary, Mapping) or not isinstance(plan, Mapping) or (
        plan.get("summary_sha256") != hashlib.sha256(canonical(summary)).hexdigest()
    ):
        issues.append("summary")
    if not isinstance(answer, Mapping) or answer.get("accept") is not True or (
        answer.get("offer_sha256") != value.get("offer_sha256")
        or not _source_valid(answer.get("source_thread_id")) or not _source_valid(answer.get("source_turn_id"))
    ):
        issues.append("answer")
    if not isinstance(value.get("frozen_at"), str) or not value["frozen_at"]:
        issues.append("frozen_at")
    if not seal_valid(value, "revision_sha256"):
        issues.append("seal")
    return issues


def write_revision(run_dir: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    frozen = sealed({**value, "schema": REVISION_SCHEMA}, "revision_sha256")
    if revision_issues(frozen):
        raise ValueError("invalid revision record")
    existing = revisions(run_dir)
    if frozen["revision"] != len(existing) + 2:
        raise ValueError("revision must be N+1")
    if existing and (frozen["parent_plan_sha256"] != existing[-1]["plan"]["plan_sha256"]
                     or frozen["run_id"] != existing[-1]["run_id"]):
        raise ValueError("revision predecessor mismatch")
    _create(run_dir / "revisions" / (str(frozen["revision"]) + ".json"), frozen)
    return frozen


def revisions(run_dir: Path) -> list[dict[str, Any]]:
    directory = run_dir / "revisions"
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("unsafe revisions directory")
    values = []
    for path in sorted(directory.iterdir()):
        value = _read(path)
        if (revision_issues(value) or value["revision"] != len(values) + 2
                or path.name != str(value["revision"]) + ".json"):
            raise ValueError("invalid revision record")
        if values and (value["parent_plan_sha256"] != values[-1]["plan"]["plan_sha256"]
                       or value["run_id"] != values[-1]["run_id"]):
            raise ValueError("revision predecessor mismatch")
        values.append(value)
    return values


__all__ = ["REQUEST_SCHEMA", "PROGRESS_SCHEMA", "OFFER_SCHEMA", "REVISION_SCHEMA", "MAX_STEERS",
           "MAX_REVISIONS", "write_request", "pending", "record_result", "result", "results", "revision_offer",
           "write_revision", "revisions", "revision_issues", "sealed", "seal_valid"]
