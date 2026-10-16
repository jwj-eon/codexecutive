#!/usr/bin/env python3
"""Acceptance-resource closure for frozen Orch Dork plans.

The closure is deliberately provider-free.  It turns acceptance requirements
into normalized resource rows, binds each row to one owner and phase, and
returns the identity hashes that a fresh ticket admission must carry.  It does
not launch work or widen a lane's production ownership.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
from typing import Any, Mapping


CLOSURE_SCHEMA = "orch-dork/acceptance-resource-closure/v1"
REPORT_SCHEMA = "orch-dork/acceptance-resource-closure-report/v1"
PHASES = frozenset(
    {"implementation", "integration", "publication", "final_verification"}
)
SURFACES = frozenset({"path", "semantic", "generated", "install", "publication"})
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


def _load_ownership():
    path = Path(__file__).resolve().with_name("orch_dork_ownership.py")
    spec = importlib.util.spec_from_file_location("orch_dork_ownership", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("ownership analyzer unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ownership = _load_ownership()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return False
    for key in sorted(keys - set(value)):
        _issue(issues, label + ":missing:" + key)
    for key in sorted(set(value) - keys):
        _issue(issues, label + ":unknown:" + str(key))
    return set(value) == keys


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _owner_label(owner: Mapping[str, Any]) -> str | None:
    kind, owner_id = owner.get("kind"), owner.get("id")
    if kind == "root" and owner_id == "root":
        return "root"
    if kind == "lane" and _text(owner_id):
        return "lane:" + str(owner_id)
    return None


def _workspace_root(closure: Mapping[str, Any], issues: list[str]) -> Path | None:
    raw = closure.get("workspace_root")
    if not _text(raw):
        _issue(issues, "closure:workspace_root_invalid")
        return None
    root = Path(str(raw)).expanduser().resolve()
    if not root.is_dir():
        _issue(issues, "closure:workspace_root_unavailable")
    return root


def _symlink_escapes(resource: Mapping[str, Any], root: Path | None) -> bool:
    if root is None or resource.get("kind") != "path":
        return False
    normalized = str(resource.get("normalized"))
    candidates = root.glob(normalized) if resource.get("pattern") else (root / normalized,)
    for candidate in candidates:
        try:
            candidate.resolve(strict=False).relative_to(root)
        except (OSError, ValueError):
            return True
    return False


def _normalized_requirement_rows(
    plan: Mapping[str, Any], issues: list[str]
) -> tuple[list[dict[str, Any]], Path | None]:
    closure = plan.get("acceptance_resource_closure")
    if not isinstance(closure, Mapping):
        return [], None
    root = _workspace_root(closure, issues)
    requirements = closure.get("requirements")
    if not isinstance(requirements, list):
        _issue(issues, "closure:requirements_not_array")
        return [], root
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    criteria = plan.get("acceptance_criteria")
    criteria_count = len(criteria) if isinstance(criteria, list) else 0
    for index, raw in enumerate(requirements):
        label = f"closure:requirements[{index}]"
        _exact(
            raw,
            {"id", "criterion", "resource", "phase", "surface", "generated"},
            label,
            issues,
        )
        if not isinstance(raw, Mapping):
            continue
        requirement_id = raw.get("id")
        if not _text(requirement_id) or requirement_id in seen:
            _issue(issues, label + ":id_invalid_or_duplicate")
            continue
        requirement_id = str(requirement_id).strip()
        seen.add(requirement_id)
        criterion = raw.get("criterion")
        if type(criterion) is not int or criterion < 0 or criterion >= criteria_count:
            _issue(issues, "closure:criterion_invalid:" + requirement_id)
        phase = raw.get("phase")
        if phase not in PHASES:
            _issue(issues, "closure:phase_invalid:" + requirement_id)
        surface = raw.get("surface")
        if surface not in SURFACES:
            _issue(issues, "closure:surface_invalid:" + requirement_id)
        if not isinstance(raw.get("generated"), bool):
            _issue(issues, "closure:generated_invalid:" + requirement_id)
        try:
            resource = ownership.normalize_resource(raw.get("resource"), workspace_root=root)
        except Exception:
            _issue(issues, "closure:resource_invalid:" + requirement_id)
            continue
        if surface == "semantic" and resource.get("kind") != "semantic":
            _issue(issues, "closure:surface_resource_mismatch:" + requirement_id)
        if surface != "semantic" and resource.get("kind") != "path":
            _issue(issues, "closure:surface_resource_mismatch:" + requirement_id)
        if bool(raw.get("generated")) != (surface == "generated"):
            _issue(issues, "closure:generated_surface_mismatch:" + requirement_id)
        if surface == "publication" and phase != "publication":
            _issue(issues, "closure:publication_phase_mismatch:" + requirement_id)
        if _symlink_escapes(resource, root):
            _issue(issues, "closure:symlink_escape:" + requirement_id)
        rows.append(
            {
                "id": requirement_id,
                "criterion": criterion,
                "resource": resource,
                "phase": phase,
                "surface": surface,
                "generated": raw.get("generated"),
            }
        )
    covered = {row["criterion"] for row in rows if type(row.get("criterion")) is int}
    for criterion in range(criteria_count):
        if criterion not in covered:
            _issue(issues, f"closure:criterion_unmapped:{criterion}")
    return rows, root


def _assignments(
    plan: Mapping[str, Any], rows: list[dict[str, Any]], issues: list[str]
) -> dict[str, list[dict[str, Any]]]:
    closure = plan.get("acceptance_resource_closure")
    values = closure.get("assignments") if isinstance(closure, Mapping) else None
    if not isinstance(values, list):
        _issue(issues, "closure:assignments_not_array")
        values = []
    known = {row["id"] for row in rows}
    result: dict[str, list[dict[str, Any]]] = {}
    for index, raw in enumerate(values):
        label = f"closure:assignments[{index}]"
        _exact(raw, {"requirement_id", "owner"}, label, issues)
        if not isinstance(raw, Mapping):
            continue
        requirement_id = raw.get("requirement_id")
        if requirement_id not in known:
            _issue(issues, label + ":requirement_unknown")
            continue
        owner = raw.get("owner")
        _exact(owner, {"kind", "id"}, label + ".owner", issues)
        owner_value = dict(owner) if isinstance(owner, Mapping) else {}
        if _owner_label(owner_value) is None:
            _issue(issues, label + ":owner_invalid")
        result.setdefault(str(requirement_id), []).append(owner_value)
    for row in rows:
        owners = result.get(row["id"], [])
        if not owners:
            _issue(issues, "closure:unowned:" + row["id"])
        elif len(owners) != 1:
            _issue(issues, "closure:multiply_owned:" + row["id"])
    return result


def _normalize_scopes(values: Any, root: Path | None, label: str, issues: list[str]):
    if not isinstance(values, list):
        _issue(issues, label + ":not_array")
        return []
    result = []
    for index, raw in enumerate(values):
        try:
            result.append(ownership.normalize_resource(raw, workspace_root=root))
        except Exception:
            _issue(issues, f"{label}[{index}]:invalid")
    return result


def _integration_owner(
    plan: Mapping[str, Any], lane_ids: set[str], issues: list[str]
) -> dict[str, Any]:
    closure = plan.get("acceptance_resource_closure")
    value = closure.get("integration_owner") if isinstance(closure, Mapping) else None
    _exact(value, {"kind", "id", "release_conditions"}, "closure:integration_owner", issues)
    if not isinstance(value, Mapping):
        return {}
    kind, owner_id, release = value.get("kind"), value.get("id"), value.get("release_conditions")
    if kind not in {"root", "lane", "none"}:
        _issue(issues, "closure:integration_owner_kind_invalid")
    if kind == "root" and owner_id != "root":
        _issue(issues, "closure:integration_owner_id_invalid")
    if kind == "lane" and owner_id not in lane_ids:
        _issue(issues, "closure:integration_owner_lane_unknown")
    if kind == "none" and owner_id is not None:
        _issue(issues, "closure:integration_owner_id_invalid")
    if not isinstance(release, list) or any(not _text(item) for item in release):
        _issue(issues, "closure:release_conditions_invalid")
        release = []
    return {"kind": kind, "id": owner_id, "release_conditions": list(release)}


def derive_binding(plan: Mapping[str, Any]) -> dict[str, str]:
    """Derive the four material identities while ignoring declared hashes."""

    issues: list[str] = []
    rows, _ = _normalized_requirement_rows(plan, issues)
    assignments = _assignments(plan, rows, issues)
    bound_rows = []
    for row in rows:
        owners = assignments.get(row["id"], [])
        owner = _owner_label(owners[0]) if len(owners) == 1 else None
        bound_rows.append(
            {
                "id": row["id"],
                "resource": row["resource"].get("original"),
                "normalized": row["resource"].get("normalized"),
                "mode": row["resource"].get("mode"),
                "phase": row["phase"],
                "surface": row["surface"],
                "generated": row["generated"],
                "owner": owner,
            }
        )
    writable = [row for row in bound_rows if row["mode"] == "write"]
    integration = [
        row
        for row in writable
        if row["phase"] in {"integration", "publication", "final_verification"}
    ]
    final = (plan.get("integration") or {}).get("final_verification", [])
    return {
        "acceptance_criteria_sha256": _sha(plan.get("acceptance_criteria", [])),
        "writable_scope_sha256": _sha(writable),
        "integration_resources_sha256": _sha(integration),
        "final_verification_sha256": _sha(final),
    }


def validate_acceptance_resource_closure(plan: Any) -> dict[str, Any]:
    issues: list[str] = []
    value = plan if isinstance(plan, Mapping) else {}
    closure = value.get("acceptance_resource_closure")
    _exact(
        closure,
        {
            "schema",
            "workspace_root",
            "binding",
            "requirements",
            "assignments",
            "integration_owner",
        },
        "closure",
        issues,
    )
    if not isinstance(closure, Mapping):
        closure = {}
    if closure.get("schema") != CLOSURE_SCHEMA:
        _issue(issues, "closure:schema_invalid")
    rows, root = _normalized_requirement_rows(value, issues)
    assignments = _assignments(value, rows, issues)
    lanes_value = value.get("lanes") if isinstance(value.get("lanes"), list) else []
    lanes = {
        str(lane.get("id")): lane
        for lane in lanes_value
        if isinstance(lane, Mapping) and _text(lane.get("id"))
    }
    integration_owner = _integration_owner(value, set(lanes), issues)
    protected = _normalize_scopes(
        value.get("protected_resources", []), root, "closure:protected_resources", issues
    )
    lane_scopes = {
        lane_id: _normalize_scopes(
            lane.get("owned_resources", []),
            root,
            "closure:lane_resources:" + lane_id,
            issues,
        )
        for lane_id, lane in lanes.items()
    }
    assigned_rows: list[dict[str, Any]] = []
    for row in rows:
        owners = assignments.get(row["id"], [])
        owner = owners[0] if len(owners) == 1 else {}
        owner_label = _owner_label(owner)
        normalized = row["resource"]
        if any(ownership.resources_intersect(normalized, item) for item in protected):
            _issue(issues, "closure:protected:" + row["id"])
        if owner.get("kind") == "lane":
            lane_id = str(owner.get("id"))
            if lane_id not in lanes:
                _issue(issues, "closure:owner_lane_unknown:" + row["id"])
            if row["phase"] == "implementation" and not any(
                scope.get("mode") == normalized.get("mode")
                and ownership.resource_contains(scope, normalized)
                for scope in lane_scopes.get(lane_id, [])
            ):
                _issue(issues, "closure:implementation_scope_uncovered:" + row["id"])
        elif owner.get("kind") == "root" and value.get("decision", {}).get("mode") == "orchestrated":
            if row["resource"].get("mode") == "write" and row["phase"] == "implementation":
                _issue(issues, "closure:root_implementation_forbidden:" + row["id"])
        if (
            row["resource"].get("mode") == "write"
            and row["phase"] in {"integration", "publication", "final_verification"}
        ):
            expected = (
                "root"
                if integration_owner.get("kind") == "root"
                else "lane:" + str(integration_owner.get("id"))
                if integration_owner.get("kind") == "lane"
                else None
            )
            if owner_label != expected:
                _issue(issues, "closure:integration_owner_mismatch:" + row["id"])
        assigned_rows.append({**row, "owner": owner_label})

    for left_index, left in enumerate(assigned_rows):
        for right in assigned_rows[left_index + 1 :]:
            if not ownership.resources_intersect(left["resource"], right["resource"]):
                continue
            if left["resource"].get("mode") == right["resource"].get("mode") == "read":
                continue
            if left["owner"] != right["owner"] or left["phase"] != right["phase"]:
                _issue(issues, f"closure:resource_multiply_owned:{left['id']}:{right['id']}")

    mutable_integration = [
        row
        for row in assigned_rows
        if row["resource"].get("mode") == "write"
        and row["phase"] in {"integration", "publication", "final_verification"}
    ]
    mode = value.get("decision", {}).get("mode")
    coordination_only = value.get("root", {}).get("coordination_only_after_freeze")
    strategy = value.get("integration", {}).get("strategy")
    if mutable_integration:
        if integration_owner.get("kind") == "none":
            _issue(issues, "closure:integration_owner_missing")
        if not integration_owner.get("release_conditions"):
            _issue(issues, "closure:release_conditions_empty")
    if mode == "orchestrated" and integration_owner.get("kind") == "root":
        if coordination_only is not False:
            _issue(issues, "closure:coordination_only_root_owns_integration")
        if strategy != "root":
            _issue(issues, "closure:root_integration_strategy_invalid")
    if mode == "orchestrated" and integration_owner.get("kind") == "lane":
        if coordination_only is not True:
            _issue(issues, "closure:dedicated_integrator_requires_coordination_root")
        if strategy != "first_completed_worker":
            _issue(issues, "closure:lane_integration_strategy_invalid")

    derived = derive_binding(value)
    binding = closure.get("binding")
    _exact(
        binding,
        {
            "acceptance_criteria_sha256",
            "writable_scope_sha256",
            "integration_resources_sha256",
            "final_verification_sha256",
        },
        "closure:binding",
        issues,
    )
    invalidation_reasons: list[str] = []
    if isinstance(binding, Mapping):
        for field, expected in derived.items():
            if not isinstance(binding.get(field), str) or not _SHA256.fullmatch(str(binding.get(field))):
                _issue(issues, "closure:binding_invalid:" + field)
            elif binding.get(field) != expected:
                _issue(issues, "closure:binding_changed:" + field)
                invalidation_reasons.append(field + "_changed")
    report_rows = [
        {
            "id": row["id"],
            "criterion": row["criterion"],
            "resource": row["resource"].get("original"),
            "normalized_resource": row["resource"].get("normalized"),
            "mode": row["resource"].get("mode"),
            "phase": row["phase"],
            "surface": row["surface"],
            "generated": row["generated"],
            "owner": row["owner"],
        }
        for row in assigned_rows
    ]
    unowned = [row["resource"] for row in report_rows if row["owner"] is None]
    issues = sorted(set(issues))
    return {
        "schema": REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "closed": not issues,
        "freeze_permitted": not issues,
        "spawn_permitted": not issues,
        "issues": issues,
        "binding": derived,
        "ticket_admission_binding_sha256": _sha(derived),
        "ticket_admission_invalidation_reasons": sorted(invalidation_reasons),
        "requirements": report_rows,
        "unowned_resources": sorted(set(unowned)),
        "integration_owner": integration_owner,
        "closure_sha256": _sha(closure),
        "provider_free": True,
        "workers_created": 0,
        "retries_permitted": False,
        "shrink_permitted": False,
        "reuse_permitted": False,
        "root_implementation_permitted_after_failure": False,
    }


def bind_closure(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of a candidate plan with the material binding sealed."""

    value = json.loads(_canonical(plan).decode("utf-8"))
    closure = value.get("acceptance_resource_closure")
    if not isinstance(closure, dict):
        raise ValueError("acceptance_resource_closure is required")
    closure["binding"] = derive_binding(value)
    return value


__all__ = [
    "CLOSURE_SCHEMA",
    "REPORT_SCHEMA",
    "PHASES",
    "SURFACES",
    "bind_closure",
    "derive_binding",
    "validate_acceptance_resource_closure",
]
