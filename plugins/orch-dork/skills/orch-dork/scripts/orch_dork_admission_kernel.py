#!/usr/bin/env python3
"""One provider-free integrity seam for Orch Dork admission.

The kernel accepts three values and returns one sealed decision.  It does not
launch work or grant authority.  Every digest is recomputed, every runtime
component is chained to the same attempt and plan, and native evidence is
re-read through a bounded local observer before ``ADMIT`` is possible.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import unicodedata
from typing import Any

try:
    from orch_dork_hostile_input import PROFILE, HostileInputError, canonicalize_bounded_json
except ImportError:  # pragma: no cover - exercised by isolated policy loading.
    _hostile_path = Path(__file__).resolve().with_name("orch_dork_hostile_input.py")
    _hostile_spec = importlib.util.spec_from_file_location("orch_dork_hostile_input", _hostile_path)
    if _hostile_spec is None or _hostile_spec.loader is None:
        raise
    _hostile = importlib.util.module_from_spec(_hostile_spec)
    sys.modules.setdefault("orch_dork_hostile_input", _hostile)
    _hostile_spec.loader.exec_module(_hostile)
    PROFILE = _hostile.PROFILE
    HostileInputError = _hostile.HostileInputError
    canonicalize_bounded_json = _hostile.canonicalize_bounded_json


SNAPSHOT_SCHEMA = "orch-dork/evidence-snapshot/v1"
PLAN_SCHEMA = "orch-dork/candidate-plan/v1"
LIVE_FACTS_SCHEMA = "orch-dork/live-runtime-facts/v1"
COMPONENT_SCHEMA = "orch-dork/admission-component/v1"
DECISION_SCHEMA = "orch-dork/admission-decision/v1"
KERNEL_VERSION = "admission-kernel/v1"

ADMIT = "ADMIT"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
REFUSE = "REFUSE"

REQUIRED_MATERIALS = (
    "acceptance_criteria",
    "authority_scope",
    "installed_identity",
    "instructions",
    "invocation_identity",
    "repository_inventory",
    "source_identity",
    "ticket_spec",
    "writable_scope",
)
COMPONENT_ORDER = (
    "inventory",
    "native_receipt",
    "spawn",
    "custody",
    "graph",
    "capability",
)
RUNTIME_EVIDENCE_TIERS = frozenset({"runtime-observed", "runtime-observed-sanitized"})
MAX_VALIDITY_SECONDS = 300
MAX_COMPONENTS = len(COMPONENT_ORDER)

_SHA256_LENGTH = 64
_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:/@+-")
_SNAPSHOT_KEYS = frozenset({"schema", "attempt_id", "root_task_id", "materials", "snapshot_sha256", "previous_admission"})
_PLAN_KEYS = frozenset({"schema", "attempt_id", "root_task_id", "evidence_snapshot_sha256", "evidence_object_sha256", "plan", "plan_sha256", "semantic_decision"})
_LIVE_KEYS = frozenset({"schema", "attempt_id", "root_task_id", "observed_at", "components"})
_MATERIAL_KEYS = frozenset({"name", "value", "sha256"})
_COMPONENT_KEYS = frozenset(
    {
        "schema",
        "kind",
        "attempt_id",
        "subject_id",
        "producer",
        "source_locator",
        "source_sha256",
        "plan_sha256",
        "prior_seal_sha256",
        "valid_from",
        "valid_until",
        "evidence_tier",
        "status",
        "payload",
        "seal_sha256",
    }
)
_LANE_KEYS = frozenset(
    {
        "id",
        "objective",
        "dependencies",
        "owned_resources",
        "excluded_resources",
        "deliverables",
        "verification",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return canonicalize_bounded_json(rendered, profile=PROFILE, batch=isinstance(value, list))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == _SHA256_LENGTH and all(char in "0123456789abcdef" for char in value)


def _is_id(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 256 and value[0].isalnum() and all(char in _ID_CHARS for char in value)


def _closed(value: Any, keys: frozenset[str], label: str, reasons: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        reasons.append(f"{label}:type_invalid")
        return {}
    unknown = sorted(set(value) - keys)
    if unknown:
        reasons.extend(f"{label}:unknown_field:{field}" for field in unknown)
    return value


def _parse_time(value: Any, label: str, reasons: list[str]) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        reasons.append(f"{label}:timestamp_invalid")
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        reasons.append(f"{label}:timestamp_invalid")
        return None
    return parsed.astimezone(timezone.utc)


def _safe_reason_list(values: Sequence[str]) -> list[str]:
    return sorted(set(str(value)[:160] for value in values))[:128]


def resource_within_writable_scope(resource: Any, writable_scope: Any) -> bool:
    """Decide capability subordination with reviewable set logic (G6/C6).

    A path resource is subordinate when it equals a writable-scope entry
    or falls under one by path-segment prefix, compared NFC-casefolded
    exactly like the kernel's resource-collision rule.  `semantic:`
    resources are coordination keys, not filesystem writes (the custody
    module derives write scopes from path resources only), so filesystem
    subordination does not constrain them.  Pure set logic: a reviewer
    can recompute the proof on one host with no formal tooling.
    """

    if not isinstance(resource, str) or not resource:
        return False
    if resource.startswith("semantic:"):
        return True
    if not isinstance(writable_scope, list):
        return False
    normalized = unicodedata.normalize("NFC", resource).casefold()
    for entry in writable_scope:
        if not isinstance(entry, str) or not entry:
            continue
        scope = unicodedata.normalize("NFC", entry).casefold()
        if normalized == scope:
            return True
        if normalized.startswith(scope.rstrip("/") + "/"):
            return True
    return False


@dataclass(frozen=True)
class Observation:
    status: str
    digest: str | None = None
    reason: str | None = None


class FileEvidenceObserver:
    """Read bounded regular files beneath explicitly named local roots."""

    def __init__(self, roots: Mapping[str, str | os.PathLike[str] | Path] | None = None) -> None:
        normalized: dict[str, Path] = {}
        for name, root in (roots or {}).items():
            if not _is_id(name):
                raise ValueError("observer_root_name_invalid")
            normalized[str(name)] = Path(root).resolve()
        self._roots = normalized

    def observe(self, locator: Any) -> Observation:
        if not isinstance(locator, str) or ":" not in locator or len(locator.encode("utf-8")) > PROFILE.max_path_bytes:
            return Observation("UNAVAILABLE", reason="source_locator_invalid")
        root_name, relative_text = locator.split(":", 1)
        root = self._roots.get(root_name)
        relative = PurePosixPath(relative_text)
        if root is None or relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            return Observation("UNAVAILABLE", reason="source_locator_unavailable")
        candidate = root.joinpath(*relative.parts)
        current = root
        try:
            for part in relative.parts:
                current = current / part
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode):
                    return Observation("REFUSED", reason="source_symlink")
            resolved = candidate.resolve(strict=True)
            if os.path.commonpath((str(root), str(resolved))) != str(root):
                return Observation("REFUSED", reason="source_escape")
            info = resolved.stat()
            if not stat.S_ISREG(info.st_mode):
                return Observation("REFUSED", reason="source_special_file")
            if info.st_size > PROFILE.canonical_json_bytes:
                return Observation("REFUSED", reason="source_too_large")
            data = resolved.read_bytes()
        except (OSError, ValueError):
            return Observation("UNAVAILABLE", reason="source_unavailable")
        if len(data) > PROFILE.canonical_json_bytes:
            return Observation("REFUSED", reason="source_too_large")
        return Observation("PASS", digest=_bytes_digest(data))


class AdmissionKernel:
    """Deep admission module; ``evaluate`` is its only decision interface."""

    def __init__(self, observer: FileEvidenceObserver | None = None, *, now: datetime | None = None) -> None:
        self._observer = observer or FileEvidenceObserver()
        self._now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    def evaluate(
        self,
        evidence_snapshot: Any,
        candidate_plan: Any,
        live_runtime_facts: Any,
    ) -> dict[str, Any]:
        refuse: list[str] = []
        review: list[str] = []
        try:
            snapshot = _closed(evidence_snapshot, _SNAPSHOT_KEYS, "snapshot", refuse)
            plan_record = _closed(candidate_plan, _PLAN_KEYS, "candidate_plan", refuse)
            live = _closed(live_runtime_facts, _LIVE_KEYS, "live_runtime_facts", refuse)
            snapshot_sha = self._validate_snapshot(snapshot, refuse, review)
            plan_sha = self._validate_plan(
                plan_record,
                snapshot_sha,
                refuse,
                writable_scope=self._material_value(snapshot, "writable_scope"),
            )
            component_seals = self._validate_live(live, plan_record, plan_sha, refuse, review)
            self._validate_previous(snapshot.get("previous_admission"), snapshot_sha, plan_sha, snapshot, refuse, review)
        except (HostileInputError, TypeError, ValueError, OverflowError):
            refuse.append("input:canonicalization_failed")
            snapshot = evidence_snapshot if isinstance(evidence_snapshot, Mapping) else {}
            plan_record = candidate_plan if isinstance(candidate_plan, Mapping) else {}
            snapshot_sha = None
            plan_sha = None
            component_seals = {}

        decision = REFUSE if refuse else REVIEW_REQUIRED if review else ADMIT
        reasons = _safe_reason_list(refuse + review)
        core = {
            "schema": DECISION_SCHEMA,
            "kernel_version": KERNEL_VERSION,
            "decision": decision,
            "admitted": decision == ADMIT,
            "attempt_id": snapshot.get("attempt_id") if isinstance(snapshot, Mapping) else None,
            "root_task_id": snapshot.get("root_task_id") if isinstance(snapshot, Mapping) else None,
            "evidence_snapshot_sha256": snapshot_sha,
            "plan_sha256": plan_sha,
            "component_seals": {key: component_seals[key] for key in sorted(component_seals)},
            "authority_scope_sha256": self._material_digest(snapshot, "authority_scope"),
            "writable_scope_sha256": self._material_digest(snapshot, "writable_scope"),
            "reasons": reasons,
            "evidence_tier": "runtime-observed-sanitized" if decision == ADMIT else "provider-free-deterministic",
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "mutation_permitted": decision == ADMIT,
        }
        core["admission_digest"] = _digest(core)
        if len(_canonical_bytes(core)) > PROFILE.canonical_json_bytes:
            fallback = {
                "schema": DECISION_SCHEMA,
                "kernel_version": KERNEL_VERSION,
                "decision": REFUSE,
                "admitted": False,
                "attempt_id": None,
                "root_task_id": None,
                "evidence_snapshot_sha256": None,
                "plan_sha256": None,
                "component_seals": {},
                "authority_scope_sha256": None,
                "writable_scope_sha256": None,
                "reasons": ["output:too_large"],
                "evidence_tier": "provider-free-deterministic",
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
                "mutation_permitted": False,
            }
            fallback["admission_digest"] = _digest(fallback)
            return fallback
        return core

    def _validate_snapshot(self, snapshot: Mapping[str, Any], refuse: list[str], review: list[str]) -> str | None:
        if snapshot.get("schema") != SNAPSHOT_SCHEMA:
            refuse.append("snapshot:schema_invalid")
        if not _is_id(snapshot.get("attempt_id")):
            refuse.append("snapshot:attempt_id_invalid")
        if not _is_id(snapshot.get("root_task_id")):
            refuse.append("snapshot:root_task_id_invalid")
        materials = snapshot.get("materials")
        if not isinstance(materials, list) or len(materials) != len(REQUIRED_MATERIALS):
            refuse.append("snapshot:materials_incomplete")
            materials = []
        names: set[str] = set()
        for index, raw in enumerate(materials):
            item = _closed(raw, _MATERIAL_KEYS, f"material[{index}]", refuse)
            name = item.get("name")
            if name not in REQUIRED_MATERIALS or name in names:
                refuse.append(f"material[{index}]:name_invalid_or_duplicate")
                continue
            names.add(str(name))
            expected = _digest(item.get("value"))
            if not _is_sha(item.get("sha256")) or item.get("sha256") != expected:
                refuse.append(f"material:{name}:digest_mismatch")
        if names != set(REQUIRED_MATERIALS):
            refuse.append("snapshot:required_material_missing")
        writable = self._material_value(snapshot, "writable_scope")
        authority = self._material_value(snapshot, "authority_scope")
        if not isinstance(writable, list) or not writable:
            refuse.append("snapshot:writable_scope_empty")
        if not isinstance(authority, Mapping) or authority.get("available") is not True:
            review.append("snapshot:authority_unavailable")
        supplied = snapshot.get("snapshot_sha256")
        material = {key: deepcopy(value) for key, value in snapshot.items() if key not in {"snapshot_sha256", "previous_admission"}}
        expected_snapshot = _digest(material)
        if not _is_sha(supplied) or supplied != expected_snapshot:
            refuse.append("snapshot:digest_mismatch")
        return expected_snapshot

    def _validate_plan(
        self,
        record: Mapping[str, Any],
        snapshot_sha: str | None,
        refuse: list[str],
        *,
        writable_scope: Any = None,
    ) -> str | None:
        if record.get("schema") != PLAN_SCHEMA:
            refuse.append("candidate_plan:schema_invalid")
        if record.get("attempt_id") is None or not _is_id(record.get("attempt_id")):
            refuse.append("candidate_plan:attempt_id_invalid")
        if record.get("evidence_snapshot_sha256") != snapshot_sha:
            refuse.append("candidate_plan:snapshot_binding_mismatch")
        plan = record.get("plan")
        if not isinstance(plan, Mapping):
            refuse.append("candidate_plan:plan_invalid")
            plan = {}
        expected = _digest(plan)
        if not _is_sha(record.get("plan_sha256")) or record.get("plan_sha256") != expected:
            refuse.append("candidate_plan:digest_mismatch")
        semantic = record.get("semantic_decision")
        required_semantic = {
            "schema",
            "contract_version",
            "disposition",
            "admitted",
            "ticket_id",
            "ticket_spec_sha256",
            "acceptance_sha256",
            "authority_scope_sha256",
            "writable_scope_sha256",
            "snapshot_digest",
            "snapshot_freshness_digest",
            "adapter_generation",
            "natural_lane_count",
            "normalized_plan",
            "unknowns",
            "risks",
            "reason_codes",
            "evidence_pointer",
            "evidence_tier",
            "mutation_permitted",
            "authority_granted",
            "workers_permitted",
            "provider_free",
            "model_calls",
            "hosted_calls",
            "decision_digest",
        }
        if not isinstance(semantic, Mapping) or set(semantic) != required_semantic:
            refuse.append("candidate_plan:semantic_decision_shape_invalid")
        else:
            semantic_core = {key: deepcopy(value) for key, value in semantic.items() if key != "decision_digest"}
            if semantic.get("decision_digest") != _digest(semantic_core):
                refuse.append("candidate_plan:semantic_decision_digest_invalid")
            if semantic.get("schema") != "orch-dork/semantic-plan-decision/v2" or semantic.get("contract_version") != "semantic-plan-v2":
                refuse.append("candidate_plan:semantic_contract_invalid")
            if semantic.get("disposition") != "ADMIT" or semantic.get("admitted") is not True:
                refuse.append("candidate_plan:semantic_not_admitted")
            if semantic.get("mutation_permitted") is not False or semantic.get("authority_granted") is not False:
                refuse.append("candidate_plan:semantic_authority_invalid")
            if semantic.get("normalized_plan") != plan:
                refuse.append("candidate_plan:semantic_plan_mismatch")
            if semantic.get("snapshot_digest") != record.get("evidence_object_sha256") or not _is_sha(record.get("evidence_object_sha256")):
                refuse.append("candidate_plan:semantic_snapshot_mismatch")
        lanes = plan.get("lanes") if isinstance(plan, Mapping) else None
        if not isinstance(lanes, list) or len(lanes) > PROFILE.max_operations:
            refuse.append("candidate_plan:lanes_invalid")
            lanes = []
        lane_ids: set[str] = set()
        dependency_map: dict[str, list[str]] = {}
        normalized_resources: dict[str, str] = {}
        for index, raw in enumerate(lanes):
            lane = _closed(raw, _LANE_KEYS, f"lane[{index}]", refuse)
            lane_id = lane.get("id")
            if not _is_id(lane_id) or lane_id in lane_ids:
                refuse.append(f"lane[{index}]:id_invalid_or_duplicate")
                continue
            lane_ids.add(str(lane_id))
            if not isinstance(lane.get("objective"), str) or not lane.get("objective", "").strip():
                refuse.append(f"lane[{index}]:objective_required")
            dependencies = lane.get("dependencies", [])
            if not isinstance(dependencies, list) or any(not _is_id(item) for item in dependencies):
                refuse.append(f"lane[{index}]:dependencies_invalid")
                dependencies = []
            dependency_map[str(lane_id)] = [str(item) for item in dependencies]
            resources = lane.get("owned_resources")
            if not isinstance(resources, list) or not resources:
                refuse.append(f"lane[{index}]:owned_resources_required")
                continue
            for resource in resources:
                if not isinstance(resource, str) or not resource:
                    refuse.append(f"lane[{index}]:resource_invalid")
                    continue
                if not resource_within_writable_scope(resource, writable_scope):
                    refuse.append(
                        f"lane[{index}]:resource_outside_writable_scope"
                    )
                    continue
                normalized = unicodedata.normalize("NFC", resource).casefold()
                if normalized in normalized_resources and normalized_resources[normalized] != str(lane_id):
                    refuse.append(f"candidate_plan:resource_collision:{normalized}")
                else:
                    normalized_resources[normalized] = str(lane_id)
        for lane_id, dependencies in dependency_map.items():
            if lane_id in dependencies or any(item not in lane_ids for item in dependencies):
                refuse.append(f"candidate_plan:dependency_invalid:{lane_id}")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> None:
            if node in visiting:
                refuse.append("candidate_plan:dependency_cycle")
                return
            if node in visited:
                return
            visiting.add(node)
            for dependency in dependency_map.get(node, []):
                visit(dependency)
            visiting.remove(node)
            visited.add(node)

        for lane_id in sorted(lane_ids):
            visit(lane_id)
        return expected

    def _validate_live(
        self,
        live: Mapping[str, Any],
        plan_record: Mapping[str, Any],
        plan_sha: str | None,
        refuse: list[str],
        review: list[str],
    ) -> dict[str, str]:
        if live.get("schema") != LIVE_FACTS_SCHEMA:
            refuse.append("live_runtime_facts:schema_invalid")
        attempt = live.get("attempt_id")
        root = live.get("root_task_id")
        if attempt != plan_record.get("attempt_id"):
            refuse.append("live_runtime_facts:attempt_mismatch")
        if root != plan_record.get("root_task_id"):
            refuse.append("live_runtime_facts:root_mismatch")
        observed_at = _parse_time(live.get("observed_at"), "live_runtime_facts", refuse)
        components = live.get("components")
        if not isinstance(components, list) or len(components) != MAX_COMPONENTS:
            refuse.append("live_runtime_facts:components_incomplete")
            components = []
        seals: dict[str, str] = {}
        previous = plan_sha
        worker_sets: dict[str, set[str]] = {}
        for index, raw in enumerate(components):
            component = _closed(raw, _COMPONENT_KEYS, f"component[{index}]", refuse)
            expected_kind = COMPONENT_ORDER[index] if index < len(COMPONENT_ORDER) else None
            kind = component.get("kind")
            if kind != expected_kind or kind in seals:
                refuse.append(f"component[{index}]:kind_or_order_invalid")
                continue
            if component.get("schema") != COMPONENT_SCHEMA:
                refuse.append(f"component:{kind}:schema_invalid")
            if component.get("attempt_id") != attempt or component.get("subject_id") != root:
                refuse.append(f"component:{kind}:subject_mismatch")
            if not _is_id(component.get("producer")):
                refuse.append(f"component:{kind}:producer_invalid")
            if component.get("plan_sha256") != plan_sha:
                refuse.append(f"component:{kind}:plan_mismatch")
            if component.get("prior_seal_sha256") != previous:
                refuse.append(f"component:{kind}:chain_mismatch")
            if component.get("status") == "UNAVAILABLE":
                review.append(f"component:{kind}:unavailable")
            elif component.get("status") != "PASS":
                refuse.append(f"component:{kind}:status_invalid")
            if component.get("evidence_tier") not in RUNTIME_EVIDENCE_TIERS:
                review.append(f"component:{kind}:evidence_not_runtime_observed")
            valid_from = _parse_time(component.get("valid_from"), f"component:{kind}:valid_from", refuse)
            valid_until = _parse_time(component.get("valid_until"), f"component:{kind}:valid_until", refuse)
            if valid_from and valid_until:
                if valid_until <= valid_from or (valid_until - valid_from).total_seconds() > MAX_VALIDITY_SECONDS:
                    refuse.append(f"component:{kind}:validity_invalid")
                if observed_at and not (valid_from <= observed_at <= valid_until):
                    refuse.append(f"component:{kind}:observation_outside_validity")
                if self._now > valid_until:
                    review.append(f"component:{kind}:expired")
            observation = self._observer.observe(component.get("source_locator"))
            if observation.status == "UNAVAILABLE":
                review.append(f"component:{kind}:{observation.reason}")
            elif observation.status != "PASS":
                refuse.append(f"component:{kind}:{observation.reason}")
            elif not _is_sha(component.get("source_sha256")) or component.get("source_sha256") != observation.digest:
                refuse.append(f"component:{kind}:source_digest_mismatch")
            seal_material = {key: deepcopy(value) for key, value in component.items() if key != "seal_sha256"}
            expected_seal = _digest(seal_material)
            if not _is_sha(component.get("seal_sha256")) or component.get("seal_sha256") != expected_seal:
                refuse.append(f"component:{kind}:seal_mismatch")
            seals[str(kind)] = expected_seal
            previous = expected_seal
            payload = component.get("payload")
            if not isinstance(payload, Mapping):
                refuse.append(f"component:{kind}:payload_invalid")
                continue
            if payload.get("attempt_id") != attempt or payload.get("plan_sha256") != plan_sha:
                refuse.append(f"component:{kind}:payload_binding_mismatch")
            ids = payload.get("worker_ids", [])
            if ids is not None:
                if not isinstance(ids, list) or any(not _is_id(item) for item in ids) or len(set(ids)) != len(ids):
                    refuse.append(f"component:{kind}:worker_ids_invalid")
                else:
                    worker_sets[str(kind)] = set(str(item) for item in ids)
            terminal_ids = payload.get("terminal_worker_ids", [])
            if kind == "spawn" and isinstance(terminal_ids, list) and set(ids or []) & set(terminal_ids):
                refuse.append("component:spawn:terminal_worker_reuse")
        if set(seals) != set(COMPONENT_ORDER):
            refuse.append("live_runtime_facts:required_component_missing")
        spawned = worker_sets.get("spawn")
        for kind in ("custody", "graph"):
            if spawned is not None and worker_sets.get(kind) is not None and worker_sets[kind] != spawned:
                refuse.append(f"component:{kind}:worker_membership_mismatch")
        if spawned and root in spawned:
            refuse.append("component:spawn:root_worker_collision")
        return seals

    def _validate_previous(
        self,
        previous: Any,
        snapshot_sha: str | None,
        plan_sha: str | None,
        snapshot: Mapping[str, Any],
        refuse: list[str],
        review: list[str],
    ) -> None:
        if previous is None:
            return
        if not isinstance(previous, Mapping):
            refuse.append("previous_admission:type_invalid")
            return
        required = {
            "schema",
            "kernel_version",
            "decision",
            "admitted",
            "attempt_id",
            "root_task_id",
            "evidence_snapshot_sha256",
            "plan_sha256",
            "component_seals",
            "authority_scope_sha256",
            "writable_scope_sha256",
            "reasons",
            "evidence_tier",
            "provider_free",
            "model_calls",
            "hosted_calls",
            "mutation_permitted",
            "admission_digest",
        }
        if set(previous) != required:
            refuse.append("previous_admission:shape_invalid")
            return
        digest = previous.get("admission_digest")
        expected = _digest({key: deepcopy(value) for key, value in previous.items() if key != "admission_digest"})
        if digest != expected:
            refuse.append("previous_admission:digest_invalid")
            return
        bindings = (
            previous.get("attempt_id") == snapshot.get("attempt_id"),
            previous.get("root_task_id") == snapshot.get("root_task_id"),
            previous.get("evidence_snapshot_sha256") == snapshot_sha,
            previous.get("plan_sha256") == plan_sha,
            previous.get("authority_scope_sha256") == self._material_digest(snapshot, "authority_scope"),
            previous.get("writable_scope_sha256") == self._material_digest(snapshot, "writable_scope"),
        )
        if not all(bindings):
            review.append("previous_admission:binding_changed")
        if previous.get("decision") != ADMIT or previous.get("admitted") is not True:
            review.append("previous_admission:not_admitted")

    @staticmethod
    def _material_value(snapshot: Mapping[str, Any], name: str) -> Any:
        materials = snapshot.get("materials")
        if isinstance(materials, list):
            for item in materials:
                if isinstance(item, Mapping) and item.get("name") == name:
                    return item.get("value")
        return None

    @classmethod
    def _material_digest(cls, snapshot: Mapping[str, Any], name: str) -> str | None:
        value = cls._material_value(snapshot, name)
        return _digest(value) if value is not None else None


def evaluate_admission_kernel(
    program: Any,
    *,
    source_roots: Mapping[str, str | os.PathLike[str] | Path] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """MCP/CLI adapter for the three-value kernel interface."""

    if not isinstance(program, Mapping) or set(program) != {"evidence_snapshot", "candidate_plan", "live_runtime_facts"}:
        kernel = AdmissionKernel(FileEvidenceObserver(source_roots), now=now)
        return kernel.evaluate({}, {}, {})
    kernel = AdmissionKernel(FileEvidenceObserver(source_roots), now=now)
    return kernel.evaluate(
        program["evidence_snapshot"],
        program["candidate_plan"],
        program["live_runtime_facts"],
    )


def build_observed_admission_program(
    *,
    attempt_id: str,
    root_task_id: str,
    ticket_id: str,
    ticket_spec: Mapping[str, Any],
    acceptance_criteria: list[Any],
    authority_scope: Mapping[str, Any],
    writable_scope: list[str],
    installed_identity: Mapping[str, Any],
    instructions: Mapping[str, Any],
    invocation_identity: Mapping[str, Any],
    repository_inventory: Mapping[str, Any],
    source_identity: Mapping[str, Any],
    plan: Mapping[str, Any],
    component_evidence: Sequence[Mapping[str, Any]],
    source_roots: Mapping[str, str | os.PathLike[str] | Path],
    semantic_evidence: Mapping[str, Any],
    observed_at: datetime,
) -> dict[str, Any]:
    """Build a kernel program only from independently observable evidence.

    This constructor owns canonical assembly and sealing, but it does not
    invent runtime facts.  The caller must supply all six ordered component
    observations, each backed by a distinct bounded file locator.  The files
    are re-read before any component receives a PASS status.
    """

    if observed_at.tzinfo is None:
        raise ValueError("observed_at:timezone_required")
    if not isinstance(component_evidence, Sequence) or isinstance(
        component_evidence, (str, bytes, bytearray)
    ):
        raise ValueError("component_evidence:type_invalid")
    rows = [deepcopy(dict(row)) for row in component_evidence]
    if len(rows) != len(COMPONENT_ORDER):
        raise ValueError("component_evidence:incomplete")
    evidence_fields = {
        "kind",
        "producer",
        "source_locator",
        "source_sha256",
        "evidence_tier",
        "status",
        "payload",
    }
    observer = FileEvidenceObserver(source_roots)
    locators: set[str] = set()
    for index, (kind, row) in enumerate(zip(COMPONENT_ORDER, rows)):
        if set(row) != evidence_fields:
            raise ValueError(f"component_evidence[{index}]:shape_invalid")
        locator = row.get("source_locator")
        observation = observer.observe(locator)
        if (
            row.get("kind") != kind
            or not _is_id(row.get("producer"))
            or not isinstance(locator, str)
            or locator in locators
            or row.get("status") != "PASS"
            or row.get("evidence_tier") not in RUNTIME_EVIDENCE_TIERS
            or not isinstance(row.get("payload"), Mapping)
            or observation.status != "PASS"
            or row.get("source_sha256") != observation.digest
        ):
            raise ValueError(f"component_evidence[{index}]:not_observed")
        locators.add(locator)

    semantic_source = deepcopy(dict(semantic_evidence))
    if (
        semantic_source.get("status") != "PASS"
        or semantic_source.get("closed") is not True
        or not _is_sha(semantic_source.get("report_sha256"))
        or semantic_source.get("report_sha256")
        != _digest(
            {
                key: deepcopy(value)
                for key, value in semantic_source.items()
                if key != "report_sha256"
            }
        )
    ):
        raise ValueError("semantic_evidence:not_closed")

    material_values = {
        "acceptance_criteria": deepcopy(list(acceptance_criteria)),
        "authority_scope": deepcopy(dict(authority_scope)),
        "installed_identity": deepcopy(dict(installed_identity)),
        "instructions": deepcopy(dict(instructions)),
        "invocation_identity": deepcopy(dict(invocation_identity)),
        "repository_inventory": deepcopy(dict(repository_inventory)),
        "source_identity": deepcopy(dict(source_identity)),
        "ticket_spec": deepcopy(dict(ticket_spec)),
        "writable_scope": deepcopy(list(writable_scope)),
    }
    materials = [
        {
            "name": name,
            "value": material_values[name],
            "sha256": _digest(material_values[name]),
        }
        for name in REQUIRED_MATERIALS
    ]
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "attempt_id": attempt_id,
        "root_task_id": root_task_id,
        "materials": materials,
    }
    snapshot["snapshot_sha256"] = _digest(snapshot)

    projected_plan = deepcopy(dict(plan))
    semantic = {
        "schema": "orch-dork/semantic-plan-decision/v2",
        "contract_version": "semantic-plan-v2",
        "disposition": "ADMIT",
        "admitted": True,
        "ticket_id": ticket_id,
        "ticket_spec_sha256": _digest(material_values["ticket_spec"]),
        "acceptance_sha256": _digest(material_values["acceptance_criteria"]),
        "authority_scope_sha256": _digest(material_values["authority_scope"]),
        "writable_scope_sha256": _digest(material_values["writable_scope"]),
        "snapshot_digest": semantic_source["report_sha256"],
        "snapshot_freshness_digest": _digest(
            {
                "observed_at": observed_at.astimezone(timezone.utc).isoformat(),
                "component_sources": [row["source_sha256"] for row in rows],
                "semantic_evidence_sha256": semantic_source["report_sha256"],
            }
        ),
        "adapter_generation": str(
            installed_identity.get("installed_version", "provider-free-v1")
        ),
        "natural_lane_count": len(projected_plan.get("lanes", [])),
        "normalized_plan": deepcopy(projected_plan),
        "unknowns": [],
        "risks": [],
        "reason_codes": [],
        "evidence_pointer": "qualification-pre-spawn#semantic-evidence",
        "evidence_tier": "provider-free-verified",
        "mutation_permitted": False,
        "authority_granted": False,
        "workers_permitted": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    semantic["decision_digest"] = _digest(semantic)
    candidate = {
        "schema": PLAN_SCHEMA,
        "attempt_id": attempt_id,
        "root_task_id": root_task_id,
        "evidence_snapshot_sha256": snapshot["snapshot_sha256"],
        "evidence_object_sha256": semantic["snapshot_digest"],
        "plan": projected_plan,
        "plan_sha256": _digest(projected_plan),
        "semantic_decision": semantic,
    }

    def timestamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")

    prior = candidate["plan_sha256"]
    components: list[dict[str, Any]] = []
    for kind, evidence in zip(COMPONENT_ORDER, rows):
        payload = deepcopy(dict(evidence["payload"]))
        payload["attempt_id"] = attempt_id
        payload["plan_sha256"] = candidate["plan_sha256"]
        component = {
            "schema": COMPONENT_SCHEMA,
            "kind": kind,
            "attempt_id": attempt_id,
            "subject_id": root_task_id,
            "producer": evidence["producer"],
            "source_locator": evidence["source_locator"],
            "source_sha256": evidence["source_sha256"],
            "plan_sha256": candidate["plan_sha256"],
            "prior_seal_sha256": prior,
            "valid_from": timestamp(observed_at - timedelta(seconds=30)),
            "valid_until": timestamp(observed_at + timedelta(seconds=120)),
            "evidence_tier": evidence["evidence_tier"],
            "status": evidence["status"],
            "payload": payload,
        }
        component["seal_sha256"] = _digest(component)
        prior = component["seal_sha256"]
        components.append(component)
    live = {
        "schema": LIVE_FACTS_SCHEMA,
        "attempt_id": attempt_id,
        "root_task_id": root_task_id,
        "observed_at": timestamp(observed_at),
        "components": components,
    }
    return {
        "evidence_snapshot": snapshot,
        "candidate_plan": candidate,
        "live_runtime_facts": live,
    }


__all__ = [
    "SNAPSHOT_SCHEMA",
    "PLAN_SCHEMA",
    "LIVE_FACTS_SCHEMA",
    "COMPONENT_SCHEMA",
    "DECISION_SCHEMA",
    "KERNEL_VERSION",
    "ADMIT",
    "REVIEW_REQUIRED",
    "REFUSE",
    "REQUIRED_MATERIALS",
    "COMPONENT_ORDER",
    "Observation",
    "FileEvidenceObserver",
    "AdmissionKernel",
    "build_observed_admission_program",
    "evaluate_admission_kernel",
    "resource_within_writable_scope",
]
