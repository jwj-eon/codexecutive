#!/usr/bin/env python3
"""Provider-free Issue 58 two-stage decomposition ground-truth contract."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import unicodedata


BENCHMARK_VERSION = "two-stage-decomposition-ground-truth/v1"
PAIR_AWARE_BENCHMARK_VERSION = "pair-aware-decomposition-ground-truth/v1"
HELDOUT_RESERVE_BENCHMARK_VERSION = "heldout-reserve-decomposition-ground-truth/v1"
CLEAN_JSON_BENCHMARK_VERSION = "clean-json-transport-ground-truth/v1"
INTEGER_BPS_BENCHMARK_VERSION = "integer-bps-transport-ground-truth/v1"
DIRECT_DEEPSEEK_BENCHMARK_VERSION = "direct-deepseek-json-ground-truth/v1"
SUPPORTED_BENCHMARK_VERSIONS = frozenset({BENCHMARK_VERSION, PAIR_AWARE_BENCHMARK_VERSION, HELDOUT_RESERVE_BENCHMARK_VERSION, CLEAN_JSON_BENCHMARK_VERSION, INTEGER_BPS_BENCHMARK_VERSION, DIRECT_DEEPSEEK_BENCHMARK_VERSION})
TRANSPORT_PROGRAM_SCHEMA = "orch-dork/reviewer-transport-qualification-program/v1"
TRANSPORT_RECEIPT_SCHEMA = "orch-dork/reviewer-transport-qualification-receipt/v1"
STAGE1_PROGRAM_SCHEMA = "orch-dork/stage1-classification-program/v1"
STAGE1_LABEL_SCHEMA = "orch-dork/stage1-classification-label/v1"
STAGE1_RECEIPT_SCHEMA = "orch-dork/stage1-classification-receipt/v1"
STAGE2_PROGRAM_SCHEMA = "orch-dork/stage2-ground-truth-program/v1"
STAGE2_LABEL_SCHEMA = "orch-dork/stage2-decomposition-label/v1"
STAGE2_RECEIPT_SCHEMA = "orch-dork/stage2-ground-truth-receipt/v1"
PAIR_ASSIGNMENT_PROGRAM_SCHEMA = "orch-dork/pair-aware-assignment-program/v1"
PAIR_ASSIGNMENT_RECEIPT_SCHEMA = "orch-dork/pair-aware-assignment-receipt/v1"
POLICY = "THREE_OWNER_APPROVED_EXTERNAL_MODELS_STAGE2"
GROUND_TRUTH_CLAIM = "owner_approved_external_model_ground_truth"
CLASSES = ("atomic", "orchestrated", "refused")
EXTERNAL_PREFIXES = ("minimax:", "openrouter:", "deepseek:")
PHASES = frozenset({"read_only", "pre_admission", "implementation", "integration", "generated", "install", "publication", "final_verification"})
EXPECTED_CANARY_CLASSES = frozenset(CLASSES)
FINAL_PER_CLASS = 40
FINAL_HELDOUT_PER_CLASS = 8
FINAL_METAMORPHIC_PAIRS = 6
TEXT = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
SHA = re.compile(r"^[0-9a-f]{64}$")


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def json_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _seal(value: Mapping[str, object], field: str) -> dict:
    result = deepcopy(dict(value))
    result[field] = json_sha256(result)
    return result


def _valid_seal(value: Mapping[str, object], field: str) -> bool:
    return isinstance(value.get(field), str) and value.get(field) == json_sha256({key: deepcopy(item) for key, item in value.items() if key != field})


def _closed(value: object, keys: frozenset[str], label: str, issues: list[str]) -> dict:
    if not isinstance(value, Mapping):
        issues.append(f"{label}:not_object")
        return {}
    row = deepcopy(dict(value))
    if set(row) != keys:
        issues.append(f"{label}:shape_invalid")
    return row


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(TEXT.fullmatch(value))


def _sha(value: object) -> bool:
    return isinstance(value, str) and bool(SHA.fullmatch(value))


def _logical_path(value: object) -> bool:
    if not isinstance(value, str) or not value or value != unicodedata.normalize("NFC", value) or value.startswith(("/", "~/")) or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _expected_predecessors(benchmark_version: object) -> int:
    if benchmark_version == DIRECT_DEEPSEEK_BENCHMARK_VERSION:
        return 7
    if benchmark_version == INTEGER_BPS_BENCHMARK_VERSION:
        return 6
    if benchmark_version == CLEAN_JSON_BENCHMARK_VERSION:
        return 5
    if benchmark_version == HELDOUT_RESERVE_BENCHMARK_VERSION:
        return 4
    if benchmark_version == PAIR_AWARE_BENCHMARK_VERSION:
        return 3
    return 2


def _task_limit(benchmark_version: object) -> int:
    return 240 if benchmark_version in {HELDOUT_RESERVE_BENCHMARK_VERSION, CLEAN_JSON_BENCHMARK_VERSION, INTEGER_BPS_BENCHMARK_VERSION, DIRECT_DEEPSEEK_BENCHMARK_VERSION} else 200


PROFILE_KEYS = frozenset({"reviewer_id", "provider", "model", "profile_sha256"})
CANARY_KEYS = frozenset({"canary_id", "expected_class", "status", "response_valid", "retry_count", "fallback_count", "scored_task_calls", "secret_values_recorded", "reasoning_recorded", "receipt_sha256"})
TRANSPORT_PROGRAM_KEYS = frozenset({"schema", "benchmark_version", "reviewer_profile", "canary_observations", "predecessor_attempts", "mutation_permitted", "authority_granted"})


def qualify_review_transport(program: object) -> dict:
    issues: list[str] = []
    value = _closed(program, TRANSPORT_PROGRAM_KEYS, "program", issues)
    benchmark_version = value.get("benchmark_version")
    if value.get("schema") != TRANSPORT_PROGRAM_SCHEMA or benchmark_version not in SUPPORTED_BENCHMARK_VERSIONS:
        issues.append("program:identity_invalid")
    profile = _closed(value.get("reviewer_profile"), PROFILE_KEYS, "reviewer_profile", issues)
    reviewer_id = profile.get("reviewer_id")
    if not _text(reviewer_id) or not str(reviewer_id).startswith(EXTERNAL_PREFIXES) or not _text(profile.get("provider")) or not _text(profile.get("model")):
        issues.append("reviewer_profile:identity_invalid")
    if profile.get("profile_sha256") != json_sha256({key: profile.get(key) for key in ("reviewer_id", "provider", "model")}):
        issues.append("reviewer_profile:seal_invalid")
    observations = value.get("canary_observations")
    classes: set[str] = set()
    canary_ids: set[str] = set()
    if not isinstance(observations, list) or len(observations) != 3:
        issues.append("canaries:count_invalid")
        observations = []
    for index, raw in enumerate(observations):
        row = _closed(raw, CANARY_KEYS, f"canaries[{index}]", issues)
        canary_id, class_name = row.get("canary_id"), row.get("expected_class")
        if not _text(canary_id) or canary_id in canary_ids or class_name not in CLASSES or class_name in classes:
            issues.append(f"canaries[{index}]:identity_invalid")
        if row.get("status") != "PASS" or row.get("response_valid") is not True:
            issues.append(f"canaries[{index}]:not_pass")
        if row.get("retry_count") != 0 or row.get("fallback_count") != 0 or row.get("scored_task_calls") != 0:
            issues.append(f"canaries[{index}]:boundary_invalid")
        if row.get("secret_values_recorded") is not False or row.get("reasoning_recorded") is not False or not _sha(row.get("receipt_sha256")):
            issues.append(f"canaries[{index}]:evidence_invalid")
        if isinstance(canary_id, str):
            canary_ids.add(canary_id)
        if isinstance(class_name, str):
            classes.add(class_name)
    if classes != EXPECTED_CANARY_CLASSES:
        issues.append("canaries:class_coverage_invalid")
    predecessors = value.get("predecessor_attempts")
    expected_predecessors = _expected_predecessors(benchmark_version)
    if not isinstance(predecessors, list) or len(predecessors) != expected_predecessors or not all(_sha(item) for item in predecessors) or len(set(predecessors)) != expected_predecessors:
        issues.append("predecessors:invalid")
    if value.get("mutation_permitted") is not False or value.get("authority_granted") is not False:
        issues.append("program:authority_boundary_invalid")
    core = {
        "schema": TRANSPORT_RECEIPT_SCHEMA,
        "benchmark_version": benchmark_version if benchmark_version in SUPPORTED_BENCHMARK_VERSIONS else None,
        "reviewer_id": reviewer_id if _text(reviewer_id) else None,
        "status": "PASS" if not issues else "FAIL",
        "canary_count": len(observations),
        "canary_classes": sorted(classes),
        "scored_calls_permitted": not issues,
        "issues": sorted(set(issues)),
        "retry_count": 0,
        "fallback_count": 0,
        "authority_granted": False,
        "mutation_permitted": False,
    }
    return _seal(core, "receipt_sha256")


TASK_KEYS = frozenset({"id", "task_sha256", "snapshot_digest", "split", "metamorphic_pair_id", "metamorphic_role", "metamorphic_expectation"})
STAGE1_LABEL_KEYS = frozenset({"schema", "task_id", "reviewer_id", "class", "natural_lane_count", "blocking_unknowns", "forbidden_effects", "confidence_bps", "abstain", "independent", "saw_peer_label", "saw_sol_output", "retry_count", "fallback_count", "record_sha256"})
STAGE1_PROGRAM_KEYS = frozenset({"schema", "benchmark_version", "policy", "tasks", "transport_receipts", "labels", "predecessor_attempts", "human_reviewer_count", "external_model_reviewer_count"})


def seal_stage1_label(value: Mapping[str, object]) -> dict:
    return _seal(value, "record_sha256")


def _validate_tasks(raw: object, issues: list[str], *, max_tasks: int = 200) -> tuple[list[dict], dict[str, dict]]:
    if not isinstance(raw, list) or not 120 <= len(raw) <= max_tasks:
        issues.append("tasks:count_invalid")
        return [], {}
    tasks: list[dict] = []
    by_id: dict[str, dict] = {}
    task_hashes: set[str] = set()
    for index, item in enumerate(raw):
        row = _closed(item, TASK_KEYS, f"tasks[{index}]", issues)
        task_id = row.get("id")
        if not _text(task_id) or task_id in by_id or not _sha(row.get("task_sha256")) or row.get("task_sha256") in task_hashes or not _sha(row.get("snapshot_digest")):
            issues.append(f"tasks[{index}]:identity_invalid")
        if row.get("split") not in {"train", "heldout", "metamorphic"}:
            issues.append(f"tasks[{index}]:split_invalid")
        pair_id = row.get("metamorphic_pair_id")
        if pair_id is None:
            if row.get("metamorphic_role") is not None or row.get("metamorphic_expectation") is not None:
                issues.append(f"tasks[{index}]:metamorphic_invalid")
        elif not _text(pair_id) or row.get("metamorphic_role") not in {"base", "variant"} or row.get("metamorphic_expectation") not in {"same", "changed"}:
            issues.append(f"tasks[{index}]:metamorphic_invalid")
        if isinstance(task_id, str):
            by_id[task_id] = row
        if isinstance(row.get("task_sha256"), str):
            task_hashes.add(row["task_sha256"])
        tasks.append(row)
    return tasks, by_id


def _validate_transport_receipts(raw: object, issues: list[str]) -> list[str]:
    if not isinstance(raw, list) or len(raw) != 3:
        issues.append("transport_receipts:count_invalid")
        return []
    reviewers = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping) or item.get("schema") != TRANSPORT_RECEIPT_SCHEMA or not _valid_seal(item, "receipt_sha256") or item.get("status") != "PASS" or item.get("scored_calls_permitted") is not True:
            issues.append(f"transport_receipts[{index}]:invalid")
            continue
        reviewer_id = item.get("reviewer_id")
        if not _text(reviewer_id) or not str(reviewer_id).startswith(EXTERNAL_PREFIXES):
            issues.append(f"transport_receipts[{index}]:reviewer_invalid")
        else:
            reviewers.append(str(reviewer_id))
    if len(set(reviewers)) != 3:
        issues.append("transport_receipts:reviewers_not_distinct")
    return reviewers


def _stage1_label(raw: object, task_id: str, reviewer_id: str, issues: list[str]) -> dict | None:
    row = _closed(raw, STAGE1_LABEL_KEYS, f"labels:{task_id}:{reviewer_id}", issues)
    if row.get("schema") != STAGE1_LABEL_SCHEMA or row.get("task_id") != task_id or row.get("reviewer_id") != reviewer_id or not _valid_seal(row, "record_sha256"):
        issues.append(f"labels:{task_id}:{reviewer_id}:identity_invalid")
        return None
    if row.get("independent") is not True or row.get("saw_peer_label") is not False or row.get("saw_sol_output") is not False or row.get("retry_count") != 0 or row.get("fallback_count") != 0:
        issues.append(f"labels:{task_id}:{reviewer_id}:boundary_invalid")
    if row.get("abstain") is True:
        if row.get("class") is not None or row.get("natural_lane_count") is not None or row.get("blocking_unknowns") != [] or row.get("forbidden_effects") != [] or row.get("confidence_bps") is not None:
            issues.append(f"labels:{task_id}:{reviewer_id}:abstention_payload_invalid")
        return row
    class_name, lane_count = row.get("class"), row.get("natural_lane_count")
    if class_name not in CLASSES or not isinstance(lane_count, int) or isinstance(lane_count, bool) or lane_count < 0:
        issues.append(f"labels:{task_id}:{reviewer_id}:classification_invalid")
    if class_name == "atomic" and lane_count != 1 or class_name == "orchestrated" and lane_count < 2 or class_name == "refused" and lane_count != 0:
        issues.append(f"labels:{task_id}:{reviewer_id}:lane_count_invalid")
    for field in ("blocking_unknowns", "forbidden_effects"):
        value = row.get(field)
        if not isinstance(value, list) or len(value) > 32 or any(not _text(item) for item in value):
            issues.append(f"labels:{task_id}:{reviewer_id}:{field}_invalid")
    if not isinstance(row.get("confidence_bps"), int) or isinstance(row.get("confidence_bps"), bool) or not 0 <= row.get("confidence_bps", -1) <= 10000:
        issues.append(f"labels:{task_id}:{reviewer_id}:confidence_invalid")
    return row


def freeze_stage1_classification(program: object) -> dict:
    issues: list[str] = []
    value = _closed(program, STAGE1_PROGRAM_KEYS, "program", issues)
    benchmark_version = value.get("benchmark_version")
    if value.get("schema") != STAGE1_PROGRAM_SCHEMA or benchmark_version not in SUPPORTED_BENCHMARK_VERSIONS or value.get("policy") != POLICY:
        issues.append("program:identity_invalid")
    tasks, by_id = _validate_tasks(value.get("tasks"), issues, max_tasks=_task_limit(benchmark_version))
    reviewers = _validate_transport_receipts(value.get("transport_receipts"), issues)
    if value.get("human_reviewer_count") != 0 or value.get("external_model_reviewer_count") != 3:
        issues.append("program:reviewer_counts_invalid")
    predecessors = value.get("predecessor_attempts")
    expected_predecessors = _expected_predecessors(benchmark_version)
    if not isinstance(predecessors, list) or len(predecessors) != expected_predecessors or not all(_sha(item) for item in predecessors) or len(set(predecessors)) != expected_predecessors:
        issues.append("program:predecessors_invalid")
    labels = value.get("labels")
    if not isinstance(labels, Mapping) or set(labels) != set(by_id):
        issues.append("labels:membership_invalid")
        labels = {}
    consensus: dict[str, dict] = {}
    unresolved = []
    for task_id in sorted(by_id):
        raw_rows = labels.get(task_id)
        if not isinstance(raw_rows, list) or len(raw_rows) != 3:
            issues.append(f"labels:{task_id}:count_invalid")
            unresolved.append(task_id)
            continue
        rows = []
        row_by_reviewer = {str(row.get("reviewer_id")): row for row in raw_rows if isinstance(row, Mapping)}
        if set(row_by_reviewer) != set(reviewers):
            issues.append(f"labels:{task_id}:reviewers_invalid")
        for reviewer_id in reviewers:
            row = _stage1_label(row_by_reviewer.get(reviewer_id), task_id, reviewer_id, issues)
            if row is not None:
                rows.append(row)
        votes = Counter((row.get("class"), row.get("natural_lane_count")) for row in rows if row.get("abstain") is False)
        if votes:
            vote, count = votes.most_common(1)[0]
            if count >= 2:
                representative = next(row for row in rows if (row.get("class"), row.get("natural_lane_count")) == vote)
                consensus[task_id] = {"class": vote[0], "natural_lane_count": vote[1], "agreement_bps": round(count / 3 * 10000), "representative_record_sha256": representative.get("record_sha256")}
                continue
        unresolved.append(task_id)
    class_counts = Counter(str(row["class"]) for row in consensus.values())
    core = {
        "schema": STAGE1_RECEIPT_SCHEMA,
        "benchmark_version": benchmark_version if benchmark_version in SUPPORTED_BENCHMARK_VERSIONS else None,
        "policy": POLICY,
        "status": "PASS" if not issues and all(class_counts.get(name, 0) >= FINAL_PER_CLASS for name in CLASSES) else "INSUFFICIENT_CONSENSUS" if not issues else "FAIL",
        "task_count": len(tasks),
        "reviewer_ids": sorted(reviewers),
        "human_reviewer_count": 0,
        "external_model_reviewer_count": len(reviewers),
        "ground_truth_claim": None,
        "consensus": consensus,
        "consensus_class_counts": dict(sorted(class_counts.items())),
        "unresolved_task_ids": unresolved,
        "issues": sorted(set(issues)),
        "stage2_permitted": not issues and all(class_counts.get(name, 0) >= FINAL_PER_CLASS for name in CLASSES),
        "authority_granted": False,
    }
    return _seal(core, "receipt_sha256")


PATH_KEYS = frozenset({"path", "owner_id", "phase"})
STAGE2_LABEL_KEYS = frozenset({"schema", "task_id", "reviewer_id", "class", "natural_lane_count", "owner_ids", "path_ownership", "dependency_edges", "absent_edge_rationales", "hidden_coupling", "integration_viable", "integration_owner", "release_conditions", "forbidden_actions", "blocking_unknowns", "abstain", "independent", "saw_peer_label", "saw_sol_output", "retry_count", "fallback_count", "record_sha256"})
STAGE2_PROGRAM_KEYS = frozenset({"schema", "benchmark_version", "policy", "stage1_receipt", "tasks", "transport_receipts", "labels", "human_reviewer_count", "external_model_reviewer_count"})


def seal_stage2_label(value: Mapping[str, object]) -> dict:
    return _seal(value, "record_sha256")


def _stage2_label(raw: object, task_id: str, reviewer_id: str, issues: list[str]) -> dict | None:
    label = f"labels:{task_id}:{reviewer_id}"
    row = _closed(raw, STAGE2_LABEL_KEYS, label, issues)
    if row.get("schema") != STAGE2_LABEL_SCHEMA or row.get("task_id") != task_id or row.get("reviewer_id") != reviewer_id or not _valid_seal(row, "record_sha256"):
        issues.append(f"{label}:identity_invalid")
        return None
    if row.get("independent") is not True or row.get("saw_peer_label") is not False or row.get("saw_sol_output") is not False or row.get("retry_count") != 0 or row.get("fallback_count") != 0:
        issues.append(f"{label}:boundary_invalid")
    if row.get("abstain") is True:
        neutral = {"class": None, "natural_lane_count": None, "owner_ids": [], "path_ownership": [], "dependency_edges": [], "absent_edge_rationales": [], "hidden_coupling": None, "integration_viable": None, "integration_owner": None, "release_conditions": [], "forbidden_actions": [], "blocking_unknowns": []}
        if any(row.get(key) != expected for key, expected in neutral.items()):
            issues.append(f"{label}:abstention_payload_invalid")
        return row
    class_name, lane_count = row.get("class"), row.get("natural_lane_count")
    if class_name not in CLASSES or not isinstance(lane_count, int) or isinstance(lane_count, bool) or lane_count < 0:
        issues.append(f"{label}:classification_invalid")
        return row
    if class_name == "atomic" and lane_count != 1 or class_name == "orchestrated" and lane_count < 2 or class_name == "refused" and lane_count != 0:
        issues.append(f"{label}:lane_count_invalid")
    owners = row.get("owner_ids")
    if not isinstance(owners, list) or len(owners) != lane_count or len(set(owners)) != len(owners) or any(not _text(item) for item in owners):
        issues.append(f"{label}:owners_invalid")
        owners = []
    paths = row.get("path_ownership")
    seen_paths = set()
    if not isinstance(paths, list) or len(paths) > 256:
        issues.append(f"{label}:paths_invalid")
        paths = []
    for path_index, item in enumerate(paths):
        path_row = _closed(item, PATH_KEYS, f"{label}:paths[{path_index}]", issues)
        path = path_row.get("path")
        if not _logical_path(path) or path in seen_paths or path_row.get("owner_id") not in owners or path_row.get("phase") not in PHASES:
            issues.append(f"{label}:paths[{path_index}]:invalid")
        if isinstance(path, str):
            seen_paths.add(path)
    edges = row.get("dependency_edges")
    if not isinstance(edges, list) or len(edges) > 256 or any(not isinstance(edge, list) or len(edge) != 2 or edge[0] == edge[1] or edge[0] not in owners or edge[1] not in owners for edge in edges):
        issues.append(f"{label}:edges_invalid")
        edges = []
    absent = row.get("absent_edge_rationales")
    if not isinstance(absent, list) or len(absent) > 256 or any(not isinstance(item, Mapping) or set(item) != {"owners", "rationale"} or not isinstance(item.get("owners"), list) or len(item["owners"]) != 2 or any(owner not in owners for owner in item["owners"]) or not _text(item.get("rationale")) for item in absent):
        issues.append(f"{label}:absent_edges_invalid")
    if not isinstance(row.get("hidden_coupling"), bool) or not isinstance(row.get("integration_viable"), bool):
        issues.append(f"{label}:booleans_invalid")
    integration_owner = row.get("integration_owner")
    if class_name == "refused":
        if integration_owner is not None or row.get("release_conditions") != []:
            issues.append(f"{label}:refusal_integration_invalid")
    elif integration_owner not in owners:
        issues.append(f"{label}:integration_owner_invalid")
    for field in ("release_conditions", "forbidden_actions", "blocking_unknowns"):
        items = row.get(field)
        if not isinstance(items, list) or len(items) > 64 or any(not _text(item) for item in items):
            issues.append(f"{label}:{field}_invalid")
    return row


def _stage2_signature(row: Mapping[str, object]) -> str:
    normalized = {
        "class": row.get("class"),
        "natural_lane_count": row.get("natural_lane_count"),
        "owner_ids": sorted(row.get("owner_ids", [])),
        "path_ownership": sorted((item.get("path"), item.get("owner_id"), item.get("phase")) for item in row.get("path_ownership", []) if isinstance(item, Mapping)),
        "dependency_edges": sorted(tuple(edge) for edge in row.get("dependency_edges", [])),
        "absent_edge_rationales": sorted((tuple(item.get("owners", [])), item.get("rationale")) for item in row.get("absent_edge_rationales", []) if isinstance(item, Mapping)),
        "hidden_coupling": row.get("hidden_coupling"),
        "integration_viable": row.get("integration_viable"),
        "integration_owner": row.get("integration_owner"),
        "release_conditions": sorted(row.get("release_conditions", [])),
        "forbidden_actions": sorted(row.get("forbidden_actions", [])),
        "blocking_unknowns": sorted(row.get("blocking_unknowns", [])),
    }
    return json_sha256(normalized)


def _select_final(consensus: Mapping[str, Mapping[str, object]], tasks: Mapping[str, Mapping[str, object]]) -> tuple[list[str], list[str]]:
    pairs: dict[str, list[str]] = {}
    for task_id, task in tasks.items():
        if task.get("metamorphic_pair_id"):
            pairs.setdefault(str(task["metamorphic_pair_id"]), []).append(task_id)
    eligible_pairs = []
    for pair_id, task_ids in sorted(pairs.items()):
        if len(task_ids) == 2 and all(task_id in consensus for task_id in task_ids) and len({consensus[task_id]["class"] for task_id in task_ids}) == 1:
            eligible_pairs.append((pair_id, sorted(task_ids)))
    if len(eligible_pairs) < FINAL_METAMORPHIC_PAIRS:
        return [], ["selection:metamorphic_pairs_insufficient"]
    selected = {task_id for _, task_ids in eligible_pairs[:FINAL_METAMORPHIC_PAIRS] for task_id in task_ids}
    for class_name in CLASSES:
        heldout = sorted(task_id for task_id, row in consensus.items() if row["class"] == class_name and tasks[task_id]["split"] == "heldout" and task_id not in selected)
        if len(heldout) < FINAL_HELDOUT_PER_CLASS:
            return [], [f"selection:{class_name}:heldout_insufficient"]
        selected.update(heldout[:FINAL_HELDOUT_PER_CLASS])
    for class_name in CLASSES:
        current = sum(consensus[task_id]["class"] == class_name for task_id in selected)
        candidates = sorted(task_id for task_id, row in consensus.items() if row["class"] == class_name and task_id not in selected)
        needed = FINAL_PER_CLASS - current
        if needed < 0 or len(candidates) < needed:
            return [], [f"selection:{class_name}:balance_insufficient"]
        selected.update(candidates[:needed])
    if len(selected) != FINAL_PER_CLASS * len(CLASSES):
        return [], ["selection:final_count_invalid"]
    return sorted(selected), []


def freeze_stage2_ground_truth(program: object) -> dict:
    issues: list[str] = []
    value = _closed(program, STAGE2_PROGRAM_KEYS, "program", issues)
    benchmark_version = value.get("benchmark_version")
    if value.get("schema") != STAGE2_PROGRAM_SCHEMA or benchmark_version not in SUPPORTED_BENCHMARK_VERSIONS or value.get("policy") != POLICY:
        issues.append("program:identity_invalid")
    stage1 = value.get("stage1_receipt")
    if not isinstance(stage1, Mapping) or stage1.get("schema") != STAGE1_RECEIPT_SCHEMA or not _valid_seal(stage1, "receipt_sha256") or stage1.get("status") != "PASS" or stage1.get("stage2_permitted") is not True:
        issues.append("stage1_receipt:invalid")
    tasks, by_id = _validate_tasks(value.get("tasks"), issues, max_tasks=_task_limit(benchmark_version))
    reviewers = _validate_transport_receipts(value.get("transport_receipts"), issues)
    if value.get("human_reviewer_count") != 0 or value.get("external_model_reviewer_count") != 3:
        issues.append("program:reviewer_counts_invalid")
    labels = value.get("labels")
    if not isinstance(labels, Mapping) or set(labels) != set(by_id):
        issues.append("labels:membership_invalid")
        labels = {}
    consensus: dict[str, dict] = {}
    unresolved = []
    for task_id in sorted(by_id):
        raw_rows = labels.get(task_id)
        if not isinstance(raw_rows, list) or len(raw_rows) != 3:
            issues.append(f"labels:{task_id}:count_invalid")
            unresolved.append(task_id)
            continue
        row_by_reviewer = {str(row.get("reviewer_id")): row for row in raw_rows if isinstance(row, Mapping)}
        if set(row_by_reviewer) != set(reviewers):
            issues.append(f"labels:{task_id}:reviewers_invalid")
        rows = []
        for reviewer_id in reviewers:
            row = _stage2_label(row_by_reviewer.get(reviewer_id), task_id, reviewer_id, issues)
            if row is not None:
                rows.append(row)
        signatures = Counter(_stage2_signature(row) for row in rows if row.get("abstain") is False)
        if signatures:
            winning, count = signatures.most_common(1)[0]
            if count >= 2:
                representative = next(row for row in rows if _stage2_signature(row) == winning)
                consensus[task_id] = {"class": representative["class"], "natural_lane_count": representative["natural_lane_count"], "label_record_sha256": representative["record_sha256"], "decomposition_sha256": winning, "agreement_bps": round(count / 3 * 10000)}
                continue
        unresolved.append(task_id)
    selected, selection_issues = _select_final(consensus, by_id) if not issues else ([], [])
    class_counts = Counter(consensus[task_id]["class"] for task_id in selected)
    status = "PASS" if not issues and not selection_issues and len(selected) == 120 else "INSUFFICIENT_CONSENSUS" if not issues else "FAIL"
    core = {
        "schema": STAGE2_RECEIPT_SCHEMA,
        "benchmark_version": benchmark_version if benchmark_version in SUPPORTED_BENCHMARK_VERSIONS else None,
        "policy": POLICY,
        "status": status,
        "ground_truth_claim": GROUND_TRUTH_CLAIM if status == "PASS" else None,
        "human_reviewer_count": 0,
        "external_model_reviewer_count": len(reviewers),
        "reviewer_ids": sorted(reviewers),
        "task_count": len(tasks),
        "consensus_task_count": len(consensus),
        "unresolved_task_ids": unresolved,
        "selected_task_ids": selected,
        "selected_class_counts": dict(sorted(class_counts.items())),
        "selection_issues": selection_issues,
        "issues": sorted(set(issues)),
        "fresh_sol_turns_permitted": status == "PASS",
        "authority_granted": False,
    }
    return _seal(core, "receipt_sha256")


PAIR_TASK_KEYS = frozenset(
    {
        "id",
        "task_sha256",
        "source_task_id",
        "construction_stratum",
        "split",
        "metamorphic_pair_id",
        "metamorphic_role",
        "metamorphic_expectation",
    }
)
PAIR_ASSIGNMENT_PROGRAM_KEYS = frozenset(
    {
        "schema",
        "benchmark_version",
        "tasks",
        "predecessor_attempts",
        "labels_present",
        "sol_outputs_present",
        "assignment_frozen",
        "human_reviewer_count",
        "external_model_reviewer_count",
        "authority_granted",
    }
)
PAIR_STRATA = {
    "atomic_public_single": "atomic",
    "orchestrated_public_issue_pair": "orchestrated",
    "refused_missing_remote_authority": "refused",
}


def freeze_pair_aware_assignment(program: object) -> dict:
    """Freeze sufficient pre-label pair reserve for the Issue 59 successor."""

    issues: list[str] = []
    value = _closed(program, PAIR_ASSIGNMENT_PROGRAM_KEYS, "program", issues)
    benchmark_version = value.get("benchmark_version")
    if value.get("schema") != PAIR_ASSIGNMENT_PROGRAM_SCHEMA or benchmark_version not in {PAIR_AWARE_BENCHMARK_VERSION, HELDOUT_RESERVE_BENCHMARK_VERSION, CLEAN_JSON_BENCHMARK_VERSION, INTEGER_BPS_BENCHMARK_VERSION, DIRECT_DEEPSEEK_BENCHMARK_VERSION}:
        issues.append("program:identity_invalid")
    predecessors = value.get("predecessor_attempts")
    expected_predecessors = _expected_predecessors(benchmark_version)
    if not isinstance(predecessors, list) or len(predecessors) != expected_predecessors or not all(_sha(item) for item in predecessors) or len(set(predecessors)) != expected_predecessors:
        issues.append("program:predecessors_invalid")
    if value.get("labels_present") is not False or value.get("sol_outputs_present") is not False or value.get("assignment_frozen") is not True or value.get("human_reviewer_count") != 0 or value.get("external_model_reviewer_count") != 3 or value.get("authority_granted") is not False:
        issues.append("program:boundary_invalid")
    raw_tasks = value.get("tasks")
    if not isinstance(raw_tasks, list) or not 120 <= len(raw_tasks) <= _task_limit(benchmark_version):
        issues.append("tasks:count_invalid")
        raw_tasks = []
    task_ids: set[str] = set()
    task_hashes: set[str] = set()
    by_stratum: dict[str, list[dict]] = {name: [] for name in PAIR_STRATA}
    pairs: dict[str, list[dict]] = {}
    for index, raw in enumerate(raw_tasks):
        row = _closed(raw, PAIR_TASK_KEYS, f"tasks[{index}]", issues)
        task_id, task_sha = row.get("id"), row.get("task_sha256")
        source_task_id, stratum = row.get("source_task_id"), row.get("construction_stratum")
        if not _text(task_id) or task_id in task_ids or not _sha(task_sha) or task_sha in task_hashes or not _text(source_task_id) or stratum not in PAIR_STRATA:
            issues.append(f"tasks[{index}]:identity_invalid")
        split, pair_id = row.get("split"), row.get("metamorphic_pair_id")
        if split not in {"train", "heldout", "metamorphic"}:
            issues.append(f"tasks[{index}]:split_invalid")
        if pair_id is None:
            if split == "metamorphic" or row.get("metamorphic_role") is not None or row.get("metamorphic_expectation") is not None:
                issues.append(f"tasks[{index}]:pair_invalid")
        elif not _text(pair_id) or split != "metamorphic" or row.get("metamorphic_role") not in {"base", "variant"} or row.get("metamorphic_expectation") != "same":
            issues.append(f"tasks[{index}]:pair_invalid")
        else:
            pairs.setdefault(str(pair_id), []).append(row)
        if isinstance(task_id, str):
            task_ids.add(task_id)
        if isinstance(task_sha, str):
            task_hashes.add(task_sha)
        if stratum in by_stratum:
            by_stratum[str(stratum)].append(row)
    stratum_counts: dict[str, int] = {}
    heldout_counts: dict[str, int] = {}
    pair_counts: Counter[str] = Counter()
    overprovisioned = benchmark_version in {HELDOUT_RESERVE_BENCHMARK_VERSION, CLEAN_JSON_BENCHMARK_VERSION, INTEGER_BPS_BENCHMARK_VERSION, DIRECT_DEEPSEEK_BENCHMARK_VERSION}
    minimum_stratum = 80 if overprovisioned else 56
    minimum_heldout = 32 if overprovisioned else 8
    minimum_pairs = 12 if overprovisioned else 8
    for stratum, rows in by_stratum.items():
        stratum_counts[stratum] = len(rows)
        heldout_counts[stratum] = sum(row.get("split") == "heldout" for row in rows)
        if len(rows) < minimum_stratum or heldout_counts[stratum] < minimum_heldout:
            issues.append(f"strata:{stratum}:reserve_insufficient")
    for pair_id, rows in pairs.items():
        strata = {row.get("construction_stratum") for row in rows}
        sources = {row.get("source_task_id") for row in rows}
        roles = {row.get("metamorphic_role") for row in rows}
        hashes = {row.get("task_sha256") for row in rows}
        if len(rows) != 2 or len(strata) != 1 or len(sources) != 1 or roles != {"base", "variant"} or len(hashes) != 2:
            issues.append(f"pairs:{pair_id}:invalid")
            continue
        pair_counts[str(next(iter(strata)))] += 1
    for stratum in PAIR_STRATA:
        if pair_counts[stratum] < minimum_pairs:
            issues.append(f"pairs:{stratum}:reserve_insufficient")
    core = {
        "schema": PAIR_ASSIGNMENT_RECEIPT_SCHEMA,
        "benchmark_version": benchmark_version if benchmark_version in SUPPORTED_BENCHMARK_VERSIONS else None,
        "status": "PASS" if not issues else "FAIL",
        "task_count": len(raw_tasks),
        "task_ids_sha256": json_sha256(sorted(task_ids)),
        "stratum_counts": dict(sorted(stratum_counts.items())),
        "heldout_counts": dict(sorted(heldout_counts.items())),
        "pair_counts": dict(sorted(pair_counts.items())),
        "pair_count": len(pairs),
        "labels_present": False,
        "sol_outputs_present": False,
        "scored_calls_permitted": not issues,
        "issues": sorted(set(issues)),
        "authority_granted": False,
    }
    return _seal(core, "receipt_sha256")


__all__ = [
    "BENCHMARK_VERSION",
    "PAIR_AWARE_BENCHMARK_VERSION",
    "HELDOUT_RESERVE_BENCHMARK_VERSION",
    "CLEAN_JSON_BENCHMARK_VERSION",
    "INTEGER_BPS_BENCHMARK_VERSION",
    "DIRECT_DEEPSEEK_BENCHMARK_VERSION",
    "CLASSES",
    "GROUND_TRUTH_CLAIM",
    "POLICY",
    "PAIR_ASSIGNMENT_PROGRAM_SCHEMA",
    "STAGE1_LABEL_SCHEMA",
    "STAGE1_PROGRAM_SCHEMA",
    "STAGE2_LABEL_SCHEMA",
    "STAGE2_PROGRAM_SCHEMA",
    "TRANSPORT_PROGRAM_SCHEMA",
    "freeze_stage1_classification",
    "freeze_stage2_ground_truth",
    "freeze_pair_aware_assignment",
    "json_sha256",
    "qualify_review_transport",
    "seal_stage1_label",
    "seal_stage2_label",
]
