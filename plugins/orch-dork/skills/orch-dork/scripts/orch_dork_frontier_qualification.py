#!/usr/bin/env python3
"""Provider-free corpus and installed-runtime qualification for Issue 151.

This module is deliberately downstream of the v2 frontier controller.  It
compiles the checked-in historical fixture vault into the controller's public
twenty-fixture corpus, materialises disposable snapshots, evaluates private
checks, sanitises blind Sol packets, and drives deterministic synthetic
observations through the sole Control Tower seam.  It never owns campaign
authority and contains no provider, network, credential, installation, release,
retry, fallback, repair, or replacement callback.

The checked-in catalogue is a controller-owned vault.  Model-facing projections
contain only a focused task, byte-identical snapshot, public checks, and the
closed Qwen tool policy.  Hidden checks, history labels, partitions, holdout
lineage, expected outcomes, and Sol option mappings never cross that boundary.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
        path = Path(__file__).with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        previous = sys.modules.get(name)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
            raise
        return module


control_tower = _load_sibling("orch_dork_control_tower")
frontier = _load_sibling("orch_dork_frontier_campaign")
run_engine = _load_sibling("orch_dork_run_engine")
run_store = _load_sibling("orch_dork_run_store")
runtime_package = _load_sibling("orch_dork_runtime_package")
topology_lab = _load_sibling("orch_dork_topology_lab")
live_sweep = _load_sibling("orch_dork_live_sweep")
zero_tool = _load_sibling("orch_dork_live_zero_tool")
zero_tool_qualification = _load_sibling(
    "orch_dork_live_zero_tool_qualification"
)
containment = _load_sibling("orch_dork_process_containment")


CATALOG_SCHEMA = "orch-dork/frontier-regression-catalog/v1"
MODEL_TASK_SCHEMA = "orch-dork/frontier-model-task/v1"
SNAPSHOT_RECEIPT_SCHEMA = "orch-dork/frontier-snapshot-receipt/v1"
CHECK_REPORT_SCHEMA = "orch-dork/frontier-fixture-check-report/v1"
SOL_PACKET_SCHEMA = "orch-dork/frontier-sol-packet/v1"
SOL_PACKET_REPORT_SCHEMA = "orch-dork/frontier-sol-packet-report/v1"
TRANSPORT_QUALIFICATION_SCHEMA = (
    "orch-dork/frontier-transport-qualification/v1"
)
INSTALLED_QUALIFICATION_SCHEMA = (
    "orch-dork/frontier-installed-runtime-qualification/v2"
)
OPENCODEX_235_CORRECTION_SCHEMA = (
    "orch-dork/opencodex-2.35-hidden-reasoning-correction/v1"
)
ISSUE154_QUALIFICATION_SHA256 = (
    "b586621dca11cea7e4f53aeec38b443efc284c8441d91f236feb3cdbcb84244d"
)
ISSUE154_RUNTIME_IDENTITY_SHA256 = (
    "d10f36cb6b2da02d97eb499cfb3da6cec2e7679c7218a2cff5131f6becd9e2fd"
)
CAMPAIGN_RECORDING_SCHEMA = "orch-dork/frontier-campaign-recording/v1"
QUALIFICATION_SCHEMA = "orch-dork/frontier-runtime-qualification/v1"
REFUSAL_MATRIX_SCHEMA = "orch-dork/frontier-refusal-matrix/v1"

CATALOG_PATH = (
    Path(__file__).resolve().parent.parent
    / "runtime"
    / "frontier-regression-corpus-v1.json"
)

QWEN_ALLOWED_TOOLS = [
    "repository_read",
    "apply_patch",
    "build_test",
    "status",
]
QWEN_ALLOWED_COMMANDS = [
    ["python3", "-m", "unittest"],
    ["python3", "-m", "compileall"],
    ["git", "diff", "--check"],
    ["git", "status", "--short"],
]
QWEN_DENIED_CAPABILITIES = [
    "network",
    "credentials",
    "install",
    "release",
    "push",
    "task_spawn",
    "git_history",
    "parent_vault",
    "outside_write",
]

ISSUE111_R5_ITEMS = [
    {"id": "evidence-00", "severity": 1, "verified": False, "corroborates": None},
    {"id": "evidence-01", "severity": 9, "verified": True, "corroborates": None},
    {"id": "evidence-02", "severity": 2, "verified": False, "corroborates": "evidence-01"},
    {"id": "evidence-03", "severity": 2, "verified": False, "corroborates": None},
    {"id": "evidence-04", "severity": 9, "verified": True, "corroborates": None},
    {"id": "evidence-05", "severity": 9, "verified": True, "corroborates": None},
    {"id": "evidence-06", "severity": 0, "verified": False, "corroborates": "evidence-05"},
    {"id": "evidence-07", "severity": 0, "verified": True, "corroborates": None},
    {"id": "evidence-08", "severity": 7, "verified": True, "corroborates": None},
    {"id": "evidence-09", "severity": 9, "verified": True, "corroborates": None},
    {"id": "evidence-10", "severity": 4, "verified": False, "corroborates": "evidence-09"},
    {"id": "evidence-11", "severity": 8, "verified": True, "corroborates": None},
    {"id": "evidence-12", "severity": 5, "verified": False, "corroborates": None},
    {"id": "evidence-13", "severity": 9, "verified": True, "corroborates": None},
    {"id": "evidence-14", "severity": 2, "verified": False, "corroborates": "evidence-13"},
    {"id": "evidence-15", "severity": 6, "verified": False, "corroborates": None},
]
ISSUE111_R5_COUPLED_PAIRS = (
    ("evidence-01", "evidence-02"),
    ("evidence-05", "evidence-06"),
    ("evidence-09", "evidence-10"),
    ("evidence-13", "evidence-14"),
)

_CATALOG_FIELDS = frozenset(
    {"schema", "catalog_id", "holdout_rotation", "tool_policy", "fixtures"}
)
_TOOL_POLICY_FIELDS = frozenset(
    {"policy_id", "allowed_tools", "allowed_commands", "denied_capabilities"}
)
_FIXTURE_FIELDS = frozenset(
    {
        "fixture_id",
        "partition",
        "rung",
        "holdout_group_id",
        "lineage_id",
        "historical_ref",
        "task",
        "snapshot_files",
        "public_checks",
        "hidden_checks",
        "artifact_paths",
        "expected_result",
        "privacy_class",
    }
)
_TASK_FIELDS = frozenset({"objective", "focus_paths", "acceptance"})
_CHECK_FIELDS = frozenset({"kind", "path", "needle"})
_PARTITIONS = ("frozen", "recent_failures", "adversarial", "holdout")
_HOLDOUTS = ("holdout-a", "holdout-b", "holdout-c")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SECRET = re.compile(
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|"
    r"credential|private[_-]?key|\bBearer\s+\S+|\bsk-[A-Za-z0-9_-]{6,}|"
    r"\bgh[pousr]_[A-Za-z0-9_-]{6,}|-----BEGIN [^-]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
_ABSOLUTE_PATH = re.compile(
    r"(?:^|[\s'\"=(])(?:/(?!/)[A-Za-z0-9._-]+(?:/[^\s'\"]+)?|"
    r"[A-Za-z]:\\[^\s'\"]+)",
    re.MULTILINE,
)
_OPTION_MAP = re.compile(
    r"(?:\bchampion\b|\bchallenger\b|\ba_role\b|option[_ -]?map)",
    re.IGNORECASE,
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _issue(issues: list[str], reason: str) -> None:
    if reason not in issues:
        issues.append(reason)


def _relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 240:
        return False
    if "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return False
    if path.parts[0].startswith(".") or ".git" in path.parts:
        return False
    return True


def _catalog_core(value: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(value))
    core.pop("catalog_sha256", None)
    return core


def _validate_check(
    value: Any,
    snapshot_files: Mapping[str, Any],
    issues: list[str],
) -> None:
    if not isinstance(value, Mapping) or set(value) != _CHECK_FIELDS:
        _issue(issues, "fixture:check_contract_invalid")
        return
    if value.get("kind") not in {"contains", "not_contains"}:
        _issue(issues, "fixture:check_kind_invalid")
    path = value.get("path")
    if not _relative_path(path) or path not in snapshot_files:
        _issue(issues, "fixture:check_path_invalid")
    needle = value.get("needle")
    if not isinstance(needle, str) or not needle or len(needle) > 512:
        _issue(issues, "fixture:check_needle_invalid")


def _validate_fixture(value: Any, issues: list[str]) -> None:
    if not isinstance(value, Mapping) or set(value) != _FIXTURE_FIELDS:
        _issue(issues, "fixture:contract_invalid")
        return
    if not _identifier(value.get("fixture_id")):
        _issue(issues, "fixture:id_invalid")
    partition = value.get("partition")
    if partition not in _PARTITIONS:
        _issue(issues, "fixture:partition_invalid")
    if type(value.get("rung")) is not int or not 1 <= value["rung"] <= 5:
        _issue(issues, "fixture:rung_invalid")
    holdout = value.get("holdout_group_id")
    if (partition == "holdout" and holdout not in _HOLDOUTS) or (
        partition != "holdout" and holdout is not None
    ):
        _issue(issues, "fixture:holdout_group_invalid")
    for field in ("lineage_id", "historical_ref"):
        text = value.get(field)
        if not isinstance(text, str) or not text or len(text) > 256:
            _issue(issues, "fixture:" + field + "_invalid")
    if value.get("privacy_class") != "hosted_restricted":
        _issue(issues, "fixture:privacy_invalid")
    if value.get("expected_result") not in {"PASS", "REFUSE"}:
        _issue(issues, "fixture:expected_result_invalid")

    task = value.get("task")
    if not isinstance(task, Mapping) or set(task) != _TASK_FIELDS:
        _issue(issues, "fixture:task_contract_invalid")
    else:
        if (
            not isinstance(task.get("objective"), str)
            or not task["objective"]
            or len(task["objective"]) > 1000
        ):
            _issue(issues, "fixture:objective_invalid")
        for field in ("focus_paths", "acceptance"):
            rows = task.get(field)
            if (
                not isinstance(rows, list)
                or not rows
                or len(rows) > 16
                or any(not isinstance(item, str) or not item for item in rows)
                or len(rows) != len(set(rows))
            ):
                _issue(issues, "fixture:task_" + field + "_invalid")
        if isinstance(task.get("focus_paths"), list) and any(
            not _relative_path(item) for item in task["focus_paths"]
        ):
            _issue(issues, "fixture:task_focus_paths_invalid")

    snapshot_files = value.get("snapshot_files")
    if (
        not isinstance(snapshot_files, Mapping)
        or not snapshot_files
        or len(snapshot_files) > 12
    ):
        _issue(issues, "fixture:snapshot_invalid")
        snapshot_files = {}
    else:
        for path, content in snapshot_files.items():
            if not _relative_path(path):
                _issue(issues, "fixture:snapshot_path_invalid")
            if not isinstance(content, str) or len(content.encode("utf-8")) > 32_768:
                _issue(issues, "fixture:snapshot_content_invalid")

    for field in ("public_checks", "hidden_checks"):
        checks = value.get(field)
        if not isinstance(checks, list) or not checks or len(checks) > 16:
            _issue(issues, "fixture:" + field + "_invalid")
        else:
            for check in checks:
                _validate_check(check, snapshot_files, issues)
    artifacts = value.get("artifact_paths")
    if (
        not isinstance(artifacts, list)
        or not artifacts
        or len(artifacts) > 8
        or len(artifacts) != len(set(artifacts))
        or any(not _relative_path(path) or path not in snapshot_files for path in artifacts)
    ):
        _issue(issues, "fixture:artifact_paths_invalid")


def validate_catalog(value: Any) -> dict[str, Any]:
    """Validate the complete controller-owned fixture vault."""

    issues: list[str] = []
    if not isinstance(value, Mapping):
        issues.append("catalog:contract_invalid")
        core: dict[str, Any] = {}
    else:
        fields = set(value)
        permitted = set(_CATALOG_FIELDS) | {"catalog_sha256"}
        if fields not in (set(_CATALOG_FIELDS), permitted):
            issues.append("catalog:contract_invalid")
        core = _catalog_core(value)
    if set(core) != _CATALOG_FIELDS:
        _issue(issues, "catalog:contract_invalid")
    if core.get("schema") != CATALOG_SCHEMA:
        _issue(issues, "catalog:schema_invalid")
    if not _identifier(core.get("catalog_id")):
        _issue(issues, "catalog:id_invalid")
    if core.get("holdout_rotation") != list(_HOLDOUTS):
        _issue(issues, "catalog:holdout_rotation_invalid")

    policy = core.get("tool_policy")
    if not isinstance(policy, Mapping) or set(policy) != _TOOL_POLICY_FIELDS:
        _issue(issues, "catalog:tool_policy_invalid")
    elif (
        policy.get("policy_id") != "qwen-bounded-snapshot/v1"
        or policy.get("allowed_tools") != QWEN_ALLOWED_TOOLS
        or policy.get("allowed_commands") != QWEN_ALLOWED_COMMANDS
        or policy.get("denied_capabilities") != QWEN_DENIED_CAPABILITIES
    ):
        _issue(issues, "catalog:tool_policy_invalid")

    fixtures = core.get("fixtures")
    if not isinstance(fixtures, list) or len(fixtures) != 30:
        _issue(issues, "catalog:fixture_count_invalid")
        fixtures = []
    for fixture in fixtures:
        _validate_fixture(fixture, issues)
    ids = [item.get("fixture_id") for item in fixtures if isinstance(item, Mapping)]
    if len(ids) != len(set(ids)):
        _issue(issues, "catalog:fixture_duplicate")
    lineages = [item.get("lineage_id") for item in fixtures if isinstance(item, Mapping)]
    if len(lineages) != len(set(lineages)):
        _issue(issues, "catalog:lineage_duplicate")

    partition_counts = {
        partition: sum(
            isinstance(item, Mapping) and item.get("partition") == partition
            for item in fixtures
        )
        for partition in _PARTITIONS
    }
    if partition_counts != {
        "frozen": 5,
        "recent_failures": 5,
        "adversarial": 5,
        "holdout": 15,
    }:
        _issue(issues, "catalog:partition_shape_invalid")
    holdout_counts = {
        group: sum(
            isinstance(item, Mapping)
            and item.get("partition") == "holdout"
            and item.get("holdout_group_id") == group
            for item in fixtures
        )
        for group in _HOLDOUTS
    }
    if holdout_counts != {group: 5 for group in _HOLDOUTS}:
        _issue(issues, "catalog:holdout_shape_invalid")
    for partition in _PARTITIONS[:-1]:
        rungs = sorted(
            item.get("rung")
            for item in fixtures
            if isinstance(item, Mapping) and item.get("partition") == partition
        )
        if rungs != [1, 2, 3, 4, 5]:
            _issue(issues, "catalog:rung_shape_invalid")
    for group in _HOLDOUTS:
        rungs = sorted(
            item.get("rung")
            for item in fixtures
            if isinstance(item, Mapping) and item.get("holdout_group_id") == group
        )
        if rungs != [1, 2, 3, 4, 5]:
            _issue(issues, "catalog:holdout_rung_shape_invalid")

    training_lineages = {
        item.get("lineage_id")
        for item in fixtures
        if isinstance(item, Mapping) and item.get("partition") != "holdout"
    }
    holdout_lineages = {
        item.get("lineage_id")
        for item in fixtures
        if isinstance(item, Mapping) and item.get("partition") == "holdout"
    }
    if training_lineages & holdout_lineages:
        _issue(issues, "catalog:holdout_lineage_overlap")

    exact = next(
        (
            item
            for item in fixtures
            if isinstance(item, Mapping)
            and item.get("fixture_id") == "adversarial-issue111-r5-cut"
        ),
        None,
    )
    try:
        evidence = json.loads(exact["snapshot_files"]["evidence.json"])
    except (KeyError, TypeError, json.JSONDecodeError):
        evidence = None
    if (
        not isinstance(exact, Mapping)
        or evidence
        != {
            "coupled_pairs": [list(pair) for pair in ISSUE111_R5_COUPLED_PAIRS],
            "items": ISSUE111_R5_ITEMS,
        }
        or exact.get("expected_result") != "REFUSE"
    ):
        _issue(issues, "catalog:issue111_r5_fixture_invalid")

    derived = None
    try:
        derived = json_sha256(core)
    except (TypeError, ValueError, OverflowError):
        _issue(issues, "catalog:canonical_invalid")
    if isinstance(value, Mapping) and "catalog_sha256" in value:
        if value.get("catalog_sha256") != derived:
            _issue(issues, "catalog:seal_invalid")
    return {
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "fixture_count": len(fixtures),
        "partition_counts": partition_counts,
        "holdout_counts": holdout_counts,
        "catalog_sha256": derived,
    }


def load_catalog(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    source = CATALOG_PATH if path is None else Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("catalog:unreadable") from exc
    if not isinstance(value, Mapping):
        raise ValueError("catalog:contract_invalid")
    sealed = deepcopy(dict(value))
    sealed["catalog_sha256"] = json_sha256(value)
    report = validate_catalog(sealed)
    if report["status"] != "PASS":
        raise ValueError(";".join(report["issues"]))
    return sealed


def catalog_fixture(catalog: Mapping[str, Any], fixture_id: str) -> dict[str, Any]:
    report = validate_catalog(catalog)
    if report["status"] != "PASS":
        raise ValueError("catalog:invalid")
    for fixture in catalog["fixtures"]:
        if fixture["fixture_id"] == fixture_id:
            return deepcopy(fixture)
    raise ValueError("fixture:not_found")


def _snapshot_rows(fixture: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "relative_path": path,
            "bytes": len(content.encode("utf-8")),
            "sha256": _sha_bytes(content.encode("utf-8")),
        }
        for path, content in sorted(fixture["snapshot_files"].items())
    ]


def _snapshot_sha256(fixture: Mapping[str, Any]) -> str:
    return json_sha256(
        {
            "schema": "orch-dork/frontier-snapshot/v1",
            "files": _snapshot_rows(fixture),
        }
    )


def model_task(catalog: Mapping[str, Any], fixture_id: str) -> dict[str, Any]:
    fixture = catalog_fixture(catalog, fixture_id)
    core = {
        "schema": MODEL_TASK_SCHEMA,
        "objective": fixture["task"]["objective"],
        "focus_paths": deepcopy(fixture["task"]["focus_paths"]),
        "acceptance": deepcopy(fixture["task"]["acceptance"]),
        "snapshot_sha256": _snapshot_sha256(fixture),
        "public_checks_sha256": json_sha256(fixture["public_checks"]),
        "tool_policy": {
            "allowed_tools": deepcopy(QWEN_ALLOWED_TOOLS),
            "allowed_commands": deepcopy(QWEN_ALLOWED_COMMANDS),
            "denied_capabilities": deepcopy(QWEN_DENIED_CAPABILITIES),
        },
    }
    return {**core, "task_sha256": json_sha256(core)}


def _compiled_fixture(catalog: Mapping[str, Any], fixture: Mapping[str, Any]) -> dict[str, Any]:
    task = model_task(catalog, fixture["fixture_id"])
    identity = {
        "schema": "orch-dork/frontier-regression-manifest/v1",
        "source_manifest_sha256": json_sha256(fixture),
        "task_sha256": task["task_sha256"],
        "snapshot_sha256": _snapshot_sha256(fixture),
        "public_checks_sha256": json_sha256(fixture["public_checks"]),
        "hidden_checks_sha256": json_sha256(fixture["hidden_checks"]),
        "tool_policy_sha256": json_sha256(catalog["tool_policy"]),
    }
    fixture_sha256 = json_sha256(identity)
    return {
        "schema": frontier.FIXTURE_SCHEMA,
        "fixture_id": fixture["fixture_id"],
        "fixture_sha256": fixture_sha256,
        "partition": fixture["partition"],
        "lineage_sha256": json_sha256({"lineage_id": fixture["lineage_id"]}),
        "rung": fixture["rung"],
        "task_input_sha256": task["task_sha256"],
        "champion_task_brief_sha256": task["task_sha256"],
        "challenger_task_brief_sha256": task["task_sha256"],
        "snapshot_sha256": identity["snapshot_sha256"],
        "public_checks_sha256": identity["public_checks_sha256"],
        "hidden_checks_sha256": identity["hidden_checks_sha256"],
        "privacy_class": "hosted_restricted",
    }


def compile_frontier_corpus(
    catalog: Mapping[str, Any], holdout_group_id: str
) -> dict[str, Any]:
    report = validate_catalog(catalog)
    if report["status"] != "PASS":
        raise ValueError("catalog:invalid")
    if holdout_group_id not in catalog["holdout_rotation"]:
        raise ValueError("catalog:holdout_group_invalid")
    selected = [
        fixture
        for fixture in catalog["fixtures"]
        if fixture["partition"] != "holdout"
        or fixture["holdout_group_id"] == holdout_group_id
    ]
    compiled = [_compiled_fixture(catalog, fixture) for fixture in selected]
    compiled.sort(
        key=lambda row: (row["rung"], _PARTITIONS.index(row["partition"]))
    )
    return {
        "schema": frontier.CORPUS_DRAFT_SCHEMA,
        "corpus_id": "frontier-regression-corpus-v1",
        "holdout_group_id": holdout_group_id,
        "fixtures": compiled,
    }


def next_holdout_group(catalog: Mapping[str, Any], current: str) -> str:
    report = validate_catalog(catalog)
    if report["status"] != "PASS" or current not in catalog["holdout_rotation"]:
        raise ValueError("catalog:holdout_group_invalid")
    rotation = catalog["holdout_rotation"]
    return rotation[(rotation.index(current) + 1) % len(rotation)]


def build_qualification_archive() -> dict[str, Any]:
    """Reproduce the frozen bounded structural frontier used by qualification."""

    axes = {
        "profile_id": ["direct/v1", "parallel_join/v1", "finite_dag/v1"],
        "lane_count": [1, 2],
        "dependency_cut": ["none", "independent", "dependency_layers"],
        "context_policy": ["none", "artifact_refs"],
        "join_class": ["none", "semantic"],
        "depth": [1, 2],
        "executor_roles": [
            "single_executor",
            "parallel_executors_integrator",
            "planner_executors_integrator",
        ],
        "early_exit": ["none", "deterministic_pass"],
        "model_profile_id": ["a-sol", "z-qwen-sol"],
        "budget_split_id": ["a-direct", "z-balanced"],
    }
    product = 1
    for values in axes.values():
        product *= len(values)
    base_metrics = {
        field: 5_000 if direction == "maximize" else 1_000_000
        for field, direction in topology_lab.OBJECTIVE_DIRECTIONS.items()
    }
    axis_deltas = {
        axis: [
            {
                "value": value,
                "metrics": {
                    field: rank if direction == "maximize" else -100 * rank
                    for field, direction in topology_lab.OBJECTIVE_DIRECTIONS.items()
                },
            }
            for rank, value in enumerate(values)
        ]
        for axis, values in axes.items()
    }
    baseline_metrics = {
        field: 4_000 if direction == "maximize" else 2_000_000
        for field, direction in topology_lab.OBJECTIVE_DIRECTIONS.items()
    }
    draft = {
        "schema": topology_lab.REGISTRY_DRAFT_SCHEMA,
        "registry_id": "issue151-frontier-qualification",
        "axes": axes,
        "model_profiles": [
            {
                "model_profile_id": "a-sol",
                "executor": "sol",
                "verifier": "sol",
                "integrator": "sol",
                "runtime_identity_sha256": json_sha256({"runtime": "sol"}),
            },
            {
                "model_profile_id": "z-qwen-sol",
                "executor": "qwen",
                "verifier": "sol",
                "integrator": "sol",
                "runtime_identity_sha256": json_sha256(
                    {"runtime": "qwen-sol"}
                ),
            },
        ],
        "budget_splits": [
            {
                "budget_split_id": "a-direct",
                "executor_bps": 6_000,
                "verification_bps": 3_000,
                "integration_bps": 0,
                "reserve_bps": 1_000,
            },
            {
                "budget_split_id": "z-balanced",
                "executor_bps": 4_000,
                "verification_bps": 2_000,
                "integration_bps": 2_000,
                "reserve_bps": 2_000,
            },
        ],
        "topology_closure_basis": {
            "schema": topology_lab.CLOSURE_BASIS_DRAFT_SCHEMA,
            "status": "PASS",
            "source_schema": "orch-dork/topology-closure/v1",
            "source_report_sha256": json_sha256(
                {"source": "issue151-topology-closure"}
            ),
            "profile_ids": list(axes["profile_id"]),
            "dependency_cuts": list(axes["dependency_cut"]),
            "context_policies": list(axes["context_policy"]),
            "join_classes": list(axes["join_class"]),
            "max_lane_count": max(axes["lane_count"]),
            "max_depth": max(axes["depth"]),
        },
        "scoring_policy": {
            "schema": topology_lab.SCORING_POLICY_SCHEMA,
            "base_metrics": base_metrics,
            "axis_deltas": axis_deltas,
            "evidence_sha256": json_sha256(
                {"source": "issue151-structural-scoring"}
            ),
        },
        "objective_directions": dict(topology_lab.OBJECTIVE_DIRECTIONS),
        "budget_envelope": {
            "total_tokens": 100_000,
            "total_cost_micros": 1_000_000,
        },
        "direct_baseline": {
            "schema": topology_lab.DIRECT_BASELINE_DRAFT_SCHEMA,
            "profile_id": "direct/v1",
            "budget_tokens": 100_000,
            "budget_cost_micros": 1_000_000,
            "metrics": baseline_metrics,
            "evidence_sha256": json_sha256(
                {"source": "issue151-direct-baseline"}
            ),
        },
        "limits": {
            "max_candidates": product,
            "max_archive_entries": 64,
            "max_processes": 2,
            "chunk_size": 256,
        },
        "resident_qwen": {
            "status": "loaded",
            "unload_permitted": False,
            "observation_sha256": json_sha256(
                {"source": "issue151-resident-qwen"}
            ),
        },
        "search_adapter": None,
    }
    sealed = topology_lab.evaluate(
        {
            "schema": topology_lab.PROGRAM_SCHEMA,
            "action": "seal_registry",
            "request": {"registry": draft},
        }
    )
    if sealed.get("status") != "PASS":
        raise ValueError("archive:registry_invalid")
    enumerated = topology_lab.evaluate(
        {
            "schema": topology_lab.PROGRAM_SCHEMA,
            "action": "enumerate",
            "request": {"registry": sealed["registry"], "process_count": 1},
        }
    )
    if enumerated.get("status") != "PASS":
        raise ValueError("archive:enumeration_failed")
    archive = enumerated["archive"]
    if topology_lab.validate_archive(archive).get("status") != "PASS":
        raise ValueError("archive:validation_failed")
    return archive


def materialize_snapshot(
    catalog: Mapping[str, Any],
    fixture_id: str,
    destination: str | os.PathLike[str],
) -> dict[str, Any]:
    fixture = catalog_fixture(catalog, fixture_id)
    target = Path(destination)
    if target.is_symlink():
        raise ValueError("snapshot:destination_symlink")
    if target.exists():
        raise ValueError("snapshot:destination_exists")
    if not target.is_absolute():
        raise ValueError("snapshot:destination_not_absolute")
    temporary_root = Path(tempfile.gettempdir()).resolve()
    try:
        parent = target.parent.resolve(strict=True)
    except OSError as exc:
        raise ValueError("snapshot:parent_invalid") from exc
    if parent != temporary_root and temporary_root not in parent.parents:
        raise ValueError("snapshot:destination_not_disposable")
    target.mkdir(mode=0o700)
    for relative, content in sorted(fixture["snapshot_files"].items()):
        path = target.joinpath(*PurePosixPath(relative).parts)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved_parent = path.parent.resolve(strict=True)
        if target.resolve(strict=True) != resolved_parent and target.resolve(strict=True) not in resolved_parent.parents:
            raise ValueError("snapshot:path_escape")
        path.write_text(content, encoding="utf-8", newline="")
    observed = []
    for path in sorted(target.rglob("*")):
        if path.is_symlink():
            raise ValueError("snapshot:symlink_created")
        if path.is_file():
            relative = path.relative_to(target).as_posix()
            data = path.read_bytes()
            observed.append(
                {
                    "relative_path": relative,
                    "bytes": len(data),
                    "sha256": _sha_bytes(data),
                }
            )
    if observed != _snapshot_rows(fixture):
        raise ValueError("snapshot:digest_mismatch")
    core = {
        "schema": SNAPSHOT_RECEIPT_SCHEMA,
        "fixture_sha256": _compiled_fixture(catalog, fixture)["fixture_sha256"],
        "snapshot_sha256": _snapshot_sha256(fixture),
        "file_count": len(observed),
        "files_sha256": json_sha256(observed),
        "allowed_tools": deepcopy(QWEN_ALLOWED_TOOLS),
        "allowed_commands_sha256": json_sha256(QWEN_ALLOWED_COMMANDS),
        "writable_roots": ["."],
        "network_granted": False,
        "credentials_mounted": False,
        "git_history_mounted": False,
        "parent_vault_mounted": False,
        "outside_write_granted": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "receipt_sha256": json_sha256(core)}


def _check_passes(check: Mapping[str, Any], files: Mapping[str, str]) -> bool:
    content = files.get(check["path"])
    if not isinstance(content, str):
        return False
    present = check["needle"] in content
    return present if check["kind"] == "contains" else not present


def evaluate_fixture_checks(
    catalog: Mapping[str, Any], fixture_id: str, files: Mapping[str, Any]
) -> dict[str, Any]:
    fixture = catalog_fixture(catalog, fixture_id)
    issues: list[str] = []
    if not isinstance(files, Mapping) or any(
        not _relative_path(path) or not isinstance(content, str)
        for path, content in files.items()
    ):
        issues.append("artifact:contract_invalid")
        normalized: dict[str, str] = {}
    else:
        normalized = deepcopy(dict(files))
    public = [
        _check_passes(check, normalized) for check in fixture["public_checks"]
    ]
    private = [
        _check_passes(check, normalized) for check in fixture["hidden_checks"]
    ]
    for index, passed in enumerate(public):
        if not passed:
            _issue(issues, "public_check:failed:" + str(index))
    for index, passed in enumerate(private):
        if not passed:
            _issue(issues, "controller_check:failed:" + str(index))
    core = {
        "schema": CHECK_REPORT_SCHEMA,
        "fixture_sha256": _compiled_fixture(catalog, fixture)["fixture_sha256"],
        "status": "PASS" if not issues else "FAIL",
        "reason_codes": sorted(issues),
        "public_check_count": len(public),
        "public_pass_count": sum(public),
        "controller_check_count": len(private),
        "controller_pass_count": sum(private),
        "public_checks_sha256": json_sha256(fixture["public_checks"]),
        "hidden_checks_sha256": json_sha256(fixture["hidden_checks"]),
        "artifact_set_sha256": json_sha256(
            [
                {"relative_path": path, "sha256": _sha_bytes(content.encode("utf-8"))}
                for path, content in sorted(normalized.items())
            ]
        ),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": json_sha256(core)}


def _packet_failure(issues: Sequence[str]) -> dict[str, Any]:
    return {
        "schema": SOL_PACKET_REPORT_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "packet": None,
        "blind_packet_sha256": None,
        "truncated": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def sanitize_sol_packet(
    catalog: Mapping[str, Any], fixture_id: str, options: Any
) -> dict[str, Any]:
    """Build one non-truncating, identity-blind Sol review packet."""

    fixture = catalog_fixture(catalog, fixture_id)
    issues: list[str] = []
    if not isinstance(options, Mapping) or set(options) != {"A", "B"}:
        return _packet_failure(["packet:option_contract_invalid"])
    projected: dict[str, list[dict[str, Any]]] = {"A": [], "B": []}
    hidden_contracts = [
        _canonical_bytes(fixture["hidden_checks"]).decode("utf-8"),
        *(
            _canonical_bytes(check).decode("utf-8")
            for check in fixture["hidden_checks"]
        ),
    ]
    for option in ("A", "B"):
        artifacts = options.get(option)
        if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 8:
            _issue(issues, "packet:artifact_contract_invalid")
            continue
        seen: set[str] = set()
        for artifact in artifacts:
            if not isinstance(artifact, Mapping) or set(artifact) != {
                "relative_path",
                "content",
                "is_symlink",
            }:
                _issue(issues, "packet:artifact_contract_invalid")
                continue
            path = artifact.get("relative_path")
            content = artifact.get("content")
            if not _relative_path(path):
                _issue(issues, "packet:traversal_leak")
                continue
            if path not in fixture["artifact_paths"]:
                _issue(issues, "packet:artifact_disallowed")
            if path in seen:
                _issue(issues, "packet:artifact_duplicate")
            seen.add(path)
            if artifact.get("is_symlink") is not False:
                _issue(issues, "packet:symlink_leak")
            if not isinstance(content, str):
                _issue(issues, "packet:artifact_content_invalid")
                continue
            if _SECRET.search(content):
                _issue(issues, "packet:secret_leak")
            if _ABSOLUTE_PATH.search(content):
                _issue(issues, "packet:absolute_path_leak")
            if "../" in content or "..\\" in content:
                _issue(issues, "packet:traversal_leak")
            if any(
                contract in content for contract in hidden_contracts
            ) or '"hidden_checks"' in content:
                _issue(issues, "packet:hidden_check_leak")
            if _OPTION_MAP.search(content):
                _issue(issues, "packet:option_map_leak")
            projected[option].append(
                {
                    "relative_path": path,
                    "content": content,
                    "content_sha256": _sha_bytes(content.encode("utf-8")),
                }
            )
    if issues:
        return _packet_failure(issues)
    core = {
        "schema": SOL_PACKET_SCHEMA,
        "task": model_task(catalog, fixture_id),
        "options": projected,
        "rubric_dimensions": list(frontier.REVIEW_DIMENSIONS),
        "score_range": [0, 4],
        "input_token_upper_bound": 0,
        "output_token_limit": 2_000,
        "total_token_limit": 12_000,
        "generation_limit": 1,
        "tools": [],
    }
    for _ in range(4):
        core["input_token_upper_bound"] = len(_canonical_bytes(core))
    if core["input_token_upper_bound"] > 8_000:
        return _packet_failure(["packet:oversize"])
    packet = deepcopy(core)
    return {
        "schema": SOL_PACKET_REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "packet": packet,
        "blind_packet_sha256": json_sha256(packet),
        "truncated": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


_LIVE_RUNTIME_FIELDS = frozenset(
    {
        "schema",
        "qwen_identity_sha256",
        "sol_identity_sha256",
        "qwen_provider",
        "sol_provider",
        "sol_model_id",
        "sol_runtime_id",
        "sol_retention",
        "sol_region",
        "sol_context_tokens",
        "sol_input_tokens",
        "sol_output_tokens",
        "sol_generations",
        "sol_tools",
        "provider_free",
        "privacy_class",
    }
)
_LIVE_RUNTIME_EXACT = {
    "qwen_provider": "opencodex-qwen-local",
    "sol_provider": "openai-responses",
    "sol_model_id": "gpt-5.6-sol",
    "sol_runtime_id": "opencodex-responses-v1",
    "sol_retention": "hosted-restricted",
    "sol_region": "account-configured",
    "sol_context_tokens": 12_000,
    "sol_input_tokens": 8_000,
    "sol_output_tokens": 2_000,
    "sol_generations": 1,
    "sol_tools": [],
    "provider_free": True,
    "privacy_class": "hosted_restricted",
}


def live_runtime_contract(
    *, qwen_identity_sha256: str, sol_identity_sha256: str
) -> dict[str, Any]:
    return {
        "schema": frontier.RUNTIME_CONTRACT_SCHEMA,
        "qwen_identity_sha256": qwen_identity_sha256,
        "sol_identity_sha256": sol_identity_sha256,
        **deepcopy(_LIVE_RUNTIME_EXACT),
    }


def validate_live_runtime_contract(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    if not isinstance(value, Mapping) or set(value) != _LIVE_RUNTIME_FIELDS:
        issues.append("runtime:contract_invalid")
        record: Mapping[str, Any] = {}
    else:
        record = value
    if record.get("schema") != frontier.RUNTIME_CONTRACT_SCHEMA:
        _issue(issues, "runtime:schema_invalid")
    for field in ("qwen_identity_sha256", "sol_identity_sha256"):
        if not _sha(record.get(field)):
            _issue(issues, "runtime:" + field + "_invalid")
    for field, expected in _LIVE_RUNTIME_EXACT.items():
        if record.get(field) != expected:
            _issue(issues, "runtime:" + field + "_invalid")
    return {"status": "PASS" if not issues else "FAIL", "issues": sorted(issues)}


def _source_closure(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    rows: list[dict[str, Any]] = []
    for relative in runtime_package.RUNTIME_ALLOWLIST:
        path = root.joinpath(*PurePosixPath(relative).parts)
        if not path.exists():
            if relative in runtime_package.RUNTIME_OPTIONAL_PATHS:
                continue
            raise ValueError("source_closure:missing_required_file")
        if path.is_symlink() or not path.is_file():
            raise ValueError("source_closure:file_invalid")
        resolved = path.resolve(strict=True)
        if root != resolved and root not in resolved.parents:
            raise ValueError("source_closure:path_escape")
        data = path.read_bytes()
        rows.append(
            {"name": relative, "bytes": len(data), "sha256": _sha_bytes(data)}
        )
    core = {"schema": "orch-dork/runtime-source-closure/v1", "files": rows}
    return {
        "file_count": len(rows),
        "source_closure_sha256": json_sha256(core),
    }


def _qwen_record(case: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema": "orch-dork/qwen-synthetic-record/v1",
        "case": case,
        "model": "qwen-local/qwen-smart",
        "runtime_id": "opencodex-qwen-local/v1",
        "identity_sha256": json_sha256({"model": "qwen-local/qwen-smart", "runtime": "opencodex-qwen-local/v1"}),
        "content": {"status": "candidate_ready", "artifact_sha256": "a" * 64},
        "reasoning": None,
        "tool_calls": [
            {
                "name": "repository_read",
                "arguments": {"relative_path": "src/target.py"},
            },
            {
                "name": "apply_patch",
                "arguments": {
                    "relative_path": "src/target.py",
                    "patch_sha256": "e" * 64,
                },
            },
            {
                "name": "build_test",
                "arguments": {"argv": ["python3", "-m", "unittest"]},
            },
            {
                "name": "status",
                "arguments": {"argv": ["git", "status", "--short"]},
            },
        ],
        "usage": {
            "input_tokens": 1_000,
            "output_tokens": 500,
            "total_tokens": 1_500,
            "generations": 1,
        },
    }
    if case == "reasoning_rich":
        record["reasoning"] = [{"type": "summary", "sha256": "b" * 64}]
    elif case == "malformed":
        record.pop("content")
    elif case == "over_budget":
        record["usage"]["total_tokens"] = 27_001
    elif case == "identity_drift":
        record["model"] = "qwen-local/qwen-fast"
    return record


def _observe_qwen_record(record: Any) -> str:
    fields = {
        "schema",
        "case",
        "model",
        "runtime_id",
        "identity_sha256",
        "content",
        "reasoning",
        "tool_calls",
        "usage",
    }
    if not isinstance(record, Mapping) or set(record) != fields:
        return "MALFORMED"
    expected_identity = json_sha256(
        {"model": "qwen-local/qwen-smart", "runtime": "opencodex-qwen-local/v1"}
    )
    if (
        record.get("model") != "qwen-local/qwen-smart"
        or record.get("runtime_id") != "opencodex-qwen-local/v1"
        or record.get("identity_sha256") != expected_identity
    ):
        return "IDENTITY_DRIFT"
    if not isinstance(record.get("content"), Mapping):
        return "MALFORMED"
    reasoning = record.get("reasoning")
    if reasoning is not None and (
        not isinstance(reasoning, list)
        or any(
            not isinstance(item, Mapping)
            or set(item) != {"type", "sha256"}
            or item.get("type") != "summary"
            or not _sha(item.get("sha256"))
            for item in reasoning
        )
    ):
        return "MALFORMED"
    tools = record.get("tool_calls")
    if not isinstance(tools, list) or len(tools) > 24:
        return "TOOL_POLICY_FAILURE"
    for item in tools:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"name", "arguments"}
            or item.get("name") not in QWEN_ALLOWED_TOOLS
            or not isinstance(item.get("arguments"), Mapping)
        ):
            return "TOOL_POLICY_FAILURE"
        name = item["name"]
        arguments = item["arguments"]
        if name == "repository_read":
            if set(arguments) != {"relative_path"} or not _relative_path(
                arguments.get("relative_path")
            ):
                return "TOOL_POLICY_FAILURE"
        elif name == "apply_patch":
            if (
                set(arguments) != {"relative_path", "patch_sha256"}
                or not _relative_path(arguments.get("relative_path"))
                or not _sha(arguments.get("patch_sha256"))
            ):
                return "TOOL_POLICY_FAILURE"
        elif name in {"build_test", "status"}:
            if (
                set(arguments) != {"argv"}
                or arguments.get("argv") not in QWEN_ALLOWED_COMMANDS
                or (
                    name == "build_test"
                    and arguments.get("argv")
                    not in (
                        ["python3", "-m", "unittest"],
                        ["python3", "-m", "compileall"],
                    )
                )
                or (
                    name == "status"
                    and arguments.get("argv")
                    not in (
                        ["git", "diff", "--check"],
                        ["git", "status", "--short"],
                    )
                )
            ):
                return "TOOL_POLICY_FAILURE"
    usage = record.get("usage")
    if not isinstance(usage, Mapping) or set(usage) != {
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "generations",
    }:
        return "MALFORMED"
    if any(type(usage[field]) is not int or usage[field] < 0 for field in usage):
        return "MALFORMED"
    if (
        usage["total_tokens"] > 27_000
        or usage["output_tokens"] > 4_096
        or usage["generations"] > 8
        or usage["total_tokens"] != usage["input_tokens"] + usage["output_tokens"]
    ):
        return "OVER_BUDGET"
    return "PASS"


def _sol_record(case: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema": "orch-dork/sol-synthetic-record/v1",
        "case": case,
        "model": "gpt-5.6-sol",
        "runtime_id": "opencodex-responses-v1",
        "identity_sha256": json_sha256({"model": "gpt-5.6-sol", "runtime": "opencodex-responses-v1"}),
        "content": {
            "option_a_scores": {dimension: 3 for dimension in frontier.REVIEW_DIMENSIONS},
            "option_b_scores": {dimension: 3 for dimension in frontier.REVIEW_DIMENSIONS},
            "winner": "TIE",
            "evidence_refs": ["c" * 64],
        },
        "reasoning": None,
        "tool_calls": [],
        "usage": {
            "input_tokens": 1_000,
            "output_tokens": 500,
            "total_tokens": 1_500,
            "generations": 1,
        },
    }
    if case == "reasoning_rich":
        record["reasoning"] = [{"type": "encrypted", "sha256": "d" * 64}]
    elif case == "malformed":
        record["content"].pop("winner")
    elif case == "over_budget":
        record["usage"]["output_tokens"] = 2_001
        record["usage"]["total_tokens"] = 3_001
    elif case == "identity_drift":
        record["runtime_id"] = "unknown"
    return record


def _observe_sol_record(record: Any) -> str:
    fields = {
        "schema",
        "case",
        "model",
        "runtime_id",
        "identity_sha256",
        "content",
        "reasoning",
        "tool_calls",
        "usage",
    }
    if not isinstance(record, Mapping) or set(record) != fields:
        return "MALFORMED"
    expected_identity = json_sha256(
        {"model": "gpt-5.6-sol", "runtime": "opencodex-responses-v1"}
    )
    if (
        record.get("model") != "gpt-5.6-sol"
        or record.get("runtime_id") != "opencodex-responses-v1"
        or record.get("identity_sha256") != expected_identity
    ):
        return "IDENTITY_DRIFT"
    if record.get("tool_calls") != []:
        return "TOOL_POLICY_FAILURE"
    content = record.get("content")
    if not isinstance(content, Mapping) or set(content) != {
        "option_a_scores",
        "option_b_scores",
        "winner",
        "evidence_refs",
    }:
        return "MALFORMED"
    for field in ("option_a_scores", "option_b_scores"):
        scores = content.get(field)
        if (
            not isinstance(scores, Mapping)
            or set(scores) != set(frontier.REVIEW_DIMENSIONS)
            or any(type(value) is not int or not 0 <= value <= 4 for value in scores.values())
        ):
            return "MALFORMED"
    if content.get("winner") != "TIE" or not isinstance(content.get("evidence_refs"), list):
        return "MALFORMED"
    reasoning = record.get("reasoning")
    if reasoning is not None and (
        not isinstance(reasoning, list)
        or any(
            not isinstance(item, Mapping)
            or set(item) != {"type", "sha256"}
            or item.get("type") != "encrypted"
            or not _sha(item.get("sha256"))
            for item in reasoning
        )
    ):
        return "MALFORMED"
    usage = record.get("usage")
    if not isinstance(usage, Mapping) or set(usage) != {
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "generations",
    }:
        return "MALFORMED"
    if any(type(usage[field]) is not int or usage[field] < 0 for field in usage):
        return "MALFORMED"
    if (
        usage["total_tokens"] > 12_000
        or usage["output_tokens"] > 2_000
        or usage["generations"] != 1
        or usage["total_tokens"] != usage["input_tokens"] + usage["output_tokens"]
    ):
        return "OVER_BUDGET"
    return "PASS"


def qualify_synthetic_transports(source_root: str | os.PathLike[str]) -> dict[str, Any]:
    closure = _source_closure(Path(source_root))
    expected = {
        "content_only": "PASS",
        "reasoning_rich": "PASS",
        "malformed": "MALFORMED",
        "over_budget": "OVER_BUDGET",
        "identity_drift": "IDENTITY_DRIFT",
    }
    qwen = {case: _observe_qwen_record(_qwen_record(case)) for case in expected}
    sol = {case: _observe_sol_record(_sol_record(case)) for case in expected}
    disallowed_tool = _qwen_record("content_only")
    disallowed_tool["tool_calls"][0]["name"] = "exec"
    traversal_tool = _qwen_record("content_only")
    traversal_tool["tool_calls"][0]["arguments"]["relative_path"] = "../vault"
    command_tool = _qwen_record("content_only")
    command_tool["tool_calls"][2]["arguments"]["argv"] = ["curl", "example.invalid"]
    qwen_tool_cases = {
        "disallowed_tool": _observe_qwen_record(disallowed_tool),
        "path_traversal": _observe_qwen_record(traversal_tool),
        "unapproved_command": _observe_qwen_record(command_tool),
    }
    expected_tool_cases = {
        "disallowed_tool": "TOOL_POLICY_FAILURE",
        "path_traversal": "TOOL_POLICY_FAILURE",
        "unapproved_command": "TOOL_POLICY_FAILURE",
    }
    issues = []
    if qwen != expected:
        issues.append("qualification:qwen_case_mismatch")
    if sol != expected:
        issues.append("qualification:sol_case_mismatch")
    if qwen_tool_cases != expected_tool_cases:
        issues.append("qualification:qwen_tool_case_mismatch")
    core = {
        "schema": TRANSPORT_QUALIFICATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "source_closure_sha256": closure["source_closure_sha256"],
        "source_file_count": closure["file_count"],
        "qwen_identity_sha256": _qwen_record("content_only")["identity_sha256"],
        "sol_identity_sha256": _sol_record("content_only")["identity_sha256"],
        "qwen_cases": qwen,
        "qwen_tool_cases": qwen_tool_cases,
        "sol_cases": sol,
        "qwen_tool_observer_qualified": (
            qwen == expected and qwen_tool_cases == expected_tool_cases
        ),
        "sol_no_tools_observer_qualified": sol == expected,
        "provider_free": True,
        "credential_reads": 0,
        "network_calls": 0,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "qualification_sha256": json_sha256(core)}


def validate_transport_qualification(
    value: Any, source_root: str | os.PathLike[str]
) -> dict[str, Any]:
    issues: list[str] = []
    expected_fields = {
        "schema",
        "status",
        "issues",
        "source_closure_sha256",
        "source_file_count",
        "qwen_identity_sha256",
        "sol_identity_sha256",
        "qwen_cases",
        "qwen_tool_cases",
        "sol_cases",
        "qwen_tool_observer_qualified",
        "sol_no_tools_observer_qualified",
        "provider_free",
        "credential_reads",
        "network_calls",
        "model_calls",
        "hosted_calls",
        "qualification_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        issues.append("qualification:contract_invalid")
        record: Mapping[str, Any] = {}
    else:
        record = value
    try:
        closure = _source_closure(Path(source_root))
    except (OSError, ValueError):
        closure = {}
        _issue(issues, "qualification:source_closure_unavailable")
    if record.get("source_closure_sha256") != closure.get("source_closure_sha256"):
        _issue(issues, "qualification:source_closure_mismatch")
    if record.get("source_file_count") != closure.get("file_count"):
        _issue(issues, "qualification:source_closure_mismatch")
    if record:
        core = dict(record)
        seal = core.pop("qualification_sha256", None)
        if seal != json_sha256(core):
            _issue(issues, "qualification:seal_mismatch")
    if (
        record.get("schema") != TRANSPORT_QUALIFICATION_SCHEMA
        or record.get("status") != "PASS"
        or record.get("issues") != []
        or record.get("qwen_tool_observer_qualified") is not True
        or record.get("sol_no_tools_observer_qualified") is not True
        or record.get("provider_free") is not True
        or any(record.get(field) != 0 for field in ("credential_reads", "network_calls", "model_calls", "hosted_calls"))
    ):
        _issue(issues, "qualification:passing_contract_invalid")
    return {"status": "PASS" if not issues else "FAIL", "issues": sorted(issues)}


def _installed_probe_request(plugin_root: Path) -> dict[str, Any]:
    request_seed = json_sha256(
        {
            "schema": "orch-dork/frontier-installed-probe-seed/v1",
            "catalog_sha256": load_catalog(
                plugin_root
                / "skills"
                / "orch-dork"
                / "runtime"
                / "frontier-regression-corpus-v1.json"
            )["catalog_sha256"],
        }
    )
    assignment_core = {
        "schema": live_sweep.LIVE_LANE_ASSIGNMENT_SCHEMA,
        "lane_id": "frontier-installed-qualification-lane",
        "request_sha256": request_seed,
        "task_family": "evidence_extraction",
        "cut_strategy": "acceptance_unit",
        "task": {
            "rules": {"finding_rule": "severity is high"},
            "items": [
                {"id": "item-00", "severity": "high"},
                {"id": "item-01", "severity": "low"},
            ],
        },
        "output_schema": live_sweep.LIVE_LANE_RESULT_SCHEMA,
    }
    assignment = {
        **assignment_core,
        "assignment_sha256": json_sha256(assignment_core),
    }
    campaign_sha256 = json_sha256(
        {"schema": "orch-dork/frontier-installed-probe-campaign/v1"}
    )
    return zero_tool.build_live_zero_tool_request(
        assignment,
        campaign_sha256=campaign_sha256,
        grant_sha256=json_sha256(
            {"schema": "orch-dork/frontier-installed-probe-grant/v1"}
        ),
        reservation_sha256=json_sha256(
            {"schema": "orch-dork/frontier-installed-probe-reservation/v1"}
        ),
        request_id="frontier-installed-qualification-lane",
        max_output_tokens=2_000,
        max_total_tokens=12_000,
        max_response_bytes=65_536,
        timeout_ms=120_000,
        evidence_root=plugin_root,
    )


def _sol_opencodex_probe(
    plugin_root: Path,
    opencodex_root: Path,
    request: Mapping[str, Any],
    *,
    runner: Callable[..., Mapping[str, Any]] | None,
) -> dict[str, Any]:
    """Run the shipped parser/adapter against the exact Sol wire identity."""

    issues: list[str] = []
    body = deepcopy(dict(request["body"]))
    body["model"] = "gpt-5.6-sol"
    assignment = request.get("assignment")
    task = assignment.get("task") if isinstance(assignment, Mapping) else None
    items = task.get("items") if isinstance(task, Mapping) else None
    identifiers = sorted(
        str(item["id"])
        for item in items or []
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    )
    terminal = {
        "schema": assignment.get("output_schema") if isinstance(assignment, Mapping) else None,
        "lane_id": assignment.get("lane_id") if isinstance(assignment, Mapping) else None,
        "request_sha256": assignment.get("request_sha256") if isinstance(assignment, Mapping) else None,
        "assignment_sha256": assignment.get("assignment_sha256") if isinstance(assignment, Mapping) else None,
        "findings": identifiers[:1],
        "unknowns": identifiers[1:],
    }
    probe_input = {
        "schema": zero_tool_qualification.PROBE_INPUT_SCHEMA,
        "opencodex_root": str(opencodex_root),
        "request_schema": request.get("schema"),
        "request_body": body,
        "terminal_result": terminal,
        "response_model": "gpt-5.6-sol",
    }
    selected_runner = runner or containment.run_contained
    process = selected_runner(
        [
            str(opencodex_root / "node_modules/bun/bin/bun.exe"),
            str(
                plugin_root
                / "skills"
                / "orch-dork"
                / "scripts"
                / "orch_dork_live_zero_tool_probe.ts"
            ),
        ],
        input_bytes=_canonical_bytes(probe_input),
        expect_json=True,
        case_id="issue151-sol-parser-adapter",
        surface="frontier-sol-parser-adapter-probe",
    )
    if (
        not isinstance(process, Mapping)
        or process.get("status") != "PASS"
        or process.get("cleanup_status") != "complete"
    ):
        issues.append("probe:process_invalid")
        parsed: Mapping[str, Any] = {}
    else:
        candidate = process.get("parsed_output")
        parsed = candidate if isinstance(candidate, Mapping) else {}
    if (
        set(parsed)
        != {
            "schema",
            "request",
            "cases",
            "credential_reads",
            "network_calls",
            "model_calls",
            "hosted_calls",
        }
        or parsed.get("schema") != zero_tool_qualification.PROBE_OUTPUT_SCHEMA
    ):
        _issue(issues, "probe:contract_invalid")
    expected_request = {
        "request_schema": zero_tool.REQUEST_SCHEMA_V2,
        "reasoning_envelope_contract": (
            zero_tool_qualification.REASONING_ENVELOPE_CONTRACT
        ),
        "include_reasoning_absent": True,
        "reasoning_output_mode": "hidden_envelope",
        "reasoning_effort": "xhigh",
        "hide_thinking_summary": True,
        "tools_count": 0,
        "tool_choice": "none",
        "stream": False,
        "store": False,
        "structured_output_type": "json_schema",
    }
    if parsed.get("request") != expected_request:
        _issue(issues, "probe:request_semantics_invalid")
    for field in ("credential_reads", "network_calls", "model_calls", "hosted_calls"):
        if parsed.get(field) != 0:
            _issue(issues, "probe:" + field + "_nonzero")
    case_statuses: dict[str, str] = {}
    cases = parsed.get("cases")
    if not isinstance(cases, list):
        _issue(issues, "probe:cases_invalid")
        cases = []
    for case in cases:
        case_id = case.get("id") if isinstance(case, Mapping) else None
        response = case.get("response") if isinstance(case, Mapping) else None
        valid = isinstance(response, Mapping)
        if valid:
            output = response.get("output")
            valid = (
                response.get("object") == "response"
                and response.get("status") == "completed"
                and response.get("model") == "gpt-5.6-sol"
                and isinstance(output, list)
                and len(output) in {1, 2}
            )
        if valid:
            envelope_issues: list[str] = []
            if len(output) == 2:
                zero_tool._hidden_reasoning_envelope(
                    output[0],
                    maximum_response_bytes=65_536,
                    issues=envelope_issues,
                )
            message = output[-1]
            valid = (
                not envelope_issues
                and isinstance(message, Mapping)
                and message.get("type") == "message"
                and message.get("role") == "assistant"
                and message.get("status") == "completed"
            )
        if valid:
            content = message.get("content")
            valid = (
                isinstance(content, list)
                and len(content) == 1
                and isinstance(content[0], Mapping)
                and content[0].get("type") == "output_text"
                and content[0].get("annotations") == []
            )
        if valid:
            try:
                observed_terminal = json.loads(content[0]["text"])
            except (KeyError, TypeError, json.JSONDecodeError):
                observed_terminal = None
            valid = observed_terminal == terminal
        if case_id in {"content_only", "reasoning_rich"}:
            case_statuses[case_id] = "PASS" if valid else "FAIL"
        else:
            _issue(issues, "probe:case_identity_invalid")
    if case_statuses != {"content_only": "PASS", "reasoning_rich": "PASS"}:
        _issue(issues, "probe:cases_failed")
    core = {
        "schema": "orch-dork/frontier-sol-opencodex-probe/v1",
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(issues),
        "wire_model": "gpt-5.6-sol",
        "cases": case_statuses,
        "tools": [],
        "provider_free": True,
        "credential_reads": 0,
        "network_calls": 0,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "probe_sha256": json_sha256(core)}


def qualify_installed_runtime(
    plugin_root: str | os.PathLike[str],
    opencodex_root: str | os.PathLike[str],
    *,
    runner: Callable[..., Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Exercise the exact installed parser/adapter closure without a model call."""

    issues: list[str] = []
    try:
        plugin = Path(plugin_root)
        opencodex = Path(opencodex_root)
        if (
            not plugin.is_absolute()
            or plugin.is_symlink()
            or plugin.resolve(strict=True) != plugin
            or not opencodex.is_absolute()
            or opencodex.is_symlink()
            or opencodex.resolve(strict=True) != opencodex
        ):
            raise ValueError("runtime:root_invalid")
        closure = _source_closure(plugin)
        synthetic = qualify_synthetic_transports(plugin)
        request = _installed_probe_request(plugin)
        qwen_probe = zero_tool_qualification.qualify_zero_tool_transport(
            request,
            zero_tool_qualification.TransportRuntime(
                plugin_root=plugin,
                opencodex_root=opencodex,
            ),
            runner=runner,
        )
        qwen_validation = (
            zero_tool_qualification.validate_zero_tool_transport_qualification(
                qwen_probe
            )
        )
        sol_probe = _sol_opencodex_probe(
            plugin,
            opencodex,
            request,
            runner=runner,
        )
        post_runtime_issues: list[str] = []
        post_runtime_identity, _post_root = (
            zero_tool_qualification._runtime_identity(
                zero_tool_qualification.TransportRuntime(
                    plugin_root=plugin,
                    opencodex_root=opencodex,
                ),
                post_runtime_issues,
            )
        )
        post_closure = _source_closure(plugin)
        if (
            post_runtime_issues
            or post_runtime_identity != qwen_probe.get("runtime_identity")
            or post_closure != closure
        ):
            issues.append("runtime:changed_during_installed_probe")
    except (OSError, TypeError, ValueError, zero_tool.LiveZeroToolError):
        closure = {}
        synthetic = {}
        qwen_probe = {}
        qwen_validation = {"status": "FAIL", "issues": ["runtime:unavailable"]}
        sol_probe = {}
        issues.append("runtime:qualification_unavailable")
    if synthetic.get("status") != "PASS":
        _issue(issues, "runtime:synthetic_transport_failed")
    if qwen_probe.get("status") != "PASS" or qwen_validation.get("status") != "PASS":
        _issue(issues, "runtime:qwen_parser_adapter_probe_failed")
    if sol_probe.get("status") != "PASS":
        _issue(issues, "runtime:sol_parser_adapter_probe_failed")
    for report, label in (
        (synthetic, "synthetic"),
        (qwen_probe, "qwen_parser"),
        (sol_probe, "sol_parser"),
    ):
        if any(
            report.get(field) != 0
            for field in (
                "credential_reads",
                "network_calls",
                "model_calls",
                "hosted_calls",
            )
        ):
            _issue(issues, "runtime:" + label + "_provider_boundary_invalid")
    runtime_identity = qwen_probe.get("runtime_identity")
    runtime_identity_sha256 = (
        runtime_identity.get("runtime_identity_sha256")
        if isinstance(runtime_identity, Mapping)
        else None
    )
    core = {
        "schema": INSTALLED_QUALIFICATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(issues),
        "source_closure_sha256": closure.get("source_closure_sha256"),
        "source_file_count": closure.get("file_count"),
        "synthetic_transport_qualification_sha256": synthetic.get(
            "qualification_sha256"
        ),
        "qwen_opencodex_qualification_sha256": qwen_probe.get(
            "qualification_sha256"
        ),
        "sol_opencodex_qualification_sha256": sol_probe.get("probe_sha256"),
        "runtime_identity_sha256": runtime_identity_sha256,
        "qwen_identity_sha256": synthetic.get("qwen_identity_sha256"),
        "sol_identity_sha256": synthetic.get("sol_identity_sha256"),
        "compatibility_correction": {
            "schema": OPENCODEX_235_CORRECTION_SCHEMA,
            "predecessor_qualification_sha256": ISSUE154_QUALIFICATION_SHA256,
            "predecessor_runtime_identity_sha256": (
                ISSUE154_RUNTIME_IDENTITY_SHA256
            ),
            "request_schema": zero_tool.REQUEST_SCHEMA_V2,
            "reasoning_envelope_contract": (
                zero_tool_qualification.REASONING_ENVELOPE_CONTRACT
            ),
        },
        "qwen_opencodex_parser_adapter_probe": (
            "PASS" if qwen_probe.get("status") == "PASS" else "FAIL"
        ),
        "qwen_frontier_tool_observer": (
            "PASS"
            if synthetic.get("qwen_tool_observer_qualified") is True
            else "FAIL"
        ),
        "sol_opencodex_parser_adapter_probe": (
            "PASS" if sol_probe.get("status") == "PASS" else "FAIL"
        ),
        "sol_frontier_structured_no_tools_observer": (
            "PASS"
            if synthetic.get("sol_no_tools_observer_qualified") is True
            else "FAIL"
        ),
        "content_only_case": (
            "PASS"
            if synthetic.get("qwen_cases", {}).get("content_only") == "PASS"
            and synthetic.get("sol_cases", {}).get("content_only") == "PASS"
            else "FAIL"
        ),
        "reasoning_rich_case": (
            "PASS"
            if synthetic.get("qwen_cases", {}).get("reasoning_rich") == "PASS"
            and synthetic.get("sol_cases", {}).get("reasoning_rich") == "PASS"
            else "FAIL"
        ),
        "malformed_case": (
            "PASS"
            if synthetic.get("qwen_cases", {}).get("malformed") == "MALFORMED"
            and synthetic.get("sol_cases", {}).get("malformed") == "MALFORMED"
            else "FAIL"
        ),
        "over_budget_case": (
            "PASS"
            if synthetic.get("qwen_cases", {}).get("over_budget") == "OVER_BUDGET"
            and synthetic.get("sol_cases", {}).get("over_budget") == "OVER_BUDGET"
            else "FAIL"
        ),
        "identity_drift_case": (
            "PASS"
            if synthetic.get("qwen_cases", {}).get("identity_drift")
            == "IDENTITY_DRIFT"
            and synthetic.get("sol_cases", {}).get("identity_drift")
            == "IDENTITY_DRIFT"
            else "FAIL"
        ),
        "provider_free": True,
        "credential_reads": 0,
        "network_calls": 0,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "qualification_sha256": json_sha256(core)}


# The campaign runner and refusal matrix follow below.  They are kept in this
# module so record/replay invokes exactly the same installed compiler, packet
# sanitizer, parser observers, and public Control Tower seam.


def _v2_program(operation: str, payload: Mapping[str, Any], sequence: int) -> dict[str, Any]:
    return {
        "schema": control_tower.PROGRAM_SCHEMA_V2,
        "program_id": "issue151-" + operation + "-" + str(sequence),
        "operation": operation,
        "payload": deepcopy(dict(payload)),
    }


class _RunResolver:
    """Create and independently resolve exact synthetic RunEngine streams."""

    def __init__(self, store: Any) -> None:
        self.store = store
        self.engine = run_engine.RunEngine(store)

    def complete_run(
        self,
        *,
        campaign_id: str,
        fixture: Mapping[str, Any],
        role: str,
        profile_id: str,
        qwen_identity_sha256: str,
        tool_policy_sha256: str,
    ) -> dict[str, Any]:
        task_sha256 = fixture[role + "_task_brief_sha256"]
        run_id = "fq-" + json_sha256(
            {
                "campaign_id": campaign_id,
                "fixture_sha256": fixture["fixture_sha256"],
                "role": role,
                "profile_id": profile_id,
            }
        )[:24]
        plan = run_engine.make_plan(
            run_id=run_id,
            name="Qualified fixture " + fixture["fixture_id"] + " " + role,
            expected_roles=("executor",),
            actors=(
                run_engine.actor(
                    kind="executor",
                    model="synthetic-qwen/v1",
                    actor_key="executor",
                    intent="execute:" + profile_id,
                ),
            ),
            origin={
                "frontier_binding": {
                    "campaign_id": campaign_id,
                    "fixture_sha256": fixture["fixture_sha256"],
                    "role": role,
                    "profile_id": profile_id,
                    "task_brief_sha256": task_sha256,
                    "qwen_identity_sha256": qwen_identity_sha256,
                    "tool_policy_sha256": tool_policy_sha256,
                }
            },
        )
        self.engine.start(plan)
        self.engine.apply(
            run_id,
            "executor",
            ["executor"],
            deliverables={
                "artifact_sha256": json_sha256(
                    {"fixture_sha256": fixture["fixture_sha256"], "role": role}
                )
            },
            evidence={
                "runtime_receipt": json_sha256(
                    {"run_id": run_id, "runtime": "synthetic-qwen/v1"}
                )
            },
        )
        self.engine.complete(run_id, "executor", "SUCCESS")
        events = list(self.engine.events(run_id, 0))
        state = self.engine.reduce(json.loads(events[0]["payload"])["plan"], events)
        return {
            "schema": frontier.RUN_REF_SCHEMA,
            "run_id": run_id,
            "stream_sha256": state["stream_sha256"],
        }

    def __call__(self, request: Mapping[str, Any]) -> dict[str, Any]:
        run_ref = request.get("run_ref") if isinstance(request, Mapping) else None
        try:
            events = list(self.engine.events(run_ref["run_id"], 0))
            plan = json.loads(events[0]["payload"])["plan"]
            state = self.engine.reduce(plan, events)
            binding = plan["origin"]["frontier_binding"]
        except (
            IndexError,
            KeyError,
            TypeError,
            ValueError,
            run_engine.RunKernelError,
        ):
            return {"status": "FAIL", "issues": ["run:unresolvable"]}
        expected = {
            field: request[field]
            for field in (
                "campaign_id",
                "fixture_sha256",
                "role",
                "profile_id",
                "task_brief_sha256",
                "qwen_identity_sha256",
                "tool_policy_sha256",
            )
        }
        if (
            binding != expected
            or not state["terminal"]
            or state["terminal_kind"] != "completed"
            or state["stream_sha256"] != run_ref.get("stream_sha256")
        ):
            return {"status": "FAIL", "issues": ["run:binding_invalid"]}
        return {
            "status": "PASS",
            "issues": [],
            "run_id": run_ref["run_id"],
            "stream_sha256": state["stream_sha256"],
            "event_count": len(events),
        }


class _CampaignHarness:
    """One deterministic public-seam recorder over an injected RunStore."""

    def __init__(
        self,
        store: Any,
        *,
        campaign_id: str,
        holdout_group_id: str,
        restart_every_transition: bool,
        expected_recording: Mapping[str, Any] | None,
    ) -> None:
        self.campaign_id = campaign_id
        self.holdout_group_id = holdout_group_id
        self.restart = bool(restart_every_transition)
        self.expected_recording = expected_recording
        self.records: list[dict[str, Any]] = []
        self.program_sequence = 0
        self._base_store = store
        self._sqlite_path: Path | None = None
        if self.restart:
            if not isinstance(store, run_store.SQLiteRunStore):
                raise ValueError("campaign:restart_requires_sqlite")
            self._sqlite_path = Path(store._path)
            store.close()

    def _open(self) -> tuple[Any, bool]:
        if self._sqlite_path is not None:
            return run_store.SQLiteRunStore(self._sqlite_path), True
        return self._base_store, False

    @staticmethod
    def _close(store: Any, owned: bool) -> None:
        if owned:
            store.close()

    def _record(self, kind: str, value: Mapping[str, Any]) -> None:
        core = {
            "index": len(self.records),
            "kind": kind,
            "value": deepcopy(dict(value)),
        }
        row = {**core, "value_sha256": json_sha256(core["value"])}
        if self.expected_recording is not None:
            expected = self.expected_recording.get("records")
            if (
                not isinstance(expected, list)
                or len(expected) <= row["index"]
                or expected[row["index"]] != row
            ):
                raise ValueError("replay:record_mismatch")
        self.records.append(row)

    def evaluate(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self.program_sequence += 1
        program = _v2_program(operation, payload, self.program_sequence)
        store, owned = self._open()
        resolver = _RunResolver(store)
        tower = control_tower.ControlTower(
            clock_ms=lambda: 1_000,
            frontier_store=store,
            frontier_run_resolver=resolver,
        )
        try:
            report = control_tower.evaluate_control_tower(program, tower=tower)
        finally:
            self._close(store, owned)
        self._record("public_seam", {"program": program, "report": report})
        return report

    def complete_run(
        self,
        *,
        fixture: Mapping[str, Any],
        role: str,
        profile_id: str,
        qwen_identity_sha256: str,
        tool_policy_sha256: str,
    ) -> dict[str, Any]:
        store, owned = self._open()
        try:
            run_ref = _RunResolver(store).complete_run(
                campaign_id=self.campaign_id,
                fixture=fixture,
                role=role,
                profile_id=profile_id,
                qwen_identity_sha256=qwen_identity_sha256,
                tool_policy_sha256=tool_policy_sha256,
            )
        finally:
            self._close(store, owned)
        self._record(
            "run_engine",
            {
                "campaign_id": self.campaign_id,
                "fixture_sha256": fixture["fixture_sha256"],
                "role": role,
                "profile_id": profile_id,
                "task_brief_sha256": fixture[role + "_task_brief_sha256"],
                "qwen_identity_sha256": qwen_identity_sha256,
                "tool_policy_sha256": tool_policy_sha256,
                "run_ref": run_ref,
            },
        )
        return run_ref

    def recording(self) -> dict[str, Any]:
        core = {
            "schema": CAMPAIGN_RECORDING_SCHEMA,
            "campaign_id": self.campaign_id,
            "holdout_group_id": self.holdout_group_id,
            "records": self.records,
            "provider_free": True,
            "external_dispatches": 0,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        recording = {**core, "recording_sha256": json_sha256(core)}
        if self.expected_recording is not None and recording != self.expected_recording:
            raise ValueError("replay:recording_mismatch")
        return recording

    def close(self) -> None:
        if self._sqlite_path is None and isinstance(
            self._base_store, run_store.SQLiteRunStore
        ):
            self._base_store.close()


def _advance_payload(
    campaign_id: str,
    cursor: Mapping[str, Any],
    kind: str,
    request: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": frontier.ADVANCE_SCHEMA,
        "kind": kind,
        "campaign_id": campaign_id,
        "prior_cursor": deepcopy(dict(cursor)),
        "request": deepcopy(dict(request)),
    }


def _require_pass(report: Mapping[str, Any], label: str) -> Mapping[str, Any]:
    if report.get("status") != "PASS":
        raise ValueError(label + ":" + ",".join(report.get("issues", [])))
    result = report.get("result")
    if not isinstance(result, Mapping):
        raise ValueError(label + ":result_missing")
    return result


def _synthetic_files(fixture: Mapping[str, Any]) -> dict[str, str]:
    files = deepcopy(dict(fixture["snapshot_files"]))
    for check in list(fixture["public_checks"]) + list(fixture["hidden_checks"]):
        content = files[check["path"]]
        needle = check["needle"]
        if check["kind"] == "contains" and needle not in content:
            content += "\n# qualified: " + needle + "\n"
        elif check["kind"] == "not_contains":
            content = content.replace(needle, "")
        files[check["path"]] = content
    return files


def _artifact_rows(
    fixture: Mapping[str, Any], files: Mapping[str, str]
) -> list[dict[str, Any]]:
    return [
        {
            "relative_path": path,
            "content": files[path],
            "is_symlink": False,
        }
        for path in fixture["artifact_paths"]
    ]


def _frontier_runtime_contract(
    transport_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": frontier.RUNTIME_CONTRACT_SCHEMA,
        "qwen_identity_sha256": transport_qualification["qwen_identity_sha256"],
        "sol_identity_sha256": transport_qualification["sol_identity_sha256"],
        "qwen_provider": "provider-free-fixture",
        "sol_provider": "provider-free-fixture",
        "sol_model_id": "gpt-sol-fixture",
        "sol_runtime_id": "sol-fixture-v1",
        "sol_retention": "none",
        "sol_region": "local-fixture",
        "sol_context_tokens": 12_000,
        "sol_input_tokens": 8_000,
        "sol_output_tokens": 2_000,
        "sol_generations": 1,
        "sol_tools": [],
        "provider_free": True,
    }


def frontier_runtime_from_live_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    report = validate_live_runtime_contract(value)
    if report["status"] != "PASS":
        raise ValueError("runtime:live_contract_invalid")
    return {
        key: deepcopy(item)
        for key, item in value.items()
        if key != "privacy_class"
    }


def _prepare_payload(
    *,
    catalog: Mapping[str, Any],
    archive: Mapping[str, Any],
    campaign_id: str,
    holdout_group_id: str,
    runtime_contract: Mapping[str, Any],
    authority_scope_sha256: str,
    prepared_at_ms: int,
) -> dict[str, Any]:
    catalog_report = validate_catalog(catalog)
    if catalog_report["status"] != "PASS":
        raise ValueError("catalog:invalid")
    if topology_lab.validate_archive(archive).get("status") != "PASS":
        raise ValueError("archive:invalid")
    if not _identifier(campaign_id) or not _sha(authority_scope_sha256):
        raise ValueError("prepare:binding_invalid")
    if type(prepared_at_ms) is not int or prepared_at_ms < 0:
        raise ValueError("prepare:clock_invalid")
    return {
        "schema": frontier.PREPARE_SCHEMA,
        "campaign_id": campaign_id,
        "archive": deepcopy(dict(archive)),
        "corpus": compile_frontier_corpus(catalog, holdout_group_id),
        "runtime_contract": deepcopy(dict(runtime_contract)),
        "authority_scope_sha256": authority_scope_sha256,
        "prompt_bundle_sha256": json_sha256(
            {
                "model_tasks": [
                    model_task(catalog, fixture["fixture_id"])["task_sha256"]
                    for fixture in catalog["fixtures"]
                    if fixture["partition"] != "holdout"
                ],
                "version": "frontier-prompts/v1",
            }
        ),
        "verification_policy_sha256": json_sha256(
            {
                "catalog_sha256": catalog["catalog_sha256"],
                "checks": "public-plus-controller-only/v1",
            }
        ),
        "cost_weights_sha256": json_sha256(
            {"version": "frontier-cost-weights/v1", "fixed": True}
        ),
        "tool_policy_sha256": json_sha256(catalog["tool_policy"]),
        "prepared_at_ms": prepared_at_ms,
    }


def build_provider_free_prepare_payload(
    *,
    catalog: Mapping[str, Any],
    archive: Mapping[str, Any],
    campaign_id: str,
    holdout_group_id: str,
    authority_scope_sha256: str,
    prepared_at_ms: int = 1_000,
) -> dict[str, Any]:
    source_root = Path(__file__).resolve().parents[3]
    transport = qualify_synthetic_transports(source_root)
    if transport["status"] != "PASS":
        raise ValueError("runtime:synthetic_qualification_failed")
    return _prepare_payload(
        catalog=catalog,
        archive=archive,
        campaign_id=campaign_id,
        holdout_group_id=holdout_group_id,
        runtime_contract=_frontier_runtime_contract(transport),
        authority_scope_sha256=authority_scope_sha256,
        prepared_at_ms=prepared_at_ms,
    )


def build_live_prepare_payload(
    *,
    catalog: Mapping[str, Any],
    archive: Mapping[str, Any],
    campaign_id: str,
    holdout_group_id: str,
    runtime_contract: Mapping[str, Any],
    authority_scope_sha256: str,
    prepared_at_ms: int,
) -> dict[str, Any]:
    return _prepare_payload(
        catalog=catalog,
        archive=archive,
        campaign_id=campaign_id,
        holdout_group_id=holdout_group_id,
        runtime_contract=frontier_runtime_from_live_contract(runtime_contract),
        authority_scope_sha256=authority_scope_sha256,
        prepared_at_ms=prepared_at_ms,
    )


def qualify_holdout_isolation(
    catalog: Mapping[str, Any], archive: Mapping[str, Any]
) -> dict[str, Any]:
    """Prove holdout rotation cannot change any experimental control."""

    issues: list[str] = []
    source_root = Path(__file__).resolve().parents[3]
    transport = qualify_synthetic_transports(source_root)
    runtime = _frontier_runtime_contract(transport)
    nonholdout_sha256s: list[str] | None = None
    controls: list[dict[str, Any]] = []
    prompt_bundle_sha256 = json_sha256(
        {
            "model_tasks": [
                model_task(catalog, fixture["fixture_id"])["task_sha256"]
                for fixture in catalog["fixtures"]
                if fixture["partition"] != "holdout"
            ],
            "version": "frontier-prompts/v1",
        }
    )
    verification_policy_sha256 = json_sha256(
        {
            "catalog_sha256": catalog.get("catalog_sha256"),
            "checks": "public-plus-controller-only/v1",
        }
    )
    cost_weights_sha256 = json_sha256(
        {"version": "frontier-cost-weights/v1", "fixed": True}
    )
    tool_policy_sha256 = json_sha256(catalog.get("tool_policy"))
    for index, group in enumerate(_HOLDOUTS, start=1):
        corpus = compile_frontier_corpus(catalog, group)
        current_nonholdouts = [
            row["fixture_sha256"]
            for row in corpus["fixtures"]
            if row["partition"] != "holdout"
        ]
        if nonholdout_sha256s is None:
            nonholdout_sha256s = current_nonholdouts
        elif current_nonholdouts != nonholdout_sha256s:
            _issue(issues, "holdout:nonholdout_manifest_drift")
        payload = {
            "schema": frontier.PREPARE_SCHEMA,
            "campaign_id": "issue151-isolation-" + group,
            "archive": deepcopy(dict(archive)),
            "corpus": corpus,
            "runtime_contract": runtime,
            "authority_scope_sha256": json_sha256(
                {"scope": "holdout-isolation", "group": group}
            ),
            "prompt_bundle_sha256": prompt_bundle_sha256,
            "verification_policy_sha256": verification_policy_sha256,
            "cost_weights_sha256": cost_weights_sha256,
            "tool_policy_sha256": tool_policy_sha256,
            "prepared_at_ms": 1_000,
        }
        report = control_tower.evaluate_control_tower(
            _v2_program("prepare", payload, index),
            tower=control_tower.ControlTower(clock_ms=lambda: 1_000),
        )
        if report.get("status") != "PASS":
            _issue(issues, "holdout:preparation_failed")
            continue
        preparation = report["result"]
        controls.append(
            {
                "archive_sha256": preparation["archive_sha256"],
                "candidate_sha256": preparation["challenger"]["candidate_sha256"],
                "runtime_contract_sha256": preparation[
                    "runtime_contract_sha256"
                ],
                "prompt_bundle_sha256": preparation["prompt_bundle_sha256"],
                "verification_policy_sha256": preparation[
                    "verification_policy_sha256"
                ],
                "cost_weights_sha256": preparation["cost_weights_sha256"],
                "tool_policy_sha256": preparation["tool_policy_sha256"],
                "review_contract_sha256": preparation["review_contract"][
                    "review_contract_sha256"
                ],
            }
        )
    if len(controls) != 3 or any(control != controls[0] for control in controls[1:]):
        _issue(issues, "holdout:experimental_control_drift")
    model_projection = [
        model_task(catalog, fixture["fixture_id"])
        for fixture in catalog["fixtures"]
    ]
    projected = json.dumps(model_projection, sort_keys=True)
    if any(
        token in projected
        for token in (
            '"partition"',
            '"lineage_id"',
            '"historical_ref"',
            '"hidden_checks"',
            '"expected_result"',
        )
    ):
        _issue(issues, "holdout:model_projection_leak")
    core = {
        "schema": "orch-dork/frontier-holdout-isolation/v1",
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(issues),
        "catalog_sha256": catalog.get("catalog_sha256"),
        "archive_sha256": controls[0]["archive_sha256"] if controls else None,
        "candidate_sha256": controls[0]["candidate_sha256"] if controls else None,
        "experimental_controls_sha256": json_sha256(controls[0]) if controls else None,
        "holdout_group_count": 3,
        "nonholdout_fixture_count": len(nonholdout_sha256s or []),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "isolation_sha256": json_sha256(core)}


def _config_observation(
    *,
    preparation: Mapping[str, Any],
    fixture: Mapping[str, Any],
    role: str,
    run_ref: Mapping[str, Any],
    artifact_sha256: str,
    check_report: Mapping[str, Any],
) -> dict[str, Any]:
    challenger = role == "challenger"
    amount = 90 if challenger else 100
    return frontier.seal_config_observation(
        {
            "schema": frontier.CONFIG_OBSERVATION_DRAFT_SCHEMA,
            "campaign_id": preparation["campaign_id"],
            "fixture_sha256": fixture["fixture_sha256"],
            "role": role,
            "run_ref": deepcopy(dict(run_ref)),
            "objective_checks": {
                field: "PASS"
                for field in (
                    "safety",
                    "privacy",
                    "authority",
                    "custody",
                    "cleanup",
                    "correctness",
                )
            },
            "usage": {
                "exact": True,
                "tokens": amount,
                "weighted_cost_micros": amount,
                "critical_path_ms": amount,
            },
            "artifact_sha256": artifact_sha256,
            "hidden_check_sha256": fixture["hidden_checks_sha256"],
            "evidence_sha256": json_sha256(
                {
                    "run_ref": run_ref,
                    "check_report_sha256": check_report["report_sha256"],
                }
            ),
        }
    )


_CALIBRATION_EXPECTED = ("A", "B", "TIE", "A", "B")


def _review_observation(
    *,
    preparation: Mapping[str, Any],
    fixture: Mapping[str, Any],
    public_intent: Mapping[str, Any],
    packet_sha256: str,
) -> dict[str, Any]:
    scores = {dimension: 3 for dimension in frontier.REVIEW_DIMENSIONS}
    return frontier.seal_review_observation(
        {
            "schema": frontier.REVIEW_OBSERVATION_DRAFT_SCHEMA,
            "campaign_id": preparation["campaign_id"],
            "fixture_sha256": fixture["fixture_sha256"],
            "review_status": "PASS",
            "sol_identity_sha256": preparation["runtime_contract"][
                "sol_identity_sha256"
            ],
            "blind_packet_sha256": public_intent["blind_packet_sha256"],
            "rubric_sha256": preparation["review_contract"][
                "review_contract_sha256"
            ],
            "option_a_scores": scores,
            "option_b_scores": scores,
            "winner": "TIE",
            "evidence_refs": [
                json_sha256(
                    {
                        "fixture_sha256": fixture["fixture_sha256"],
                        "packet_sha256": packet_sha256,
                    }
                )
            ],
            "calibration_pair_sha256": public_intent[
                "calibration_pair_sha256"
            ],
            "calibration_disposition": (
                _CALIBRATION_EXPECTED[fixture["rung"] - 1]
                if public_intent["calibration_required"]
                else None
            ),
            "tokens": 100,
            "review_evidence_sha256": json_sha256(
                {
                    "packet_sha256": packet_sha256,
                    "observer": "synthetic-sol-proxy/v1",
                }
            ),
        }
    )


def run_provider_free_campaign(
    *,
    catalog: Mapping[str, Any],
    archive: Mapping[str, Any],
    store: Any,
    campaign_id: str,
    holdout_group_id: str,
    restart_every_transition: bool = False,
    _expected_recording: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run all five real-corpus rungs with deterministic synthetic evidence."""

    started_at = time.monotonic()
    catalog_report = validate_catalog(catalog)
    if catalog_report["status"] != "PASS":
        return {
            "schema": QUALIFICATION_SCHEMA,
            "status": "FAIL",
            "issues": catalog_report["issues"],
            "recording": None,
        }
    source_root = Path(__file__).resolve().parents[3]
    transport = qualify_synthetic_transports(source_root)
    transport_validation = validate_transport_qualification(transport, source_root)
    if transport_validation["status"] != "PASS":
        return {
            "schema": QUALIFICATION_SCHEMA,
            "status": "FAIL",
            "issues": transport_validation["issues"],
            "recording": None,
        }
    harness = _CampaignHarness(
        store,
        campaign_id=campaign_id,
        holdout_group_id=holdout_group_id,
        restart_every_transition=restart_every_transition,
        expected_recording=_expected_recording,
    )
    rung_timings: list[float] = []
    terminal: Mapping[str, Any] | None = None
    inspection: Mapping[str, Any] | None = None
    try:
        runtime = _frontier_runtime_contract(transport)
        prepare_payload = _prepare_payload(
            catalog=catalog,
            archive=archive,
            campaign_id=campaign_id,
            holdout_group_id=holdout_group_id,
            runtime_contract=runtime,
            authority_scope_sha256=json_sha256(
                {
                    "class_id": frontier.AUTHORITY_CLASS,
                    "campaign_id": campaign_id,
                    "catalog_sha256": catalog["catalog_sha256"],
                }
            ),
            prepared_at_ms=1_000,
        )
        preparation = _require_pass(
            harness.evaluate("prepare", prepare_payload), "campaign:prepare"
        )
        if preparation["preparation_status"] != "READY":
            raise ValueError("campaign:no_eligible_challenger")
        registration = frontier.seal_authority_registration(
            {
                "schema": frontier.AUTHORITY_REGISTRATION_DRAFT_SCHEMA,
                "class_id": frontier.AUTHORITY_CLASS,
                "campaign_id": campaign_id,
                "authority_scope_sha256": preparation["authority_scope_sha256"],
                "registration_id": "issue151-provider-free-registration",
                "registered_at_ms": 1_000,
                "provider_free": True,
            }
        )
        started = _require_pass(
            harness.evaluate(
                "advance",
                _advance_payload(
                    campaign_id,
                    frontier.genesis_cursor(campaign_id),
                    "start",
                    {
                        "preparation": preparation,
                        "authority_registration": registration,
                    },
                ),
            ),
            "campaign:start",
        )
        cursor = started["cursor"]
        challenger_profile = preparation["challenger"]["genome"]["profile_id"]
        private_by_id = {
            fixture["fixture_id"]: fixture
            for fixture in catalog["fixtures"]
            if fixture["partition"] != "holdout"
            or fixture["holdout_group_id"] == holdout_group_id
        }
        current_rung = 1
        rung_started = time.monotonic()
        for fixture_index, fixture in enumerate(preparation["fixtures"]):
            reserved = _require_pass(
                harness.evaluate(
                    "advance",
                    _advance_payload(
                        campaign_id,
                        cursor,
                        "reserve_pair",
                        {"fixture_id": fixture["fixture_id"]},
                    ),
                ),
                "campaign:reserve",
            )
            cursor = reserved["cursor"]
            private = private_by_id[fixture["fixture_id"]]
            files = _synthetic_files(private)
            check_report = evaluate_fixture_checks(
                catalog, fixture["fixture_id"], files
            )
            if check_report["status"] != "PASS":
                raise ValueError("campaign:synthetic_fixture_invalid")
            artifacts: dict[str, list[dict[str, Any]]] = {}
            artifact_sha256s: dict[str, str] = {}
            roles = (
                ("champion", "challenger")
                if fixture_index % 2 == 0
                else ("challenger", "champion")
            )
            for role in roles:
                dispatched = _require_pass(
                    harness.evaluate(
                        "advance",
                        _advance_payload(
                            campaign_id,
                            cursor,
                            "dispatch_config",
                            {"fixture_id": fixture["fixture_id"], "role": role},
                        ),
                    ),
                    "campaign:dispatch_config",
                )
                cursor = dispatched["cursor"]
                profile_id = "direct/v1" if role == "champion" else challenger_profile
                run_ref = harness.complete_run(
                    fixture=fixture,
                    role=role,
                    profile_id=profile_id,
                    qwen_identity_sha256=runtime["qwen_identity_sha256"],
                    tool_policy_sha256=preparation["tool_policy_sha256"],
                )
                rows = _artifact_rows(private, files)
                artifact_sha256 = json_sha256(
                    [
                        {
                            "relative_path": row["relative_path"],
                            "content_sha256": _sha_bytes(row["content"].encode("utf-8")),
                        }
                        for row in rows
                    ]
                )
                artifacts[role] = rows
                artifact_sha256s[role] = artifact_sha256
                observation = _config_observation(
                    preparation=preparation,
                    fixture=fixture,
                    role=role,
                    run_ref=run_ref,
                    artifact_sha256=artifact_sha256,
                    check_report=check_report,
                )
                observed = _require_pass(
                    harness.evaluate(
                        "advance",
                        _advance_payload(
                            campaign_id,
                            cursor,
                            "observe_config",
                            {"observation": observation},
                        ),
                    ),
                    "campaign:observe_config",
                )
                cursor = observed["cursor"]

            packet_report = sanitize_sol_packet(
                catalog,
                fixture["fixture_id"],
                {"A": artifacts["champion"], "B": artifacts["challenger"]},
            )
            if packet_report["status"] != "PASS":
                raise ValueError(
                    "campaign:packet_invalid:" + ",".join(packet_report["issues"])
                )
            review_dispatch = _require_pass(
                harness.evaluate(
                    "advance",
                    _advance_payload(
                        campaign_id,
                        cursor,
                        "dispatch_review",
                        {
                            "fixture_id": fixture["fixture_id"],
                            "blind_packet_sha256": packet_report[
                                "blind_packet_sha256"
                            ],
                            "input_tokens": packet_report["packet"][
                                "input_token_upper_bound"
                            ],
                            "artifact_sha256s": [
                                artifact_sha256s["champion"],
                                artifact_sha256s["challenger"],
                            ],
                        },
                    ),
                ),
                "campaign:dispatch_review",
            )
            cursor = review_dispatch["cursor"]
            public_intent = review_dispatch["intents"][0]
            review = _review_observation(
                preparation=preparation,
                fixture=fixture,
                public_intent=public_intent,
                packet_sha256=packet_report["blind_packet_sha256"],
            )
            reviewed = _require_pass(
                harness.evaluate(
                    "advance",
                    _advance_payload(
                        campaign_id,
                        cursor,
                        "observe_review",
                        {"observation": review},
                    ),
                ),
                "campaign:observe_review",
            )
            cursor = reviewed["cursor"]

            if (fixture_index + 1) % 4 == 0:
                reconciled = _require_pass(
                    harness.evaluate(
                        "advance",
                        _advance_payload(campaign_id, cursor, "reconcile", {}),
                    ),
                    "campaign:commit_rung",
                )
                cursor = reconciled["cursor"]
                rung_timings.append((time.monotonic() - rung_started) * 1000)
                current_rung += 1
                rung_started = time.monotonic()
                if fixture_index == 19:
                    terminal = _require_pass(
                        harness.evaluate(
                            "advance",
                            _advance_payload(campaign_id, cursor, "reconcile", {}),
                        ),
                        "campaign:terminal",
                    )
                    cursor = terminal["cursor"]
        inspect_started = time.monotonic()
        inspection = _require_pass(
            harness.evaluate(
                "inspect",
                {
                    "schema": frontier.INSPECTION_QUERY_SCHEMA,
                    "campaign_id": campaign_id,
                    "after_seq": 0,
                    "max_events": 64,
                },
            ),
            "campaign:inspect",
        )
        inspect_elapsed_ms = (time.monotonic() - inspect_started) * 1000
        recording = harness.recording()
    except Exception:
        harness.close()
        raise
    finally:
        harness.close()

    if terminal is None or inspection is None or terminal.get("terminal") is None:
        raise ValueError("campaign:terminal_missing")
    terminal_record = terminal["terminal"]
    successor = terminal_record["successor"]
    deterministic = {
        "schema": QUALIFICATION_SCHEMA,
        "catalog_sha256": catalog["catalog_sha256"],
        "corpus_sha256": preparation["corpus_sha256"],
        "archive_sha256": preparation["archive_sha256"],
        "candidate_sha256": preparation["challenger"]["candidate_sha256"],
        "transport_qualification_sha256": transport["qualification_sha256"],
        "source_closure_sha256": transport["source_closure_sha256"],
        "campaign_id": campaign_id,
        "holdout_group_id": holdout_group_id,
        "recording_sha256": recording["recording_sha256"],
        "terminal_sha256": terminal_record["terminal_sha256"],
        "terminal_outcome": terminal_record["outcome"],
        "successor_sha256": successor["successor_sha256"],
        "sealed_rungs": inspection["sealed_rungs"],
        "completed_fixtures": inspection["completed_fixtures"],
        "provider_free": True,
        "external_dispatches": 0,
        "credential_reads": 0,
        "network_calls": 0,
        "model_calls": 0,
        "hosted_calls": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
    }
    elapsed_ms = (time.monotonic() - started_at) * 1000
    timings_ms = {
        "total": elapsed_ms,
        "max_rung": max(rung_timings),
        "inspect_successor": inspect_elapsed_ms,
    }
    performance_issues = []
    if timings_ms["max_rung"] > 10_000:
        performance_issues.append("performance:rung_bound_exceeded")
    if timings_ms["total"] > 60_000:
        performance_issues.append("performance:campaign_bound_exceeded")
    if timings_ms["inspect_successor"] > 2_000:
        performance_issues.append("performance:inspect_successor_bound_exceeded")
    return {
        **deterministic,
        "status": "PASS" if not performance_issues else "FAIL",
        "issues": performance_issues,
        "corpus_shape": {
            "catalog_fixtures": 30,
            "campaign_fixtures": 20,
            "rungs": 5,
            "fixtures_per_rung": 4,
            "partitions": list(_PARTITIONS),
        },
        "runtime_evidence": {
            "python_implementation": sys.implementation.name,
            "python_version": ".".join(str(item) for item in sys.version_info[:3]),
            "source_file_count": transport["source_file_count"],
            "source_closure_sha256": transport["source_closure_sha256"],
            "qwen_identity_sha256": transport["qwen_identity_sha256"],
            "sol_identity_sha256": transport["sol_identity_sha256"],
        },
        "performance_status": "PASS" if not performance_issues else "FAIL",
        "performance_bounds_ms": {
            "rung": 10_000,
            "campaign": 60_000,
            "inspect_successor": 2_000,
        },
        "timings_ms": timings_ms,
        "recording": recording,
        "qualification_sha256": json_sha256(deterministic),
    }


def replay_provider_free_campaign(
    *,
    catalog: Mapping[str, Any],
    archive: Mapping[str, Any],
    recording: Mapping[str, Any],
    store: Any,
) -> dict[str, Any]:
    if (
        not isinstance(recording, Mapping)
        or recording.get("schema") != CAMPAIGN_RECORDING_SCHEMA
        or recording.get("recording_sha256")
        != json_sha256(
            {key: value for key, value in recording.items() if key != "recording_sha256"}
        )
        or recording.get("provider_free") is not True
        or recording.get("external_dispatches") != 0
        or recording.get("model_calls") != 0
        or recording.get("hosted_calls") != 0
    ):
        return {
            "schema": QUALIFICATION_SCHEMA,
            "status": "FAIL",
            "issues": ["replay:recording_invalid"],
            "external_dispatches": 0,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    return run_provider_free_campaign(
        catalog=catalog,
        archive=archive,
        store=store,
        campaign_id=recording["campaign_id"],
        holdout_group_id=recording["holdout_group_id"],
        _expected_recording=recording,
    )


def _objective_terminal_probe(
    *,
    catalog: Mapping[str, Any],
    archive: Mapping[str, Any],
    campaign_id: str,
    target_role: str,
    target_check: str,
    target_status: str,
    run_identity_drift: bool = False,
) -> dict[str, Any]:
    """Drive one real fixture pair to an objective terminal through v2."""

    store = run_store.InMemoryRunStore()
    resolver = _RunResolver(store)
    tower = control_tower.ControlTower(
        clock_ms=lambda: 1_000,
        frontier_store=store,
        frontier_run_resolver=resolver,
    )
    payload = build_provider_free_prepare_payload(
        catalog=catalog,
        archive=archive,
        campaign_id=campaign_id,
        holdout_group_id="holdout-a",
        authority_scope_sha256=json_sha256(
            {"probe": "objective-terminal", "campaign_id": campaign_id}
        ),
    )
    preparation_report = control_tower.evaluate_control_tower(
        _v2_program("prepare", payload, 1), tower=tower
    )
    if preparation_report.get("status") != "PASS":
        return {"status": "FAIL", "issues": ["probe:prepare_failed"]}
    preparation = preparation_report["result"]
    registration = frontier.seal_authority_registration(
        {
            "schema": frontier.AUTHORITY_REGISTRATION_DRAFT_SCHEMA,
            "class_id": frontier.AUTHORITY_CLASS,
            "campaign_id": campaign_id,
            "authority_scope_sha256": preparation["authority_scope_sha256"],
            "registration_id": campaign_id + "-registration",
            "registered_at_ms": 1_000,
            "provider_free": True,
        }
    )
    started = control_tower.evaluate_control_tower(
        _v2_program(
            "advance",
            _advance_payload(
                campaign_id,
                frontier.genesis_cursor(campaign_id),
                "start",
                {
                    "preparation": preparation,
                    "authority_registration": registration,
                },
            ),
            2,
        ),
        tower=tower,
    )
    if started.get("status") != "PASS":
        return {"status": "FAIL", "issues": ["probe:start_failed"]}
    cursor = started["result"]["cursor"]
    fixture = preparation["fixtures"][0]
    reserved = control_tower.evaluate_control_tower(
        _v2_program(
            "advance",
            _advance_payload(
                campaign_id,
                cursor,
                "reserve_pair",
                {"fixture_id": fixture["fixture_id"]},
            ),
            3,
        ),
        tower=tower,
    )
    if reserved.get("status") != "PASS":
        return {"status": "FAIL", "issues": ["probe:reserve_failed"]}
    cursor = reserved["result"]["cursor"]
    private = catalog_fixture(catalog, fixture["fixture_id"])
    files = _synthetic_files(private)
    check_report = evaluate_fixture_checks(catalog, fixture["fixture_id"], files)
    rows = _artifact_rows(private, files)
    artifact_sha256 = json_sha256(
        [
            {
                "relative_path": row["relative_path"],
                "content_sha256": _sha_bytes(row["content"].encode("utf-8")),
            }
            for row in rows
        ]
    )
    challenger_profile = preparation["challenger"]["genome"]["profile_id"]
    for index, role in enumerate(("champion", "challenger"), start=4):
        dispatched = control_tower.evaluate_control_tower(
            _v2_program(
                "advance",
                _advance_payload(
                    campaign_id,
                    cursor,
                    "dispatch_config",
                    {"fixture_id": fixture["fixture_id"], "role": role},
                ),
                index * 2,
            ),
            tower=tower,
        )
        if dispatched.get("status") != "PASS":
            return {"status": "FAIL", "issues": ["probe:dispatch_failed"]}
        cursor = dispatched["result"]["cursor"]
        profile_id = "direct/v1" if role == "champion" else challenger_profile
        run_ref = resolver.complete_run(
            campaign_id=campaign_id,
            fixture=fixture,
            role=role,
            profile_id=profile_id,
            qwen_identity_sha256=(
                "0" * 64
                if run_identity_drift and role == target_role
                else preparation["runtime_contract"]["qwen_identity_sha256"]
            ),
            tool_policy_sha256=preparation["tool_policy_sha256"],
        )
        observation = _config_observation(
            preparation=preparation,
            fixture=fixture,
            role=role,
            run_ref=run_ref,
            artifact_sha256=artifact_sha256,
            check_report=check_report,
        )
        if role == target_role:
            draft = deepcopy(observation)
            draft.pop("observation_sha256")
            draft["schema"] = frontier.CONFIG_OBSERVATION_DRAFT_SCHEMA
            draft["objective_checks"][target_check] = target_status
            observation = frontier.seal_config_observation(draft)
        observed = control_tower.evaluate_control_tower(
            _v2_program(
                "advance",
                _advance_payload(
                    campaign_id,
                    cursor,
                    "observe_config",
                    {"observation": observation},
                ),
                index * 2 + 1,
            ),
            tower=tower,
        )
        if run_identity_drift and role == target_role:
            return {
                "status": (
                    "PASS"
                    if observed.get("status") == "FAIL"
                    and observed.get("issues") == ["advance:run_evidence_invalid"]
                    else "FAIL"
                ),
                "issues": (
                    []
                    if observed.get("status") == "FAIL"
                    else ["probe:identity_drift_accepted"]
                ),
                "outcome": "IDENTITY_DRIFT_REFUSED",
                "reason": (
                    observed.get("issues", [None])[0]
                    if observed.get("issues")
                    else None
                ),
                "successor_kind": None,
                "terminal_sha256": None,
            }
        if observed.get("status") != "PASS":
            return {"status": "FAIL", "issues": ["probe:observation_failed"]}
        cursor = observed["result"]["cursor"]
        if observed["result"].get("next_action") == "SEAL_TERMINAL":
            break
    terminal = control_tower.evaluate_control_tower(
        _v2_program(
            "advance",
            _advance_payload(campaign_id, cursor, "reconcile", {}),
            20,
        ),
        tower=tower,
    )
    if terminal.get("status") != "PASS":
        return {"status": "FAIL", "issues": ["probe:terminal_failed"]}
    record = terminal.get("result", {}).get("terminal")
    if not isinstance(record, Mapping):
        return {"status": "FAIL", "issues": ["probe:terminal_missing"]}
    return {
        "status": "PASS",
        "issues": [],
        "outcome": record["outcome"],
        "reason": record["reason"],
        "successor_kind": record["successor"]["kind"],
        "terminal_sha256": record["terminal_sha256"],
    }


def run_real_manifest_refusal_matrix(
    *, catalog: Mapping[str, Any], archive: Mapping[str, Any]
) -> dict[str, Any]:
    """Re-exercise the closed refusal families against the real manifest set.

    The deep transition matrix remains owned by ``FrontierCampaignController``;
    this qualification proves that the complete compiled corpus reaches that
    same seam, survives durable restart, and cannot widen each adjacent ingress
    contract.  Every check below performs a real validator or public evaluator
    operation—none is a prose assertion.
    """

    issues: list[str] = []
    checks: dict[str, str] = {}
    corpus = compile_frontier_corpus(catalog, "holdout-a")
    source_root = Path(__file__).resolve().parents[3]
    transport = qualify_synthetic_transports(source_root)
    runtime = _frontier_runtime_contract(transport)

    def mark(name: str, passed: bool) -> None:
        checks[name] = "PASS" if passed else "FAIL"
        if not passed:
            issues.append("matrix:" + name + "_failed")

    base_payload = {
        "schema": frontier.PREPARE_SCHEMA,
        "campaign_id": "issue151-refusal-matrix",
        "archive": deepcopy(dict(archive)),
        "corpus": corpus,
        "runtime_contract": runtime,
        "authority_scope_sha256": json_sha256({"matrix": "authority"}),
        "prompt_bundle_sha256": json_sha256({"matrix": "prompts"}),
        "verification_policy_sha256": json_sha256({"matrix": "checks"}),
        "cost_weights_sha256": json_sha256({"matrix": "cost"}),
        "tool_policy_sha256": json_sha256(catalog["tool_policy"]),
        "prepared_at_ms": 1_000,
    }
    tower = control_tower.ControlTower(clock_ms=lambda: 1_000)
    prepared_report = control_tower.evaluate_control_tower(
        _v2_program("prepare", base_payload, 1), tower=tower
    )
    prepared = prepared_report.get("result")
    mark(
        "schema",
        prepared_report.get("status") == "PASS"
        and control_tower.evaluate_control_tower(
            {
                **_v2_program("prepare", base_payload, 2),
                "unknown": True,
            },
            tower=tower,
        ).get("status")
        == "FAIL",
    )

    privacy = deepcopy(base_payload)
    privacy["corpus"]["fixtures"][0]["privacy_class"] = "local_only"
    mark(
        "custody",
        control_tower.evaluate_control_tower(
            _v2_program("prepare", privacy, 3), tower=tower
        ).get("status")
        == "FAIL",
    )
    bad_tool_record = _qwen_record("content_only")
    bad_tool_record["tool_calls"][0]["name"] = "exec"
    mark(
        "tool",
        catalog["tool_policy"]["allowed_tools"] == QWEN_ALLOWED_TOOLS
        and set(catalog["tool_policy"]["denied_capabilities"])
        == set(QWEN_DENIED_CAPABILITIES)
        and _observe_qwen_record(bad_tool_record) == "TOOL_POLICY_FAILURE",
    )
    over_budget_record = _qwen_record("over_budget")
    mark(
        "budget",
        isinstance(prepared, Mapping)
        and prepared["budget_contract"]["aggregate_reserved_tokens"] == 2_400_000
        and prepared["budget_contract"]["sol_review_limit"] == 20
        and _observe_qwen_record(over_budget_record) == "OVER_BUDGET",
    )

    if isinstance(prepared, Mapping):
        wrong_registration = frontier.seal_authority_registration(
            {
                "schema": frontier.AUTHORITY_REGISTRATION_DRAFT_SCHEMA,
                "class_id": frontier.AUTHORITY_CLASS,
                "campaign_id": prepared["campaign_id"],
                "authority_scope_sha256": "0" * 64,
                "registration_id": "matrix-wrong-authority",
                "registered_at_ms": 1_000,
                "provider_free": True,
            }
        )
        authority_report = control_tower.evaluate_control_tower(
            _v2_program(
                "advance",
                _advance_payload(
                    prepared["campaign_id"],
                    frontier.genesis_cursor(prepared["campaign_id"]),
                    "start",
                    {
                        "preparation": prepared,
                        "authority_registration": wrong_registration,
                    },
                ),
                4,
            ),
            tower=tower,
        )
        mark("authority", authority_report.get("status") == "FAIL")

        stale = frontier.genesis_cursor(prepared["campaign_id"])
        stale["seq"] = 1
        cursor_report = control_tower.evaluate_control_tower(
            _v2_program(
                "advance",
                _advance_payload(
                    prepared["campaign_id"], stale, "start", {}
                ),
                5,
            ),
            tower=tower,
        )
        mark("cursor", cursor_report.get("status") == "FAIL")
    else:
        mark("authority", False)
        mark("cursor", False)

    malformed_qwen = _qwen_record("malformed")
    drift_qwen = _qwen_record("identity_drift")
    unknown_terminal = _objective_terminal_probe(
        catalog=catalog,
        archive=archive,
        campaign_id="issue151-matrix-objective-unknown",
        target_role="champion",
        target_check="correctness",
        target_status="UNKNOWN",
    )
    champion_retained = _objective_terminal_probe(
        catalog=catalog,
        archive=archive,
        campaign_id="issue151-matrix-champion-retained",
        target_role="challenger",
        target_check="correctness",
        target_status="FAIL",
    )
    safety_stop = _objective_terminal_probe(
        catalog=catalog,
        archive=archive,
        campaign_id="issue151-matrix-safety-stop",
        target_role="challenger",
        target_check="safety",
        target_status="FAIL",
    )
    run_identity_drift = _objective_terminal_probe(
        catalog=catalog,
        archive=archive,
        campaign_id="issue151-matrix-run-identity-drift",
        target_role="champion",
        target_check="correctness",
        target_status="PASS",
        run_identity_drift=True,
    )
    mark(
        "unknown_observation",
        _observe_qwen_record(malformed_qwen) == "MALFORMED"
        and unknown_terminal.get("status") == "PASS"
        and unknown_terminal.get("outcome") == "INCONCLUSIVE",
    )
    mark(
        "identity_drift",
        _observe_qwen_record(drift_qwen) == "IDENTITY_DRIFT"
        and run_identity_drift.get("status") == "PASS"
        and run_identity_drift.get("outcome") == "IDENTITY_DRIFT_REFUSED",
    )

    with tempfile.TemporaryDirectory(prefix="orch-dork-151-matrix-") as raw:
        durable = run_provider_free_campaign(
            catalog=catalog,
            archive=archive,
            store=run_store.SQLiteRunStore(Path(raw) / "matrix.sqlite3"),
            campaign_id="issue151-matrix-durable",
            holdout_group_id="holdout-a",
            restart_every_transition=True,
        )
    mark("crash_pre_post", durable.get("status") == "PASS")

    def private_projection_clean(value: Any) -> bool:
        serialized = json.dumps(value, sort_keys=True)
        return all(
            forbidden not in serialized
            for forbidden in (
                '"snapshot_files"',
                '"hidden_checks":',
                '"expected_result"',
                '"response_body"',
                '"transport_body"',
            )
        )

    leaking_control = deepcopy(durable)
    leaking_control["snapshot_files"] = {"private.py": "forbidden"}
    mark(
        "private_projection",
        durable.get("status") == "PASS"
        and private_projection_clean(durable)
        and not private_projection_clean(leaking_control),
    )
    mark(
        "terminal_branches",
        durable.get("terminal_outcome") == "CHALLENGER_RETAINED"
        and isinstance(durable.get("terminal_sha256"), str)
        and isinstance(durable.get("successor_sha256"), str),
    )

    exhausted_archive = deepcopy(dict(archive))
    exhausted_archive["frontier"] = []
    exhausted_archive["frontier_candidate_sha256s"] = []
    exhausted_archive["feasible_count"] = 0
    exhausted_archive["pruned_count"] = exhausted_archive["candidate_count"]
    exhausted_archive["decision_counts"] = {
        "FEASIBLE": 0,
        "PRUNED": exhausted_archive["candidate_count"],
    }
    exhausted_archive["archive_sha256"] = topology_lab.json_sha256(
        {
            key: value
            for key, value in exhausted_archive.items()
            if key != "archive_sha256"
        }
    )
    exhausted_payload = build_provider_free_prepare_payload(
        catalog=catalog,
        archive=exhausted_archive,
        campaign_id="issue151-matrix-exhausted",
        holdout_group_id="holdout-a",
        authority_scope_sha256=json_sha256({"matrix": "exhausted"}),
    )
    exhausted_report = control_tower.evaluate_control_tower(
        _v2_program("prepare", exhausted_payload, 11),
        tower=control_tower.ControlTower(clock_ms=lambda: 1_000),
    )
    terminal_branches_passed = (
        checks["terminal_branches"] == "PASS"
        and champion_retained.get("status") == "PASS"
        and champion_retained.get("outcome") == "CHAMPION_RETAINED"
        and champion_retained.get("successor_kind") == "NEXT_ELIGIBLE"
        and unknown_terminal.get("status") == "PASS"
        and unknown_terminal.get("outcome") == "INCONCLUSIVE"
        and unknown_terminal.get("successor_kind") == "DIAGNOSIS"
        and safety_stop.get("status") == "PASS"
        and safety_stop.get("outcome") == "CHAMPION_RETAINED"
        and exhausted_report.get("status") == "PASS"
        and exhausted_report.get("result", {}).get("preparation_status")
        == "NO_ELIGIBLE_CHALLENGER"
        and exhausted_report.get("result", {})
        .get("terminal", {})
        .get("successor", {})
        .get("kind")
        == "STOP"
        and exhausted_report.get("result", {}).get("model_calls") == 0
    )
    mark("terminal_branches", terminal_branches_passed)

    # Cancellation and timeout use the same public controller with real corpus.
    if isinstance(prepared, Mapping):
        cancellation_store = run_store.InMemoryRunStore()
        cancellation_tower = control_tower.ControlTower(
            clock_ms=lambda: 1_000,
            frontier_store=cancellation_store,
        )
        registration = frontier.seal_authority_registration(
            {
                "schema": frontier.AUTHORITY_REGISTRATION_DRAFT_SCHEMA,
                "class_id": frontier.AUTHORITY_CLASS,
                "campaign_id": prepared["campaign_id"],
                "authority_scope_sha256": prepared["authority_scope_sha256"],
                "registration_id": "matrix-cancel-registration",
                "registered_at_ms": 1_000,
                "provider_free": True,
            }
        )
        start = control_tower.evaluate_control_tower(
            _v2_program(
                "advance",
                _advance_payload(
                    prepared["campaign_id"],
                    frontier.genesis_cursor(prepared["campaign_id"]),
                    "start",
                    {"preparation": prepared, "authority_registration": registration},
                ),
                6,
            ),
            tower=cancellation_tower,
        )
        if start.get("status") == "PASS":
            cancelled = control_tower.evaluate_control_tower(
                _v2_program(
                    "advance",
                    _advance_payload(
                        prepared["campaign_id"],
                        start["result"]["cursor"],
                        "cancel",
                        {
                            "reason": "qualification matrix",
                            "cleanup_status": "UNKNOWN",
                            "owned_descendants": 0,
                            "cleanup_evidence_sha256": json_sha256({"cleanup": "unknown"}),
                            "elapsed_ms": 60_001,
                        },
                    ),
                    7,
                ),
                tower=cancellation_tower,
            )
        else:
            cancelled = {}
        mark(
            "cancellation",
            cancelled.get("status") == "PASS"
            and cancelled.get("result", {}).get("terminal", {}).get("outcome")
            == "CANCELLED",
        )
        timeout_now = [1_000]
        timeout_id = "issue151-matrix-timeout"
        timeout_payload = build_provider_free_prepare_payload(
            catalog=catalog,
            archive=archive,
            campaign_id=timeout_id,
            holdout_group_id="holdout-a",
            authority_scope_sha256=json_sha256(
                {"matrix": "timeout", "campaign_id": timeout_id}
            ),
        )
        timeout_store = run_store.InMemoryRunStore()
        timeout_tower = control_tower.ControlTower(
            clock_ms=lambda: timeout_now[0],
            frontier_store=timeout_store,
        )
        timeout_prepared_report = control_tower.evaluate_control_tower(
            _v2_program("prepare", timeout_payload, 8), tower=timeout_tower
        )
        timeout_prepared = timeout_prepared_report.get("result", {})
        timeout_registration = frontier.seal_authority_registration(
            {
                "schema": frontier.AUTHORITY_REGISTRATION_DRAFT_SCHEMA,
                "class_id": frontier.AUTHORITY_CLASS,
                "campaign_id": timeout_id,
                "authority_scope_sha256": timeout_prepared.get(
                    "authority_scope_sha256"
                ),
                "registration_id": "matrix-timeout-registration",
                "registered_at_ms": 1_000,
                "provider_free": True,
            }
        )
        timeout_start = control_tower.evaluate_control_tower(
            _v2_program(
                "advance",
                _advance_payload(
                    timeout_id,
                    frontier.genesis_cursor(timeout_id),
                    "start",
                    {
                        "preparation": timeout_prepared,
                        "authority_registration": timeout_registration,
                    },
                ),
                9,
            ),
            tower=timeout_tower,
        )
        timeout_now[0] += 36_000_001
        timeout_terminal = control_tower.evaluate_control_tower(
            _v2_program(
                "advance",
                _advance_payload(
                    timeout_id,
                    timeout_start.get("result", {}).get("cursor", {}),
                    "reconcile",
                    {},
                ),
                10,
            ),
            tower=timeout_tower,
        )
        mark(
            "timeout",
            timeout_prepared_report.get("status") == "PASS"
            and timeout_start.get("status") == "PASS"
            and timeout_terminal.get("status") == "PASS"
            and timeout_terminal.get("result", {})
            .get("terminal", {})
            .get("outcome")
            == "TIMEOUT",
        )
    else:
        mark("cancellation", False)
        mark("timeout", False)

    core = {
        "schema": REFUSAL_MATRIX_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(issues),
        "catalog_sha256": catalog.get("catalog_sha256"),
        "checks": checks,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
    }
    return {**core, "matrix_sha256": json_sha256(core)}


__all__ = [
    "CATALOG_SCHEMA",
    "MODEL_TASK_SCHEMA",
    "SNAPSHOT_RECEIPT_SCHEMA",
    "CHECK_REPORT_SCHEMA",
    "SOL_PACKET_SCHEMA",
    "TRANSPORT_QUALIFICATION_SCHEMA",
    "INSTALLED_QUALIFICATION_SCHEMA",
    "CAMPAIGN_RECORDING_SCHEMA",
    "QUALIFICATION_SCHEMA",
    "QWEN_ALLOWED_TOOLS",
    "QWEN_ALLOWED_COMMANDS",
    "QWEN_DENIED_CAPABILITIES",
    "ISSUE111_R5_ITEMS",
    "ISSUE111_R5_COUPLED_PAIRS",
    "json_sha256",
    "validate_catalog",
    "load_catalog",
    "catalog_fixture",
    "model_task",
    "compile_frontier_corpus",
    "next_holdout_group",
    "build_qualification_archive",
    "materialize_snapshot",
    "evaluate_fixture_checks",
    "sanitize_sol_packet",
    "live_runtime_contract",
    "validate_live_runtime_contract",
    "qualify_synthetic_transports",
    "validate_transport_qualification",
    "qualify_installed_runtime",
    "qualify_holdout_isolation",
    "frontier_runtime_from_live_contract",
    "build_provider_free_prepare_payload",
    "build_live_prepare_payload",
    "run_provider_free_campaign",
    "replay_provider_free_campaign",
    "run_real_manifest_refusal_matrix",
]


if __name__ == "__main__":
    raise SystemExit("Import the provider-free qualification helpers; no CLI is provided.")
