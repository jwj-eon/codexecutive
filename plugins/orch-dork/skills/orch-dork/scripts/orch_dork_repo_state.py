#!/usr/bin/env python3
"""Deterministic evaluators for versioned repository state.

North star phase P3 (Part II section 20) builds the provider-free, purely
deterministic state-layer evaluators that decide from declared evidence only:
write-set overlap detection across nodes, optimistic-concurrency (stale write)
rejection against authoritative file versions, and the worktree-per-node
integration-release gate. None of the functions here read the filesystem, run
git, or touch a provider; enforcement belongs to the later state layer.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence


WRITE_SET_PROGRAM_SCHEMA = "orch-dork/write-set-program/v1"
WRITE_SET_REPORT_SCHEMA = "orch-dork/write-set-report/v1"
STALE_WRITE_PROGRAM_SCHEMA = "orch-dork/stale-write-program/v1"
STALE_WRITE_REPORT_SCHEMA = "orch-dork/stale-write-report/v1"
INTEGRATION_RELEASE_PROGRAM_SCHEMA = "orch-dork/integration-release-program/v1"
INTEGRATION_RELEASE_REPORT_SCHEMA = "orch-dork/integration-release-report/v1"

WORKSPACE_BASE = "WORKSPACE"
_COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")


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


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, fields: set[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, f"{path}:not_object")
        return False
    for key in sorted(fields - set(value)):
        _issue(issues, f"{path}:missing:{key}")
    for key in sorted(set(value) - fields):
        _issue(issues, f"{path}:unknown:{key}")
    return set(value) == fields


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096


def _base_commit(value: Any) -> bool:
    return (
        isinstance(value, str)
        and (_COMMIT.fullmatch(value) is not None or value == WORKSPACE_BASE)
    )


def _report_footer(core: dict[str, Any]) -> dict[str, Any]:
    """Attach the provider-free attestation fields and the sealed report sha."""

    attested = {
        **core,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "evidence_tier": "submitted",
    }
    return {**attested, "report_sha256": _sha256(attested)}


def _clean_path(entry: Any, path: str, issues: list[str]) -> str | None:
    """Validate one repo-relative path or glob pattern entry."""

    if not isinstance(entry, str) or not entry.strip():
        _issue(issues, f"{path}:invalid")
        return None
    value = entry.strip()
    if value.startswith("/"):
        _issue(issues, f"{path}:path_absolute")
        return None
    if any(part == ".." for part in value.split("/")):
        _issue(issues, f"{path}:path_traversal")
        return None
    return value


def _path_set(value: Any, path: str, issues: list[str]) -> list[str]:
    """Validate a list of repo-relative paths or glob patterns."""

    if not isinstance(value, list):
        _issue(issues, f"{path}:not_array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        clean = _clean_path(item, f"{path}[{index}]", issues)
        if clean is not None:
            result.append(clean)
    if len(result) != len(set(result)):
        _issue(issues, f"{path}:duplicates")
    return result


def _overlap_kind(first: str, second: str) -> str | None:
    """Classify the overlap of two write/read patterns.

    Returns "exact" when the entries are identical, "glob" when one pattern
    plausibly covers the other (fnmatch in both directions plus the "d/**"
    directory-containment prefix rule), or None when they are disjoint.
    """

    if first == second:
        return "exact"
    if fnmatch.fnmatchcase(second, first) or fnmatch.fnmatchcase(first, second):
        return "glob"
    for needle, base in ((second, first), (first, second)):
        prefix = base[:-3] if base.endswith("/**") else None
        if prefix is not None and prefix and needle.startswith(prefix):
            return "glob"
    return None


def _overlap_label(kind: str, first: str, second: str) -> str:
    if kind == "exact":
        return first
    return "#".join(sorted((first, second)))


def validate_write_sets(program: Any) -> dict[str, Any]:
    """Detect write-set overlaps and advisory read/write hazards between nodes.

    Overlaps are not auto-fatal: they force the caller to serialize the
    involved node pairs. Read/write hazards are advisory and never fail a
    program.
    """

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(value, {"schema", "nodes"}, "program", issues)
    if value.get("schema") != WRITE_SET_PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")

    nodes_value = value.get("nodes")
    if not isinstance(nodes_value, list):
        _issue(issues, "nodes:not_array")
        nodes_value = []
    if not nodes_value:
        _issue(issues, "nodes:empty")

    node_ids: list[str] = []
    normalized: list[dict[str, Any]] = []
    for index, node in enumerate(nodes_value):
        path = f"node[{index}]"
        _exact(
            node,
            {"id", "base_commit", "read_set", "expected_write_set"},
            path,
            issues,
        )
        if not isinstance(node, Mapping):
            continue
        node_id = node.get("id")
        if not _identifier(node_id):
            _issue(issues, f"{path}:id_invalid")
            node_id = f"<invalid-{index}>"
        else:
            node_ids.append(str(node_id))
        if not _base_commit(node.get("base_commit")):
            _issue(issues, f"{path}:base_commit_invalid")
        reads = _path_set(node.get("read_set"), f"{path}.read_set", issues)
        writes = _path_set(
            node.get("expected_write_set"), f"{path}.expected_write_set", issues
        )
        if not writes:
            _issue(issues, f"{path}:expected_write_set:empty")
        normalized.append(
            {"id": str(node_id), "read_set": reads, "expected_write_set": writes}
        )
    if len(node_ids) != len(set(node_ids)):
        _issue(issues, "nodes:duplicate_ids")

    conflicts: list[dict[str, Any]] = []
    seen_conflicts: set[tuple[str, str, tuple[str, ...]]] = set()
    for left in normalized:
        for right in normalized:
            if left is right:
                continue
            node_pair = tuple(sorted((left["id"], right["id"])))
            for left_entry in left["expected_write_set"]:
                for right_entry in right["expected_write_set"]:
                    kind = _overlap_kind(left_entry, right_entry)
                    if kind is None:
                        continue
                    label = _overlap_label(kind, left_entry, right_entry)
                    key = (kind, label, node_pair)
                    if key in seen_conflicts:
                        continue
                    seen_conflicts.add(key)
                    conflicts.append(
                        {
                            "path_or_pattern": label,
                            "node_ids": list(node_pair),
                            "kind": kind,
                        }
                    )
    conflicts.sort(
        key=lambda item: (
            item["kind"],
            item["path_or_pattern"],
            tuple(item["node_ids"]),
        )
    )
    required_serializations: list[list[str]] = [
        list(item["node_ids"]) for item in conflicts
    ]

    hazards: list[dict[str, Any]] = []
    seen_hazards: set[tuple[str, str, str, str]] = set()
    for node in normalized:
        for entry in node["expected_write_set"]:
            if entry not in node["read_set"]:
                key = ("undeclared_read", node["id"], entry, "")
                if key not in seen_hazards:
                    seen_hazards.add(key)
                    hazards.append(
                        {
                            "kind": "undeclared_read",
                            "node_id": node["id"],
                            "path_or_pattern": entry,
                        }
                    )
        for other in normalized:
            if other is node:
                continue
            for entry in node["expected_write_set"]:
                for other_read in other["read_set"]:
                    kind = _overlap_kind(entry, other_read)
                    if kind is None:
                        continue
                    key = ("read_write_overlap", node["id"], entry, other_read)
                    if key in seen_hazards:
                        continue
                    seen_hazards.add(key)
                    hazards.append(
                        {
                            "kind": "read_write_overlap",
                            "node_id": node["id"],
                            "path_or_pattern": entry,
                            "other_node_id": other["id"],
                            "other_read": other_read,
                        }
                    )
    hazards.sort(
        key=lambda item: (
            item["kind"],
            item["node_id"],
            item["path_or_pattern"],
            item.get("other_node_id", ""),
        )
    )

    if issues:
        status = "FAIL"
    elif conflicts:
        status = "PASS_WITH_CONFLICTS"
    else:
        status = "PASS"
    core = {
        "schema": WRITE_SET_REPORT_SCHEMA,
        "status": status,
        "issues": sorted(issues),
        "node_count": len(normalized),
        "conflicts": conflicts,
        "required_serializations": required_serializations,
        "read_write_hazards": hazards,
    }
    return _report_footer(core)



def evaluate_stale_writes(program: Any) -> dict[str, Any]:
    """Reject stale or unread writes against the authoritative file versions.

    Writes are processed in declared order. An accepted write bumps that path's
    current version, so later writes in the same batch see the new version. A
    based_on entry of version -1 asserts the path is absent and validates only
    while the path is not among the authoritative versions.
    """

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(value, {"schema", "file_versions", "writes"}, "program", issues)
    if value.get("schema") != STALE_WRITE_PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")

    versions: dict[str, int] = {}
    file_versions = value.get("file_versions")
    if not isinstance(file_versions, list):
        _issue(issues, "file_versions:not_array")
        file_versions = []
    for index, item in enumerate(file_versions):
        path_label = f"file_versions[{index}]"
        _exact(item, {"path", "version"}, path_label, issues)
        if not isinstance(item, Mapping):
            continue
        path = item.get("path")
        if not _text(path):
            _issue(issues, f"{path_label}:path_invalid")
            continue
        version = item.get("version")
        if type(version) is not int or version < 0:
            _issue(issues, f"{path_label}:version_invalid")
            continue
        if str(path) in versions:
            _issue(issues, f"file_versions:duplicate_path:{path}")
        versions[str(path)] = version

    writes_value = value.get("writes")
    if not isinstance(writes_value, list):
        _issue(issues, "writes:not_array")
        writes_value = []

    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for index, write in enumerate(writes_value):
        write_issues: list[str] = []
        path_label = f"write[{index}]"
        _exact(
            write,
            {"node_id", "path", "based_on", "write_id"},
            path_label,
            issues,
        )
        if not isinstance(write, Mapping):
            continue
        if not _identifier(write.get("node_id")):
            _issue(write_issues, f"{path_label}:node_id_invalid")
        write_id = write.get("write_id")
        if not _text(write_id):
            _issue(write_issues, f"{path_label}:write_id_invalid")
        target = write.get("path")
        if not _text(target):
            _issue(write_issues, f"{path_label}:path_invalid")
            target = None
        based_on = write.get("based_on")
        if not isinstance(based_on, list):
            _issue(write_issues, f"{path_label}:based_on:not_array")
            based_on = []

        based_versions: dict[str, list[int]] = {}
        for based_index, based in enumerate(based_on):
            based_label = f"{path_label}.based_on[{based_index}]"
            _exact(based, {"path", "version"}, based_label, issues)
            if not isinstance(based, Mapping):
                continue
            based_path = based.get("path")
            if not _text(based_path):
                _issue(write_issues, f"{based_label}:path_invalid")
                continue
            based_version = based.get("version")
            if type(based_version) is not int or based_version < -1:
                _issue(write_issues, f"{based_label}:version_invalid")
                continue
            based_versions.setdefault(str(based_path), []).append(based_version)

        if target is not None:
            for based_path in sorted(based_versions):
                current = versions.get(based_path)
                for expected in sorted(set(based_versions[based_path])):
                    if expected == -1 and current is not None:
                        write_issues.append(
                            f"write[{index}]:stale_dependency:{based_path}:"
                            f"HAVE:-1:CURRENT:{current}"
                        )
                    elif expected != -1 and current != expected:
                        write_issues.append(
                            f"write[{index}]:stale_dependency:{based_path}:"
                            f"HAVE:{expected}:CURRENT:{current}"
                        )
            if str(target) not in based_versions:
                _issue(write_issues, f"write[{index}]:unread_write:{target}")

        if target is None or write_issues:
            rejected.append(
                {
                    "write_id": str(write_id) if _text(write_id) else None,
                    "path": str(target) if target is not None else None,
                    "issues": sorted(write_issues),
                }
            )
        else:
            next_version = versions[target] + 1 if target in versions else 0
            versions[target] = next_version
            accepted.append(
                {
                    "write_id": str(write_id),
                    "path": str(target),
                    "new_version": next_version,
                }
            )

    if issues:
        status = "FAIL"
    elif rejected:
        status = "PASS_WITH_REJECTIONS"
    else:
        status = "PASS"
    core = {
        "schema": STALE_WRITE_REPORT_SCHEMA,
        "status": status,
        "issues": sorted(issues),
        "write_count": len(writes_value),
        "accepted": accepted,
        "rejected": rejected,
        "final_versions": [
            {"path": path, "version": version}
            for path, version in sorted(versions.items())
        ],
    }
    return _report_footer(core)


def validate_integration_release(program: Any) -> dict[str, Any]:
    """Validate one worktree-per-node integration release as declared evidence."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        value,
        {
            "schema",
            "node_id",
            "base_commit",
            "artifact_refs",
            "tests",
            "boundary_checks",
            "writes_frozen",
        },
        "program",
        issues,
    )
    if value.get("schema") != INTEGRATION_RELEASE_PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not _identifier(value.get("node_id")):
        _issue(issues, "program:node_id_invalid")
    if not _base_commit(value.get("base_commit")):
        _issue(issues, "program:base_commit_invalid")
    if value.get("writes_frozen") is not True:
        _issue(issues, "release:writes_not_frozen")

    artifact_refs = value.get("artifact_refs")
    if not isinstance(artifact_refs, list):
        _issue(issues, "artifact_refs:not_array")
        artifact_refs = []
    if not artifact_refs:
        _issue(issues, "artifact_refs:empty")
    else:
        for index, ref in enumerate(artifact_refs):
            if not _text(ref):
                _issue(issues, f"artifact_refs[{index}]:invalid")
        if len(artifact_refs) != len(set(artifact_refs)):
            _issue(issues, "artifact_refs:duplicates")

    tests = value.get("tests")
    _exact(tests, {"command", "exit_code", "source_pointer"}, "tests", issues)
    if isinstance(tests, Mapping):
        if not _text(tests.get("command")):
            _issue(issues, "tests:command_invalid")
        exit_code = tests.get("exit_code")
        if type(exit_code) is not int or exit_code < 0:
            _issue(issues, "tests:exit_code_invalid")
        elif exit_code != 0:
            _issue(issues, "release:tests_failed")
        if not _text(tests.get("source_pointer")):
            _issue(issues, "tests:source_pointer_invalid")

    boundary_checks = value.get("boundary_checks")
    if not isinstance(boundary_checks, list):
        _issue(issues, "boundary_checks:not_array")
        boundary_checks = []
    for index, check in enumerate(boundary_checks):
        path = f"boundary_checks[{index}]"
        _exact(check, {"name", "passed", "source_pointer"}, path, issues)
        if not isinstance(check, Mapping):
            continue
        name = check.get("name")
        if not _text(name):
            _issue(issues, f"{path}:name_invalid")
        if not isinstance(check.get("passed"), bool):
            _issue(issues, f"{path}:passed_invalid")
        elif check.get("passed") is False and _text(name):
            _issue(issues, f"release:boundary_failed:{name}")
        if not _text(check.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")

    status = "FAIL" if issues else "PASS"
    node_id = value.get("node_id") if isinstance(value, Mapping) else None
    base_commit = value.get("base_commit") if isinstance(value, Mapping) else None
    core = {
        "schema": INTEGRATION_RELEASE_REPORT_SCHEMA,
        "status": status,
        "node_id": node_id if _identifier(node_id) else None,
        "base_commit": base_commit if _base_commit(base_commit) else None,
        "artifact_count": len(artifact_refs),
        "boundary_check_count": len(boundary_checks),
        "issues": sorted(issues),
    }
    if status == "PASS":
        core["release_sha256"] = _sha256(value)
    return _report_footer(core)


def _read_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON: {path}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provider-free Orch Dork versioned repository state evaluators"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    write_sets = sub.add_parser("validate-write-sets")
    write_sets.add_argument("program")
    stale = sub.add_parser("evaluate-stale-writes")
    stale.add_argument("program")
    release = sub.add_parser("validate-integration-release")
    release.add_argument("program")
    args = parser.parse_args(argv)
    value = _read_json(args.program)
    if args.command == "validate-write-sets":
        result = validate_write_sets(value)
    elif args.command == "evaluate-stale-writes":
        result = evaluate_stale_writes(value)
    else:
        result = validate_integration_release(value)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

