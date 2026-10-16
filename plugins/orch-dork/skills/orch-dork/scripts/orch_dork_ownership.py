#!/usr/bin/env python3
"""Provider-free ownership and dirty-workspace analysis for Orch Dork."""

from __future__ import annotations

import argparse
import ast
import builtins
from contextlib import ExitStack, closing, contextmanager
from contextvars import ContextVar
from enum import EnumMeta
import fnmatch
import hashlib
from inspect import CO_OPTIMIZED
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import sys
import threading
import time
import types
import uuid
from typing import Any, Iterable, Mapping


def _qualified_codes(code: types.CodeType, *, derive: bool = False) -> dict[str, types.CodeType]:
    """Every code object a module's code defines, by qualified name.

    co_qualname arrives in Python 3.11.  The supported macOS system python3 is
    3.9, where the same names are derived for module-level functions, classes
    and their methods: a function's children are its locals and a class body's
    children are its members.  derive forces the derivation, for tests.
    """

    found: dict[str, types.CodeType] = {}
    pending = [(code, "<module>")]
    while pending:
        nested, derived = pending.pop()
        qualified = derived if derive else getattr(nested, "co_qualname", derived)
        found[qualified] = nested
        for item in nested.co_consts:
            if type(item) is not types.CodeType:
                continue
            if nested is code:
                child = item.co_name
            elif nested.co_flags & CO_OPTIMIZED:
                child = qualified + ".<locals>." + item.co_name
            else:
                child = qualified + "." + item.co_name
            pending.append((item, child))
    return found


def _load_process_containment():
    """Load only the two exact siblings; preserve their canonical shared state."""
    root = Path(__file__).resolve(strict=True).parent
    published = {}
    dependencies = ("orch_dork_hostile_input", "orch_dork_process_containment")
    references = {}
    profile_pair = None
    literal_types = (type(None), bool, int, float, str, bytes, tuple, list, dict, set, frozenset)

    def same_data(actual, expected):
        if profile_pair is not None and expected is profile_pair[1]:
            return actual is profile_pair[0]
        if type(actual) is not type(expected):
            return False
        if type(expected) in (type(None), bool, int, float, str, bytes):
            return actual == expected
        if type(expected) in (tuple, list):
            return len(actual) == len(expected) and all(same_data(a, e) for a, e in zip(actual, expected))
        if type(expected) is dict:
            return (all(type(key) is str for key in actual)
                    and len(actual) == len(expected)
                    and all(key in actual and same_data(actual[key], value) for key, value in expected.items()))
        if type(expected) in (set, frozenset):
            return all(type(item) is str for item in actual) and actual == expected
        return False

    def reference_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in references:
            return references[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    loaded = []
    try:
        for name in dependencies:
            path = root / (name + ".py")
            # Read source directly: no ambient finder, symlink or bytecode cache.
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            with os.fdopen(os.open(path, flags), "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise ImportError("ownership dependency is not regular source: " + name)
                source = stream.read()
            after = path.lstat()
            if (not stat.S_ISREG(after.st_mode)
                    or (after.st_dev, after.st_ino) != (metadata.st_dev, metadata.st_ino)):
                raise ImportError("ownership dependency source changed: " + name)
            code = compile(source, str(path), "exec", dont_inherit=True)
            if name in sys.modules:
                module = sys.modules[name]
                if type(module) is not types.ModuleType:
                    raise ImportError("foreign ownership dependency: " + name)
                fields = vars(module)
                spec = fields.get("__spec__")
                if type(spec) is not importlib.machinery.ModuleSpec:
                    raise ImportError("foreign ownership dependency spec: " + name)
                spec_fields = vars(spec)
                loader = spec_fields.get("loader")
                if (spec_fields.get("_initializing", False) is not False
                        or type(loader) is not importlib.machinery.SourceFileLoader
                        or fields.get("__loader__") is not loader):
                    raise ImportError("foreign ownership dependency: " + name)
                for values, key, wanted in (
                        (fields, "__name__", name), (fields, "__file__", str(path)),
                        (spec_fields, "name", name), (spec_fields, "origin", str(path)),
                        (vars(loader), "name", name), (vars(loader), "path", str(path))):
                    if type(values.get(key)) is not str or values[key] != wanted:
                        raise ImportError("foreign ownership dependency: " + name)
                # Build expected configuration from the held trusted source. This
                # private namespace is never returned; sibling imports
                # use the verified reference, not potentially substituted cached data.
                # dataclasses resolves annotations through sys.modules: give it only
                # this fresh namespace, then remove the temporary registration.
                reference_name = "_orch_dork_source_reference_" + uuid.uuid4().hex
                if reference_name in sys.modules:
                    raise ImportError("ownership reference namespace collision")
                reference = types.ModuleType(reference_name)
                vars(reference).update(__file__=str(path), __builtins__={
                    **vars(builtins), "__import__": reference_import,
                })
                sys.modules[reference_name] = reference
                try:
                    exec(code, vars(reference))
                finally:
                    if sys.modules.get(reference_name) is reference:
                        del sys.modules[reference_name]
                if name == "orch_dork_hostile_input":
                    profile = fields.get("PROFILE")
                    if (type(profile) is not fields.get("DefensiveProfile")
                            or not same_data(object.__getattribute__(profile, "__dict__"),
                                             vars(reference.PROFILE))):
                        raise ImportError("foreign ownership dependency profile")
                    profile_pair = (profile, reference.PROFILE)
                for key, value in vars(reference).items():
                    if (key.isupper() and not key.startswith("_")
                            and (type(value) in literal_types
                                 or (profile_pair is not None and value is profile_pair[1]))
                            and (key not in fields or not same_data(fields[key], value))):
                        raise ImportError("foreign ownership dependency configuration: " + key)
                # Check every source-defined function/method, including private helpers.
                # Nested function bodies are already part of their parent's code object.
                # Generated dataclass methods and arbitrary mutable process state
                # remain outside this check; canonical configuration/defaults do not.
                expected = _qualified_codes(code)
                source_tree = ast.parse(source)
                for node in source_tree.body:
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                        for target in node.targets:
                            if (isinstance(target, ast.Name)
                                    and fields.get(target.id) is not fields.get(node.value.id)):
                                raise ImportError("foreign ownership dependency alias: " + target.id)
                definitions = [(node, module, reference, "") for node in source_tree.body]
                while definitions:
                    node, owner, reference_owner, prefix = definitions.pop()
                    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        continue
                    export = prefix + node.name
                    value = vars(owner).get(node.name)
                    reference_value = vars(reference_owner).get(node.name)
                    if isinstance(node, ast.ClassDef):
                        if (type(value) not in (type, EnumMeta)
                                or type(vars(value).get("__module__")) is not str
                                or vars(value)["__module__"] != name):
                            raise ImportError("foreign ownership dependency class: " + export)
                        for key, member in vars(value).items():
                            if key not in vars(reference_value) and (callable(member) or type(member) is property):
                                raise ImportError("foreign ownership dependency class member: " + export + "." + key)
                        for child in node.body:
                            if (isinstance(child, ast.AnnAssign) and child.value is not None
                                    and isinstance(child.target, ast.Name)
                                    and not same_data(vars(value).get(child.target.id),
                                                      vars(reference_value).get(child.target.id))):
                                raise ImportError("foreign ownership dependency class default: " + export)
                        definitions.extend((child, value, reference_value, export + ".") for child in node.body)
                        continue
                    decorators = [item.id if isinstance(item, ast.Name) else None
                                  for item in node.decorator_list]
                    if decorators == ["property"]:
                        if type(value) is not property or value.fset is not None or value.fdel is not None:
                            raise ImportError("foreign ownership dependency property: " + export)
                        value = value.fget
                        reference_value = reference_value.fget
                    elif decorators == ["contextmanager"]:
                        # __wrapped__ alone cannot vouch for a substituted outer function.
                        wrapper = contextmanager(lambda: None)
                        if (type(value) is not types.FunctionType
                                or value.__code__ != wrapper.__code__
                                or value.__globals__ is not wrapper.__globals__
                                or value.__closure__ is None or len(value.__closure__) != 1
                                or value.__closure__[0].cell_contents is not getattr(value, "__wrapped__", None)):
                            raise ImportError("foreign ownership dependency wrapper: " + export)
                        value = value.__wrapped__
                        reference_value = reference_value.__wrapped__
                    elif decorators:
                        raise ImportError("unsupported ownership dependency decorator: " + export)
                    if (type(value) is not types.FunctionType
                            or value.__code__ != expected.get(export)
                            or value.__globals__ is not module.__dict__
                            or not same_data(value.__defaults__, reference_value.__defaults__)
                            or not same_data(value.__kwdefaults__, reference_value.__kwdefaults__)):
                        raise ImportError("foreign ownership dependency code: " + export)
                    if value.__code__.co_freevars:
                        if (value.__code__.co_freevars != ("__class__",)
                                or value.__closure__ is None or len(value.__closure__) != 1
                                or value.__closure__[0].cell_contents is not owner):
                            raise ImportError("foreign ownership dependency closure: " + export)
                references[name] = reference
            else:
                spec = importlib.util.spec_from_file_location(name, path)
                module = importlib.util.module_from_spec(spec)
                # dataclasses and subsequent normal imports need this exact instance.
                sys.modules[name] = module
                published[name] = module
                exec(code, module.__dict__)
                references[name] = module
                if name == "orch_dork_hostile_input":
                    profile_pair = (module.PROFILE, module.PROFILE)
            loaded.append(module)
        hostile, containment = loaded
        if (vars(hostile).get("PROFILE") is None
                or vars(containment).get("PROFILE") is not vars(hostile).get("PROFILE")
                or vars(containment).get("parse_bounded_json") is not vars(hostile).get("parse_bounded_json")
                or vars(containment).get("HostileInputError") is not vars(hostile).get("HostileInputError")):
            raise ImportError("ownership containment profile is not the exact sibling profile")
        return containment
    except BaseException:
        for name, module in reversed(tuple(published.items())):
            if sys.modules.get(name) is module:
                del sys.modules[name]
        raise


_containment = _load_process_containment()
current_dispatch_scope = _containment.current_dispatch_scope
run_contained = _containment.run_contained


SCHEMA = "orch-dork/ownership-analysis/v1"
BASELINE_SCHEMA = "orch-dork/workspace-baseline/v1"
PRESERVATION_SCHEMA = "orch-dork/workspace-preservation/v1"
MAX_BASELINE_ENTRIES = 10_000
MAX_EXPANSION_ENTRIES = 10_000
MAX_EXPANSION_DEPTH = 64
MAX_ANALYSIS_WORK = 100_000
ANALYSIS_TIMEOUT_SECONDS = 5
_MAGIC = "*?["


class OwnershipError(ValueError):
    pass


class _AnalysisBudget:
    def __init__(self):
        self.deadline = time.monotonic() + ANALYSIS_TIMEOUT_SECONDS
        self.work = 0
        self.entries = 0

    def check(self):
        scope = current_dispatch_scope()
        if time.monotonic() >= self.deadline or (scope is not None and scope.stopped()):
            raise OwnershipError("ownership:time_budget_exceeded")

    def take(self, *, entry=False, depth=0):
        self.check()
        if depth > MAX_EXPANSION_DEPTH:
            raise OwnershipError("ownership:depth_budget_exceeded")
        self.work += 1
        if self.work > MAX_ANALYSIS_WORK:
            raise OwnershipError("ownership:work_budget_exceeded")
        if entry:
            self.entries += 1
            if self.entries > MAX_EXPANSION_ENTRIES:
                raise OwnershipError("ownership:entry_budget_exceeded")


_BUDGET = ContextVar("ownership_budget", default=None)
_PROCESS_EVIDENCE = threading.local()


def _work():
    budget = _BUDGET.get()
    if budget is not None:
        budget.take()


class _Expansion:
    """Shared bounded directory cache; recursion never enters a foreign root."""

    def __init__(self, root, budget):
        self.root = root
        self.budget = budget
        self.directories = {}
        self.matches = {}

    def entries(self, relative):
        self.budget.take(depth=len(relative.parts))
        if relative in self.directories:
            return self.directories[relative]
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_NONBLOCK
        with ExitStack() as cleanup:
            descriptor = os.open(self.root, flags)
            cleanup.callback(os.close, descriptor)
            for component in relative.parts:
                self.budget.take()
                descriptor = os.open(component, flags, dir_fd=descriptor)
                cleanup.callback(os.close, descriptor)
            rows = []
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    self.budget.take(entry=True)
                    rows.append((entry.name, entry.is_dir(follow_symlinks=False), entry.is_symlink()))
            self.budget.check()
        self.directories[relative] = tuple(sorted(rows))
        return self.directories[relative]

    def resolve(self, relative):
        self.budget.take(depth=len(relative.parts))
        path = (self.root / relative).resolve(strict=False)
        self.budget.check()
        return path

    def candidates(self, resource):
        normalized = resource["normalized"]
        if normalized in self.matches:
            self.budget.take()
            return self.matches[normalized]
        if not resource["pattern"]:
            self.matches[normalized] = (self.root / normalized,)
            return self.matches[normalized]
        parts = PurePosixPath(normalized).parts
        found = set()
        visited = set()
        def walk(logical, physical, index):
            self.budget.take(depth=len(logical.parts))
            state = (logical, physical, index)
            if state in visited:
                return
            visited.add(state)
            if index == len(parts):
                found.add(self.root / logical)
                return
            part = parts[index]
            if part == "**":
                walk(logical, physical, index + 1)
            for name, directory, symlink in self.entries(physical):
                self.budget.take()
                if part != "**" and not fnmatch.fnmatchcase(name, part):
                    continue
                child = logical / name
                if part != "**" and index + 1 == len(parts):
                    found.add(self.root / child)
                    continue
                if symlink:
                    # ** skips symlink recursion. Its zero-depth branch above
                    # selects any link that actually matches the next component.
                    if part == "**":
                        continue
                    resolved = self.resolve(child)
                    if not _inside(resolved, self.root):
                        found.add(self.root / child)
                        continue
                    directory = resolved.is_dir()
                    physical_child = resolved.relative_to(self.root)
                else:
                    physical_child = physical / name
                if directory:
                    walk(child, physical_child, index if part == "**" else index + 1)
        walk(PurePosixPath(), PurePosixPath(), 0)
        self.matches[normalized] = tuple(sorted(found))
        return self.matches[normalized]


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


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _split_mode(raw: str) -> tuple[str, str]:
    if raw.startswith("read:"):
        return "read", raw[5:]
    if raw.startswith("write:"):
        return "write", raw[6:]
    return "write", raw


def _literal_prefix(pattern: str) -> str:
    parts = []
    for part in PurePosixPath(pattern).parts:
        if any(char in part for char in _MAGIC):
            break
        parts.append(part)
    return PurePosixPath(*parts).as_posix() if parts else "."


def normalize_resource(
    value: Any, *, workspace_root: str | Path | None = None
) -> dict[str, Any]:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise OwnershipError("resource must be non-empty text")
    mode, body = _split_mode(value.strip())
    if not body:
        raise OwnershipError("resource body is empty")
    if body.startswith("semantic:"):
        key = body[9:].strip()
        if not key or any(char in key for char in _MAGIC):
            raise OwnershipError("semantic resource must be an exact key")
        return {
            "original": value,
            "mode": mode,
            "kind": "semantic",
            "normalized": key,
            "pattern": False,
            "literal_prefix": key,
        }

    body = body.replace("\\", "/")
    candidate = PurePosixPath(body)
    if ".." in candidate.parts:
        raise OwnershipError("resource path escapes through '..'")
    root = Path(workspace_root).resolve() if workspace_root is not None else None
    if candidate.is_absolute():
        if root is None:
            normalized = candidate.as_posix()
        else:
            absolute = Path(candidate.as_posix()).resolve(strict=False)
            if not _inside(absolute, root):
                raise OwnershipError("absolute resource escapes workspace")
            normalized = absolute.relative_to(root).as_posix()
    else:
        normalized = candidate.as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", "."}:
        raise OwnershipError("workspace root is too broad a resource")
    pattern = any(char in normalized for char in _MAGIC)
    return {
        "original": value,
        "mode": mode,
        "kind": "path",
        "normalized": normalized,
        "pattern": pattern,
        "literal_prefix": _literal_prefix(normalized),
    }


def _path_intersects(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    a, b = str(left["normalized"]), str(right["normalized"])
    if not left["pattern"] and not right["pattern"]:
        return (
            a == b
            or a.startswith(b.rstrip("/") + "/")
            or b.startswith(a.rstrip("/") + "/")
        )
    if not left["pattern"]:
        return fnmatch.fnmatchcase(a, b) or a.startswith(
            str(right["literal_prefix"]).rstrip("/") + "/"
        )
    if not right["pattern"]:
        return fnmatch.fnmatchcase(b, a) or b.startswith(
            str(left["literal_prefix"]).rstrip("/") + "/"
        )
    ap, bp = str(left["literal_prefix"]), str(right["literal_prefix"])
    return (
        ap == bp
        or ap.startswith(bp.rstrip("/") + "/")
        or bp.startswith(ap.rstrip("/") + "/")
    )


def resources_intersect(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    if left.get("kind") != right.get("kind"):
        return False
    if left.get("kind") == "semantic":
        return left.get("normalized") == right.get("normalized")
    return _path_intersects(left, right)


def resource_contains(scope: Mapping[str, Any], value: Mapping[str, Any]) -> bool:
    if scope.get("kind") != value.get("kind"):
        return False
    if scope.get("kind") == "semantic":
        return scope.get("normalized") == value.get("normalized")
    path = str(value.get("normalized"))
    pattern = str(scope.get("normalized"))
    if scope.get("pattern"):
        return fnmatch.fnmatchcase(path, pattern)
    return path == pattern or path.startswith(pattern.rstrip("/") + "/")


def deliverable_is_path_shaped(value: Any) -> bool:
    """Whether a deliverable entry names a location rather than an outcome.

    The deliverables field is free text in both frozen plan contracts: an
    entry may name a concrete artifact path or describe an outcome in prose.
    Only a path-shaped entry asserts a write target that can be compared
    against a resource scope. "docs/report.md" and "semantic:join" are write
    targets; "Completed API behavior" is a description of done and carries no
    location to check.

    This lives beside `normalize_resource` and `resource_contains` because
    every caller that asks the question needs those two next, and because the
    two plan validators must agree on which entries are checkable. A second
    copy of the predicate would be a second answer to that question.
    """

    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate or any(char.isspace() for char in candidate):
        return False
    if candidate.startswith("semantic:"):
        return True
    if "/" in candidate:
        return True
    return "." in candidate


def deliverables_outside_ownership(
    deliverables: Iterable[Any], owned: Iterable[Any]
) -> list[tuple[int, str]]:
    """Index and reason for every deliverable outside its own write scope.

    A plan that names a deliverable the lane does not own is internally
    contradictory: the lane is required to produce the artifact and its every
    write of that artifact is an out-of-scope access. Custody derives lane
    scope from `owned_resources` alone, so the contradiction only surfaces
    after the wave runs. Both plan validators call this, so a plan cannot pass
    one validating surface and fail the other.

    Returns `(index, reason)` pairs where reason is `not_owned` or
    `unnormalizable`; the caller formats them into its own issue namespace.
    Malformed ownership entries are skipped rather than reported here, since
    `analyze_ownership` already reports a parse failure against the same plan
    and double-reporting it as a coverage failure would mislead.
    """

    declared = list(deliverables)
    scopes = []
    for raw in owned:
        try:
            scopes.append(normalize_resource(raw))
        except Exception:
            continue
    if not declared or not scopes:
        return []
    findings: list[tuple[int, str]] = []
    for index, raw in enumerate(declared):
        if not deliverable_is_path_shaped(raw):
            continue
        try:
            target = normalize_resource(raw)
        except Exception:
            findings.append((index, "unnormalizable"))
            continue
        if not any(resource_contains(scope, target) for scope in scopes):
            findings.append((index, "not_owned"))
    return findings


def _resource_list(
    values: Any,
    label: str,
    issues: list[str],
    *,
    workspace_root: str | Path | None,
) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        issues.append(label + ":not_array")
        return []
    result = []
    for index, value in enumerate(values):
        _work()
        try:
            result.append(normalize_resource(value, workspace_root=workspace_root))
        except OwnershipError as exc:
            issues.append(f"{label}[{index}]:{exc}")
    return result


def _symlink_escapes(resource: Mapping[str, Any], root: Path, expansion: _Expansion) -> list[str]:
    if resource.get("kind") != "path":
        return []
    normalized = str(resource["normalized"])
    escapes = []
    for candidate in expansion.candidates(resource):
        try:
            resolved = expansion.resolve(PurePosixPath(candidate.relative_to(root)))
        except (OSError, RuntimeError):
            escapes.append(normalized)
            continue
        if not _inside(resolved, root):
            escapes.append(
                candidate.relative_to(root).as_posix()
                if _inside(candidate, root)
                else str(candidate)
            )
    return sorted(set(escapes))


def _analyze_ownership(
    plan: Mapping[str, Any],
    *,
    workspace_root: str | Path | None = None,
    baseline: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    issues: list[str] = []
    root = Path(workspace_root).resolve() if workspace_root is not None else None
    if root is not None and not root.is_dir():
        issues.append("workspace:root_unavailable")
    lanes_value = plan.get("lanes") if isinstance(plan, Mapping) else None
    if (
        lanes_value is None
        and isinstance(plan, Mapping)
        and plan.get("schema") == "orch-dork/logical-plan/v1"
    ):
        lanes_value = plan.get("workers")
    if not isinstance(lanes_value, list):
        lanes_value = []
        issues.append("plan:lanes_not_array")
    lanes: list[dict[str, Any]] = []
    for index, lane in enumerate(lanes_value):
        _work()
        if not isinstance(lane, Mapping):
            issues.append(f"lanes[{index}]:not_object")
            continue
        lane_id = lane.get("id")
        if not isinstance(lane_id, str) or not lane_id:
            issues.append(f"lanes[{index}]:id_invalid")
            continue
        owned = _resource_list(
            lane.get("owned_resources"),
            f"lanes[{index}].owned_resources",
            issues,
            workspace_root=root,
        )
        excluded = _resource_list(
            lane.get("excluded_resources", []),
            f"lanes[{index}].excluded_resources",
            issues,
            workspace_root=root,
        )
        lanes.append(
            {
                "id": lane_id,
                "lane_id": lane_id,
                "owned": owned,
                "excluded": excluded,
                "read_only": bool(owned)
                and all(item["mode"] == "read" for item in owned),
            }
        )
    protected = _resource_list(
        plan.get("protected_resources", []) if isinstance(plan, Mapping) else [],
        "protected_resources",
        issues,
        workspace_root=root,
    )

    overlaps: list[dict[str, Any]] = []
    for left_index, left in enumerate(lanes):
        for right in lanes[left_index + 1 :]:
            for a in left["owned"]:
                for b in right["owned"]:
                    _work()
                    if resources_intersect(a, b) and not (
                        a["mode"] == b["mode"] == "read"
                    ):
                        overlaps.append(
                            {
                                "left_lane": left["lane_id"],
                                "right_lane": right["lane_id"],
                                "left": a["original"],
                                "right": b["original"],
                            }
                        )
                        issues.append(
                            f"ownership:lane_overlap:{left['lane_id']}:{right['lane_id']}"
                        )
    protected_conflicts: list[dict[str, Any]] = []
    for lane in lanes:
        for owned in lane["owned"]:
            if owned["mode"] != "write":
                continue
            for item in protected:
                _work()
                if resources_intersect(owned, item):
                    protected_conflicts.append(
                        {
                            "lane_id": lane["lane_id"],
                            "owned": owned["original"],
                            "protected": item["original"],
                        }
                    )
                    issues.append(f"ownership:protected_overlap:{lane['lane_id']}")
            for item in lane["excluded"]:
                _work()
                if resources_intersect(owned, item):
                    issues.append(f"ownership:excluded_overlap:{lane['lane_id']}")

    symlink_escapes: list[dict[str, Any]] = []
    if root is not None and root.is_dir():
        expansion = _Expansion(root, _BUDGET.get())
        for lane in lanes:
            for resource in lane["owned"]:
                _work()
                for path in _symlink_escapes(resource, root, expansion):
                    symlink_escapes.append(
                        {
                            "lane_id": lane["lane_id"],
                            "resource": resource["original"],
                            "path": path,
                        }
                    )
                    issues.append(f"ownership:symlink_escape:{lane['lane_id']}")

    dirty_conflicts: list[dict[str, Any]] = []
    dirty_paths = baseline.get("dirty_paths", []) if isinstance(baseline, Mapping) else []
    if baseline is not None and not isinstance(dirty_paths, list):
        issues.append("baseline:dirty_paths_not_array")
        dirty_paths = []
    for dirty in dirty_paths:
        _work()
        try:
            dirty_resource = normalize_resource(
                "write:" + str(dirty), workspace_root=root
            )
        except OwnershipError:
            issues.append("baseline:dirty_path_invalid")
            continue
        for lane in lanes:
            conflict = False
            for item in lane["owned"]:
                _work()
                conflict |= item["mode"] == "write" and resources_intersect(item, dirty_resource)
            if conflict:
                dirty_conflicts.append(
                    {"lane_id": lane["lane_id"], "path": dirty_resource["normalized"]}
                )
                issues.append(f"ownership:dirty_conflict:{lane['lane_id']}")

    issues = sorted(set(issues))
    _BUDGET.get().check()
    return {
        "schema": SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "safe": not issues,
        "issues": issues,
        "plan_sha256": _sha(plan if isinstance(plan, Mapping) else {}),
        "workspace_root": str(root) if root is not None else None,
        "lanes": lanes,
        "read_only_lanes": sorted(
            lane["lane_id"] for lane in lanes if lane["read_only"]
        ),
        "overlaps": overlaps,
        "protected_conflicts": protected_conflicts,
        "symlink_escapes": symlink_escapes,
        "dirty_conflicts": dirty_conflicts,
        "evidence_tier": "provider-free-local",
    }


def _failure(plan, issue):
    return {"schema": SCHEMA, "status": "FAIL", "safe": False, "issues": [issue],
            "plan_sha256": _sha(plan if isinstance(plan, Mapping) else {}),
            "workspace_root": None, "lanes": [], "read_only_lanes": [],
            "overlaps": [], "protected_conflicts": [], "symlink_escapes": [],
            "dirty_conflicts": [], "evidence_tier": "provider-free-local"}


def analyze_ownership(plan, *, workspace_root=None, baseline=None):
    """Bound traversal and comparison work across the complete analysis."""
    budget = _AnalysisBudget()
    token = _BUDGET.set(budget)
    try:
        result = _analyze_ownership(plan, workspace_root=workspace_root, baseline=baseline)
        budget.check()
        return result
    except OwnershipError as error:
        return _failure(plan, str(error))
    except (OSError, RuntimeError):
        return _failure(plan, "ownership:filesystem_unavailable")
    finally:
        _BUDGET.reset(token)


def _native_task_workspace(task_id, native_home):
    """Read Codex 0.160's exact task index; no rollout search or caller fallback."""
    if not isinstance(task_id, str):
        raise OwnershipError("ownership:task_root_unavailable")
    try:
        if str(uuid.UUID(task_id)) != task_id:
            raise ValueError("noncanonical task id")
        home = Path(native_home).expanduser().resolve(strict=True)
        path = home / "state_5.sqlite"
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise OSError("unsafe native index")
        budget = _AnalysisBudget()
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=.25)) as database:
            database.execute("PRAGMA query_only=ON")
            database.set_progress_handler(lambda: int(time.monotonic() >= budget.deadline), 100)
            row = database.execute("SELECT cwd FROM threads WHERE id=? AND archived=0", (task_id,)).fetchone()
        after = path.lstat()
        if (after.st_dev, after.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise OSError("native index changed")
        budget.check()
        if row is None or not isinstance(row[0], str) or not Path(row[0]).is_absolute():
            raise ValueError("task absent")
        root = Path(row[0]).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("task workspace absent")
        return root
    except (OSError, ValueError, sqlite3.Error) as error:
        raise OwnershipError("ownership:task_root_unavailable") from error


def _execute_ownership(job):
    plan = job.get("plan", {})
    try:
        root = job.get("workspace_root")
        if job["require_task_root"]:
            native_root = _native_task_workspace(job.get("task_id"), job["native_home"])
            if root is not None and Path(root).expanduser().resolve(strict=False) != native_root:
                raise OwnershipError("ownership:task_root_mismatch")
            root = native_root
        return analyze_ownership(plan, workspace_root=root, baseline=job.get("baseline"))
    except (OwnershipError, OSError, ValueError) as error:
        issue = str(error) if isinstance(error, OwnershipError) else "ownership:task_root_unavailable"
        return _failure(plan, issue)


def _ownership_argv():
    return [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--ownership-job"]


def evaluate_ownership(plan, *, workspace_root=None, baseline=None, task_id=None, require_task_root=False):
    """Model-facing analysis runs in one owned cancellable, bounded process."""
    scope = current_dispatch_scope()
    if scope is not None:
        scope.managed = True
    job = {"plan": plan, "workspace_root": workspace_root, "baseline": baseline,
           "task_id": task_id, "require_task_root": require_task_root,
           "native_home": os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))}
    execution = run_contained(_ownership_argv(),
                              input_bytes=_canonical(job), config={"wall_seconds": ANALYSIS_TIMEOUT_SECONDS},
                              expect_json=True, scope=scope, surface="ownership-analysis")
    _PROCESS_EVIDENCE.result = execution
    result = execution.get("parsed_output")
    if (execution["status"] == "PASS" and isinstance(result, dict)
            and result.get("schema") == SCHEMA and result.get("status") in {"PASS", "FAIL"}
            and result.get("safe") is (result["status"] == "PASS")
            and isinstance(result.get("issues"), list) and result["plan_sha256"] == _sha(plan)):
        return result
    issue = ("ownership:time_budget_exceeded" if execution.get("reason") == "HARD_WALL_TIMEOUT"
             else "ownership:analysis_unavailable")
    return _failure(plan, issue)


def _entry(path: Path, root: Path) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {
            "path": relative,
            "exists": False,
            "kind": "missing",
            "sha256": None,
            "target": None,
        }
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
        kind = "symlink"
    elif stat.S_ISREG(info.st_mode):
        target = None
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        kind = "file"
    elif stat.S_ISDIR(info.st_mode):
        target = None
        digest = None
        kind = "directory"
    else:
        target = None
        digest = None
        kind = "other"
    return {
        "path": relative,
        "exists": True,
        "kind": kind,
        "sha256": digest,
        "target": target,
    }


def capture_workspace_baseline(
    workspace_root: str | Path, resources: list[str]
) -> dict[str, Any]:
    root = Path(workspace_root).resolve()
    if not root.is_dir():
        raise OwnershipError("workspace root unavailable")
    paths: dict[str, Path] = {}
    for raw in resources:
        resource = normalize_resource(raw, workspace_root=root)
        if resource["kind"] != "path":
            continue
        candidates: Iterable[Path]
        if resource["pattern"]:
            candidates = root.glob(resource["normalized"])
        else:
            candidates = (root / resource["normalized"],)
        for candidate in candidates:
            if len(paths) >= MAX_BASELINE_ENTRIES:
                raise OwnershipError("baseline entry limit exceeded")
            if not _inside(candidate, root):
                raise OwnershipError("baseline path escapes workspace")
            paths[candidate.relative_to(root).as_posix()] = candidate
    entries = [_entry(paths[key], root) for key in sorted(paths)]
    result = {
        "schema": BASELINE_SCHEMA,
        "workspace_root": str(root),
        "entries": entries,
    }
    result["baseline_sha256"] = _sha(result)
    return result


def compare_workspace_baselines(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    allowed_resources: list[str],
) -> dict[str, Any]:
    issues: list[str] = []
    if (
        before.get("schema") != BASELINE_SCHEMA
        or after.get("schema") != BASELINE_SCHEMA
    ):
        issues.append("baseline:schema_invalid")
    if before.get("workspace_root") != after.get("workspace_root"):
        issues.append("baseline:workspace_mismatch")
    scopes = []
    for value in allowed_resources:
        try:
            resource = normalize_resource(
                value, workspace_root=before.get("workspace_root")
            )
        except OwnershipError:
            issues.append("baseline:allowed_resource_invalid")
            continue
        if resource["mode"] == "write":
            scopes.append(resource)
    left = {
        item.get("path"): item
        for item in before.get("entries", [])
        if isinstance(item, Mapping)
    }
    right = {
        item.get("path"): item
        for item in after.get("entries", [])
        if isinstance(item, Mapping)
    }
    changed = []
    unrelated = []
    for path in sorted(set(left) | set(right)):
        if left.get(path) == right.get(path):
            continue
        changed.append(path)
        value = normalize_resource(
            "write:" + str(path), workspace_root=before.get("workspace_root")
        )
        if not any(resource_contains(scope, value) for scope in scopes):
            unrelated.append(path)
            issues.append("baseline:unrelated_change:" + str(path))
    issues = sorted(set(issues))
    return {
        "schema": PRESERVATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "preserved": not issues,
        "issues": issues,
        "before_sha256": before.get("baseline_sha256"),
        "after_sha256": after.get("baseline_sha256"),
        "changed_paths": changed,
        "unrelated_changed_paths": unrelated,
    }


def _load(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze")
    analyze.add_argument("plan")
    analyze.add_argument("--workspace-root")
    analyze.add_argument("--baseline")
    baseline = sub.add_parser("baseline")
    baseline.add_argument("workspace_root")
    baseline.add_argument("resources", nargs="+")
    compare = sub.add_parser("compare")
    compare.add_argument("before")
    compare.add_argument("after")
    compare.add_argument("allowed_resources", nargs="+")
    args = parser.parse_args(argv)
    if args.command == "analyze":
        result = analyze_ownership(
            _load(args.plan),
            workspace_root=args.workspace_root,
            baseline=_load(args.baseline) if args.baseline else None,
        )
    elif args.command == "baseline":
        result = capture_workspace_baseline(args.workspace_root, args.resources)
    else:
        result = compare_workspace_baselines(
            _load(args.before),
            _load(args.after),
            allowed_resources=args.allowed_resources,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status", "PASS") == "PASS" else 2


if __name__ == "__main__":
    if sys.argv[1:] == ["--ownership-job"]:
        job = _containment.parse_bounded_json(sys.stdin.buffer.read(262145), batch=False)
        if not isinstance(job, dict) or set(job) != {"plan", "workspace_root", "baseline", "task_id", "require_task_root", "native_home"}:
            raise SystemExit(2)
        sys.stdout.buffer.write(_canonical(_execute_ownership(job)) + b"\n")
    else:
        raise SystemExit(main())
