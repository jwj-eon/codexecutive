#!/usr/bin/env python3
"""Render and lint the exact Orch Dork worker-brief v2 preamble."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping


PREAMBLE_SCHEMA = "orch-dork/worker-preamble/v2"
LINT_REPORT_SCHEMA = "orch-dork/worker-brief-lint/v2"
CALIBRATION_SCHEMA = "orch-dork/brief-deadline-calibration/v1"
MAX_BRIEF_BYTES = 65_536
MAX_PATH_BYTES = 4_096
MAX_BRANCH_BYTES = 512
MAX_DEADLINE_SECONDS = 86_400
MAX_CONTEXT_BUDGET_TOKENS = 1_000_000
MAX_CALIBRATION_BYTES = 65_536
LINT_REPORT_FIELDS = (
    "schema",
    "status",
    "issues",
    "preamble_sha256",
    "report_sha256",
)

_MARKER = "<!-- " + PREAMBLE_SCHEMA + " -->"


def _utc_now() -> datetime:
    """Read the host clock at the calibration decision boundary."""

    return datetime.now(timezone.utc)


def _load_sibling(name: str):
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name + " unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    import orch_dork_evidence_core as evidence_core
    import orch_dork_observer_receipt as observer_receipts
except ModuleNotFoundError:  # standalone spec loading in focused tests
    evidence_core = _load_sibling("orch_dork_evidence_core")
    observer_receipts = _load_sibling("orch_dork_observer_receipt")


_SHA256 = evidence_core.SHA256_PATTERN
_CALIBRATION_FIELDS = {
    "schema",
    "mode",
    "brief_shape_sha256",
    "observed_startup_seconds",
    "bootstrap_allowance_seconds",
    "fixed_margin_seconds",
    "deadline_seconds",
    "calibrated_at",
    "source_pointer",
    "receipt_sha256",
}


class WorkerBriefError(ValueError):
    """Worker-brief inputs cannot be normalized without widening scope."""


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    return evidence_core.digest(value)


def _absolute_path(value: str | os.PathLike[str], field: str) -> Path:
    try:
        path = Path(value)
    except TypeError as exc:
        raise WorkerBriefError(field + " must be a path") from exc
    if not path.is_absolute():
        raise WorkerBriefError(field + " must be absolute")
    if "\x00" in str(path) or len(str(path).encode("utf-8")) > MAX_PATH_BYTES:
        raise WorkerBriefError(field + " is invalid or too long")
    return path.resolve(strict=False)


def _contained(path: Path, root: Path, field: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise WorkerBriefError(field + " escapes its declared root") from exc


def _positive_int(value: Any, field: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > maximum
    ):
        raise WorkerBriefError(field + " must be a positive bounded integer")
    return value


def _timestamp(value: Any) -> bool:
    return evidence_core.instant(value) is not None


def _resolve_instruction_files(
    base_checkout: Path,
    instruction_files: Iterable[str | os.PathLike[str]] | None,
) -> list[str]:
    if instruction_files is None:
        candidates = [
            directory / "AGENTS.md"
            for directory in reversed((base_checkout, *base_checkout.parents))
        ]
        paths = [
            candidate.resolve()
            for candidate in candidates
            if candidate.is_file() and not candidate.is_symlink()
        ]
    else:
        if isinstance(instruction_files, (str, bytes, os.PathLike)):
            raise WorkerBriefError("instruction_files must be an iterable of paths")
        try:
            raw_paths = list(instruction_files)
        except TypeError as exc:
            raise WorkerBriefError(
                "instruction_files must be an iterable of paths"
            ) from exc
        paths = []
        for index, raw in enumerate(raw_paths):
            path = _absolute_path(raw, f"instruction_files[{index}]")
            if (
                path.name != "AGENTS.md"
                or not path.is_file()
                or path.is_symlink()
            ):
                raise WorkerBriefError(
                    f"instruction_files[{index}] must be an existing regular AGENTS.md"
                )
            try:
                base_checkout.relative_to(path.parent)
            except ValueError as exc:
                raise WorkerBriefError(
                    f"instruction_files[{index}] is not inherited by the base checkout"
                ) from exc
            paths.append(path)
    rendered = sorted({str(path) for path in paths}, key=lambda value: (len(Path(value).parts), value))
    if len(rendered) != len(paths):
        raise WorkerBriefError("instruction_files may not contain duplicates")
    return rendered


def _shape(
    *,
    base_checkout: str | os.PathLike[str],
    branch: str,
    lane_workspace: str | os.PathLike[str],
    brief_path: str | os.PathLike[str],
    protected_resources: Iterable[str | os.PathLike[str]],
    instruction_files: Iterable[str | os.PathLike[str]] | None,
    context_budget_tokens: int,
) -> dict[str, Any]:
    checkout = _absolute_path(base_checkout, "base_checkout")
    workspace = _absolute_path(lane_workspace, "lane_workspace")
    brief = _absolute_path(brief_path, "brief_path")
    if not checkout.is_dir():
        raise WorkerBriefError("base_checkout must be an existing directory")
    if not workspace.is_dir():
        raise WorkerBriefError("lane_workspace must be an existing directory")
    _contained(brief, workspace, "brief_path")
    if (
        not isinstance(branch, str)
        or not branch
        or "\x00" in branch
        or "\n" in branch
        or "\r" in branch
        or len(branch.encode("utf-8")) > MAX_BRANCH_BYTES
    ):
        raise WorkerBriefError("branch must be a non-empty single-line string")
    budget = _positive_int(
        context_budget_tokens,
        "context_budget_tokens",
        MAX_CONTEXT_BUDGET_TOKENS,
    )
    if isinstance(protected_resources, (str, bytes, os.PathLike)):
        raise WorkerBriefError("protected_resources must be an iterable of paths")
    try:
        candidates = list(protected_resources)
    except TypeError as exc:
        raise WorkerBriefError(
            "protected_resources must be an iterable of paths"
        ) from exc
    protected: list[str] = []
    for index, candidate in enumerate(candidates):
        path = _absolute_path(candidate, f"protected_resources[{index}]")
        _contained(path, checkout, f"protected_resources[{index}]")
        protected.append(str(path))
    protected = sorted(protected)
    if len(protected) != len(set(protected)):
        raise WorkerBriefError("protected_resources may not contain duplicates")
    instructions = _resolve_instruction_files(checkout, instruction_files)
    return {
        "schema": PREAMBLE_SCHEMA,
        "base_checkout": str(checkout),
        "branch": branch,
        "lane_workspace": str(workspace),
        "brief_path": str(brief),
        "protected_resources": protected,
        "instruction_files": instructions,
        "context_budget_tokens": budget,
    }


def brief_shape_sha256(**kwargs: Any) -> str:
    """Return the stable digest a calibration receipt must bind."""

    return _sha256_json(_shape(**kwargs))


def _calibration(
    value: Mapping[str, Any],
    *,
    expected_shape_sha256: str,
    evaluation_time: datetime | str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkerBriefError("calibration_receipt must be an object")
    signed = observer_receipts.require_signed_payload(
        value,
        expected_kind="brief-calibration",
        expected_payload={"brief_shape_sha256": expected_shape_sha256},
        # A calibration controls a live first-patch deadline, so it expires at
        # the signed boundary. Historical replay is appropriate for custody,
        # not for a fresh scheduling decision.
        evaluation_time=(
            evaluation_time
            if evaluation_time is not None
            else _utc_now()
        ),
    )
    if signed.get("status") != "PASS" or not isinstance(
        signed.get("payload"), Mapping
    ):
        if signed.get("reason") == "receipt:subject_mismatch:brief_shape_sha256":
            raise WorkerBriefError(
                "calibration_receipt brief shape does not match"
            )
        raise WorkerBriefError(
            "calibration_receipt host signature is "
            + str(signed.get("reason", "invalid"))
        )
    receipt = dict(signed["payload"])
    missing = _CALIBRATION_FIELDS - set(receipt)
    unknown = set(receipt) - _CALIBRATION_FIELDS
    if missing or unknown:
        detail = (
            "missing " + ",".join(sorted(missing))
            if missing
            else "unknown " + ",".join(sorted(unknown))
        )
        raise WorkerBriefError("calibration_receipt has " + detail)
    if receipt.get("schema") != CALIBRATION_SCHEMA:
        raise WorkerBriefError("calibration_receipt schema is invalid")
    if receipt.get("brief_shape_sha256") != expected_shape_sha256:
        raise WorkerBriefError("calibration_receipt brief shape does not match")
    mode = receipt.get("mode")
    observed = receipt.get("observed_startup_seconds")
    bootstrap = receipt.get("bootstrap_allowance_seconds")
    margin = _positive_int(
        receipt.get("fixed_margin_seconds"),
        "calibration fixed margin",
        MAX_DEADLINE_SECONDS,
    )
    deadline = _positive_int(
        receipt.get("deadline_seconds"),
        "calibration deadline",
        MAX_DEADLINE_SECONDS,
    )
    if mode == "observed":
        observed_value = _positive_int(
            observed,
            "calibration observed startup",
            MAX_DEADLINE_SECONDS,
        )
        if bootstrap is not None:
            raise WorkerBriefError(
                "calibration observed mode may not carry a bootstrap allowance"
            )
        expected_deadline = observed_value + margin
    elif mode == "bootstrap":
        if observed is not None:
            raise WorkerBriefError(
                "calibration bootstrap mode may not claim observed startup"
            )
        bootstrap_value = _positive_int(
            bootstrap,
            "calibration bootstrap allowance",
            MAX_DEADLINE_SECONDS,
        )
        expected_deadline = bootstrap_value + margin
    else:
        raise WorkerBriefError(
            "calibration mode must be observed or bootstrap"
        )
    if deadline != expected_deadline or expected_deadline > MAX_DEADLINE_SECONDS:
        raise WorkerBriefError("calibration deadline arithmetic is invalid")
    if not _timestamp(receipt.get("calibrated_at")):
        raise WorkerBriefError("calibration calibrated_at is invalid")
    if not isinstance(receipt.get("source_pointer"), str) or not receipt.get(
        "source_pointer"
    ):
        raise WorkerBriefError("calibration source_pointer is invalid")
    claimed = receipt.get("receipt_sha256")
    if not isinstance(claimed, str) or _SHA256.fullmatch(claimed) is None:
        raise WorkerBriefError("calibration receipt seal is invalid")
    if not evidence_core.check_seal(receipt, "receipt_sha256"):
        raise WorkerBriefError("calibration receipt seal does not match")
    return receipt


def _inputs(
    *,
    calibration_receipt: Mapping[str, Any],
    **shape_kwargs: Any,
) -> dict[str, Any]:
    shape = _shape(**shape_kwargs)
    receipt = _calibration(
        calibration_receipt,
        expected_shape_sha256=_sha256_json(shape),
    )
    return {"shape": shape, "calibration": receipt}


def render_worker_preamble(
    *,
    base_checkout: str | os.PathLike[str],
    branch: str,
    lane_workspace: str | os.PathLike[str],
    brief_path: str | os.PathLike[str],
    protected_resources: Iterable[str | os.PathLike[str]],
    instruction_files: Iterable[str | os.PathLike[str]] | None,
    calibration_receipt: Mapping[str, Any],
    context_budget_tokens: int,
) -> str:
    """Render the canonical v2 preamble that must begin at brief byte zero."""

    normalized = _inputs(
        base_checkout=base_checkout,
        branch=branch,
        lane_workspace=lane_workspace,
        brief_path=brief_path,
        protected_resources=protected_resources,
        instruction_files=instruction_files,
        calibration_receipt=calibration_receipt,
        context_budget_tokens=context_budget_tokens,
    )
    shape = normalized["shape"]
    receipt = normalized["calibration"]
    instruction_lines = (
        ["  - `" + path + "`" for path in shape["instruction_files"]]
        or ["  - _(none found)_"]
    )
    protected_lines = (
        ["  - `" + path + "`" for path in shape["protected_resources"]]
        or ["  - _(none)_"]
    )
    if shape["base_checkout"] == shape["lane_workspace"]:
        workspace_rule = (
            "2. The lane workspace is the base checkout; path isolation is "
            "advisory. Work only in this checkout on the declared branch and "
            "obey the frozen ownership and protected-resource limits."
        )
    else:
        workspace_rule = (
            "2. Perform every write inside `"
            + shape["lane_workspace"]
            + "` on branch `"
            + shape["branch"]
            + "`; the base checkout is read-only."
        )
    timing_line = (
        "- Observed startup: "
        + str(receipt["observed_startup_seconds"])
        + " seconds"
        if receipt["mode"] == "observed"
        else "- Bootstrap allowance: "
        + str(receipt["bootstrap_allowance_seconds"])
        + " seconds"
    )
    lines = [
        _MARKER,
        "# Orch Dork worker preamble",
        "",
        "- Base checkout: `" + shape["base_checkout"] + "`",
        "- Branch: `" + shape["branch"] + "`",
        "- Lane workspace: `" + shape["lane_workspace"] + "`",
        "- Brief file: `" + shape["brief_path"] + "`",
        "- Applicable instruction files:",
        *instruction_lines,
        "- Protected resources:",
        *protected_lines,
        "- Context budget: "
        + str(shape["context_budget_tokens"])
        + " tokens",
        "- Brief shape: `" + receipt["brief_shape_sha256"] + "`",
        "- Calibration mode: " + receipt["mode"],
        timing_line,
        "- Fixed calibration margin: "
        + str(receipt["fixed_margin_seconds"])
        + " seconds",
        "- First-patch deadline: "
        + str(receipt["deadline_seconds"])
        + " seconds",
        "- Calibration receipt: `" + receipt["receipt_sha256"] + "`",
        "",
        "1. Read every applicable instruction file listed above, in order, "
        "before any other repository action.",
        workspace_rule,
        "3. Modify files only through the native `apply_patch` pathway. If "
        "it is unavailable, run the `apply_patch` CLI from the lane "
        "workspace with a heredoc.",
        "4. If no owned-file patch exists after "
        + str(receipt["deadline_seconds"])
        + " seconds, stop and report the exact blocker; do not probe, retry, "
        "replace, or reuse the attempt.",
        "5. Stop before exceeding the "
        + str(shape["context_budget_tokens"])
        + "-token context budget and return a bounded handoff.",
        "6. After any context compaction, re-read this brief file before acting.",
        "7. You must not spawn nested workers and must not widen ownership, "
        "authority, protected resources, tools, or workspace scope.",
        "",
    ]
    return "\n".join(lines)


def lint_worker_brief(**kwargs: Any) -> dict[str, Any]:
    """Compare one on-disk brief with its exact frozen v2 preamble."""

    expected = render_worker_preamble(**kwargs)
    path = _absolute_path(kwargs["brief_path"], "brief_path")
    issues: list[str] = []
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raw = None
        issues.append("brief:missing")
    except OSError:
        raw = None
        issues.append("brief:unreadable")
    if raw is not None:
        if len(raw) > MAX_BRIEF_BYTES:
            issues.append("brief:oversized")
        if b"\x00" in raw:
            issues.append("brief:nul")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
            issues.append("brief:utf8_invalid")
        if text is not None:
            marker_count = text.count(_MARKER)
            if marker_count == 0:
                issues.append("preamble:missing")
            elif marker_count > 1:
                issues.append("preamble:duplicate")
            if marker_count == 1 and not text.startswith(expected):
                issues.append("preamble:mismatch")
    report = {
        "schema": LINT_REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "preamble_sha256": _sha256_text(expected),
    }
    report["report_sha256"] = _sha256_json(report)
    return report


def _read_calibration_receipt(path_value: str) -> Mapping[str, Any]:
    path = _absolute_path(path_value, "calibration_receipt")
    try:
        if path.is_symlink() or not path.is_file():
            raise WorkerBriefError(
                "calibration_receipt must be a regular JSON file"
            )
        raw = path.read_bytes()
    except OSError as exc:
        raise WorkerBriefError("calibration_receipt is unreadable") from exc
    if len(raw) > MAX_CALIBRATION_BYTES:
        raise WorkerBriefError("calibration_receipt is oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerBriefError("calibration_receipt is not valid UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise WorkerBriefError("calibration_receipt must contain an object")
    return value


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-checkout", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--lane-workspace", required=True)
    parser.add_argument("--brief-path", required=True)
    parser.add_argument(
        "--agents-file",
        action="append",
        default=None,
        dest="instruction_files",
    )
    parser.add_argument(
        "--protected-resource",
        action="append",
        default=[],
        dest="protected_resources",
    )
    parser.add_argument("--context-budget-tokens", type=int, required=True)
    parser.add_argument("--calibration-receipt", required=True)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render or lint an Orch Dork worker brief"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    _add_common(commands.add_parser("render"))
    _add_common(commands.add_parser("lint"))
    args = parser.parse_args(argv)
    try:
        inputs = {
            "base_checkout": args.base_checkout,
            "branch": args.branch,
            "lane_workspace": args.lane_workspace,
            "brief_path": args.brief_path,
            "instruction_files": args.instruction_files,
            "protected_resources": args.protected_resources,
            "context_budget_tokens": args.context_budget_tokens,
            "calibration_receipt": _read_calibration_receipt(
                args.calibration_receipt
            ),
        }
        if args.command == "render":
            sys.stdout.write(render_worker_preamble(**inputs))
            return 0
        report = lint_worker_brief(**inputs)
    except WorkerBriefError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2
    sys.stdout.write(
        json.dumps(
            report,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "CALIBRATION_SCHEMA",
    "LINT_REPORT_FIELDS",
    "LINT_REPORT_SCHEMA",
    "MAX_BRIEF_BYTES",
    "PREAMBLE_SCHEMA",
    "WorkerBriefError",
    "brief_shape_sha256",
    "lint_worker_brief",
    "render_worker_preamble",
]
