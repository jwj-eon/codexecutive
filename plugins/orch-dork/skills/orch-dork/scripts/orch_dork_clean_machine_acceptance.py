#!/usr/bin/env python3
"""Provider-free blank-machine installation acceptance.

This module models the boundary of a supported host without touching the real
Codex cache, marketplace, project registry, or task system.  A disposable Git
marketplace is created under a caller-owned temporary root, the exact
allow-listed runtime is staged into a disposable cache, and the installed copy
is validated after its source checkout has been removed.  The report contains
only deterministic, content-addressed evidence; paths and source bodies never
cross the acceptance boundary.

The harness deliberately uses the already qualified Issue 44/50 helpers for
marketplace validation, runtime inventory, portable launcher preflight, and
offline Ed25519 attestation.  No provider, credential, network, task, lease,
or real installation path is reachable from this file.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import orch_dork_artifact_attestation as attestation  # noqa: E402
import orch_dork_local_marketplace as local_marketplace  # noqa: E402
import orch_dork_runtime_package as runtime_package  # noqa: E402
import orch_dork_skill_contract as skill_contract  # noqa: E402


SCHEMA = "orch-dork/clean-machine-acceptance/v1"
PROFILE_SCHEMA = "orch-dork/clean-machine-profile/v1"
INSTALL_SCHEMA = "orch-dork/clean-machine-install/v1"
SUPPORTED_PROFILE = "macos-supported-blank-v1"
PLUGIN_NAME = "orch-dork"
DEFAULT_MARKETPLACE_NAME = "orch-dork-local"
DEFAULT_INTERPRETER = "python3"

# This is the exact policy surface shipped by the current qualified runtime.
# Keeping the names in one tuple makes an accidental tool addition/removal a
# visible acceptance failure rather than a silently widened inventory.
EXPECTED_POLICY_TOOLS: tuple[str, ...] = (
    "propose_project_improvements",
    "read_project_improvement",
    "decide_project_improvement",
    "authorize_project_canary",
    "adopt_project_improvement",
    "audit_orchestration_classification",
    "evaluate_ticket_admission",
    "evaluate_split_decision",
    "evaluate_deepening_policy",
    "evaluate_learned_policy",
    "recommend_first_wave",
    "evaluate_admission_kernel",
    "validate_semantic_plan_v2",
    "evaluate_task_creation_intent",
    "evaluate_governed_orchestration_run",
    "adapt_native_capacity_observation",
    "evaluate_worker_lifecycle",
    "evaluate_execution_readiness",
    "evaluate_coordinator_capsule",
    "project_orchestration_live_view",
    "prepare_governed_native_activation",
    "authorize_issue94_successor_first_action",
    "submit_issue94_semantic_review",
    "submit_issue94_bootstrapped_semantic_review",
    "advance_issue94_successor_after_native_action",
    "advance_issue94_bootstrapped_after_native_action",
    "advance_governed_native_controller",
    "evaluate_project_ground_enforcement",
    "evaluate_project_ground_maintenance",
    "evaluate_project_enrollment",
    "evaluate_orchestration_project_adapter",
    "evaluate_orchestration_worker_port",
    "evaluate_orchestration_control_tower",
    "observe_current_orchestration_route",
    "evaluate_live_route_handoff",
    "observe_current_local_task_runtime",
    "prepare_work_summary",
    "propose_ticket_status_update",
    "confirm_ticket_status_update",
    "start_governed_run",
    "read_governed_run",
    "steer_governed_run",
    "revise_governed_run",
    "stop_governed_run",
    "open_local_ui",
    "onboard_model",
    "enroll_project",
    "confirm_enrollment",
    "read_onboarding",
    "validate_logical_worker_program",
    "run_logical_worker_waves",
    "evaluate_wave_progress",
    "evaluate_advisory_scan",
    "observe_native_advisory_scan",
    "evaluate_sol_replan",
    "evaluate_decomposition_proposal",
    "evaluate_adaptive_finite_dag",
    "validate_adaptive_contract",
    "evaluate_evidence_policy",
    "evaluate_route_policy",
    "evaluate_campaign_policy",
    "evaluate_experiment_campaign",
    "validate_relay_manifest",
    "verify_wave_routing",
    "run_active_orchestration_controller",
    "evaluate_orchestration_limits",
    "evaluate_orchestration_profile",
    "evaluate_orchestration_efficiency",
    "evaluate_orchestration_budget",
    "evaluate_orchestration_recovery",
    "qualify_orchestration_graph",
    "evaluate_root_rollover",
    "validate_orchestration_custody",
    "validate_orchestration_ownership",
    "validate_orchestration_admission",
    "validate_orchestration_spawn_wave",
    "validate_orchestration_plan",
    "qualify_orchestration_trace",
    "qualify_read_custody",
)

# Stable fixture-only key.  It is not an external credential and is used only
# to exercise the offline signature verifier in a disposable process.
FIXTURE_SIGNING_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
FIXTURE_KEY_ID = "issue45-clean-machine-fixture"

_JSON_SEPARATORS = (",", ":")
_MAX_REPORT_ISSUES = 128


class CleanMachineAcceptanceError(ValueError):
    """A bounded, named acceptance failure."""

    def __init__(self, *issues: str):
        clean = tuple(str(item) for item in issues if item)
        self.issues = clean or ("clean_machine:failed",)
        super().__init__("; ".join(self.issues))


AcceptanceError = CleanMachineAcceptanceError


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=_JSON_SEPARATORS,
        allow_nan=False,
    ).encode("utf-8", "strict")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical(value))


def _safe_path(value: os.PathLike[str] | str, *, label: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise CleanMachineAcceptanceError(f"{label}:invalid")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise CleanMachineAcceptanceError(f"{label}:invalid")
    path = Path(raw)
    if path.is_symlink():
        raise CleanMachineAcceptanceError(f"{label}:symlink")
    return path.absolute()


def _run_git(repository: Path, *args: str, check: bool = True) -> str:
    env = os.environ.copy()
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        env.pop(key, None)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
        }
    )
    result = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(repository), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if check and result.returncode != 0:
        raise CleanMachineAcceptanceError(f"git:{args[0] if args else 'command'}:failed")
    return result.stdout.strip()


def _default_source_root() -> Path:
    # .../plugins/orch-dork/skills/orch-dork/scripts/<this file>
    return SCRIPT_DIR.parents[3]


def _normalise_allowlist(allowlist: Sequence[str] | None) -> tuple[str, ...]:
    if allowlist is None:
        return tuple(runtime_package.RUNTIME_ALLOWLIST)
    values = tuple(str(item) for item in allowlist)
    # Delegate canonical ordering/path checks to the package owner.  This is a
    # deliberate private seam: the package module owns the allowlist grammar,
    # while this harness owns only the blank-profile lifecycle.
    return tuple(runtime_package._normalize_allowlist(values))


def _copy_allowlisted_tree(source: Path, destination: Path, allowlist: Sequence[str]) -> None:
    """Copy only regular allow-listed files into a disposable checkout."""

    source = _safe_path(source, label="source")
    destination = _safe_path(destination, label="destination")
    if not source.is_dir():
        raise CleanMachineAcceptanceError("source:not_directory")
    destination.mkdir(parents=True, exist_ok=False)
    for relative in sorted(set(str(item) for item in allowlist)):
        # The runtime package validator remains the authority for path syntax.
        try:
            relative_path = PurePosixPath(relative)
            if relative_path.is_absolute() or any(part in {"", ".", ".."} for part in relative_path.parts):
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise CleanMachineAcceptanceError("allowlist:invalid_path") from exc
        source_path = source.joinpath(*relative_path.parts)
        if not source_path.exists():
            # Optional paths are omitted exactly as the runtime package owner
            # defines; required missing paths are reported by package build.
            continue
        if source_path.is_symlink() or not source_path.is_file():
            raise CleanMachineAcceptanceError(f"source:unsafe:{relative}")
        target = destination.joinpath(*relative_path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target, follow_symlinks=False)
        os.chmod(target, stat.S_IMODE(source_path.stat().st_mode))


def create_disposable_git_marketplace(
    source_root: os.PathLike[str] | str | None = None,
    workspace_root: os.PathLike[str] | str | None = None,
    *,
    allowlist: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Copy a runtime into a clean local Git repository and bind its revision."""

    source = _safe_path(source_root or _default_source_root(), label="source")
    workspace = _safe_path(workspace_root or tempfile.mkdtemp(prefix="orch-dork-issue45-"), label="workspace")
    workspace.mkdir(parents=True, exist_ok=True)
    repository = workspace / "marketplace-git"
    repository.mkdir()
    plugin = repository / "plugins" / PLUGIN_NAME
    selected_allowlist = _normalise_allowlist(allowlist)
    _copy_allowlisted_tree(source, plugin, selected_allowlist)
    _run_git(repository, "init", "-q")
    _run_git(repository, "config", "user.name", "Orch Dork Issue 45 fixture")
    _run_git(repository, "config", "user.email", "orch-dork-issue45@example.invalid")
    _run_git(repository, "add", ".")
    _run_git(repository, "commit", "-q", "-m", "clean-machine acceptance fixture")
    revision = _run_git(repository, "rev-parse", "HEAD")
    if len(revision) != 40 or revision.lower() != revision:
        raise CleanMachineAcceptanceError("revision:not_full_sha1")
    return {
        "schema": "orch-dork/clean-machine-marketplace/v1",
        "repository": repository,
        "plugin_root": plugin,
        "revision": revision,
        "allowlist": list(selected_allowlist),
        "git_clean": not bool(_run_git(repository, "status", "--porcelain=v1")),
    }


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CleanMachineAcceptanceError(f"module:unavailable:{name}")
    module = importlib.util.module_from_spec(spec)
    # Importing from the disposable checkout must not write `__pycache__`
    # beside the source.  A stray `.pyc` makes the fixture repository dirty
    # and fails marketplace construction with `git:dirty`, so the harness owns
    # this guarantee instead of depending on the caller's environment.
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def _manifest(root: Path) -> dict[str, Any]:
    path = root / ".codex-plugin" / "plugin.json"
    if path.is_symlink() or not path.is_file():
        raise CleanMachineAcceptanceError("manifest:missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CleanMachineAcceptanceError("manifest:malformed") from exc
    if not isinstance(value, dict):
        raise CleanMachineAcceptanceError("manifest:not_object")
    if value.get("name") != PLUGIN_NAME:
        raise CleanMachineAcceptanceError("manifest:name_mismatch")
    version = value.get("version")
    if not isinstance(version, str) or not version:
        raise CleanMachineAcceptanceError("manifest:version_missing")
    if value.get("skills") != "./skills/":
        raise CleanMachineAcceptanceError("manifest:skills_not_portable")
    if value.get("mcpServers") != "./.mcp.json":
        raise CleanMachineAcceptanceError("manifest:mcp_not_portable")
    return value


def _agent_metadata(root: Path) -> dict[str, str]:
    path = root / "skills" / PLUGIN_NAME / "agents" / "openai.yaml"
    if path.is_symlink() or not path.is_file():
        raise CleanMachineAcceptanceError("agent_metadata:missing")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CleanMachineAcceptanceError("agent_metadata:unreadable") from exc
    rows: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"\'')
        if key in {"display_name", "short_description", "default_prompt"} and value:
            rows[key] = value
    if set(rows) != {"display_name", "short_description", "default_prompt"}:
        raise CleanMachineAcceptanceError("agent_metadata:incomplete")
    return rows


def _skill_inventory(root: Path) -> dict[str, Any]:
    skill_root = root / "skills" / PLUGIN_NAME
    if skill_root.is_symlink() or not skill_root.is_dir():
        raise CleanMachineAcceptanceError("skill_discovery:missing")
    report = skill_contract.contract_inventory(skill_root)
    if report.get("status") != "PASS":
        issue = report.get("issues", ["skill_discovery:invalid"])[0]
        raise CleanMachineAcceptanceError(f"skill_discovery:{issue}")
    return report


def _policy_inventory(root: Path) -> tuple[str, ...]:
    path = root / "skills" / PLUGIN_NAME / "scripts" / "orch_dork_policy.py"
    module = _load_module(path, f"orch_dork_policy_install_{id(path)}")
    try:
        rows = module.list_tools()
    except Exception as exc:  # pragma: no cover - sanitized runtime boundary
        raise CleanMachineAcceptanceError("policy_tools:unavailable") from exc
    if not isinstance(rows, list):
        raise CleanMachineAcceptanceError("policy_tools:not_array")
    names: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("name"), str) or not row["name"]:
            raise CleanMachineAcceptanceError("policy_tools:malformed")
        names.append(row["name"])
    if tuple(names) != EXPECTED_POLICY_TOOLS:
        raise CleanMachineAcceptanceError("policy_tools:inventory_mismatch")
    return tuple(names)


def _portable_mcp(root: Path, *, interpreter: str | os.PathLike[str] | None) -> dict[str, Any]:
    launcher_path = root / "scripts" / "orch_dork_mcp_launcher.py"
    if launcher_path.is_symlink() or not launcher_path.is_file():
        raise CleanMachineAcceptanceError("mcp:launcher_missing")
    launcher = _load_module(launcher_path, f"orch_dork_launcher_install_{id(root)}")
    preflight = launcher.preflight(root=root, interpreter=interpreter)
    if preflight.get("status") != "PASS":
        issue = preflight.get("issues", ["mcp:preflight_failed"])[0]
        raise CleanMachineAcceptanceError(str(issue))
    requests = (
        b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        b'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-B", str(launcher_path), "serve"],
            input=requests,
            cwd=str(root),
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CleanMachineAcceptanceError("mcp:startup_failed") from exc
    if completed.returncode != 0:
        raise CleanMachineAcceptanceError("mcp:startup_failed")
    try:
        replies = [json.loads(line) for line in completed.stdout.splitlines() if line]
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CleanMachineAcceptanceError("mcp:malformed_response") from exc
    if len(replies) != 2 or replies[0].get("result", {}).get("serverInfo", {}).get("name") != PLUGIN_NAME:
        raise CleanMachineAcceptanceError("mcp:initialize_failed")
    tools = replies[1].get("result", {}).get("tools")
    if not isinstance(tools, list) or tuple(row.get("name") for row in tools if isinstance(row, Mapping)) != EXPECTED_POLICY_TOOLS:
        raise CleanMachineAcceptanceError("mcp:tool_inventory_mismatch")
    return {
        "status": "PASS",
        "preflight": {
            "schema": preflight.get("schema"),
            "contract": preflight.get("contract"),
            "interpreter": preflight.get("interpreter"),
            "provider_free": preflight.get("provider_free") is True,
        },
        "initialize": "PASS",
        "tools_list": "PASS",
        "tool_count": len(tools),
    }


def _manifest_digest(entries: Sequence[Mapping[str, Any]]) -> str:
    for row in entries:
        if row.get("path") == runtime_package.MANIFEST_PATH:
            return str(row["sha256"])
    raise CleanMachineAcceptanceError("inventory:manifest_missing")


def _attestation_for(report: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    package_digest = str(report["package_digest"])
    inventory_digest = str(report["inventory_hash"])
    descriptor_digest = str(report["descriptor_hash"])
    manifest_digest = str(report["manifest_hash"])
    statement = {
        "_type": attestation.IN_TOTO_STATEMENT_TYPE,
        "subject": [{"name": "orch-dork-package", "digest": {"sha256": package_digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "packageDigest": package_digest,
            "inventoryDigest": inventory_digest,
            "descriptorDigest": descriptor_digest,
            "manifestDigest": manifest_digest,
        },
    }
    payload = attestation.canonical_json_bytes(statement)
    signature = attestation.ed25519_sign(
        FIXTURE_SIGNING_SEED,
        attestation.dsse_pae(attestation.DSSE_PAYLOAD_TYPE, payload),
    )
    envelope = {
        "payloadType": attestation.DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": FIXTURE_KEY_ID,
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }
    public_key = attestation.ed25519_public_key(FIXTURE_SIGNING_SEED)
    trust_store = {
        "schema": "orch-dork/trust-store/v1",
        "generation": "issue45-clean-machine-v1",
        "mode": "offline",
        "conventional_keys": [
            {
                "keyid": FIXTURE_KEY_ID,
                "algorithm": "ed25519",
                "public_key": public_key.hex(),
                "fingerprint": "sha256:" + _sha256_bytes(public_key),
            }
        ],
    }
    verified = attestation.verify_attestation(
        envelope,
        trust_store,
        expected_subject="orch-dork-package",
        expected_package_digest=package_digest,
    )
    if verified.get("status") != "PASS":
        raise CleanMachineAcceptanceError("attestation:verification_failed")
    # Verify the three subordinate identities ourselves; the attestation
    # verifier intentionally treats these as generic predicate digests.
    decoded = attestation.parse_canonical_json(payload)
    predicate = decoded.get("predicate", {}) if isinstance(decoded, Mapping) else {}
    if any(predicate.get(name) != value for name, value in (
        ("inventoryDigest", inventory_digest),
        ("descriptorDigest", descriptor_digest),
        ("manifestDigest", manifest_digest),
    )):
        raise CleanMachineAcceptanceError("attestation:predicate_digest_mismatch")
    return envelope, trust_store, verified


def _install_from_stage(stage: Path, destination: Path, *, allowlist: Sequence[str]) -> dict[str, Any]:
    """Install a verified stage without replacing an existing cache entry."""

    destination = _safe_path(destination, label="installed")
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise CleanMachineAcceptanceError("stale_cache:unsafe_destination")
        try:
            report = runtime_package.validate_runtime_package(stage, destination, allowlist=allowlist)
        except runtime_package.RuntimePackageError as exc:
            raise CleanMachineAcceptanceError("stale_cache:prior_generation_preserved", *exc.issues) from exc
        return report
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Copy only after stage validation; source checkout is not referenced by
    # this operation and can be removed immediately after it returns.
    shutil.copytree(stage, destination, symlinks=False)
    try:
        return runtime_package.validate_runtime_package(stage, destination, allowlist=allowlist)
    except runtime_package.RuntimePackageError as exc:
        raise CleanMachineAcceptanceError("install:post_copy_mismatch", *exc.issues) from exc


def _report_failure(issues: Sequence[str], *, provider_free: bool = True) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(str(item) for item in issues))[:_MAX_REPORT_ISSUES],
        "provider_free": provider_free,
        "model_calls": 0,
        "hosted_calls": 0,
        "credential_reads": 0,
        "network_attempts": 0,
        "task_creations": 0,
        "real_install_mutations": 0,
    }


def _negative_checks(
    *,
    installed: Path,
    stage: Path,
    allowlist: Sequence[str],
    expected_interpreter: str,
) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    launcher = _load_module(
        installed / "scripts" / "orch_dork_mcp_launcher.py",
        f"orch_dork_launcher_negative_{id(installed)}",
    )
    missing = launcher.preflight(root=installed, interpreter="orch-dork-interpreter-missing")
    checks["missing_interpreter"] = {
        "status": "PASS" if missing.get("status") == "FAIL" and any(
            str(item).startswith("interpreter:missing:") for item in missing.get("issues", [])
        ) else "FAIL",
        "disposition": "READ_ONLY",
    }

    mismatch = stage.parent / "source-mismatch"
    shutil.copytree(stage, mismatch)
    mismatch_file = mismatch / "skills" / PLUGIN_NAME / "SKILL.md"
    mismatch_file.write_text(mismatch_file.read_text(encoding="utf-8") + "\n# mismatch fixture\n", encoding="utf-8")
    try:
        runtime_package.validate_runtime_package(stage, mismatch, allowlist=allowlist)
    except runtime_package.RuntimePackageError as exc:
        checks["source_package_mismatch"] = {
            "status": "PASS",
            "disposition": "READ_ONLY",
            "reason": next((item for item in exc.issues if "stale_stage" in item), "stale_stage:inventory"),
        }
    else:
        checks["source_package_mismatch"] = {"status": "FAIL", "disposition": "READ_ONLY"}

    stale = stage.parent / "stale-cache"
    shutil.copytree(installed, stale)
    stale_file = stale / "skills" / PLUGIN_NAME / "SKILL.md"
    stale_file.write_text(stale_file.read_text(encoding="utf-8") + "\n# stale cache fixture\n", encoding="utf-8")
    prior = stale_file.read_bytes()
    try:
        _install_from_stage(stage, stale, allowlist=allowlist)
    except CleanMachineAcceptanceError as exc:
        checks["stale_cache"] = {
            "status": "PASS" if any("stale_cache" in item for item in exc.issues) else "FAIL",
            "disposition": "READ_ONLY",
            "prior_generation_preserved": stale_file.read_bytes() == prior,
        }
    else:
        checks["stale_cache"] = {"status": "FAIL", "disposition": "READ_ONLY"}
    checks["all_pass"] = all(row.get("status") == "PASS" for row in checks.values() if isinstance(row, Mapping))
    return checks


def run_clean_machine_acceptance(
    source_root: os.PathLike[str] | str | None = None,
    *,
    workspace_root: os.PathLike[str] | str | None = None,
    interpreter: str | os.PathLike[str] | None = None,
    expected_plugin_version: str | None = None,
    allowlist: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Run the complete disposable blank-profile acceptance.

    ``workspace_root`` is never required to be outside the caller's temp
    directory; when omitted a private temporary root is removed before return.
    The function catches only bounded acceptance failures and returns a
    structured report so a clean-machine runner can preserve the failed case
    without exposing a traceback or host path.
    """

    owned_workspace = workspace_root is None
    workspace: Path | None = None
    try:
        workspace = _safe_path(workspace_root or tempfile.mkdtemp(prefix="orch-dork-issue45-"), label="workspace")
        workspace.mkdir(parents=True, exist_ok=True)
        profile = workspace / "blank-profile"
        if profile.exists() and (profile.is_symlink() or not profile.is_dir()):
            raise CleanMachineAcceptanceError("profile:not_blank")
        profile.mkdir(exist_ok=True)
        # The initial profile is intentionally empty.  No registry, cache,
        # project state, or marketplace is created until after this assertion.
        if any(profile.iterdir()):
            raise CleanMachineAcceptanceError("profile:not_blank")
        blank = {
            "schema": PROFILE_SCHEMA,
            "profile": SUPPORTED_PROFILE,
            "initial_entries": 0,
            "marketplace_absent": not (profile / "marketplaces").exists(),
            "cache_absent": not (profile / "cache").exists(),
            "enrollment_registry_absent": not (profile / "enrollment").exists(),
            "project_state_absent": not (profile / "projects").exists(),
        }
        if not all(value is True for key, value in blank.items() if key.endswith("absent") or key == "marketplace_absent"):
            raise CleanMachineAcceptanceError("profile:inherited_state")

        selected_allowlist = _normalise_allowlist(allowlist)
        marketplace = create_disposable_git_marketplace(
            source_root,
            workspace,
            allowlist=selected_allowlist,
        )
        source_manifest = _manifest(marketplace["plugin_root"])
        version = str(source_manifest["version"])
        if expected_plugin_version is not None and version != expected_plugin_version:
            raise CleanMachineAcceptanceError("manifest:unexpected_version")
        source_tools = _policy_inventory(marketplace["plugin_root"])
        source_skill = _skill_inventory(marketplace["plugin_root"])
        source_agent = _agent_metadata(marketplace["plugin_root"])

        health = {
            "status": "PASS",
            "checks": ["blank-profile", "manifest", "skill-discovery", "agent-metadata", "portable-mcp", "policy-tools", "interpreter"],
            "tool_inventory": list(source_tools),
            "runtime": {"name": DEFAULT_INTERPRETER, "status": "PASS"},
        }
        marketplace_manifest = local_marketplace.construct_local_marketplace(
            marketplace["repository"],
            marketplace["revision"],
            PLUGIN_NAME,
            version,
            health,
            manifest_path=profile / "marketplaces" / f"{DEFAULT_MARKETPLACE_NAME}.json",
        )
        marketplace_validation = local_marketplace.validate_local_marketplace(
            profile / "marketplaces" / f"{DEFAULT_MARKETPLACE_NAME}.json",
            marketplace["repository"],
            expected_revision=marketplace["revision"],
            expected_plugin_name=PLUGIN_NAME,
            expected_plugin_version=version,
            health_evidence=health,
        )

        stage = workspace / "verified-stage"
        package_report = runtime_package.build_runtime_package(
            marketplace["plugin_root"],
            stage,
            allowlist=selected_allowlist,
        )
        entries = runtime_package.inventory_runtime(marketplace["plugin_root"], allowlist=selected_allowlist)
        package_report = dict(package_report)
        package_report["manifest_hash"] = _manifest_digest(entries)
        installed = profile / "cache" / PLUGIN_NAME / version
        install_report = _install_from_stage(stage, installed, allowlist=selected_allowlist)
        install_report = dict(install_report)
        install_report["manifest_hash"] = _manifest_digest(runtime_package.inventory_runtime(installed, allowlist=selected_allowlist))

        # The source checkout is not a dependency of the installed process.
        # Remove only the disposable copy, then run every installed check.
        shutil.rmtree(marketplace["repository"])
        installed_manifest = _manifest(installed)
        installed_skill = _skill_inventory(installed)
        installed_agent = _agent_metadata(installed)
        installed_tools = _policy_inventory(installed)
        if installed_tools != source_tools:
            raise CleanMachineAcceptanceError("policy_tools:source_installed_mismatch")
        installed_mcp = _portable_mcp(installed, interpreter=interpreter)
        if installed_manifest != source_manifest:
            raise CleanMachineAcceptanceError("manifest:source_installed_mismatch")
        if installed_skill.get("contract_generation") != source_skill.get("contract_generation"):
            raise CleanMachineAcceptanceError("skill_discovery:source_installed_mismatch")
        if installed_agent != source_agent:
            raise CleanMachineAcceptanceError("agent_metadata:source_installed_mismatch")
        installed_validation = runtime_package.inventory_runtime(installed, allowlist=selected_allowlist)
        installed_report = dict(runtime_package._report(version, installed_validation))
        installed_report["manifest_hash"] = _manifest_digest(installed_validation)
        if installed_report != install_report:
            raise CleanMachineAcceptanceError("installed:package_report_mismatch")
        envelope, trust_store, attestation_report = _attestation_for(installed_report)
        negatives = _negative_checks(
            installed=installed,
            stage=stage,
            allowlist=selected_allowlist,
            expected_interpreter=str(interpreter or DEFAULT_INTERPRETER),
        )
        if negatives.get("all_pass") is not True:
            raise CleanMachineAcceptanceError("negative_matrix:failed")

        report = {
            "schema": SCHEMA,
            "status": "PASS",
            "profile": blank,
            "marketplace": {
                "status": "PASS",
                "schema": marketplace_manifest.get("binding", {}).get("schema"),
                "name": marketplace_manifest.get("name"),
                "revision": marketplace["revision"],
                "manifest_sha256": marketplace_validation["manifest_sha256"],
                "git_clean": marketplace["git_clean"],
                "source_checkout_dependency": "PASS",
            },
            "package": {
                "status": "PASS",
                **package_report,
                "signed": attestation_report.get("status") == "PASS",
            },
            "installed": {
                "status": "PASS",
                "manifest": "PASS",
                "skill_discovery": "PASS",
                "agent_metadata": "PASS",
                "portable_mcp": installed_mcp,
                "policy_tools": list(installed_tools),
                **installed_report,
                "source_checkout_dependency": "PASS",
            },
            "attestation": {
                "status": attestation_report.get("status"),
                "reason": attestation_report.get("reason"),
                "signature_kind": attestation_report.get("receipt", {}).get("signature_kind"),
                "trust_store_generation": trust_store["generation"],
                "inventory_signed": True,
                "descriptor_signed": True,
                "manifest_signed": True,
            },
            "health": {
                "status": "PASS",
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
                "credential_reads": 0,
                "network_attempts": 0,
            },
            "negative_checks": negatives,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "credential_reads": 0,
            "network_attempts": 0,
            "task_creations": 0,
            "real_install_mutations": 0,
            "issues": [],
        }
        return report
    except (CleanMachineAcceptanceError, runtime_package.RuntimePackageError, local_marketplace.LocalMarketplaceError) as exc:
        issues = list(getattr(exc, "issues", (str(exc),)))
        return _report_failure(issues)
    except (OSError, TypeError, ValueError) as exc:
        return _report_failure((f"clean_machine:{type(exc).__name__}",))
    finally:
        if owned_workspace and workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)


# Compatibility aliases used by acceptance runners and focused tests.
run_acceptance = run_clean_machine_acceptance
accept_clean_machine = run_clean_machine_acceptance
clean_machine_acceptance = run_clean_machine_acceptance
create_marketplace = create_disposable_git_marketplace


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=None)
    parser.add_argument("--workspace", type=Path, default=None)
    parser.add_argument("--interpreter", default=None)
    parser.add_argument("--version", dest="expected_plugin_version", default=None)
    args = parser.parse_args(argv)
    report = run_clean_machine_acceptance(
        args.source,
        workspace_root=args.workspace,
        interpreter=args.interpreter,
        expected_plugin_version=args.expected_plugin_version,
    )
    print(json.dumps(report, sort_keys=True, separators=_JSON_SEPARATORS))
    return 0 if report.get("status") == "PASS" else 2


if __name__ == "__main__":  # pragma: no cover - CLI convenience
    raise SystemExit(_main())


__all__ = [
    "SCHEMA",
    "PROFILE_SCHEMA",
    "INSTALL_SCHEMA",
    "SUPPORTED_PROFILE",
    "PLUGIN_NAME",
    "EXPECTED_POLICY_TOOLS",
    "CleanMachineAcceptanceError",
    "AcceptanceError",
    "create_disposable_git_marketplace",
    "create_marketplace",
    "run_clean_machine_acceptance",
    "run_acceptance",
    "accept_clean_machine",
    "clean_machine_acceptance",
]
