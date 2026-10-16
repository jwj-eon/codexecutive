"""Same-process owner for the final Issue 170 action sequence.

This module retains physical objects; it does not turn persisted reports into
authority.  The provider-free campaign and four test profiles run against one
unchanged source checkout.  Only that rebuilt gate may spend the candidate
claim. Historical E--K completion evidence is not replayed at this boundary.
Release and live effects remain closed until their fixed physical
readers have independently accepted source pins.
"""
from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import builtins
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
import types
import weakref


_FIXED_MODULE_NAMES = (
    "orch_dork_release_marketplace",
    "orch_dork_predecessor_readiness",
    "orch_dork_observer_receipt",
    "orch_dork_runtime_package",
    "lifecycle_conformance.action_authority",
    "lifecycle_conformance.candidate_identity",
    "lifecycle_conformance.completion_gate",
    "lifecycle_conformance.consumption",
    "lifecycle_conformance.host_attestation",
    "lifecycle_conformance.live_qualification_execution",
    "lifecycle_conformance.promotion_authentication",
    "lifecycle_conformance.release_execution",
    "lifecycle_conformance.reference_values",
    "lifecycle_conformance.source_scope_closure",
    "lifecycle_conformance.values",
)


def _compiled_origin(module):
    """True when stored bytecode for this module exists on disk."""
    cached = getattr(module, "__cached__", None)
    return bool(cached) and Path(cached).exists()


def _source_code(loader, fullname):
    path = loader.get_filename(fullname)
    return loader.source_to_code(loader.get_data(path), path)


def _refuse_bytecode(loader, fullname):
    raise ImportError("action_host:source_only_import:" + fullname)


# -B alone can read an existing cache.  Install the source-only loader before
# any repository-owned dependency enters this process.
importlib.machinery.SourceFileLoader.get_code = _source_code
importlib.machinery.SourcelessFileLoader.get_code = _refuse_bytecode

import orch_dork_release_marketplace as release_marketplace
import orch_dork_predecessor_readiness as predecessor_readiness
import orch_dork_observer_receipt as observer_receipt
import orch_dork_runtime_package as runtime_package
from lifecycle_conformance import (
    action_authority,
    candidate_identity,
    completion_gate,
    consumption,
    host_attestation,
    live_qualification_execution,
    promotion_authentication,
    release_execution,
    reference_values as rv,
    source_scope_closure,
    values,
)


SCHEMA = "orch-dork/issue170-action-host/v1"
CANDIDATE_RECEIPT_SCHEMA = "orch-dork/issue170-candidate-physical-receipt/v1"
CANDIDATE_READINESS_SCHEMA = "orch-dork/candidate-readiness/v5"
CANDIDATE_READINESS_VALIDATION_SCHEMA = (
    "orch-dork/candidate-readiness-validation/v3"
)
PREDECESSOR_RECOVERY_RECEIPT_SCHEMA = (
    "orch-dork/qualification-observed-spawn-stall-recovery-"
    "artifact-receipt/v2"
)
PREDECESSOR_RECOVERY_RECEIPT_KIND = "stage-l-predecessor-recovery"
PREDECESSOR_CLOSED_FAILURE_SCHEMA = "orch-dork/closed-qualification-failure/v1"
PREDECESSOR_CLOSED_FAILURE_KIND = "stage-l-closed-qualification-failure"
PREDECESSOR_SETTLEMENT_SCHEMA = (
    "orch-dork/qualification-observed-spawn-stall-settlement/v1"
)
# A predecessor whose root turn failed before any native action is closed by
# orch_dork_pre_native_failure_recovery: the controller's sanctioned
# pre-native terminalization, settled through the terminal predecessor
# capacity settlement (decision TERMINALIZED, zero lanes released) and signed
# with the same host recovery kind.  Generation v51 ended this way and had
# no binding path until this receipt existed.
PREDECESSOR_PRE_NATIVE_RECOVERY_RECEIPT_SCHEMA = (
    "orch-dork/qualification-pre-native-failure-recovery-"
    "artifact-receipt/v1"
)
PREDECESSOR_PRE_NATIVE_RECOVERY_DECISION = "PRE_NATIVE_FAILURE_RECOVERED"
PREDECESSOR_PRE_NATIVE_SETTLEMENT_SCHEMA = (
    "orch-dork/qualification-predecessor-capacity-settlement/v2"
)
PREDECESSOR_PRE_NATIVE_TERMINALIZATION_SCHEMA = (
    "orch-dork/qualification-pre-native-failure-settlement/v1"
)
PREDECESSOR_PRE_NATIVE_PROGRAM_SCHEMA = (
    "orch-dork/pre-native-failure-terminalization-program/v1"
)
# A predecessor that completed its own qualified live run leaves no recovery
# receipt.  Its identity comes from that run's sealed PASS evidence instead:
# the promotion receipt names the generation and seals the owner's terminal
# evidence, and that evidence records the controller, run, attempt and root
# task the live observer must report before and after release.
PREDECESSOR_QUALIFICATION_RECEIPT_SCHEMA = (
    "orch-dork/promotion-qualification-receipt/v1"
)
PREDECESSOR_QUALIFICATION_EVIDENCE_SCHEMA = (
    "orch-dork/issue170-qualification-owner-complete/v1"
)
_PREDECESSOR_QUALIFICATION_RECEIPT_FIELDS = frozenset({
    "schema", "status", "ticket_id", "repair_branch", "generation",
    "runtime_package_digest", "source_commit",
    "qualification_evidence_sha256",
})
# The exact top-level shape the owner seals as its PASS terminal evidence.
_PREDECESSOR_QUALIFICATION_EVIDENCE_FIELDS = frozenset({
    "schema", "status", "disposition", "ticket_id", "repair_branch",
    "source_commit", "generation", "runtime_package_digest",
    "terminal_order", "action_turns", "bindings",
    "promotion_receipt_binding",
})
# One ticket owns one "codex/issue-<ticket>-repair" branch; the owner request
# and the predecessor receipt are both held to that rule.  The owner
# (orch_dork_issue170_qualification_owner.repair_branch_for_ticket) and the
# durable-recovery reader (live_qualification_execution._owner_repair_branch)
# carry the same rule, and a test holds the three copies equal.
_TICKET_TEXT = re.compile(r"[1-9][0-9]{0,8}\Z")
_PREDECESSOR_GENERATION_TEXT = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}\Z"
)
_INSTALLED_PLUGIN_CACHE = "plugins/cache/orch-dork-local/orch-dork"
# The predecessor is whichever controller the live observer reports.  Its
# identity is bound at handoff time between the recovery artifact, the signed
# recovery receipt and the observed readiness report; it is never compiled into
# this module.  Earlier generations pinned one controller id here, which
# forced a runtime edit, a ledger reseal and a fresh generation after every
# failed live attempt before the next attempt could begin.
PREDECESSOR_ATTEMPT_SUFFIX = "-issue94-attempt"
PREDECESSOR_RUN_SUFFIX = "-issue94-run"
PREDECESSOR_LOGICAL_LANE_IDS = ("spec", "standards")
_PREDECESSOR_IDENTITY_FIELDS = (
    "controller_id", "controller_run_id", "root_task_id",
    "attempt_id", "run_id",
)
# Owner counters that must all be zero for an installed attempt that created no task.
_CLOSED_FAILURE_NO_TASK_COUNTERS = (
    "task_creations", "model_calls", "native_calls", "network_calls",
    "hosted_calls", "credential_reads",
)
# The qualified-prior cut's observation binds the preceding PASS pair by path, size and digest.
_CLOSED_FAILURE_QUALIFIED_PRIOR_FIELDS = frozenset({
    "prior_qualification_receipt_path", "prior_qualification_receipt_sha256",
    "prior_qualification_receipt_size_bytes", "prior_qualification_evidence_path",
    "prior_qualification_evidence_sha256", "prior_qualification_evidence_size_bytes",
})
_PREDECESSOR_ID_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_PREDECESSOR_SETTLEMENT_FIELDS = {
    "schema", "status", "decision", "issues", "evaluation_time",
    "predecessor", "closure_report", "capacity_admission_report",
    "settlement_program", "settlement_report", "capacity_authority_before",
    "capacity_authority_after", "released_authority_lane_ids",
    "released_logical_lane_ids", "started_logical_lane_id",
    "never_started_logical_lane_ids", "boundary", "provider_free",
    "counters", "report_sha256",
}
_PREDECESSOR_SETTLEMENT_COUNTERS = {
    "capacity_lanes_released": 2,
    "cleanup_observer_receipts_issued": 2,
    "host_seed_credential_reads": 1,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "network_calls": 0,
    "pre_native_failures_terminalized": 0,
    "provider_calls": 0,
    "task_creations": 0,
    "worker_creations": 0,
}
# orch_dork_qualification_successor._SETTLEMENT_REPORT_FIELDS and the
# TERMINALIZED counters of QualificationPredecessorSettlementArtifact; held
# equal by a test, never imported into this frozen module surface.
_PREDECESSOR_PRE_NATIVE_SETTLEMENT_FIELDS = {
    "schema", "status", "decision", "issues", "evaluation_time",
    "predecessor", "capacity_authority_before",
    "pre_native_failure_settlement_report", "capacity_admission_report",
    "failed_settlement_report", "settlement_program", "settlement_report",
    "capacity_authority_after", "released_authority_lane_ids",
    "released_logical_lane_ids", "boundary", "provider_free", "counters",
    "report_sha256",
}
_PREDECESSOR_PRE_NATIVE_SETTLEMENT_COUNTERS = {
    "capacity_lanes_released": 0,
    "cleanup_observer_receipts_issued": 0,
    "host_seed_credential_reads": 0,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "network_calls": 0,
    "pre_native_failures_terminalized": 1,
    "provider_calls": 0,
    "task_creations": 0,
    "worker_creations": 0,
}
_PREDECESSOR_PRE_NATIVE_TERMINALIZATION_FIELDS = {
    "schema", "status", "decision", "issues", "evaluation_time",
    "controller_program", "controller_report",
    "predecessor_authority_before", "predecessor_authority_after",
    "boundary", "provider_free", "counters", "report_sha256",
}
_PREDECESSOR_PRE_NATIVE_TERMINALIZATION_COUNTERS = {
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "network_calls": 0,
    "provider_calls": 0,
    "task_creations": 0,
    "terminalizations": 1,
    "worker_creations": 0,
}
_PREDECESSOR_SUCCESSOR_BOUNDARY = {
    "native_action_called": False,
    "next_transition": "successor_activation",
    "provider_boundary_crossed": False,
    "successor_activation_started": False,
    "task_created": False,
    "worker_created": False,
}
_PREDECESSOR_PRE_NATIVE_TERMINALIZATION_BOUNDARY = {
    "native_action_called": False,
    "next_transition": "terminal_predecessor_capacity_check",
    "provider_boundary_crossed": False,
    "successor_activation_started": False,
    "task_created": False,
    "worker_created": False,
}
PROFILES = ("campaign", "focused", "rehearsal", "full_suite")
CAMPAIGN_TIMEOUT_SECONDS = host_attestation.MAX_TIMEOUT_SECONDS
_TOKEN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_AUTHORITY = object()
_STAGE_L_RELEASE_AUTHORITY = object()
_STAGE_L_LIVE_AUTHORITY = object()
_ISSUED = {}
_STATES = {}

# Independently reviewed pins for the final physical release boundary.  The
# release-execution pin normalizes only its accepted guard value; the helper
# below checks that value independently and binds every other source byte.
_ACCEPTED_RELEASE_GUARD_PINS = {
    "action_authority": "5d43425f6b4e1853b293afca2902df4a591d3f05900631ad997cbaa710d02f26",
    "release_execution": "3df34571eaace9b64e615eb9fd55767222465f457be703d00d0fe0f9fdc7d8f7",
    "release_marketplace": "9a9e179e09be4b114b558595c85086db26b26494e9b6c76ba0c48bcbe4985d18",
}

_FIXED_BUILD_GATE = completion_gate.build_completion_report
_FIXED_VALIDATE_GATE = completion_gate.validate_completion_report
_FIXED_BUILD_STAGE_L = action_authority.build_stage_l_campaign_report
_FIXED_VALIDATE_STAGE_L = action_authority.validate_stage_l_campaign_report
_FIXED_HOST_RUN = host_attestation.run
_FIXED_HOST_READBACK = host_attestation.readback
_FIXED_PROFILE_TIMEOUT = host_attestation.profile_timeout_seconds
_FIXED_TEST_SET = host_attestation.validate_test_run_set
_FIXED_CANDIDATE_VERIFY = candidate_identity.verify_cachebuster_identity_transition
_FIXED_CANDIDATE_VALIDATE = candidate_identity.validate_cachebuster_identity_transition
_FIXED_CREATE_STORE = consumption.create_store
_FIXED_CLAIM_PHASE = consumption.claim_phase
_FIXED_RECORD_OUTCOME = consumption.record_outcome
_FIXED_PREPARE_RELEASE = action_authority.prepare_release_action
_FIXED_EXECUTE_RELEASE = release_execution.execute_release
_FIXED_FINALIZE_RELEASE = release_execution.finalize_release
_FIXED_RELEASE_REPORT = release_execution.release_report
_FIXED_PREPARE_LIVE = live_qualification_execution.prepare_live_qualification
_FIXED_EXECUTE_LIVE = live_qualification_execution.execute_live_qualification
_FIXED_LIVE_REPORT = live_qualification_execution.live_report
_FIXED_LIVE_FACTS = live_qualification_execution.completion_facts
_FIXED_LIVE_ORIGINALS = live_qualification_execution.completion_originals
_FIXED_PUBLISH_PROMOTION = promotion_authentication.publish_successful_execution
_FIXED_SOURCE_SNAPSHOT = source_scope_closure.read_source_snapshot

# The complete source inventory is a distinct wire field at the committed base;
# it is a strict superset of the runtime package's Python entries.  The fixed
# reader derives it from its own module location, so this owner may only run
# against the checkout that reader is pinned to.
_SOURCE_SCOPE_ROOT = Path(source_scope_closure._ROOT).resolve(strict=True)


# --- In-memory identity of the fixed dependencies ---------------------------
#
# Disk bytes and module __file__ paths describe where a module CAME FROM; they
# say nothing about the objects now bound in its namespace.  A caller that
# imports a fixed dependency first, rebinds one of its attributes, and only
# then imports this owner gets that rebound object captured into the _FIXED_*
# references below.  Every path-and-digest check still passes, because the file
# on disk was never touched.
#
# So the contract is established against the running objects.  Each fixed
# module's verified source bytes are compiled and executed into a private
# namespace, and the live module surface is compared to that reference
# surface, function by function.  A legitimate sibling import produces a
# namespace that matches its own source exactly, so ordinary test discovery is
# unaffected.  A rebound, deleted or added attribute does not, and is refused.
#
# Code-object equality alone is forgeable: types.FunctionType(genuine_code,
# caller_globals) reuses the genuine code with a namespace the caller controls,
# so every global the function reads resolves through the attacker.  Each
# function is therefore bound on four axes -- code, __defaults__/__kwdefaults__,
# __globals__ provenance (identity with the owning module's own __dict__, not
# merely an equal mapping) and closure shape.  Code objects are compared by
# value rather than by marshal digest: marshal encodes interned-constant
# identity, so two structurally identical code objects can serialize
# differently, while == compares the fields that decide behaviour and still
# separates a one-byte body edit, a changed constant and a changed global name.

_REFERENCE_GLOBALS = ("__name__", "__file__", "__package__", "__spec__", "__loader__")


def _reference_namespace(name, module, source):
    """Execute verified source bytes into a private namespace.

    Import side effects are contained: the private namespace is never installed
    in sys.modules, and the two process-global effects a fixed module performs
    at import time -- replacing the loader get_code slots and registering a
    fork handler -- are restored and suppressed so the reference run cannot
    disturb the owner it is verifying.
    """
    loaders = (importlib.machinery.SourceFileLoader.get_code,
               importlib.machinery.SourcelessFileLoader.get_code)
    register_at_fork = getattr(os, "register_at_fork", None)
    modules = set(sys.modules)
    namespace = {key: getattr(module, key, None) for key in _REFERENCE_GLOBALS}
    namespace["__builtins__"] = builtins.__dict__
    try:
        if register_at_fork is not None:
            os.register_at_fork = lambda **handlers: None
        # dont_inherit mirrors SourceFileLoader.source_to_code exactly.  Without
        # it this owner's own `from __future__ import annotations` would leak
        # into the reference compile and every dependency that lacks that import
        # would mismatch on co_flags.
        exec(compile(source, module.__file__, "exec", dont_inherit=True), namespace)
    except BaseException as error:
        raise values.LifecycleContractError(
            "action_host:reference_source_not_executable:" + name) from error
    finally:
        if register_at_fork is not None:
            os.register_at_fork = register_at_fork
        (importlib.machinery.SourceFileLoader.get_code,
         importlib.machinery.SourcelessFileLoader.get_code) = loaders
    _require(set(sys.modules) == modules, "reference_import_side_effect:" + name)
    return namespace


def _function_surface(namespace, module_name):
    """Every function reachable from a module namespace, by stable label.

    Covers module-level functions, the methods of classes the module itself
    declares (including the ones dataclass generates at import time) and the
    functions wrapped by staticmethod, classmethod and property descriptors.
    """
    surface = {}

    def record(label, value):
        function = value
        if isinstance(function, (staticmethod, classmethod)):
            function = function.__func__
        if type(function) is types.FunctionType:
            _require(label not in surface, "duplicate_surface_label:" + label)
            surface[label] = function

    def record_property(label, value):
        for part, function in (("fget", value.fget), ("fset", value.fset),
                               ("fdel", value.fdel)):
            if function is not None:
                record(label + "@" + part, function)

    for name, value in namespace.items():
        if name.startswith("__") and name.endswith("__"):
            continue
        record(name, value)
        if isinstance(value, property):
            record_property(name, value)
        if isinstance(value, type) and getattr(value, "__module__", None) == module_name:
            for attribute, member in vars(value).items():
                record(name + "." + attribute, member)
                if isinstance(member, property):
                    record_property(name + "." + attribute, member)
    return surface


# copy and pickle cache a computed slot listing on the class the first time
# they inspect it.  It is derived from __slots__ by the interpreter, carries no
# behaviour, and appears only after an unrelated copy attempt, so it is not
# part of the identity the source determines.
_INTERPRETER_CACHED_ATTRIBUTES = frozenset({"__slotnames__"})


def _class_shape(value):
    """Structure of a module-declared class that its own source determines."""
    return (
        tuple(base.__qualname__ for base in value.__bases__),
        tuple(sorted(set(vars(value)) - _INTERPRETER_CACHED_ATTRIBUTES)),
        tuple(getattr(value, "__slots__", ()) or ()),
    )


def _equal(left, right):
    """Value equality that neither side can turn into an error."""
    try:
        return type(left) is type(right) and bool(left == right)
    except BaseException:
        return False


_MUTABLE_CONTAINERS = (dict, list, set, bytearray)


def _runtime_registry(value):
    """True for a container the source creates empty for later writes.

    Emptiness at import is the discriminator, and it is read from the
    reference execution rather than from the live module, so a caller cannot
    turn a populated constant into a registry by emptying it.
    """
    return type(value) in _MUTABLE_CONTAINERS and len(value) == 0


def _data_surface(namespace, module_name):
    """Every non-function value reachable from a module namespace, by label.

    Functions are bound separately by the function surface.  Imported modules
    are skipped: each fixed module is bound by its own entry in the fixed set,
    and comparing module objects across executions is meaningless.
    """
    surface = {}

    def record(label, value):
        if isinstance(value, (types.FunctionType, types.ModuleType, staticmethod,
                              classmethod, property)):
            return
        surface[label] = value

    for name, value in namespace.items():
        if name.startswith("__") and name.endswith("__"):
            continue
        if isinstance(value, type) and getattr(value, "__module__", None) == module_name:
            surface[name + "#class"] = _class_shape(value)
            for attribute, member in vars(value).items():
                if attribute.startswith("__") and attribute.endswith("__"):
                    continue
                record(name + "." + attribute, member)
            continue
        record(name, value)
    return surface


def _bind_module_data(name, module, first, second):
    """Bind the values two independent reference executions agree on.

    A module may create genuinely fresh state at import: an authority sentinel,
    a per-process token, a lock.  Those differ between two executions of the
    same verified source, so they carry no cross-execution expectation and are
    bound by type alone.  Everything the source determines -- the frozensets,
    tuples, patterns and paths that decide what the fixed readers accept -- is
    identical across both runs and is bound by exact type and value.

    A mutable container needs one further distinction, because this contract is
    re-established throughout the campaign and must not drift against the
    module's own legitimate work.  A container the source leaves EMPTY at import
    is a runtime registry this module writes to as it operates, so only its type
    is a fixed fact.  A container the source FILLS at import is a computed
    constant that nothing should write to again, so its contents are bound
    exactly and in-place poisoning is refused.
    """
    live = _data_surface(vars(module), name)
    reference = _data_surface(first, name)
    _require(set(live) == set(reference), "module_data_drift:" + name)
    other = _data_surface(second, name)
    _require(set(other) == set(reference), "reference_data_unstable:" + name)
    bound = 0
    for label in sorted(reference):
        expected, repeated, actual = reference[label], other[label], live[label]
        if _runtime_registry(expected):
            _require(type(actual) is type(expected),
                     "module_registry_type_drift:" + name + ":" + label)
        elif _equal(expected, repeated):
            _require(_equal(actual, expected), "module_constant_drift:" + name + ":" + label)
            bound += 1
        else:
            # Regenerated per execution: the exact value cannot be predicted,
            # but its type still can.
            _require(type(actual) is type(expected),
                     "module_constant_type_drift:" + name + ":" + label)
    return bound


def _same_free_variable(name, module, actual, expected):
    """Compare one captured free variable against its reference cell.

    Closure cells carry the values a nested function reads without going
    through module globals, so a function can be rebuilt with genuine code,
    genuine globals and a matching closure SHAPE while its captured values are
    caller-chosen.  dataclass builds exactly this pattern: the frozen setattr
    guard closes over the owning class and the error type it raises.
    """
    try:
        left, right = actual.cell_contents, expected.cell_contents
    except ValueError:
        # An empty cell on both sides is a recursive definition not yet bound.
        return _empty_cell(actual) and _empty_cell(expected)
    if isinstance(right, type):
        # The reference execution declares its own copies of the module's
        # classes, so identity cannot match across executions.  Require the
        # live capture to be the very class this module exports under that
        # name, or the identical foreign class the reference captured.
        if right.__module__ == name:
            return getattr(module, right.__name__, None) is left
        return left is right
    if type(left) is types.FunctionType or type(right) is types.FunctionType:
        return (type(left) is types.FunctionType and type(right) is types.FunctionType
                and left.__code__ == right.__code__)
    return _equal(left, right)


def _empty_cell(cell):
    try:
        cell.cell_contents
    except ValueError:
        return True
    return False


def _bind_module_identity(name, module, source):
    """Refuse any live object that the module's own source did not produce."""
    reference = _reference_namespace(name, module, source)
    live_surface = _function_surface(vars(module), name)
    reference_surface = _function_surface(reference, name)
    _require(set(live_surface) == set(reference_surface),
             "module_surface_drift:" + name)
    for label in sorted(reference_surface):
        live, expected = live_surface[label], reference_surface[label]
        if live is expected:
            continue
        _require(live.__code__ == expected.__code__, "module_code_drift:" + name + ":" + label)
        _require(live.__defaults__ == expected.__defaults__,
                 "module_default_drift:" + name + ":" + label)
        _require(live.__kwdefaults__ == expected.__kwdefaults__,
                 "module_default_drift:" + name + ":" + label)
        # A function the module defines must read the module's own globals.
        # A re-exported function must keep the exact namespace it was defined
        # in.  Identity, not equality: an equal copy is still caller-owned.
        if expected.__globals__ is reference:
            _require(live.__globals__ is module.__dict__,
                     "module_globals_drift:" + name + ":" + label)
        else:
            _require(live.__globals__ is expected.__globals__,
                     "module_globals_drift:" + name + ":" + label)
        live_closure, expected_closure = live.__closure__, expected.__closure__
        _require((live_closure is None) == (expected_closure is None)
                 and (live_closure is None or len(live_closure) == len(expected_closure)),
                 "module_closure_drift:" + name + ":" + label)
        for index, cells in enumerate(zip(live_closure or (), expected_closure or ())):
            actual_cell, expected_cell = cells
            _require(_same_free_variable(name, module, actual_cell, expected_cell),
                     "module_closure_value_drift:" + name + ":" + label + ":" + str(index))
    # A second independent execution of the same verified bytes separates the
    # values the source fixes from the state each import legitimately recreates.
    repeated = _reference_namespace(name, module, source)
    return {
        "functions": len(reference_surface),
        "constants": _bind_module_data(name, module, reference, repeated),
    }


def _require(condition, reason):
    if condition is not True:
        raise values.LifecycleContractError("action_host:" + reason)


def _remaining_campaign_timeout(deadline):
    remaining = deadline - time.monotonic()
    _require(remaining >= 1, "campaign_timeout")
    return remaining


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _existing_root(value, label):
    _require(isinstance(value, (str, os.PathLike)), label)
    path = Path(value).absolute()
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise values.LifecycleContractError("action_host:" + label) from error
    _require(path == resolved and path.is_dir() and not path.is_symlink(), label)
    return path


def _absent_root(value, label):
    _require(isinstance(value, (str, os.PathLike)), label)
    path = Path(value).absolute()
    _require(not path.exists() and not path.is_symlink(), label + "_not_create_only")
    parent = path.parent.resolve(strict=True)
    _require(path.parent == parent and parent.is_dir(), label + "_parent")
    return path


def _overlap(left, right):
    return left == right or left in right.parents or right in left.parents


def _tree_snapshot(root):
    entries = {}
    for directory, names, files in os.walk(root):
        names[:] = sorted(name for name in names if name not in (".git", "__pycache__"))
        for name in names:
            _require(not (Path(directory) / name).is_symlink(), "source_directory_symlink")
        for name in sorted(files):
            if name == ".git" or name.endswith(".pyc"):
                continue
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            _require(stat.S_ISREG(info.st_mode), "source_not_regular:" + relative)
            raw = path.read_bytes()
            after = path.lstat()
            _require(
                (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                 info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns),
                "source_changed_while_reading:" + relative,
            )
            entries[relative] = {
                "sha256": _sha(raw),
                "bytes": len(raw),
                "mode": stat.S_IMODE(info.st_mode),
                "device": info.st_dev,
                "inode": info.st_ino,
            }
    _require(bool(entries), "source_empty")
    logical = {
        path: {key: row[key] for key in ("sha256", "bytes", "mode")}
        for path, row in entries.items()
    }
    return rv.freeze({
        "entries": entries,
        "logical_sha256": values.canonical_digest(logical),
        "physical_sha256": values.canonical_digest(entries),
    })


def _same_logical_tree(left, right):
    left_entries = left.to_plain()["entries"]
    right_entries = right.to_plain()["entries"]
    strip = lambda rows: {
        path: {key: row[key] for key in ("sha256", "bytes", "mode")}
        for path, row in rows.items()
    }
    return strip(left_entries) == strip(right_entries)


def _module_contract(source_root):
    scripts = source_root / "skills/orch-dork/scripts"
    modules = {
        "lifecycle_conformance.action_host": sys.modules[__name__],
        "lifecycle_conformance.host_attestation": host_attestation,
        "lifecycle_conformance.live_qualification_execution": live_qualification_execution,
        "lifecycle_conformance.promotion_authentication": promotion_authentication,
        "lifecycle_conformance.release_execution": release_execution,
        "lifecycle_conformance.completion_gate": completion_gate,
        "lifecycle_conformance.candidate_identity": candidate_identity,
        "lifecycle_conformance.consumption": consumption,
        "lifecycle_conformance.action_authority": action_authority,
        "lifecycle_conformance.source_scope_closure": source_scope_closure,
        "lifecycle_conformance.values": values,
        "lifecycle_conformance.reference_values": rv,
        "orch_dork_runtime_package": runtime_package,
        "orch_dork_release_marketplace": release_marketplace,
        "orch_dork_predecessor_readiness": predecessor_readiness,
        "orch_dork_observer_receipt": observer_receipt,
    }
    result = {}
    _require(sys.dont_write_bytecode is True, "bytecode_disabled_required")
    _require(sorted(modules) == sorted(_FIXED_MODULE_NAMES + (__name__,)),
             "fixed_module_set_drift")
    cached = getattr(sys.modules[__name__], "__cached__", None)
    _require(not cached or not Path(cached).exists(), "action_host_compiled_cache")
    _require(importlib.machinery.SourceFileLoader.get_code is _source_code
             and importlib.machinery.SourcelessFileLoader.get_code is _refuse_bytecode,
             "source_only_loader_replaced")
    for name, module in modules.items():
        relative = Path(*name.split(".")).with_suffix(".py")
        if name.startswith("lifecycle_conformance."):
            expected = scripts / relative
        else:
            expected = scripts / relative.name
        actual = Path(module.__file__).resolve(strict=True)
        loader = module.__spec__.loader
        # The module object registered under this name must be the one this
        # owner holds: a caller cannot leave a decoy in sys.modules.
        _require(sys.modules.get(name) is module, "fixed_module_registry:" + name)
        _require(
            actual == expected
            and actual.suffix == ".py"
            and type(loader) is importlib.machinery.SourceFileLoader
            and module.__loader__ is loader
            and not _compiled_origin(module)
            and Path(loader.get_filename(name)).resolve(strict=True) == actual,
            "foreign_or_compiled_module:" + name,
        )
        # Read once, then bind BOTH the recorded digest and the running objects
        # to those exact bytes, so the record cannot describe a file the loaded
        # module never came from.
        source = actual.read_bytes()
        result[name] = {
            "path": str(actual),
            "sha256": _sha(source),
            **_bind_module_identity(name, module, source),
        }
    return rv.freeze(result)


@dataclass
class _State:
    phase: str
    frozen_source: rv.FrozenValue
    initial_candidate: rv.FrozenValue
    modules: rv.FrozenValue
    host_runs: dict
    attestations: dict
    evidence: dict | None = None
    sources: dict | None = None
    registries: dict | None = None
    report: rv.FrozenValue | None = None
    anchor: dict | None = None
    transition: rv.FrozenValue | None = None
    release_inputs: object | None = None
    release_result: object | None = None
    release_report: rv.FrozenValue | None = None
    live_inputs: object | None = None
    live_result: object | None = None
    live_report: rv.FrozenValue | None = None
    predecessor_projection: dict | None = None
    predecessor_preflight: rv.FrozenValue | None = None
    predecessor_after_release: rv.FrozenValue | None = None
    candidate_readiness: rv.FrozenValue | None = None
    candidate_readiness_sha256: str | None = None
    candidate_readiness_path: str | None = None
    candidate_readiness_validation: rv.FrozenValue | None = None
    predecessor_recovery_receipt: rv.FrozenValue | None = None
    predecessor_recovery_receipt_sha256: str | None = None
    predecessor_recovery_receipt_path: str | None = None
    predecessor_recovery_binding: rv.FrozenValue | None = None
    predecessor_pre_native_receipt: rv.FrozenValue | None = None
    predecessor_pre_native_receipt_sha256: str | None = None
    predecessor_pre_native_receipt_path: str | None = None
    predecessor_closed_failure_receipt: rv.FrozenValue | None = None
    predecessor_closed_failure_receipt_sha256: str | None = None
    predecessor_closed_failure_receipt_path: str | None = None
    predecessor_qualification_receipt: rv.FrozenValue | None = None
    predecessor_qualification_receipt_sha256: str | None = None
    predecessor_qualification_receipt_path: str | None = None
    predecessor_qualification_evidence_sha256: str | None = None
    predecessor_qualification_evidence_path: str | None = None
    predecessor_qualification_identity: rv.FrozenValue | None = None
    stage_l_action_authority: object | None = None
    qualification_workspace: str | None = None
    owner_ticket_id: int | None = None
    owner_repair_branch: str | None = None


class ActionHost:
    """Opaque process-local owner.  Construct with :func:`create_action_host`."""

    __slots__ = (
        "source_root", "candidate_root", "output_root", "consumption_root",
        "release_root", "_authority", "__weakref__",
    )

    def __init__(self, authority, **roots):
        _require(authority is _AUTHORITY, "factory_required")
        for name, value in roots.items():
            setattr(self, name, value)
        self._authority = authority


@dataclass(frozen=True)
class StageLExecution:
    """Retained physical results; possessing this value grants no authority."""

    release_execution: object
    live_execution: object
    predecessor_preflight: rv.FrozenValue
    predecessor_after_release: rv.FrozenValue


def _fingerprint(host):
    return (
        str(host.source_root), str(host.candidate_root), str(host.output_root),
        str(host.consumption_root), str(host.release_root), id(host._authority),
    )


def _issue(host, state):
    identity = id(host)
    _ISSUED[identity] = (
        weakref.ref(host, lambda _: (_ISSUED.pop(identity, None), _STATES.pop(identity, None))),
        os.getpid(),
        _fingerprint(host),
    )
    _STATES[identity] = state
    return host


def _state(host):
    _require(type(host) is ActionHost, "host_type")
    record = _ISSUED.get(id(host))
    _require(
        record is not None and record[0]() is host and record[1] == os.getpid()
        and record[2] == _fingerprint(host) and host._authority is _AUTHORITY,
        "issued_host_binding",
    )
    return _STATES[id(host)]


def _clear_after_fork():
    _ISSUED.clear()
    _STATES.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_clear_after_fork)


def _assert_source_frozen(host, state):
    _require(_tree_snapshot(host.source_root) == state.frozen_source, "pre_source_drift")
    _require(_module_contract(host.source_root) == state.modules, "loaded_source_drift")


def _assert_candidate_initial(host, state):
    candidate = _tree_snapshot(host.candidate_root)
    _require(candidate == state.initial_candidate, "candidate_drift_before_claim")
    _require(_same_logical_tree(state.frozen_source, candidate), "candidate_not_exact_copy")
    left = state.frozen_source.to_plain()["entries"]
    right = candidate.to_plain()["entries"]
    _require(
        all((left[path]["device"], left[path]["inode"])
            != (right[path]["device"], right[path]["inode"]) for path in left),
        "candidate_shared_inode",
    )


def create_action_host(*, source_root, candidate_root, output_root,
                       consumption_root, release_root):
    """Freeze exact roots before any host profile can execute."""
    source = _existing_root(source_root, "source_root")
    candidate = _existing_root(candidate_root, "candidate_root")
    output = _absent_root(output_root, "output_root")
    consumed = _absent_root(consumption_root, "consumption_root")
    release = _absent_root(release_root, "release_root")
    roots = (source, candidate, output, consumed, release)
    _require(all(not _overlap(a, b) for index, a in enumerate(roots)
                 for b in roots[index + 1:]), "root_overlap")
    modules = _module_contract(source)
    frozen = _tree_snapshot(source)
    candidate_frozen = _tree_snapshot(candidate)
    host = ActionHost(
        _AUTHORITY,
        source_root=source,
        candidate_root=candidate,
        output_root=output,
        consumption_root=consumed,
        release_root=release,
    )
    state = _State("FROZEN", frozen, candidate_frozen, modules, {}, {})
    _issue(host, state)
    _assert_candidate_initial(host, state)
    output.mkdir(mode=0o700)
    return host


def _generation(sources, runtime, registries):
    return {"sources": sources, "runtime": runtime,
            "registry_components": registries}


def _fixed_source_scope(host):
    """Re-read the complete inventory the fixed gate will bind against.

    The gate distinguishes the complete source inventory from the runtime
    package inventory and re-reads originals through its own fixed reader.  A
    caller-supplied scope cannot select that inventory, so this owner reads it
    from the same frozen root and refuses any mismatch before the first effect.
    """
    _require(host.source_root == _SOURCE_SCOPE_ROOT, "source_scope_reader_root")
    snapshot = _FIXED_SOURCE_SNAPSHOT()
    _require(type(snapshot) is dict and set(snapshot) == {"sources", "runtime"},
             "source_scope_snapshot_shape")
    sources, runtime = snapshot["sources"], snapshot["runtime"]
    _require(type(sources) is dict and bool(sources), "source_scope_sources")
    _require(type(runtime) is dict and bool(runtime), "source_scope_runtime")
    package = runtime["python_source_hashes"]
    _require(type(package) is dict and bool(package), "source_scope_runtime_python")
    # Complete source is a superset of the runtime package's Python entries and
    # every runtime entry must hash exactly to the retained source bytes.
    _require(set(sources) >= set(package), "source_scope_not_superset")
    _require(all(_sha(sources[path].encode("utf-8")) == digest
                 for path, digest in package.items()), "source_scope_runtime_binding")
    return sources, runtime


def _component(kind, originals, report, generation):
    material = {
        "report_sha256": report.digest(),
        "generation_sha256": values.canonical_digest(generation),
    }
    return {
        "schema": completion_gate.COMPONENT_SCHEMA,
        "kind": kind,
        "case_id": completion_gate.case_identity(kind, material),
        "material": material,
        "originals": {**originals, "generation": generation},
    }


def _run_host_profiles_concurrently(host, deadline):
    """Start every disjoint manifest partition under one aggregate deadline."""

    def execute_profile(profile):
        manifest_timeout = _FIXED_PROFILE_TIMEOUT(
            profile, source_root=host.source_root)
        return _FIXED_HOST_RUN(
            profile, source_root=host.source_root,
            output_root=host.output_root / profile,
            timeout_seconds=min(
                manifest_timeout,
                _remaining_campaign_timeout(deadline),
            ),
        )

    with ThreadPoolExecutor(max_workers=len(PROFILES),
                            thread_name_prefix="issue170-host") as executor:
        futures = {
            profile: executor.submit(execute_profile, profile)
            for profile in PROFILES
        }
        runs = {}
        failures = []
        for profile in PROFILES:
            try:
                runs[profile] = futures[profile].result()
            except BaseException as error:
                failures.append(error)
    if failures:
        if len(failures) == 1:
            raise failures[0]
        raise BaseExceptionGroup(
            "action_host:multiple_host_profile_failures", failures
        )
    _remaining_campaign_timeout(deadline)
    return runs


def run_provider_free_campaign(host):
    """Run the four fixed release profiles and build the Stage L gate.

    The complete source inventory and runtime identity come from the fixed
    source reader against the frozen root. Historical E--K evidence and
    registry selections are not inputs to this release boundary.
    """
    state = _state(host)
    deadline = time.monotonic() + CAMPAIGN_TIMEOUT_SECONDS
    _require(state.phase == "READINESS_BOUND", "provider_free_wrong_order")
    _assert_candidate_readiness_retained(state)
    sources, fixed_runtime = _fixed_source_scope(host)
    state.phase = "HOST_ACTIVE"
    try:
        _assert_source_frozen(host, state)
        runs = _run_host_profiles_concurrently(host, deadline)
        _remaining_campaign_timeout(deadline)
        _assert_source_frozen(host, state)
        for profile in PROFILES:
            run = runs[profile]
            state.host_runs[run.witness.invocation_id] = run
            attestation = _FIXED_HOST_READBACK(
                source_root=host.source_root,
                artifact_root=run.artifact_root,
                witness=run.witness,
                expected_invocation_id=run.witness.invocation_id,
            )
            state.attestations[profile] = attestation
            _require(attestation.report.to_plain()["status"] == "PASS",
                     "host_profile_failed:" + profile)
            _remaining_campaign_timeout(deadline)
        _assert_source_frozen(host, state)
        tests = _FIXED_TEST_SET({
            profile: state.attestations[profile]
            for profile in ("focused", "rehearsal", "full_suite")
        })
        # Re-read after the profiles: the fixed inventory must be unchanged.
        recheck_sources, runtime = _fixed_source_scope(host)
        _require(recheck_sources == sources and runtime == fixed_runtime,
                 "source_scope_drift")
        _remaining_campaign_timeout(deadline)
        joined = {
            "schema": action_authority.STAGE_L_EVIDENCE_SCHEMA,
            "runtime": runtime,
            "components": [{
                "kind": "manifest_host_campaign",
                "originals": {
                    "source_root": str(host.source_root),
                    "runs": {profile: runs[profile] for profile in PROFILES},
                    "attestations": {
                        profile: state.attestations[profile] for profile in PROFILES
                    },
                    "test_set": tests,
                },
            }],
            "consumption": {
                "candidate": None, "release_install": None, "live_attempt": None,
            },
        }
        report = _FIXED_BUILD_STAGE_L(
            joined,
            sources=sources,
            host_runs=state.host_runs,
        )
        _FIXED_VALIDATE_STAGE_L(
            report,
            joined,
            sources=sources,
            host_runs=state.host_runs,
        )
        _remaining_campaign_timeout(deadline)
        state.evidence = joined
        state.sources = sources
        state.registries = {}
        state.report = report
        plain = report.to_plain()
        state.phase = "CAMPAIGN_PASSED" if (
            plain["status"] == "PASS"
            and plain["campaign_authorized"] is True
            and plain["candidate_authorized"] is True
        ) else "CAMPAIGN_BLOCKED"
        return report
    except BaseException:
        state.phase = "TERMINAL_HOST_FAILURE"
        raise


def _pre_runtime(source_root):
    entries, version, _ = runtime_package._projectable_source_entries(
        source_root, runtime_package.RUNTIME_ALLOWLIST
    )
    return runtime_package._report(version, entries)


_CANDIDATE_READINESS_FIELDS = frozenset({
    "schema", "status", "source_commit", "generation",
    "runtime_package_digest", "qualification_workspace",
    "qualification_workspace_enrollment", "behavioral_failure_classes_total",
    "behavioral_failure_classes_exercised", "injected_guards_total",
    "injected_guards_exercised", "refusal_templates_total",
    "refusal_templates_exercised", "distinct_observed_refusal_codes",
    "shadow_scenarios_total",
    "shadow_scenarios_exercised", "shadow_scenario_manifest_sha256",
    "real_v29_fixture_sha256", "real_v29_shadow",
    "reachable_terminal_paths", "sentinel_success_paths",
    "installed_layout_rehearsal", "real_codex_smoke",
    "unexpected_failures", "leftover_processes", "leftover_sockets",
    "reserved_lanes", "worktree_cleanup", "run_root", "started_at",
    "completed_at", "checks", "issues",
    "host_execution_receipt",
})
_CANDIDATE_READINESS_CHECKS = frozenset({
    "preflight", "qualification_workspace", "release", "failure_atlas",
    "real_codex_smoke",
})


def _source_commit(source_root):
    try:
        completed = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "LC_ALL": "C",
                "GIT_TERMINAL_PROMPT": "0",
            },
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise values.LifecycleContractError(
            "action_host:candidate_readiness_source_commit"
        ) from error
    try:
        commit = completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise values.LifecycleContractError(
            "action_host:candidate_readiness_source_commit"
        ) from error
    _require(
        completed.returncode == 0 and _COMMIT.fullmatch(commit) is not None,
        "candidate_readiness_source_commit",
    )
    return commit


def _ready_count(report, total, exercised):
    return (
        type(report.get(total)) is int
        and report[total] > 0
        and report.get(exercised) == report[total]
    )


def _candidate_readiness_semantics(report, *, commit, runtime):
    if type(report) is not dict:
        return False
    checks = report.get("checks")
    preflight = checks.get("preflight") if type(checks) is dict else None
    qualification = (
        checks.get("qualification_workspace")
        if type(checks) is dict
        else None
    )
    return (
        set(report) == _CANDIDATE_READINESS_FIELDS
        and report.get("schema") == CANDIDATE_READINESS_SCHEMA
        and report.get("status") == "READY"
        and report.get("source_commit") == commit
        and report.get("generation") == runtime["version"]
        and report.get("runtime_package_digest")
        == runtime["package_digest"]
        and isinstance(report.get("qualification_workspace"), str)
        and report.get("qualification_workspace_enrollment") == "PASS"
        and _ready_count(
            report, "behavioral_failure_classes_total", "behavioral_failure_classes_exercised"
        )
        and _ready_count(
            report, "injected_guards_total", "injected_guards_exercised"
        )
        and _ready_count(
            report, "refusal_templates_total", "refusal_templates_exercised"
        )
        and type(report.get("distinct_observed_refusal_codes")) is int
        and 0 < report["distinct_observed_refusal_codes"]
        <= report["refusal_templates_exercised"]
        and _ready_count(
            report, "shadow_scenarios_total", "shadow_scenarios_exercised"
        )
        and isinstance(report.get("shadow_scenario_manifest_sha256"), str)
        and _DIGEST.fullmatch(report["shadow_scenario_manifest_sha256"])
        is not None
        and isinstance(report.get("real_v29_fixture_sha256"), str)
        and _DIGEST.fullmatch(report["real_v29_fixture_sha256"]) is not None
        and all(
            report.get(field) == "PASS"
            for field in (
                "real_v29_shadow", "reachable_terminal_paths",
                "sentinel_success_paths", "installed_layout_rehearsal",
                "real_codex_smoke", "worktree_cleanup",
            )
        )
        and all(
            report.get(field) == 0
            for field in (
                "unexpected_failures", "leftover_processes",
                "leftover_sockets", "reserved_lanes",
            )
        )
        and isinstance(report.get("run_root"), str)
        and isinstance(report.get("started_at"), str)
        and isinstance(report.get("completed_at"), str)
        and type(report.get("host_execution_receipt")) is dict
        and report.get("issues") == []
        and type(checks) is dict
        and set(checks) == _CANDIDATE_READINESS_CHECKS
        and all(
            type(check) is dict and check.get("status") == "PASS"
            for check in checks.values()
        )
        and type(preflight) is dict
        and preflight.get("source_commit") == commit
        and preflight.get("generation") == runtime["version"]
        and preflight.get("runtime_package_digest")
        == runtime["package_digest"]
        and preflight.get("issues") == []
        and type(qualification) is dict
        and qualification.get("status") == "PASS"
        and qualification.get("expected_source_commit") == commit
        and qualification.get("workspace")
        == report["qualification_workspace"]
    )


_CANDIDATE_READINESS_VALIDATION_FIELDS = frozenset({
    "schema", "status", "source_commit", "generation",
    "runtime_package_digest", "readiness_sha256",
    "release_result_sha256", "shadow_result_sha256",
    "scenario_manifest_sha256", "workers", "behavioral_failure_classes_total",
    "injected_guards_total", "refusal_templates_total",
    "distinct_observed_refusal_codes", "shadow_scenarios_total", "issues",
    "host_execution_receipt_sha256", "host_execution_key_id",
    "host_execution_trust_generation",
})


def _validate_candidate_readiness_artifact(
    host, path, *, raw_sha256, commit, runtime
):
    script = host.source_root / ".github/scripts/orch_dork_candidate_readiness.py"
    command = [
        sys.executable,
        "-I",
        "-S",
        "-B",
        str(script),
        "--validate-ready-artifact",
        str(path),
        "--source-root",
        str(host.source_root),
    ]
    observed = _FIXED_RUN_PREFLIGHT_PROCESS(
        command,
        cwd=host.source_root,
        environment={
            "HOME": os.environ.get("HOME", str(Path.home())),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", os.defpath),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        timeout_seconds=120,
    )
    if observed["termination_reason"] == "timeout":
        raise values.LifecycleContractError(
            "action_host:candidate_readiness_validation_timeout"
        )
    if observed["termination_reason"] in {"stdout_limit", "stderr_limit"}:
        raise values.LifecycleContractError(
            "action_host:candidate_readiness_validation_output"
        )
    if observed["cleanup"] is not True:
        raise values.LifecycleContractError(
            "action_host:candidate_readiness_validation_cleanup",
            detail={"cleanup_reason": observed.get("cleanup_reason")},
        )
    _require(
        observed["termination_reason"] is None
        and observed["exit_code"] == 0
        and not observed["stderr"]
        and 0 < len(observed["stdout"]) <= 65_536,
        "candidate_readiness_validation_execution",
    )
    try:
        receipt = json.loads(observed["stdout"].decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError(
            "action_host:candidate_readiness_validation_output"
        ) from error
    _require(
        type(receipt) is dict
        and set(receipt) == _CANDIDATE_READINESS_VALIDATION_FIELDS
        and receipt.get("schema") == CANDIDATE_READINESS_VALIDATION_SCHEMA
        and receipt.get("status") == "PASS"
        and receipt.get("source_commit") == commit
        and receipt.get("generation") == runtime["version"]
        and receipt.get("runtime_package_digest")
        == runtime["package_digest"]
        and receipt.get("readiness_sha256") == raw_sha256
        and all(
            isinstance(receipt.get(field), str)
            and _DIGEST.fullmatch(receipt[field]) is not None
            for field in (
                "release_result_sha256", "shadow_result_sha256",
                "scenario_manifest_sha256", "host_execution_receipt_sha256",
            )
        )
        and isinstance(receipt.get("host_execution_key_id"), str)
        and bool(receipt["host_execution_key_id"])
        and isinstance(receipt.get("host_execution_trust_generation"), str)
        and bool(receipt["host_execution_trust_generation"])
        and receipt.get("workers") == 4
        and all(
            type(receipt.get(field)) is int and receipt[field] > 0
            for field in (
                "behavioral_failure_classes_total", "injected_guards_total",
                "refusal_templates_total", "distinct_observed_refusal_codes",
                "shadow_scenarios_total",
            )
        )
        and receipt["distinct_observed_refusal_codes"]
        <= receipt["refusal_templates_total"]
        and receipt.get("issues") == [],
        "candidate_readiness_validation_report",
    )
    return rv.freeze(receipt)


def _accept_candidate_readiness(host, artifact):
    _require(isinstance(artifact, (str, os.PathLike)), "candidate_readiness_path")
    path = Path(artifact).absolute()
    descriptor = None
    try:
        before = path.lstat()
        _require(
            stat.S_ISREG(before.st_mode) and not path.is_symlink(),
            "candidate_readiness_path",
        )
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        raw = os.read(descriptor, 2_097_153)
        after = os.fstat(descriptor)
        _require(
            len(raw) <= 2_097_152
            and (before.st_dev, before.st_ino, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_ctime_ns),
            "candidate_readiness_identity",
        )
    except (OSError, RuntimeError) as error:
        raise values.LifecycleContractError(
            "action_host:candidate_readiness_path"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        report = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError(
            "action_host:candidate_readiness_json"
        ) from error
    _require(
        type(report) is dict and report.get("status") == "READY",
        "candidate_readiness_not_ready",
    )
    runtime = _pre_runtime(host.source_root)
    commit = _source_commit(host.source_root)
    raw_sha256 = _sha(raw)
    _require(
        _candidate_readiness_semantics(
            report, commit=commit, runtime=runtime
        ),
        "candidate_readiness_not_ready",
    )
    validation = _validate_candidate_readiness_artifact(
        host,
        path,
        raw_sha256=raw_sha256,
        commit=commit,
        runtime=runtime,
    )
    return rv.freeze(report), raw_sha256, str(path), validation


def _assert_candidate_readiness_retained(state):
    _require(
        state.candidate_readiness is not None
        and type(state.candidate_readiness_sha256) is str
        and _DIGEST.fullmatch(state.candidate_readiness_sha256) is not None
        and isinstance(state.candidate_readiness_path, str)
        and state.candidate_readiness.to_plain().get("status") == "READY"
        and state.candidate_readiness.digest()
        == rv.freeze(state.candidate_readiness.to_plain()).digest(),
        "candidate_readiness_not_retained",
    )
    validation = (
        state.candidate_readiness_validation.to_plain()
        if state.candidate_readiness_validation is not None
        else None
    )
    _require(
        type(validation) is dict
        and validation.get("schema")
        == CANDIDATE_READINESS_VALIDATION_SCHEMA
        and validation.get("status") == "PASS"
        and validation.get("readiness_sha256")
        == state.candidate_readiness_sha256
        and validation.get("source_commit")
        == state.candidate_readiness.to_plain().get("source_commit")
        and validation.get("runtime_package_digest")
        == state.candidate_readiness.to_plain().get(
            "runtime_package_digest"
        ),
        "candidate_readiness_validation_not_retained",
    )


def bind_candidate_readiness(host, *, candidate_readiness):
    """Validate fresh readiness and retain it across the bounded campaign."""
    state = _state(host)
    _require(state.phase == "FROZEN", "candidate_readiness_wrong_order")
    state.phase = "READINESS_VALIDATING"
    try:
        _assert_source_frozen(host, state)
        _assert_candidate_initial(host, state)
        readiness, readiness_sha256, readiness_path, readiness_validation = (
            _accept_candidate_readiness(host, candidate_readiness)
        )
        _assert_source_frozen(host, state)
        _assert_candidate_initial(host, state)
        state.candidate_readiness = readiness
        state.candidate_readiness_sha256 = readiness_sha256
        state.candidate_readiness_path = readiness_path
        state.candidate_readiness_validation = readiness_validation
        _assert_candidate_readiness_retained(state)
        state.phase = "READINESS_BOUND"
        return readiness_validation
    except BaseException:
        state.candidate_readiness = None
        state.candidate_readiness_sha256 = None
        state.candidate_readiness_path = None
        state.candidate_readiness_validation = None
        state.phase = "FROZEN"
        raise


def _candidate_outcome(claim, outcome, physical):
    return _canonical_bytes({
        "schema": consumption.OUTCOME_SCHEMA,
        "phase": "candidate",
        "claim_sha256": claim.digest(),
        "outcome": outcome,
        "transport": {
            "schema": consumption.TRANSPORT_SCHEMA,
            "status": "VALIDATED" if outcome == "SUCCEEDED" else "REFUSED",
            "original_receipt_json": _canonical_bytes(physical).decode("utf-8"),
        },
    })


def _rewrite_candidate_manifest(candidate_root, cachebuster):
    _require(type(cachebuster) is str and _TOKEN.fullmatch(cachebuster) is not None,
             "cachebuster_token")
    path = candidate_root / runtime_package.MANIFEST_PATH
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), "candidate_manifest")
    raw = path.read_bytes()
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError("action_host:candidate_manifest_json") from error
    _require(type(manifest) is dict and type(manifest.get("version")) is str,
             "candidate_manifest_shape")
    original_version = manifest["version"]
    version_prefix = original_version.split("+", 1)[0]
    manifest["version"] = version_prefix + "+codex." + cachebuster
    updated = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    _require(updated != raw, "cachebuster_noop")
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    try:
        view = memoryview(updated)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, "candidate_manifest_short_write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _require(stat.S_IMODE(path.lstat().st_mode) == stat.S_IMODE(before.st_mode),
             "candidate_manifest_mode_changed")
    return original_version, manifest["version"]


def _require_post_candidate_release_authorized(report):
    _require(
        report.to_plain().get("release_authorized") is True,
        "post_candidate_release_not_authorized",
    )


def _record_candidate_failure(host, state, claim, error):
    if state.anchor is not None and state.anchor["latest_receipt"] is claim:
        physical = {
            "schema": CANDIDATE_RECEIPT_SCHEMA,
            "status": "FAIL",
            "error_type": type(error).__name__,
            "error_sha256": _sha(
                str(error).encode("utf-8", errors="replace")
            ),
        }
        try:
            failed = _FIXED_RECORD_OUTCOME(
                host.consumption_root,
                claim,
                outcome_receipt=_candidate_outcome(
                    claim, "FAILED", physical
                ),
                expected_binding=claim.to_plain()["binding"],
            )
            state.anchor["latest_receipt"] = failed
        except BaseException as record_error:
            state.phase = "TERMINAL_CANDIDATE_FAILURE_UNRECORDED"
            raise values.LifecycleContractError(
                "action_host:candidate_failure_not_recorded"
            ) from record_error
    state.phase = "TERMINAL_CANDIDATE_FAILURE"


def claim_and_build_candidate(host, *, cachebuster):
    """Spend candidate before the sole exact manifest rewrite, then re-gate."""
    state = _state(host)
    _require(state.phase == "CAMPAIGN_PASSED", "candidate_wrong_order")
    _assert_source_frozen(host, state)
    _assert_candidate_initial(host, state)
    _assert_candidate_readiness_retained(state)
    plain = state.report.to_plain()
    _require(plain["campaign_authorized"] is True
             and plain["candidate_authorized"] is True, "candidate_not_authorized")
    campaign_bytes = _canonical_bytes(plain) + b"\n"
    initial = _FIXED_CREATE_STORE(
        host.consumption_root,
        campaign_receipt=campaign_bytes,
        pre_runtime=_pre_runtime(host.source_root),
    )
    claim = _FIXED_CLAIM_PHASE(
        host.consumption_root,
        initial,
        phase="candidate",
        expected_binding=initial.to_plain()["binding"],
    )
    state.anchor = {
        "root": host.consumption_root,
        "initial_receipt": initial,
        "latest_receipt": claim,
        "campaign_receipt_json": campaign_bytes.decode("utf-8"),
    }
    state.phase = "CANDIDATE_CLAIMED"
    try:
        original_version, candidate_version = _rewrite_candidate_manifest(
            host.candidate_root, cachebuster
        )
        _assert_source_frozen(host, state)
        transition = _FIXED_CANDIDATE_VERIFY(host.source_root, host.candidate_root)
        _FIXED_CANDIDATE_VALIDATE(host.source_root, host.candidate_root, transition)
        physical = {
            "schema": CANDIDATE_RECEIPT_SCHEMA,
            "status": "PASS",
            "original_version": original_version,
            "candidate_version": candidate_version,
            "transition_sha256": transition.digest(),
        }
        latest = _FIXED_RECORD_OUTCOME(
            host.consumption_root,
            claim,
            outcome_receipt=_candidate_outcome(claim, "SUCCEEDED", physical),
            expected_binding=claim.to_plain()["binding"],
            transition=transition,
            original_root=host.source_root,
            candidate_root=host.candidate_root,
        )
        state.anchor["latest_receipt"] = latest
        generation = _generation(state.sources, state.evidence["runtime"], state.registries)
        state.evidence["components"].append(_component(
            "candidate_identity_transition",
            {"report": transition, "original_root": str(host.source_root),
             "candidate_root": str(host.candidate_root)},
            transition,
            generation,
        ))
        state.evidence["consumption"]["candidate"] = latest.to_plain()
        if state.evidence["schema"] == action_authority.STAGE_L_EVIDENCE_SCHEMA:
            report = _FIXED_BUILD_STAGE_L(
                state.evidence,
                sources=state.sources,
                host_runs=state.host_runs,
                consumption_anchor=state.anchor,
            )
            _FIXED_VALIDATE_STAGE_L(
                report,
                state.evidence,
                sources=state.sources,
                host_runs=state.host_runs,
                consumption_anchor=state.anchor,
            )
        else:
            report = _FIXED_BUILD_GATE(
                state.evidence,
                sources=state.sources,
                registry_components=state.registries,
                host_runs=state.host_runs,
                consumption_anchor=state.anchor,
            )
            _FIXED_VALIDATE_GATE(
                report,
                state.evidence,
                sources=state.sources,
                registry_components=state.registries,
                host_runs=state.host_runs,
                consumption_anchor=state.anchor,
            )
        _require_post_candidate_release_authorized(report)
        state.report = report
        state.transition = transition
        state.release_inputs = _FIXED_PREPARE_RELEASE(
            report,
            state.evidence,
            sources=state.sources,
            registry_components=state.registries,
            host_runs=state.host_runs,
            consumption_anchor=state.anchor,
            original_root=host.source_root,
            candidate_root=host.candidate_root,
        )
        state.phase = "CANDIDATE_SUCCEEDED"
        return transition
    except BaseException as error:
        _record_candidate_failure(host, state, claim, error)
        raise


def _reviewed_release_execution_sha256(raw):
    """Hash release execution while normalizing its accepted guard literal.

    Release execution binds this ActionHost's exact source bytes.  ActionHost
    therefore cannot pin release execution's raw bytes without creating a hash
    cycle.  Normalizing only the reviewed guard value keeps every executable
    byte pinned while the independently checked guard still binds this caller.
    """
    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source, filename="release_execution.py")
    except (UnicodeError, SyntaxError) as error:
        raise values.LifecycleContractError(
            "action_host:release_guard_source_invalid"
        ) from error
    assignments = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "_ACCEPTED_RELEASE_GUARD_SHA256"
    ]
    _require(len(assignments) == 1, "release_guard_assignment")
    value = assignments[0].value
    _require(
        isinstance(value, ast.Constant)
        and (
            value.value is None
            or type(value.value) is str
            and len(value.value) == 64
            and set(value.value) <= set("0123456789abcdef")
        ),
        "release_guard_value",
    )
    lines = raw.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:value.lineno - 1]) + value.col_offset
    end = sum(len(line) for line in lines[:value.end_lineno - 1]) + value.end_col_offset
    _require(0 <= start < end <= len(raw), "release_guard_span")
    return _sha(raw[:start] + b"'reviewed-release-guard-sha256'" + raw[end:])


def _require_accepted_release_guard(source_root):
    _require(_ACCEPTED_RELEASE_GUARD_PINS is not None,
             "release_guard_review_repair_pending")
    paths = {
        "action_authority": source_root / "skills/orch-dork/scripts/lifecycle_conformance/action_authority.py",
        "release_execution": source_root / "skills/orch-dork/scripts/lifecycle_conformance/release_execution.py",
        "release_marketplace": source_root / "skills/orch-dork/scripts/orch_dork_release_marketplace.py",
    }
    raw = {name: path.read_bytes() for name, path in paths.items()}
    pins = {
        "action_authority": _sha(raw["action_authority"]),
        "release_execution": _reviewed_release_execution_sha256(
            raw["release_execution"]
        ),
        "release_marketplace": _sha(raw["release_marketplace"]),
    }
    _require(pins == _ACCEPTED_RELEASE_GUARD_PINS, "release_guard_pin_mismatch")
    accepted = getattr(release_execution, "_ACCEPTED_RELEASE_GUARD_SHA256", None)
    _require(
        type(accepted) is str
        and len(accepted) == 64
        and set(accepted) <= set("0123456789abcdef")
        and release_execution._release_guard_sha256() == accepted,
        "release_execution_guard_mismatch",
    )


def release_and_install_candidate(host, *, codex_executable,
                                  codex_home=None, home_directory=None):
    """Enter the fixed physical release only after accepted operation pins."""
    state = _state(host)
    _require(state.phase == "CANDIDATE_SUCCEEDED", "release_wrong_order")
    _assert_candidate_readiness_retained(state)
    _require(
        state.stage_l_action_authority is _STAGE_L_RELEASE_AUTHORITY
        and state.predecessor_recovery_binding is not None
        and _predecessor_binding_source(state) is not None,
        "stage_l_release_authority",
    )
    predecessor = (
        state.predecessor_preflight.to_plain()
        if state.predecessor_preflight is not None else None
    )
    _assert_exact_predecessor(
        predecessor,
        "stage_l_predecessor_not_ready",
        recovery_binding=state.predecessor_recovery_binding,
    )
    state.stage_l_action_authority = None
    _assert_source_frozen(host, state)
    _FIXED_CANDIDATE_VALIDATE(host.source_root, host.candidate_root, state.transition)
    _require_accepted_release_guard(host.source_root)
    executable = Path(codex_executable).absolute()
    try:
        resolved_executable = executable.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise values.LifecycleContractError(
            "action_host:codex_executable"
        ) from error
    _require(executable == resolved_executable and executable.is_file()
             and os.access(executable, os.X_OK), "codex_executable")
    home = Path.home() if home_directory is None else Path(home_directory).absolute()
    codex = (Path(os.environ.get("CODEX_HOME", str(home / ".codex"))).absolute()
             if codex_home is None else Path(codex_home).absolute())
    _require(home.is_dir() and codex.is_dir(), "release_home_directory")
    state.phase = "RELEASE_ACTIVE"
    try:
        execution = _FIXED_EXECUTE_RELEASE(
            state.release_inputs,
            {
                "release_root": host.release_root,
                "codex_executable": executable,
                "codex_home": codex,
                "home_directory": home,
            },
        )
        report = _FIXED_RELEASE_REPORT(execution)
        plain = report.to_plain()
        _require(
            plain["status"] == "PASS"
            and plain["physical_execution_validated"] is True
            and tuple(plain["facts"])
            == ("release_host_consumed", "install_parity_mcp_consumed"),
            "release_physical_reader_refused",
        )
        _physical, latest = _FIXED_FINALIZE_RELEASE(execution)
        _require(
            latest is state.anchor["latest_receipt"]
            and latest.to_plain()["phase"] == "release_install"
            and latest.to_plain()["status"] == "SUCCEEDED",
            "release_durable_outcome",
        )
        generation = _generation(
            state.sources, state.evidence["runtime"], state.registries
        )
        state.evidence["components"].append(
            _component(
                "release_consumption",
                {"execution": execution, "report": report},
                report,
                generation,
            )
        )
        state.evidence["consumption"] = {
            "candidate": None,
            "release_install": latest.to_plain(),
            "live_attempt": None,
        }
        if state.evidence["schema"] == action_authority.STAGE_L_EVIDENCE_SCHEMA:
            _require(
                state.report.to_plain()["release_authorized"] is True,
                "post_release_live_not_authorized",
            )
        else:
            gate = _FIXED_BUILD_GATE(
                state.evidence,
                sources=state.sources,
                registry_components=state.registries,
                host_runs=state.host_runs,
                consumption_anchor=state.anchor,
            )
            _FIXED_VALIDATE_GATE(
                gate,
                state.evidence,
                sources=state.sources,
                registry_components=state.registries,
                host_runs=state.host_runs,
                consumption_anchor=state.anchor,
            )
            _require(
                gate.to_plain()["live_attempt_authorized"] is True,
                "post_release_live_not_authorized",
            )
            state.report = gate
        state.release_result = execution
        state.release_report = report
        state.phase = "RELEASE_SUCCEEDED"
        return execution
    except BaseException:
        state.phase = "TERMINAL_RELEASE_FAILURE"
        raise


def begin_live_qualification(host, owner_request):
    """Spend the sole live attempt through the fixed owner and durable reader."""
    state = _state(host)
    _require(state.phase == "RELEASE_SUCCEEDED", "live_wrong_order")
    _require(
        state.stage_l_action_authority is _STAGE_L_LIVE_AUTHORITY,
        "stage_l_live_authority",
    )
    before = (
        state.predecessor_preflight.to_plain()
        if state.predecessor_preflight is not None else None
    )
    after = (
        state.predecessor_after_release.to_plain()
        if state.predecessor_after_release is not None else None
    )
    _assert_exact_predecessor(
        before,
        "stage_l_predecessor_not_ready",
        recovery_binding=state.predecessor_recovery_binding,
    )
    _assert_exact_predecessor(
        after,
        "stage_l_predecessor_changed_after_release",
        recovery_binding=state.predecessor_recovery_binding,
    )
    _require(
        before.get("report_sha256") == after.get("report_sha256"),
        "stage_l_predecessor_changed_after_release",
    )
    _bind_qualification_workspace(state, owner_request)
    state.stage_l_action_authority = None
    _assert_source_frozen(host, state)
    _FIXED_CANDIDATE_VALIDATE(
        host.source_root, host.candidate_root, state.transition
    )
    gate = state.report.to_plain()
    if state.evidence["schema"] == action_authority.STAGE_L_EVIDENCE_SCHEMA:
        release = state.release_report.to_plain()
        durable = state.anchor["latest_receipt"].to_plain()
        _require(
            gate["release_authorized"] is True
            and release["status"] == "PASS"
            and release["physical_execution_validated"] is True
            and durable["phase"] == "release_install"
            and durable["status"] == "SUCCEEDED",
            "live_not_authorized",
        )
    else:
        _require(
            gate["live_attempt_authorized"] is True
            and gate["qualification_authorized"] is True
            and gate["promotion_authorized"] is False,
            "live_not_authorized",
        )
    state.phase = "LIVE_ACTIVE"
    try:
        prepared = _FIXED_PREPARE_LIVE(state.anchor, owner_request)
        state.live_inputs = prepared
        execution = _FIXED_EXECUTE_LIVE(prepared)
        report = _FIXED_LIVE_REPORT(execution)
        facts = _FIXED_LIVE_FACTS(execution)
        _require(
            facts
            == ("fresh_live_attempt_consumed_once", "terminal_live_result_preserved"),
            "live_physical_reader_refused",
        )
        originals = _FIXED_LIVE_ORIGINALS(execution)
        latest = originals["latest_receipt"]
        _require(
            latest is state.anchor["latest_receipt"]
            and latest.to_plain()["phase"] == "live_attempt"
            and latest.to_plain()["status"]
            in {"SUCCEEDED", "FAILED", "REFUSED", "CRASHED"},
            "live_durable_outcome",
        )
        generation = _generation(
            state.sources, state.evidence["runtime"], state.registries
        )
        state.evidence["components"].append(
            _component(
                "live_attempt_consumption",
                {
                    "report": report,
                    "store_root": state.anchor["root"],
                    "claim_receipt": originals["claim_receipt"],
                    "latest_receipt": latest,
                    "expected_binding": latest.to_plain()["binding"],
                    "outcome_receipt": originals["outcome_receipt"],
                    "receipt_path": originals["promotion_receipt_path"],
                },
                report,
                generation,
            )
        )
        state.evidence["consumption"] = {
            "candidate": None,
            "release_install": None,
            "live_attempt": latest.to_plain(),
        }
        succeeded = latest.to_plain()["status"] == "SUCCEEDED"
        if state.evidence["schema"] != action_authority.STAGE_L_EVIDENCE_SCHEMA:
            final_gate = _FIXED_BUILD_GATE(
                state.evidence,
                sources=state.sources,
                registry_components=state.registries,
                host_runs=state.host_runs,
                consumption_anchor=state.anchor,
            )
            _FIXED_VALIDATE_GATE(
                final_gate,
                state.evidence,
                sources=state.sources,
                registry_components=state.registries,
                host_runs=state.host_runs,
                consumption_anchor=state.anchor,
            )
            _require(
                final_gate.to_plain()["promotion_authorized"] is succeeded,
                "post_live_promotion_binding",
            )
            state.report = final_gate
        if succeeded:
            _FIXED_PUBLISH_PROMOTION(execution)
        state.live_result = execution
        state.live_report = report
        state.phase = "LIVE_SUCCEEDED" if succeeded else "TERMINAL_LIVE_FAILURE"
        return execution
    except BaseException:
        state.phase = "TERMINAL_LIVE_FAILURE"
        raise


_PREFLIGHT_PROCESS_IDENTITY_UNKNOWN = object()

# Why the bounded runner reported cleanup false.  The runner fails closed
# whenever it cannot prove which processes it owns; these closed values record
# the step that ended cleanup and the observation that made ownership
# uncertain, so a refusal can be classified from its own result.  Recording
# never changes a verdict.
_PREFLIGHT_CLEANUP_STEPS = frozenset({
    "leader_unretained",
    "observe_during_run",
    "stop_leader_invalid",
    "observe_during_stop",
    "signal_failed",
    "survivors_at_deadline",
    "unrecorded",
})
_PREFLIGHT_CLEANUP_OBSERVATIONS = frozenset({
    "leader_identity_absent",
    "leader_identity_unknown",
    "leader_identity_replaced",
    "leader_not_group_leader",
    "group_probe_failed",
    "proc_listing_unreadable",
    "proc_entry_unreadable",
    "member_identity_unknown",
    "retained_identity_unknown",
    "retained_identity_replaced",
    "retained_identity_left_group",
    "unretained_member_without_owner",
    "signal_identity_unknown",
    "signal_identity_replaced",
    "pidfd_unavailable",
    "signal_send_failed",
})
_PREFLIGHT_IDENTITY_RECHECKS = frozenset({
    "absent", "not_owned", "unreadable", "unparseable", "readable",
})
_PREFLIGHT_CLEANUP_REASON_LIMIT = 16


def _preflight_cleanup_recorder():
    """Start an empty record of why cleanup could not be proven."""

    return {"step": None, "signal": None, "observations": [], "survivors": []}


def _preflight_identity_recheck(pid):
    """Re-read one process entry to say why its identity was unknown.

    This is a later read, so the process may have changed in between; it is
    recorded as a hint beside the observation and never decides anything.
    """

    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return "unparseable"
    directory = Path("/proc") / str(pid)
    try:
        if directory.stat().st_uid != os.getuid():
            return "not_owned"
        raw = (directory / "stat").read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError):
        return "absent"
    except (PermissionError, OSError, UnicodeError):
        return "unreadable"
    closing = raw.rfind(")")
    if closing < 0 or len(raw[closing + 2 :].split()) <= 19:
        return "unparseable"
    return "readable"


def _note_preflight_uncertainty(recorder, observation, pid=None):
    """Record one uncertain ownership observation beside a fail-closed result."""

    if recorder is None or len(recorder["observations"]) >= _PREFLIGHT_CLEANUP_REASON_LIMIT:
        return
    note = {"observation": observation, "pid": pid}
    if observation.endswith("_unknown") and isinstance(pid, int):
        note["recheck"] = _preflight_identity_recheck(pid)
    recorder["observations"].append(note)


def _note_preflight_step(recorder, step, signal_number=None):
    """Record the stop step that ended cleanup; the first step recorded wins."""

    if recorder is None or recorder["step"] is not None:
        return
    recorder["step"] = step
    recorder["signal"] = (
        None if signal_number is None else signal.Signals(signal_number).name
    )


def _preflight_survivors(identities):
    """Describe retained processes that outlived the stop deadline."""

    survivors = []
    for identity in list(identities)[:_PREFLIGHT_CLEANUP_REASON_LIMIT]:
        state = "unknown"
        try:
            raw = (Path("/proc") / str(identity[0]) / "stat").read_text(
                encoding="utf-8"
            )
            fields = raw[raw.rfind(")") + 2 :].split()
            if fields:
                state = fields[0]
        except (FileNotFoundError, ProcessLookupError):
            state = "absent"
        except (PermissionError, OSError, UnicodeError):
            state = "unknown"
        survivors.append(
            {"pid": identity[0], "process_group": identity[2], "state": state}
        )
    return survivors


def _preflight_cleanup_reason(recorder):
    """Return the closed reason for a cleanup false result."""

    return {
        "step": recorder["step"] or "unrecorded",
        "signal": recorder["signal"],
        "observations": list(recorder["observations"]),
        "survivors": list(recorder["survivors"]),
    }


def _preflight_process_identity(pid, *, unreaped_child=False):
    """Return one exact identity, confirmed absence, or unknown observation.

    A zombie is reported absent, except to the parent that has not yet waited
    for it: its own unreaped child keeps its pid, start time and group, so a
    fast command that exits before this read is still bound exactly.
    """

    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN
    directory = Path("/proc") / str(pid)
    try:
        if directory.stat().st_uid != os.getuid():
            return _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN
        raw = (directory / "stat").read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except (PermissionError, OSError, UnicodeError):
        return _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN
    try:
        closing = raw.rfind(")")
        fields = raw[closing + 2 :].split()
        if closing < 0 or len(fields) <= 19:
            return _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN
        if fields[0] == "Z" and not (unreaped_child and int(fields[1]) == os.getpid()):
            return None
        return pid, int(fields[19]), int(fields[2])
    except ValueError:
        return _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN


def _preflight_process_group_identities(process_group, recorder=None):
    """Snapshot exact live identities in one retained private group."""

    if not isinstance(process_group, int) or process_group <= 1:
        return None
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return []
    except (PermissionError, OSError):
        _note_preflight_uncertainty(recorder, "group_probe_failed", process_group)
        return None
    found = []
    try:
        entries = Path("/proc").iterdir()
    except (PermissionError, OSError):
        _note_preflight_uncertainty(recorder, "proc_listing_unreadable")
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != os.getuid():
                continue
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, OSError):
            _note_preflight_uncertainty(
                recorder, "proc_entry_unreadable", int(entry.name)
            )
            return None
        identity = _preflight_process_identity(int(entry.name))
        if identity is _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN:
            _note_preflight_uncertainty(
                recorder, "member_identity_unknown", int(entry.name)
            )
            return None
        if isinstance(identity, tuple) and identity[2] == process_group:
            found.append(identity)
    return sorted(found)


def _preflight_process_has_owner_token(pid, owner_token):
    """Match one exact invocation-local token inherited by descendants."""

    if not isinstance(owner_token, str) or not owner_token:
        return False
    expected = (
        b"ORCH_DORK_PREFLIGHT_PROCESS_OWNER="
        + owner_token.encode("ascii")
    )
    try:
        values = (Path("/proc") / str(pid) / "environ").read_bytes()
    except (OSError, UnicodeError):
        return False
    return expected in values.split(b"\0")


def _signal_preflight_process(identity, signal_number, recorder=None):
    """Signal only the retained process identity through a pidfd."""

    pid = identity[0]

    def unchanged(current):
        if current is _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN:
            _note_preflight_uncertainty(recorder, "signal_identity_unknown", pid)
            return False
        if current != identity:
            _note_preflight_uncertainty(recorder, "signal_identity_replaced", pid)
            return False
        return True

    current = _preflight_process_identity(pid)
    if current is None:
        return True
    if not unchanged(current):
        return False
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        _note_preflight_uncertainty(recorder, "pidfd_unavailable", pid)
        return False
    descriptor = None
    try:
        descriptor = os.pidfd_open(pid, 0)
        current = _preflight_process_identity(pid)
        if current is None:
            return True
        if not unchanged(current):
            return False
        signal.pidfd_send_signal(descriptor, signal_number)
        return True
    except ProcessLookupError:
        if _preflight_process_identity(pid) is None:
            return True
        _note_preflight_uncertainty(recorder, "signal_send_failed", pid)
        return False
    except OSError:
        _note_preflight_uncertainty(recorder, "signal_send_failed", pid)
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _retained_preflight_group(
    retained_leader, retained_identities, owner_token=None, recorder=None
):
    """Observe a group without adopting identities after leader loss/reuse."""

    trusted = set(retained_identities)

    def leader_unchanged(observed):
        if observed is _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN:
            _note_preflight_uncertainty(
                recorder, "leader_identity_unknown", retained_leader[0]
            )
            return False
        if observed not in {None, retained_leader}:
            _note_preflight_uncertainty(
                recorder, "leader_identity_replaced", retained_leader[0]
            )
            return False
        return True

    before = _preflight_process_identity(retained_leader[0])
    if not leader_unchanged(before):
        return None
    current = _preflight_process_group_identities(retained_leader[2], recorder)
    if current is None:
        return None
    after = _preflight_process_identity(retained_leader[0])
    if not leader_unchanged(after):
        return None
    current_identities = set(current)
    for identity in trusted:
        observed = _preflight_process_identity(identity[0])
        if observed is _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN:
            _note_preflight_uncertainty(
                recorder, "retained_identity_unknown", identity[0]
            )
            return None
        if observed not in {None, identity}:
            _note_preflight_uncertainty(
                recorder, "retained_identity_replaced", identity[0]
            )
            return None
        if observed == identity and identity not in current_identities:
            _note_preflight_uncertainty(
                recorder, "retained_identity_left_group", identity[0]
            )
            return None
    if before == retained_leader and after == retained_leader:
        trusted.update(current)
    else:
        unretained = [
            identity for identity in current if identity not in trusted
        ]
        if owner_token is None or not all(
            _preflight_process_has_owner_token(identity[0], owner_token)
            for identity in unretained
        ):
            if unretained:
                _note_preflight_uncertainty(
                    recorder, "unretained_member_without_owner", unretained[0][0]
                )
                return None
        trusted.update(unretained)
    return current, sorted(trusted)


def _stop_preflight_process(
    process,
    retained_leader,
    retained_identities=(),
    owner_token=None,
    recorder=None,
):
    """Reap exact identities from one retained provider-free process group."""

    if (
        not isinstance(retained_leader, tuple)
        or len(retained_leader) != 3
        or retained_leader[0] != process.pid
        or retained_leader[2] != process.pid
    ):
        _note_preflight_step(recorder, "stop_leader_invalid")
        return False

    trusted = set(retained_identities)
    trusted.add(retained_leader)
    remaining = []

    def settle(signal_number):
        nonlocal trusted, remaining
        observed = _retained_preflight_group(
            retained_leader, sorted(trusted), owner_token, recorder
        )
        if observed is None:
            _note_preflight_step(recorder, "observe_during_stop", signal_number)
            return None
        identities, retained = observed
        trusted.update(retained)
        if not all(
            _signal_preflight_process(identity, signal_number, recorder)
            for identity in identities
        ):
            _note_preflight_step(recorder, "signal_failed", signal_number)
            return None
        if process.poll() is None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            observed = _retained_preflight_group(
                retained_leader, sorted(trusted), owner_token, recorder
            )
            if observed is None:
                _note_preflight_step(recorder, "observe_during_stop", signal_number)
                return None
            identities, retained = observed
            trusted.update(retained)
            if not identities:
                return True
            remaining = identities
            time.sleep(0.02)
        return False

    first = settle(signal.SIGTERM)
    if first is True:
        return True
    if first is None:
        return False
    second = settle(signal.SIGKILL)
    if second is False:
        _note_preflight_step(recorder, "survivors_at_deadline", signal.SIGKILL)
        if recorder is not None:
            recorder["survivors"] = _preflight_survivors(remaining)
    return second is True


def _run_preflight_process(command, *, cwd, environment, timeout_seconds=30):
    """Run one process group with hard per-stream output and cleanup bounds."""

    owner_token = secrets.token_hex(32)
    owned_environment = dict(environment)
    owned_environment["ORCH_DORK_PREFLIGHT_PROCESS_OWNER"] = owner_token
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=owned_environment,
        start_new_session=True,
    )
    retained_leader = _preflight_process_identity(process.pid, unreaped_child=True)
    retained_identities = set()
    recorder = _preflight_cleanup_recorder()
    ownership_uncertain = (
        not isinstance(retained_leader, tuple)
        or retained_leader[2] != process.pid
    )
    if not ownership_uncertain:
        retained_identities.add(retained_leader)
    else:
        _note_preflight_uncertainty(
            recorder,
            "leader_identity_absent"
            if retained_leader is None
            else "leader_identity_unknown"
            if retained_leader is _PREFLIGHT_PROCESS_IDENTITY_UNKNOWN
            else "leader_not_group_leader",
            process.pid,
        )
        _note_preflight_step(recorder, "leader_unretained")
    selector = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    streams = ((process.stdout, "stdout"), (process.stderr, "stderr"))
    try:
        selector = selectors.DefaultSelector()
        for stream, label in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        deadline = time.monotonic() + timeout_seconds
        termination_reason = None
        while selector.get_map() or process.poll() is None:
            if not ownership_uncertain:
                observed = _retained_preflight_group(
                    retained_leader,
                    sorted(retained_identities),
                    owner_token,
                    recorder,
                )
                if observed is None:
                    ownership_uncertain = True
                    _note_preflight_step(recorder, "observe_during_run")
                else:
                    _current, retained = observed
                    retained_identities.update(retained)
            if termination_reason is None and time.monotonic() >= deadline:
                termination_reason = "timeout"
            if termination_reason is not None:
                break
            if process.poll() is not None:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    termination_reason = "descendant_after_leader"
                    break
            for key, _mask in selector.select(0.02):
                label = key.data
                try:
                    chunk = os.read(key.fd, 16_384)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                available = 65_536 - len(buffers[label])
                buffers[label].extend(chunk[:available])
                if len(chunk) > available:
                    termination_reason = label + "_limit"
                    break
        if termination_reason is None and process.poll() is not None:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                termination_reason = "descendant_after_leader"
    finally:
        cleaned = (
            False
            if ownership_uncertain
            else _stop_preflight_process(
                process,
                retained_leader,
                sorted(retained_identities),
                owner_token,
                recorder,
            )
        )
        if selector is not None:
            selector.close()
        for stream, _label in streams:
            if stream is not None:
                stream.close()
    return {
        "stdout": bytes(buffers["stdout"]),
        "stderr": bytes(buffers["stderr"]),
        "exit_code": process.returncode,
        "termination_reason": termination_reason,
        "cleanup": cleaned,
        "cleanup_reason": (
            None if cleaned is True else _preflight_cleanup_reason(recorder)
        ),
    }


def _stable_owned_artifact(path, *, maximum, issue):
    descriptor = None
    try:
        path = Path(path).absolute()
        before = path.lstat()
        _require(
            stat.S_ISREG(before.st_mode)
            and not path.is_symlink()
            and before.st_uid == os.getuid(),
            issue,
        )
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        _require(
            len(raw) <= maximum
            and (before.st_dev, before.st_ino, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_ctime_ns),
            issue + "_identity",
        )
        return path, raw
    except values.LifecycleContractError:
        raise
    except (OSError, RuntimeError, TypeError) as error:
        raise values.LifecycleContractError(
            "action_host:" + issue
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _observer_authority_paths(
    observer_trust_store,
    observer_replay_db,
    *,
    issue,
):
    """Resolve the host observer's trust store and replay guard.

    Each predecessor closure that verifies a host signature names its own
    refusal, so a bad trust-store argument surfaces under the closure that
    was actually being accepted.
    """

    _require(
        isinstance(observer_trust_store, (str, os.PathLike))
        and isinstance(observer_replay_db, (str, os.PathLike)),
        issue,
    )
    trust = Path(observer_trust_store).absolute()
    replay = Path(observer_replay_db).absolute()
    try:
        resolved_trust = trust.resolve(strict=True)
        resolved_replay = replay.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise values.LifecycleContractError("action_host:" + issue) from error
    _require(
        resolved_trust == trust
        and resolved_replay == replay
        and trust.parent == replay.parent
        and trust.name == "observer-trust.json"
        and replay.name == "observer-replay.sqlite3"
        and trust.is_file()
        and replay.is_file()
        and not trust.is_symlink()
        and not replay.is_symlink(),
        issue,
    )
    return trust, replay


def _predecessor_run_id(predecessor):
    """Return the run id of one well-formed predecessor identity, else None.

    The attempt and run ids derive from the root task id by fixed suffixes and
    every identity field is bounded text.  Which controller it names is not
    decided here; the caller binds it against the observed readiness report.
    """
    if type(predecessor) is not dict:
        return None
    if any(
        not isinstance(predecessor.get(field), str)
        or _PREDECESSOR_ID_TEXT.fullmatch(predecessor[field]) is None
        for field in _PREDECESSOR_IDENTITY_FIELDS
    ):
        return None
    root_task_id = predecessor["root_task_id"]
    if (
        predecessor["attempt_id"] != root_task_id + PREDECESSOR_ATTEMPT_SUFFIX
        or predecessor["run_id"] != root_task_id + PREDECESSOR_RUN_SUFFIX
    ):
        return None
    return predecessor["run_id"]


def _predecessor_authority_lane_ids(run_id):
    return [run_id + ":" + lane for lane in PREDECESSOR_LOGICAL_LANE_IDS]


def _accept_predecessor_recovery_receipt(
    artifact,
    *,
    observer_trust_store=None,
    observer_replay_db=None,
):
    _require(
        isinstance(artifact, (str, os.PathLike)),
        "stage_l_predecessor_recovery_receipt",
    )
    path, raw = _stable_owned_artifact(
        artifact,
        maximum=65_536,
        issue="stage_l_predecessor_recovery_receipt",
    )
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_recovery_receipt_json"
        ) from error
    fields = {
        "schema", "status", "decision", "issues", "artifact_path",
        "artifact_size_bytes", "artifact_sha256", "report_sha256",
        "predecessor_controller_id", "released_authority_lane_ids",
        "disposition", "host_recovery_receipt", "receipt_sha256",
    }
    core = (
        {key: value for key, value in receipt.items()
         if key != "receipt_sha256"}
        if type(receipt) is dict else {}
    )
    signed_payload = (
        {
            key: value for key, value in receipt.items()
            if key not in {"host_recovery_receipt", "receipt_sha256"}
        }
        if type(receipt) is dict else {}
    )
    lanes = receipt.get("released_authority_lane_ids") if core else None
    _require(
        type(receipt) is dict
        and set(receipt) == fields
        and receipt.get("schema") == PREDECESSOR_RECOVERY_RECEIPT_SCHEMA
        and receipt.get("status") == "PASS"
        and receipt.get("decision") == "OBSERVED_SPAWN_STALL_RECOVERED"
        and receipt.get("issues") == []
        and isinstance(receipt.get("predecessor_controller_id"), str)
        and _PREDECESSOR_ID_TEXT.fullmatch(
            receipt["predecessor_controller_id"]
        ) is not None
        and isinstance(lanes, list)
        and len(lanes) == 2
        and lanes == sorted(set(lanes))
        and all(isinstance(lane, str) and lane for lane in lanes)
        and receipt.get("disposition")
        == "READY_FOR_FRESH_SUCCESSOR_ACTIVATION"
        and all(
            isinstance(receipt.get(field), str)
            and _DIGEST.fullmatch(receipt[field]) is not None
            for field in (
                "artifact_sha256", "report_sha256", "receipt_sha256"
            )
        )
        and receipt.get("receipt_sha256") == _sha(_canonical_bytes(core)),
        "stage_l_predecessor_recovery_receipt_report",
    )
    recovery_path, recovery_raw = _stable_owned_artifact(
        receipt["artifact_path"],
        maximum=4_194_304,
        issue="stage_l_predecessor_recovery_artifact",
    )
    _require(
        str(recovery_path) == receipt["artifact_path"]
        and len(recovery_raw) == receipt["artifact_size_bytes"]
        and _sha(recovery_raw) == receipt["artifact_sha256"],
        "stage_l_predecessor_recovery_artifact_binding",
    )
    try:
        recovery = json.loads(recovery_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_recovery_artifact_json"
        ) from error
    recovery_core = (
        {key: value for key, value in recovery.items()
         if key != "report_sha256"}
        if type(recovery) is dict else {}
    )
    predecessor = recovery.get("predecessor") if recovery_core else None
    closure = recovery.get("closure_report") if recovery_core else None
    closure_receipt = (
        closure.get("receipt") if isinstance(closure, dict) else None
    )
    admission = (
        recovery.get("capacity_admission_report") if recovery_core else None
    )
    admission_receipt = (
        admission.get("receipt") if isinstance(admission, dict) else None
    )
    admission_bindings = (
        admission_receipt.get("bindings")
        if isinstance(admission_receipt, dict) else None
    )
    settlement = recovery.get("settlement_report") if recovery_core else None
    settlement_receipt = (
        settlement.get("receipt") if isinstance(settlement, dict) else None
    )
    settlement_bindings = (
        settlement_receipt.get("bindings")
        if isinstance(settlement_receipt, dict) else None
    )
    before = (
        recovery.get("capacity_authority_before") if recovery_core else None
    )
    after = recovery.get("capacity_authority_after") if recovery_core else None
    before_state = before.get("state") if isinstance(before, dict) else None
    after_state = after.get("state") if isinstance(after, dict) else None
    predecessor_run_id = _predecessor_run_id(predecessor)
    expected_lanes = (
        _predecessor_authority_lane_ids(predecessor_run_id)
        if predecessor_run_id is not None
        else None
    )
    expected_logical_lanes = list(PREDECESSOR_LOGICAL_LANE_IDS)
    # The stalled batch may have started one lane or every lane before the
    # owner died (generation 47 lost both workers before their first hook
    # event).  The settlement summary and the closure receipt must agree on
    # one partition of the expected logical lanes: the durably observed lane
    # started, and the never-started lanes are a subset of the rest in wave
    # order.  Which lane started is evidence, not a compiled constant.
    started_lane = (
        recovery.get("started_logical_lane_id") if recovery_core else None
    )
    never_started = (
        recovery.get("never_started_logical_lane_ids")
        if recovery_core else None
    )
    lane_partition_valid = (
        started_lane in expected_logical_lanes
        and type(never_started) is list
        and started_lane not in never_started
        and never_started == [
            lane for lane in expected_logical_lanes if lane in never_started
        ]
    )
    _require(
        type(recovery) is dict
        and set(recovery) == _PREDECESSOR_SETTLEMENT_FIELDS
        and recovery.get("schema") == PREDECESSOR_SETTLEMENT_SCHEMA
        and recovery.get("status") == "PASS"
        and recovery.get("decision") == "SETTLED"
        and recovery.get("issues") == []
        and recovery.get("provider_free") is True
        and predecessor_run_id is not None
        and set(predecessor) == {
            *_PREDECESSOR_IDENTITY_FIELDS, "binding_sha256", "authority_sha256",
        }
        and predecessor["controller_id"]
        == receipt["predecessor_controller_id"]
        and all(
            isinstance(predecessor.get(field), str)
            and _DIGEST.fullmatch(predecessor[field]) is not None
            for field in ("binding_sha256", "authority_sha256")
        )
        and recovery.get("released_authority_lane_ids") == expected_lanes
        and lanes == expected_lanes
        and recovery.get("released_logical_lane_ids") == expected_logical_lanes
        and lane_partition_valid
        and type(closure) is dict
        and closure.get("schema")
        == "orch-dork/observed-spawn-stall-terminalization-stage/v1"
        and closure.get("operation")
        == "observed_spawn_stall_terminalization"
        and closure.get("status") == "PASS"
        and closure.get("disposition")
        == "OBSERVED_SPAWN_STALL_TERMINALIZED"
        and closure.get("issues") == []
        and closure.get("next_action") == "terminal_capacity_settlement"
        and type(closure_receipt) is dict
        and closure_receipt.get("created_logical_lane_id") == started_lane
        and closure_receipt.get("never_started_logical_lane_ids")
        == never_started
        and closure_receipt.get("worker_terminal_receipt_observed") is (
            closure_receipt.get("failure_cut") == "owner_closed_after_denied_second_continuation"
        )
        and closure_receipt.get("worker_process_match_count") == 0
        and closure_receipt.get("owner_process_match_count") == 0
        and closure_receipt.get("owner_process_group_cleaned") is True
        and type(admission) is dict
        and admission.get("status") == "PASS"
        and admission.get("disposition") == "SPAWN_AUTHORIZED"
        and admission.get("issues") == []
        and type(admission_bindings) is dict
        and admission_bindings.get("capacity_authority_lane_ids")
        == expected_lanes
        and admission_bindings.get("current_wave_logical_lane_ids")
        == expected_logical_lanes
        and type(before) is dict
        and before.get("status") == "VERIFIED"
        and before.get("continuity_verified") is True
        and before.get("reason_codes") == []
        and isinstance(before.get("state_sha256"), str)
        and _DIGEST.fullmatch(before["state_sha256"]) is not None
        and type(before_state) is dict
        and before_state.get("active_lane_ids") == expected_lanes
        and admission_bindings.get("capacity_authority_state_sha256")
        == before.get("state_sha256")
        and type(settlement) is dict
        and settlement.get("status") == "PASS"
        and settlement.get("disposition") == "CAPACITY_RELEASED"
        and settlement.get("issues") == []
        and type(settlement_bindings) is dict
        and settlement_bindings.get("failed_logical_lane_ids")
        == expected_logical_lanes
        and type(after) is dict
        and after.get("status") == "VERIFIED"
        and after.get("continuity_verified") is True
        and after.get("reason_codes") == []
        and type(after_state) is dict
        and after_state.get("active_lane_ids") == []
        and type(recovery.get("settlement_program")) is dict
        and recovery.get("boundary") == _PREDECESSOR_SUCCESSOR_BOUNDARY
        and recovery.get("counters") == _PREDECESSOR_SETTLEMENT_COUNTERS
        and recovery.get("report_sha256") == receipt["report_sha256"]
        and recovery.get("report_sha256")
        == _sha(_canonical_bytes(recovery_core)),
        "stage_l_predecessor_recovery_artifact_report",
    )
    trust_path, replay_path = _observer_authority_paths(
        observer_trust_store,
        observer_replay_db,
        issue="stage_l_predecessor_recovery_signature",
    )
    try:
        signed_recovery = receipt["host_recovery_receipt"]
        verification = observer_receipt.verify_signed_receipt(
            signed_recovery,
            expected_kind=PREDECESSOR_RECOVERY_RECEIPT_KIND,
            expected_payload=signed_payload,
            # Recovery provenance is a durable historical fact.  Validate
            # that the signed envelope was fresh when issued; the separate
            # live predecessor observer proves current clean-terminal state.
            evaluation_time=(
                signed_recovery.get("issued_at")
                if isinstance(signed_recovery, dict)
                else datetime.now(timezone.utc)
            ),
            trust_store=observer_receipt.ObserverTrustStore.from_host_file(
                trust_path
            ),
            replay_guard=observer_receipt.SQLiteReplayGuard(replay_path),
            environ={},
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        verification = {"status": "DENY"}
    _require(
        verification.get("status") == "PASS"
        and verification.get("payload") == signed_payload,
        "stage_l_predecessor_recovery_signature",
    )
    recovery_binding = {
        "predecessor": dict(predecessor),
        "capacity_sha256": _sha(_canonical_bytes(after)),
    }
    return (
        rv.freeze(receipt),
        _sha(raw),
        str(path),
        rv.freeze(recovery_binding),
    )


def _verified_capacity_read(value):
    """True for one VERIFIED shared-capacity read with no reserved lane."""

    state = value.get("state") if type(value) is dict else None
    return (
        type(value) is dict
        and value.get("status") == "VERIFIED"
        and value.get("continuity_verified") is True
        and value.get("reason_codes") == []
        and isinstance(value.get("state_sha256"), str)
        and _DIGEST.fullmatch(value["state_sha256"]) is not None
        and type(state) is dict
        and state.get("active_lane_ids") == []
    )


def _lifecycle_binding_status(authority):
    lifecycle = (
        authority.get("lifecycle") if type(authority) is dict else None
    )
    return (
        lifecycle.get("expected_binding_status")
        if type(lifecycle) is dict else None
    )


def _accept_predecessor_pre_native_recovery_receipt(
    artifact,
    *,
    observer_trust_store=None,
    observer_replay_db=None,
):
    """Accept the signed closure of a predecessor that failed before any
    native action.

    The artifact is the terminal predecessor capacity settlement with
    decision TERMINALIZED: it embeds the controller's sealed pre-native
    terminalization, records a WAITING authority before and a TERMINAL one
    after, and releases no lane because none was reserved.  The receipt is
    host-signed with the predecessor-recovery kind.
    """

    _require(
        isinstance(artifact, (str, os.PathLike)),
        "stage_l_predecessor_pre_native_receipt",
    )
    path, raw = _stable_owned_artifact(
        artifact,
        maximum=65_536,
        issue="stage_l_predecessor_pre_native_receipt",
    )
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_pre_native_receipt_json"
        ) from error
    fields = {
        "schema", "status", "decision", "issues", "artifact_path",
        "artifact_size_bytes", "artifact_sha256", "report_sha256",
        "predecessor_controller_id", "released_authority_lane_ids",
        "disposition", "host_recovery_receipt", "receipt_sha256",
    }
    core = (
        {key: value for key, value in receipt.items()
         if key != "receipt_sha256"}
        if type(receipt) is dict else {}
    )
    signed_payload = (
        {
            key: value for key, value in receipt.items()
            if key not in {"host_recovery_receipt", "receipt_sha256"}
        }
        if type(receipt) is dict else {}
    )
    _require(
        type(receipt) is dict
        and set(receipt) == fields
        and receipt.get("schema") == PREDECESSOR_PRE_NATIVE_RECOVERY_RECEIPT_SCHEMA
        and receipt.get("status") == "PASS"
        and receipt.get("decision") == PREDECESSOR_PRE_NATIVE_RECOVERY_DECISION
        and receipt.get("issues") == []
        and isinstance(receipt.get("predecessor_controller_id"), str)
        and _PREDECESSOR_ID_TEXT.fullmatch(
            receipt["predecessor_controller_id"]
        ) is not None
        and receipt.get("released_authority_lane_ids") == []
        and receipt.get("disposition")
        == "READY_FOR_FRESH_SUCCESSOR_ACTIVATION"
        and all(
            isinstance(receipt.get(field), str)
            and _DIGEST.fullmatch(receipt[field]) is not None
            for field in (
                "artifact_sha256", "report_sha256", "receipt_sha256"
            )
        )
        and receipt.get("receipt_sha256") == _sha(_canonical_bytes(core)),
        "stage_l_predecessor_pre_native_receipt_report",
    )
    recovery_path, recovery_raw = _stable_owned_artifact(
        receipt["artifact_path"],
        maximum=4_194_304,
        issue="stage_l_predecessor_pre_native_artifact",
    )
    _require(
        str(recovery_path) == receipt["artifact_path"]
        and len(recovery_raw) == receipt["artifact_size_bytes"]
        and _sha(recovery_raw) == receipt["artifact_sha256"],
        "stage_l_predecessor_pre_native_artifact_binding",
    )
    try:
        recovery = json.loads(recovery_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_pre_native_artifact_json"
        ) from error
    recovery_core = (
        {key: value for key, value in recovery.items()
         if key != "report_sha256"}
        if type(recovery) is dict else {}
    )
    predecessor = recovery.get("predecessor") if recovery_core else None
    before = (
        recovery.get("capacity_authority_before") if recovery_core else None
    )
    after = recovery.get("capacity_authority_after") if recovery_core else None
    terminalization = (
        recovery.get("pre_native_failure_settlement_report")
        if recovery_core else None
    )
    terminalization_core = (
        {key: value for key, value in terminalization.items()
         if key != "report_sha256"}
        if type(terminalization) is dict else {}
    )
    program = (
        terminalization.get("controller_program")
        if terminalization_core else None
    )
    controller_report = (
        terminalization.get("controller_report")
        if terminalization_core else None
    )
    controller_state = (
        controller_report.get("controller_state")
        if type(controller_report) is dict else None
    )
    stage_report = (
        controller_report.get("stage_report")
        if type(controller_report) is dict else None
    )
    stage_receipt = (
        stage_report.get("receipt") if type(stage_report) is dict else None
    )
    predecessor_run_id = _predecessor_run_id(predecessor)
    _require(
        type(recovery) is dict
        and set(recovery) == _PREDECESSOR_PRE_NATIVE_SETTLEMENT_FIELDS
        and recovery.get("schema") == PREDECESSOR_PRE_NATIVE_SETTLEMENT_SCHEMA
        and recovery.get("status") == "PASS"
        and recovery.get("decision") == "TERMINALIZED"
        and recovery.get("issues") == []
        and recovery.get("provider_free") is True
        and predecessor_run_id is not None
        and set(predecessor) == {
            *_PREDECESSOR_IDENTITY_FIELDS, "binding_sha256", "authority_sha256",
        }
        and predecessor["controller_id"]
        == receipt["predecessor_controller_id"]
        and all(
            isinstance(predecessor.get(field), str)
            and _DIGEST.fullmatch(predecessor[field]) is not None
            for field in ("binding_sha256", "authority_sha256")
        )
        and recovery.get("released_authority_lane_ids") == []
        and recovery.get("released_logical_lane_ids") == []
        and recovery.get("capacity_admission_report") is None
        and recovery.get("failed_settlement_report") is None
        and recovery.get("settlement_program") is None
        and recovery.get("settlement_report") is None
        and _verified_capacity_read(before)
        and _verified_capacity_read(after)
        and before == after
        and recovery.get("boundary") == _PREDECESSOR_SUCCESSOR_BOUNDARY
        and recovery.get("counters") == _PREDECESSOR_PRE_NATIVE_SETTLEMENT_COUNTERS
        and type(terminalization) is dict
        and set(terminalization) == _PREDECESSOR_PRE_NATIVE_TERMINALIZATION_FIELDS
        and terminalization.get("schema")
        == PREDECESSOR_PRE_NATIVE_TERMINALIZATION_SCHEMA
        and terminalization.get("status") == "PASS"
        and terminalization.get("decision") == "PRE_NATIVE_FAILURE_TERMINALIZED"
        and terminalization.get("issues") == []
        and terminalization.get("provider_free") is True
        and terminalization.get("boundary")
        == _PREDECESSOR_PRE_NATIVE_TERMINALIZATION_BOUNDARY
        and terminalization.get("counters")
        == _PREDECESSOR_PRE_NATIVE_TERMINALIZATION_COUNTERS
        and terminalization.get("report_sha256")
        == _sha(_canonical_bytes(terminalization_core))
        and type(program) is dict
        and program.get("schema") == PREDECESSOR_PRE_NATIVE_PROGRAM_SCHEMA
        and program.get("controller_id") == predecessor["controller_id"]
        and type(program.get("failure_evidence")) is dict
        and type(controller_report) is dict
        and controller_report.get("status") == "PASS"
        and controller_report.get("decision")
        == "PRE_NATIVE_FAILURE_TERMINALIZED"
        and controller_report.get("controller_id") == predecessor["controller_id"]
        and controller_report.get("issues") == []
        and controller_report.get("action") is None
        and type(controller_state) is dict
        and controller_state.get("terminal") is True
        and controller_state.get("cleanup_required") is False
        and type(stage_report) is dict
        and stage_report.get("operation") == "pre_native_failure_terminalization"
        and stage_report.get("disposition") == "PRE_NATIVE_FAILURE_TERMINALIZED"
        and stage_report.get("next_action") == "terminal"
        and type(stage_receipt) is dict
        and stage_receipt.get("owner_process_group_cleaned") is True
        and isinstance(stage_receipt.get("abandoned_turn_id"), str)
        and isinstance(stage_receipt.get("abandoned_turn_status"), str)
        and _lifecycle_binding_status(
            terminalization.get("predecessor_authority_before")
        ) == "WAITING"
        and _lifecycle_binding_status(
            terminalization.get("predecessor_authority_after")
        ) == "TERMINAL"
        and recovery.get("report_sha256") == receipt["report_sha256"]
        and recovery.get("report_sha256")
        == _sha(_canonical_bytes(recovery_core)),
        "stage_l_predecessor_pre_native_artifact_report",
    )
    trust_path, replay_path = _observer_authority_paths(
        observer_trust_store,
        observer_replay_db,
        issue="stage_l_predecessor_pre_native_signature",
    )
    try:
        signed_recovery = receipt["host_recovery_receipt"]
        verification = observer_receipt.verify_signed_receipt(
            signed_recovery,
            expected_kind=PREDECESSOR_RECOVERY_RECEIPT_KIND,
            expected_payload=signed_payload,
            evaluation_time=(
                signed_recovery.get("issued_at")
                if isinstance(signed_recovery, dict)
                else datetime.now(timezone.utc)
            ),
            trust_store=observer_receipt.ObserverTrustStore.from_host_file(
                trust_path
            ),
            replay_guard=observer_receipt.SQLiteReplayGuard(replay_path),
            environ={},
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        verification = {"status": "DENY"}
    _require(
        verification.get("status") == "PASS"
        and verification.get("payload") == signed_payload,
        "stage_l_predecessor_pre_native_signature",
    )
    recovery_binding = {
        "predecessor": dict(predecessor),
        "capacity_sha256": _sha(_canonical_bytes(after)),
    }
    return (
        rv.freeze(receipt),
        _sha(raw),
        str(path),
        rv.freeze(recovery_binding),
    )


def _bind_qualification_workspace(state, owner_request):
    _require(type(owner_request) is dict, "stage_l_owner_request")
    requested = owner_request.get("workspace")
    readiness = (
        state.candidate_readiness.to_plain()
        if state.candidate_readiness is not None else {}
    )
    expected = readiness.get("qualification_workspace")
    _require(
        isinstance(requested, (str, os.PathLike))
        and isinstance(expected, str),
        "stage_l_qualification_workspace",
    )
    try:
        requested_path = Path(requested).absolute().resolve(strict=True)
        expected_path = Path(expected).absolute().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_qualification_workspace"
        ) from error
    _require(
        requested_path == expected_path,
        "stage_l_qualification_workspace_mismatch",
    )
    state.qualification_workspace = str(expected_path)


def _repair_branch_for_ticket(ticket_id):
    return "codex/issue-" + str(ticket_id) + "-repair"


def _bind_owner_ticket(state, owner_request):
    """Refuse an owner request whose ticket and repair branch disagree.

    The owner refuses the same pair itself, but only after release and
    install have happened; binding it here keeps that mistake in front of
    every physical effect.  The accepted pair is retained as report evidence
    only; the owner remains the authority that writes it into the receipt.
    """

    ticket_id = owner_request.get("ticket_id")
    _require(
        type(ticket_id) is int
        and _TICKET_TEXT.fullmatch(str(ticket_id)) is not None
        and owner_request.get("repair_branch")
        == _repair_branch_for_ticket(ticket_id),
        "stage_l_owner_ticket_binding",
    )
    state.owner_ticket_id = ticket_id
    state.owner_repair_branch = owner_request["repair_branch"]


def _predecessor_binding_source(state):
    """Name the one accepted artifact that binds the predecessor, else None."""

    recovery_bound = (
        state.predecessor_recovery_receipt is not None
        and type(state.predecessor_recovery_receipt_sha256) is str
        and _DIGEST.fullmatch(state.predecessor_recovery_receipt_sha256)
        is not None
        and isinstance(state.predecessor_recovery_receipt_path, str)
    )
    pre_native_bound = (
        state.predecessor_pre_native_receipt is not None
        and type(state.predecessor_pre_native_receipt_sha256) is str
        and _DIGEST.fullmatch(state.predecessor_pre_native_receipt_sha256)
        is not None
        and isinstance(state.predecessor_pre_native_receipt_path, str)
    )
    qualification_bound = (
        state.predecessor_qualification_receipt is not None
        and state.predecessor_qualification_identity is not None
        and type(state.predecessor_qualification_receipt_sha256) is str
        and _DIGEST.fullmatch(state.predecessor_qualification_receipt_sha256)
        is not None
        and isinstance(state.predecessor_qualification_receipt_path, str)
        and type(state.predecessor_qualification_evidence_sha256) is str
        and _DIGEST.fullmatch(state.predecessor_qualification_evidence_sha256)
        is not None
        and isinstance(state.predecessor_qualification_evidence_path, str)
    )
    closed_failure_bound = (
        state.predecessor_closed_failure_receipt is not None
        and isinstance(state.predecessor_closed_failure_receipt_path, str)
        and isinstance(state.predecessor_closed_failure_receipt_sha256, str)
        and _DIGEST.fullmatch(state.predecessor_closed_failure_receipt_sha256)
        is not None
    )
    # Stage L binds through exactly one branch, so two sources cannot be
    # bound today; the exclusion stays so a later second binding site cannot
    # stack sources silently.
    bound = [
        name for name, flag in (
            ("recovery_receipt", recovery_bound),
            ("pre_native_recovery_receipt", pre_native_bound),
            ("qualification_receipt", qualification_bound),
            ("closed_failure_receipt", closed_failure_bound),
        )
        if flag
    ]
    return bound[0] if len(bound) == 1 else None


def observe_closed_failure_predecessor(
    terminal_artifact, *, plugin_data, observer_trust_store, runtime_root,
    codex_home, prior_terminal_artifact=None, prior_qualification_receipt=None,
    prior_qualification_evidence=None,
):
    """Observe a closed negative, including an install that created no task.

    The no-task cut additionally binds the prior closed root's terminal and
    read to the current authenticated predecessor. The qualified-prior cut
    binds an owner session that failed before creating any task to the
    preceding generation's PASS receipt and the terminal evidence it seals:
    the authenticated predecessor must still be exactly the controller that
    evidence names, as a clean terminal. That pair supplies identity only.
    No cut mutates the controller or grants qualification credit. The caller
    signs the result.
    """
    issue = "stage_l_predecessor_closed_failure_receipt"
    path, raw = _stable_owned_artifact(terminal_artifact, maximum=65_536, issue=issue)
    terminal = _closed_failure_json(raw, issue)
    qualified_prior = (
        prior_qualification_receipt is not None
        or prior_qualification_evidence is not None
    )
    _require(not (qualified_prior and prior_terminal_artifact is not None), issue)
    prior_path = None
    prior_raw = None
    qualification = None
    owner_terminal = None
    if qualified_prior:
        _require_closed_failure_owner_session_terminal(terminal, issue)
        qualification = _read_closed_failure_qualification(
            prior_qualification_receipt, prior_qualification_evidence, issue,
        )
        _require(qualification["receipt"]["generation"] != terminal["generation"], issue)
    elif prior_terminal_artifact is None:
        _require_closed_failure_terminal(terminal, issue)
        owner_terminal = terminal
    else:
        _require_closed_failure_no_task_terminal(terminal, issue)
        prior_path, prior_raw = _stable_owned_artifact(
            prior_terminal_artifact, maximum=65_536, issue=issue,
        )
        owner_terminal = _closed_failure_json(prior_raw, issue)
        _require_closed_failure_terminal(owner_terminal, issue)
        _require(owner_terminal["generation"] != terminal["generation"], issue)
    installed = Path(codex_home).absolute() / _INSTALLED_PLUGIN_CACHE / terminal["generation"]
    _require(Path(runtime_root).absolute() == installed
             and _installed_generations(codex_home) == [terminal["generation"]], issue)
    runtime = runtime_package.validate_runtime_package(runtime_root, runtime_root)
    _require(runtime["package_digest"] == terminal["runtime_package_digest"], issue)

    def observe():
        return predecessor_readiness.observe_predecessor_readiness(
            plugin_data=plugin_data, observer_trust_store=observer_trust_store,
            expected_generation=terminal["generation"],
            expected_runtime_package_digest=terminal["runtime_package_digest"],
            runtime_root=runtime_root,
        )

    before = observe()
    _assert_exact_predecessor(before, issue)
    authority = predecessor_readiness._ReadOnlyNativeGrantStore(
        predecessor_readiness.native_grant_store.canonical_database_path(plugin_data)
    ).canonical_authority()
    lifecycle = authority.get("lifecycle", {}) if type(authority) is dict else {}
    if qualification is None:
        _require(
            _sha(_canonical_bytes(authority)) == before["authority_sha256"]
            and lifecycle.get("terminal") is True
            and lifecycle.get("terminal_qualified") is False,
            issue,
        )
        _require_closed_failure_task_read(owner_terminal, before["predecessor"], issue)
    else:
        # The failed owner session created nothing, so the canonical controller
        # is still the one the PASS evidence names, closed as a clean terminal.
        _require(
            _sha(_canonical_bytes(authority)) == before["authority_sha256"]
            and lifecycle.get("terminal") is True,
            issue,
        )
        _require_qualified_prior_identity(before, qualification["identity"], issue)
    for closed in (terminal,) if prior_path is None else (terminal, owner_terminal):
        pgid = closed["host_cleanup"].get("pgid")
        _require(type(pgid) is int and pgid > 0, issue)
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            pass
        else:
            _require(False, issue)
    if prior_path is not None:
        _prior_path, after_prior = _stable_owned_artifact(prior_path, maximum=65_536, issue=issue)
        _require(after_prior == prior_raw, issue)
    if qualification is not None:
        again = _read_closed_failure_qualification(
            qualification["receipt_path"], qualification["evidence_path"], issue,
        )
        _require(again["receipt_raw"] == qualification["receipt_raw"]
                 and again["evidence_raw"] == qualification["evidence_raw"], issue)
    _after_path, after_raw = _stable_owned_artifact(path, maximum=65_536, issue=issue)
    _require(observe() == before and after_raw == raw, issue)
    observation = {
        "schema": PREDECESSOR_CLOSED_FAILURE_SCHEMA,
        "status": "CLOSED_FAILURE_OBSERVED",
        "generation": terminal["generation"],
        "runtime_package_digest": terminal["runtime_package_digest"],
        "source_commit": terminal["source_commit"],
        "terminal_path": str(path), "terminal_sha256": _sha(raw),
        "terminal_size_bytes": len(raw),
        "predecessor_observation": before,
        "terminal_qualified": False,
    }
    if prior_path is not None:
        observation.update(
            prior_terminal_path=str(prior_path), prior_terminal_sha256=_sha(prior_raw),
            prior_terminal_size_bytes=len(prior_raw),
        )
    if qualification is not None:
        observation.update(
            prior_qualification_receipt_path=str(qualification["receipt_path"]),
            prior_qualification_receipt_sha256=_sha(qualification["receipt_raw"]),
            prior_qualification_receipt_size_bytes=len(qualification["receipt_raw"]),
            prior_qualification_evidence_path=str(qualification["evidence_path"]),
            prior_qualification_evidence_sha256=_sha(qualification["evidence_raw"]),
            prior_qualification_evidence_size_bytes=len(qualification["evidence_raw"]),
        )
    return observation


def _read_closed_failure_qualification(receipt_artifact, evidence_artifact, issue):
    """Read the preceding PASS pair for the qualified-prior cut under its refusal."""
    try:
        receipt, receipt_raw, receipt_path, evidence_raw, evidence_path, identity = (
            _read_predecessor_qualification(receipt_artifact, evidence_artifact)
        )
    except values.LifecycleContractError as error:
        raise values.LifecycleContractError("action_host:" + issue) from error
    return {"receipt": receipt, "receipt_raw": receipt_raw, "receipt_path": receipt_path,
            "evidence_raw": evidence_raw, "evidence_path": evidence_path, "identity": identity}


def _require_qualified_prior_identity(report, identity, issue):
    """The observed predecessor is exactly the clean terminal the PASS evidence names."""
    observed = report.get("predecessor")
    _require(
        report.get("decision") == "PREDECESSOR_CLEAN_TERMINAL"
        and type(observed) is dict
        and all(observed.get(field) == identity[field] for field in _PREDECESSOR_IDENTITY_FIELDS),
        issue,
    )


def _require_closed_failure_task_read(terminal, predecessor, issue):
    _path, raw = _stable_owned_artifact(
        terminal["last_thread_read"]["path"], maximum=16_777_216, issue=issue,
    )
    last_read = _closed_failure_json(raw, issue)
    _require(_sha(raw) == terminal["last_thread_read"]["sha256"]
             and last_read.get("task_id") == predecessor["root_task_id"], issue)


def _closed_failure_json(raw, issue):
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError("action_host:" + issue) from error
    _require(type(result) is dict, issue)
    return result


def _require_closed_failure_metadata(terminal, issue):
    cleanup = terminal.get("host_cleanup") if type(terminal) is dict else None
    _require(
        type(terminal) is dict
        and terminal.get("schema") == "orch-dork/issue170-qualification-owner-terminal/v1"
        and terminal.get("status") == "FAIL"
        and terminal.get("promotion_receipt_emitted") is False
        and isinstance(terminal.get("generation"), str)
        and _PREDECESSOR_GENERATION_TEXT.fullmatch(terminal["generation"]) is not None
        and isinstance(terminal.get("source_commit"), str)
        and _COMMIT.fullmatch(terminal["source_commit"]) is not None
        and isinstance(terminal.get("runtime_package_digest"), str)
        and _DIGEST.fullmatch(terminal["runtime_package_digest"]) is not None
        and type(cleanup) is dict and cleanup.get("status") == "PASS"
        and all(cleanup.get(field) is True for field in (
            "host_closed", "process_reaped", "process_group_absent",
            "owner_socket_absent", "descendants_absent"))
        and type(cleanup.get("remaining_descendants")) is int
        and cleanup["remaining_descendants"] == 0
        and type(cleanup.get("process_group_members")) is int
        and cleanup["process_group_members"] == 0,
        issue,
    )


def _require_closed_failure_terminal(terminal, issue):
    _require_closed_failure_metadata(terminal, issue)
    read = terminal.get("last_thread_read")
    _require(
        terminal.get("issue") == "issue170_owner:verified_failure_closed"
        and terminal.get("phase") == "terminal"
        and type(read) is dict and read.get("state") == "PRESERVED"
        and isinstance(read.get("path"), str)
        and isinstance(read.get("sha256"), str)
        and _DIGEST.fullmatch(read["sha256"]) is not None,
        issue,
    )


def _require_closed_failure_no_task_terminal(terminal, issue):
    """Keep canary calls distinct from the owner's zero-task cleanup counters."""
    _require_closed_failure_metadata(terminal, issue)
    cleanup = terminal["host_cleanup"]
    _require(
        terminal.get("phase") == "pre_turn"
        and terminal.get("issue") == "pre_spawn:input_artifact_binding_invalid"
        and terminal.get("last_thread_read") == {"state": "NOT_OBSERVED", "path": None}
        and cleanup.get("provider_free") is True
        and all(type(cleanup.get(field)) is int and cleanup[field] == 0
                for field in _CLOSED_FAILURE_NO_TASK_COUNTERS),
        issue,
    )


def _require_closed_failure_owner_session_terminal(terminal, issue):
    """An installed owner session that failed before creating any task.

    As in the pre-turn cut, every owner counter is zero and no thread was
    read; nothing was published either. The generation is spent, and the
    controller the preceding generation qualified is left as it was.
    """
    _require_closed_failure_metadata(terminal, issue)
    cleanup = terminal["host_cleanup"]
    publication = terminal.get("partial_publication")
    _require(
        terminal.get("phase") == "owner_session"
        and terminal.get("issue") == "issue170_owner:owner_session_failed"
        and terminal.get("last_thread_read") == {"state": "NOT_OBSERVED", "path": None}
        and type(publication) is dict and publication.get("state") == "ABSENT"
        and cleanup.get("provider_free") is True
        and all(type(cleanup.get(field)) is int and cleanup[field] == 0
                for field in _CLOSED_FAILURE_NO_TASK_COUNTERS),
        issue,
    )


def _accept_predecessor_closed_failure_receipt(artifact, *, observer_trust_store,
                                              observer_replay_db, codex_home):
    issue = "stage_l_predecessor_closed_failure_receipt"
    path, raw = _stable_owned_artifact(artifact, maximum=65_536, issue=issue)
    receipt = _closed_failure_json(raw, issue)
    _require(type(receipt) is dict and set(receipt) == {
        "observation", "host_observation_receipt", "receipt_sha256"}, issue)
    core = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    _require(receipt["receipt_sha256"] == _sha(_canonical_bytes(core)), issue)
    observation = receipt["observation"]
    legacy_fields = {
        "schema", "status", "generation", "runtime_package_digest", "source_commit",
        "terminal_path", "terminal_sha256", "terminal_size_bytes", "predecessor_observation",
        "terminal_qualified",
    }
    prior_fields = {"prior_terminal_path", "prior_terminal_sha256", "prior_terminal_size_bytes"}
    qualified_fields = set(_CLOSED_FAILURE_QUALIFIED_PRIOR_FIELDS)
    _require(type(observation) is dict
             and set(observation) in (legacy_fields, legacy_fields | prior_fields,
                                      legacy_fields | qualified_fields), issue)
    no_task = set(observation) == legacy_fields | prior_fields
    qualified_prior = set(observation) == legacy_fields | qualified_fields
    _require(observation["schema"] == PREDECESSOR_CLOSED_FAILURE_SCHEMA
             and observation["status"] == "CLOSED_FAILURE_OBSERVED"
             and observation["terminal_qualified"] is False
             and isinstance(observation["generation"], str)
             and _PREDECESSOR_GENERATION_TEXT.fullmatch(observation["generation"]) is not None
             and isinstance(observation["source_commit"], str)
             and _COMMIT.fullmatch(observation["source_commit"]) is not None
             and all(isinstance(observation[k], str) and _DIGEST.fullmatch(observation[k]) is not None
                     for k in ("runtime_package_digest", "terminal_sha256")), issue)
    signed = receipt["host_observation_receipt"]
    _require(type(signed) is dict, issue)
    trust_path, replay_path = _observer_authority_paths(
        observer_trust_store, observer_replay_db, issue=issue)
    try:
        verified = observer_receipt.verify_signed_receipt(
            signed, expected_kind=PREDECESSOR_CLOSED_FAILURE_KIND,
            expected_payload=observation, evaluation_time=signed.get("issued_at"),
            trust_store=observer_receipt.ObserverTrustStore.from_host_file(trust_path),
            replay_guard=observer_receipt.SQLiteReplayGuard(replay_path), environ={},
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        verified = {"status": "DENY"}
    _require(verified.get("status") == "PASS"
             and verified.get("payload") == observation, issue)
    terminal_path, terminal_raw = _stable_owned_artifact(
        observation["terminal_path"], maximum=65_536, issue=issue)
    _require(str(terminal_path) == observation["terminal_path"]
             and len(terminal_raw) == observation["terminal_size_bytes"]
             and _sha(terminal_raw) == observation["terminal_sha256"], issue)
    terminal = _closed_failure_json(terminal_raw, issue)
    if qualified_prior:
        _require_closed_failure_owner_session_terminal(terminal, issue)
    elif no_task:
        _require_closed_failure_no_task_terminal(terminal, issue)
    else:
        _require_closed_failure_terminal(terminal, issue)
    _require(all(terminal.get(k) == observation[k] for k in
                 ("generation", "runtime_package_digest", "source_commit")), issue)
    _require(_installed_generations(codex_home) == [observation["generation"]], issue)
    before = observation["predecessor_observation"]
    _assert_exact_predecessor(before, issue)
    _require(before["observer_runtime"] == {
        "generation": observation["generation"],
        "runtime_package_digest": observation["runtime_package_digest"]}, issue)
    if no_task:
        _require(isinstance(observation["prior_terminal_sha256"], str)
                 and _DIGEST.fullmatch(observation["prior_terminal_sha256"]) is not None, issue)
        prior_path, prior_raw = _stable_owned_artifact(
            observation["prior_terminal_path"], maximum=65_536, issue=issue,
        )
        _require(str(prior_path) == observation["prior_terminal_path"]
                 and len(prior_raw) == observation["prior_terminal_size_bytes"]
                 and _sha(prior_raw) == observation["prior_terminal_sha256"], issue)
        prior = _closed_failure_json(prior_raw, issue)
        _require_closed_failure_terminal(prior, issue)
        _require(prior["generation"] != terminal["generation"], issue)
        _require_closed_failure_task_read(prior, before["predecessor"], issue)
        _prior_path, after_prior = _stable_owned_artifact(prior_path, maximum=65_536, issue=issue)
        _terminal_path, after_terminal = _stable_owned_artifact(terminal_path, maximum=65_536, issue=issue)
        _require(after_prior == prior_raw and after_terminal == terminal_raw, issue)
    if qualified_prior:
        qualification = _read_closed_failure_qualification(
            observation["prior_qualification_receipt_path"],
            observation["prior_qualification_evidence_path"], issue,
        )
        _require(
            str(qualification["receipt_path"]) == observation["prior_qualification_receipt_path"]
            and len(qualification["receipt_raw"]) == observation["prior_qualification_receipt_size_bytes"]
            and _sha(qualification["receipt_raw"]) == observation["prior_qualification_receipt_sha256"]
            and str(qualification["evidence_path"]) == observation["prior_qualification_evidence_path"]
            and len(qualification["evidence_raw"]) == observation["prior_qualification_evidence_size_bytes"]
            and _sha(qualification["evidence_raw"]) == observation["prior_qualification_evidence_sha256"],
            issue,
        )
        _require(qualification["receipt"]["generation"] != terminal["generation"], issue)
        _require_qualified_prior_identity(before, qualification["identity"], issue)
        _terminal_path, after_terminal = _stable_owned_artifact(terminal_path, maximum=65_536, issue=issue)
        _require(after_terminal == terminal_raw, issue)
    return (rv.freeze(receipt), _sha(raw), str(path), rv.freeze({
        "predecessor": before["predecessor"], "capacity_sha256": before["capacity_sha256"]}))


def _predecessor_qualification_identity(evidence):
    """Read the controller identity one sealed PASS evidence records."""

    bindings = evidence.get("bindings")
    settlement = (
        bindings.get("completion_settlement")
        if type(bindings) is dict else None
    )
    authority = (
        settlement.get("authority_after")
        if type(settlement) is dict else None
    )
    identity = (
        authority.get("identity") if type(authority) is dict else None
    )
    controller = (
        settlement.get("controller_before")
        if type(settlement) is dict else None
    )
    stage = (
        controller.get("stage_report") if type(controller) is dict else None
    )
    if type(identity) is not dict or type(stage) is not dict:
        return None
    predecessor = {
        "controller_id": identity.get("controller_id"),
        "controller_run_id": identity.get("controller_run_id"),
        "root_task_id": stage.get("root_task_id"),
        "attempt_id": stage.get("attempt_id"),
        "run_id": stage.get("run_id"),
    }
    if _predecessor_run_id(predecessor) is None:
        return None
    return predecessor


def _installed_generations(codex_home):
    """List the version directories under the Codex plugin cache, exactly.

    Every entry must be a real directory: a symlinked alias, a stray file or
    an unreadable cache is a reason to refuse, because the receipt is read
    as naming the single generation materialised there.  All three causes
    share one refusal code with the mismatch itself, since each means the
    cache cannot name a sole generation.
    """

    try:
        root = (
            Path(codex_home).absolute().resolve(strict=True)
            / _INSTALLED_PLUGIN_CACHE
        )
        entries = sorted(root.iterdir())
    except (OSError, RuntimeError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_qualification_generation"
        ) from error
    _require(
        all(
            entry.is_dir() and not entry.is_symlink() for entry in entries
        ),
        "stage_l_predecessor_qualification_generation",
    )
    return [entry.name for entry in entries]


def _read_predecessor_qualification(receipt_artifact, evidence_artifact):
    """Read one closed PASS promotion receipt and the terminal evidence it seals.

    Returns the receipt, its raw bytes and path, the evidence's raw bytes and
    path, and the controller identity the evidence records. What is
    installed now is the caller's to bind.
    """

    _require(
        isinstance(receipt_artifact, (str, os.PathLike))
        and isinstance(evidence_artifact, (str, os.PathLike)),
        "stage_l_predecessor_qualification_receipt",
    )
    receipt_path, receipt_raw = _stable_owned_artifact(
        receipt_artifact,
        maximum=65_536,
        issue="stage_l_predecessor_qualification_receipt",
    )
    try:
        receipt = json.loads(receipt_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_qualification_receipt_json"
        ) from error
    _require(
        type(receipt) is dict
        and set(receipt) == _PREDECESSOR_QUALIFICATION_RECEIPT_FIELDS
        and receipt.get("schema") == PREDECESSOR_QUALIFICATION_RECEIPT_SCHEMA
        and receipt.get("status") == "PASS"
        and isinstance(receipt.get("ticket_id"), str)
        and _TICKET_TEXT.fullmatch(receipt["ticket_id"])
        is not None
        and receipt.get("repair_branch")
        == _repair_branch_for_ticket(receipt["ticket_id"])
        and isinstance(receipt.get("generation"), str)
        and _PREDECESSOR_GENERATION_TEXT.fullmatch(receipt["generation"])
        is not None
        and isinstance(receipt.get("source_commit"), str)
        and _COMMIT.fullmatch(receipt["source_commit"]) is not None
        and all(
            isinstance(receipt.get(field), str)
            and _DIGEST.fullmatch(receipt[field]) is not None
            for field in (
                "runtime_package_digest", "qualification_evidence_sha256",
            )
        ),
        "stage_l_predecessor_qualification_receipt_report",
    )
    evidence_path, evidence_raw = _stable_owned_artifact(
        evidence_artifact,
        maximum=16_777_216,
        issue="stage_l_predecessor_qualification_evidence",
    )
    _require(
        _sha(evidence_raw) == receipt["qualification_evidence_sha256"],
        "stage_l_predecessor_qualification_evidence_binding",
    )
    try:
        evidence = json.loads(evidence_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_qualification_evidence_json"
        ) from error
    _require(
        type(evidence) is dict
        and set(evidence) == _PREDECESSOR_QUALIFICATION_EVIDENCE_FIELDS
        and evidence.get("schema")
        == PREDECESSOR_QUALIFICATION_EVIDENCE_SCHEMA
        and evidence.get("status") == "PASS"
        and evidence.get("disposition") == "QUALIFICATION_OWNER_COMPLETED"
        and evidence.get("generation") == receipt["generation"]
        and evidence.get("runtime_package_digest")
        == receipt["runtime_package_digest"]
        and evidence.get("source_commit") == receipt["source_commit"]
        and type(evidence.get("ticket_id")) is int
        and str(evidence["ticket_id"]) == receipt["ticket_id"]
        and evidence.get("repair_branch") == receipt["repair_branch"],
        "stage_l_predecessor_qualification_evidence_report",
    )
    identity = _predecessor_qualification_identity(evidence)
    _require(
        identity is not None,
        "stage_l_predecessor_qualification_identity",
    )
    return receipt, receipt_raw, receipt_path, evidence_raw, evidence_path, identity


def _accept_predecessor_qualification(
    receipt_artifact,
    evidence_artifact,
    *,
    codex_home,
):
    """Bind the predecessor to the qualified live run that installed it.

    The receipt must be a closed PASS promotion receipt whose sealed terminal
    evidence names the controller, run, attempt and root task the observer
    must report, and it must name the single generation installed now so the
    identity describes the live predecessor and not an older one.

    Unlike a recovery receipt, this pair carries no observer signature: it is
    an identity source, not an authority.  Every safety fact (clean terminal,
    no active lanes, unchanged state, pinned capacity, exact recheck) still
    comes from the trust-store-verified observer, which must report exactly
    this identity before the pair binds anything.  The installed-generation
    rule also bounds reuse: once a successor installs, the receipt no longer
    names the sole installed generation and cannot bind a second run.
    """

    receipt, receipt_raw, receipt_path, evidence_raw, evidence_path, identity = (
        _read_predecessor_qualification(receipt_artifact, evidence_artifact)
    )
    _require(
        _installed_generations(codex_home) == [receipt["generation"]],
        "stage_l_predecessor_qualification_generation",
    )
    return (
        rv.freeze(receipt),
        _sha(receipt_raw),
        str(receipt_path),
        _sha(evidence_raw),
        str(evidence_path),
        rv.freeze(identity),
    )


def _bind_clean_predecessor(state, report):
    """Pin the first READY observation to the accepted qualification identity.

    The decision check restates what a READY report must already carry; the
    capacity digest check is the load-bearing one, because the report
    validator permits a null digest and the binding needs a real one.
    """

    identity = state.predecessor_qualification_identity.to_plain()
    observed = report.get("predecessor")
    _require(
        report.get("decision") == "PREDECESSOR_CLEAN_TERMINAL"
        and report.get("active_lane_ids") == []
        and type(observed) is dict
        and all(
            observed.get(field) == identity[field]
            for field in _PREDECESSOR_IDENTITY_FIELDS
        )
        and isinstance(report.get("capacity_sha256"), str)
        and _DIGEST.fullmatch(report["capacity_sha256"]) is not None,
        "stage_l_predecessor_identity",
    )
    # The field holds whichever predecessor binding Stage L accepted; the
    # report names its source separately.
    state.predecessor_recovery_binding = rv.freeze({
        "predecessor": observed,
        "capacity_sha256": report["capacity_sha256"],
    })


def _assert_exact_predecessor(report, issue, *, recovery_binding=None):
    recovery = (
        recovery_binding.to_plain()
        if isinstance(recovery_binding, rv.FrozenValue)
        else recovery_binding
    )
    _require(
        predecessor_readiness.validate_report(report)
        and report.get("status") == "READY"
        and _predecessor_run_id(report.get("predecessor")) is not None
        and report.get("controller_id")
        == report["predecessor"]["controller_id"]
        and report.get("active_lane_ids") == [],
        issue,
    )
    if recovery is not None:
        _require(
            type(recovery) is dict
            and set(recovery) == {"predecessor", "capacity_sha256"}
            and report.get("predecessor") == recovery.get("predecessor")
            and report.get("authority_sha256")
            == recovery.get("predecessor", {}).get("authority_sha256")
            and report.get("capacity_sha256")
            == recovery.get("capacity_sha256"),
            issue,
        )


def _projected_predecessor_preflight(
    host,
    *,
    codex_home,
    owner_request,
):
    """Run the observer from one exact projected candidate runtime."""

    state = _state(host)
    _require(type(owner_request) is dict, "stage_l_owner_request")
    trust_value = owner_request.get("observer_trust_store")
    _require(isinstance(trust_value, (str, os.PathLike)),
             "stage_l_observer_trust_store")
    trust = Path(trust_value).absolute()
    try:
        trust = trust.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_observer_trust_store"
        ) from error
    _require(trust.is_file() and not trust.is_symlink(),
             "stage_l_observer_trust_store")

    projection = host.output_root / "stage-l-predecessor-runtime"
    if state.predecessor_projection is None:
        package = runtime_package.project_runtime_source(
            host.candidate_root,
            projection,
        )
        state.predecessor_projection = {
            "root": str(projection.resolve(strict=True)),
            "package": dict(package),
        }
    else:
        _require(
            state.predecessor_projection.get("root")
            == str(projection.resolve(strict=True)),
            "stage_l_predecessor_projection_drift",
        )
        parity = runtime_package.validate_projected_runtime_package(
            host.candidate_root,
            projection,
        )
        _require(
            parity.get("status") == "PASS"
            and parity.get("package")
            == state.predecessor_projection.get("package"),
            "stage_l_predecessor_projection_drift",
        )
        package = parity["package"]
    generation = package.get("version")
    digest = package.get("package_digest")
    _require(
        isinstance(generation, str)
        and isinstance(digest, str)
        and len(digest) == 64,
        "stage_l_predecessor_projection_identity",
    )
    codex = Path(codex_home).absolute()
    try:
        codex = codex.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_codex_home"
        ) from error
    plugin_data = codex / "plugins/data/orch-dork-orch-dork-local"
    command = [
        sys.executable,
        "-I",
        "-S",
        "-B",
        str(
            projection
            / "skills/orch-dork/scripts/"
            "orch_dork_predecessor_readiness.py"
        ),
        "--plugin-data",
        str(plugin_data),
        "--observer-trust-store",
        str(trust),
        "--expected-generation",
        generation,
        "--expected-runtime-package-digest",
        digest,
    ]
    environment = {
        "HOME": os.environ.get("HOME", str(Path.home())),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for name in (
        native_name
        for native_name in (
            native_grant_witness_environment_name(),
            "XDG_STATE_HOME",
        )
        if native_name in os.environ
    ):
        environment[name] = os.environ[name]
    observed = _FIXED_RUN_PREFLIGHT_PROCESS(
        command,
        cwd=projection,
        environment=environment,
        timeout_seconds=30,
    )
    if observed["termination_reason"] == "timeout":
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_preflight_timeout"
        )
    if observed["termination_reason"] in {"stdout_limit", "stderr_limit"}:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_preflight_output"
        )
    if observed["cleanup"] is not True:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_preflight_cleanup",
            detail={"cleanup_reason": observed.get("cleanup_reason")},
        )
    stdout = observed["stdout"]
    stderr = observed["stderr"]
    _require(
        observed["termination_reason"] is None
        and observed["exit_code"] in {0, 2}
        and not stderr
        and 0 < len(stdout) <= 65_536,
        "stage_l_predecessor_preflight_execution",
    )
    try:
        report = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise values.LifecycleContractError(
            "action_host:stage_l_predecessor_preflight_output"
        ) from error
    _require(
        predecessor_readiness.validate_report(report)
        and report.get("observer_runtime")
        == {
            "generation": generation,
            "runtime_package_digest": digest,
        }
        and (observed["exit_code"] == 0)
        == (report.get("status") == "READY"),
        "stage_l_predecessor_preflight_report",
    )
    if report.get("status") == "READY":
        # A READY observation is only meaningful relative to an identity Stage
        # L already accepted: a recovery receipt names the predecessor it
        # closed, and a predecessor qualification names the controller its own
        # live run completed.  Without either there is nothing to bind, so a
        # READY report cannot pass on its own.
        if (
            state.predecessor_recovery_binding is None
            and state.predecessor_qualification_identity is not None
        ):
            _bind_clean_predecessor(state, report)
        _require(
            state.predecessor_recovery_binding is not None,
            "stage_l_predecessor_identity",
        )
        _assert_exact_predecessor(
            report,
            "stage_l_predecessor_identity",
            recovery_binding=state.predecessor_recovery_binding,
        )
    return report


def native_grant_witness_environment_name():
    """Keep the projected observer's external-witness namespace explicit."""

    return "ORCH_DORK_NATIVE_WITNESS_ROOT"


_FIXED_RELEASE_ACTION = release_and_install_candidate
_FIXED_LIVE_ACTION = begin_live_qualification
_FIXED_RUN_PREFLIGHT_PROCESS = _run_preflight_process
_FIXED_PREDECESSOR_PREFLIGHT = _projected_predecessor_preflight


def release_install_and_qualify_candidate(
    host,
    *,
    codex_executable,
    owner_request,
    predecessor_recovery_receipt=None,
    predecessor_pre_native_receipt=None,
    predecessor_closed_failure_receipt=None,
    predecessor_qualification_receipt=None,
    predecessor_qualification_evidence=None,
    codex_home=None,
    home_directory=None,
):
    """Run Stage L without serializing or surrendering release authority.

    The accepted ``ReleaseActionInputs`` remain owned by this ActionHost and
    this process across the physical release/install boundary and the sole
    fresh qualification attempt. No callback or compatibility CLI can replace
    either fixed public action.

    The predecessor is bound by exactly one accepted artifact: a signed
    observed-spawn-stall recovery receipt when the predecessor stalled after
    a spawn, a signed pre-native-failure recovery receipt when its root turn
    failed before any native action, or the predecessor generation's own
    PASS promotion receipt with the terminal evidence it seals when that
    generation completed its live run cleanly, or a signed observation of a
    normally closed failed qualification, including an install that created
    no task, bound to the closed root before it or to the PASS run before it.
    The latter preserves its FAIL verdict and grants no qualification or
    promotion credit.
    """
    state = _state(host)
    _require(state.phase == "CANDIDATE_SUCCEEDED", "stage_l_wrong_order")
    release_inputs = state.release_inputs
    _require(type(release_inputs) is action_authority.ReleaseActionInputs,
             "stage_l_action_inputs")
    _assert_source_frozen(host, state)
    _assert_candidate_readiness_retained(state)
    _bind_qualification_workspace(state, owner_request)
    _bind_owner_ticket(state, owner_request)
    home = (
        Path.home()
        if home_directory is None
        else Path(home_directory).absolute()
    )
    codex = (
        Path(os.environ.get("CODEX_HOME", str(home / ".codex"))).absolute()
        if codex_home is None
        else Path(codex_home).absolute()
    )
    qualification_supplied = (
        predecessor_qualification_receipt is not None
        or predecessor_qualification_evidence is not None
    )
    _require(
        sum((
            predecessor_recovery_receipt is not None,
            predecessor_pre_native_receipt is not None,
            predecessor_closed_failure_receipt is not None,
            qualification_supplied,
        )) <= 1,
        "stage_l_predecessor_binding_ambiguous",
    )
    if predecessor_closed_failure_receipt is not None:
        receipt, digest, path, binding = _accept_predecessor_closed_failure_receipt(
            predecessor_closed_failure_receipt,
            observer_trust_store=owner_request.get("observer_trust_store"),
            observer_replay_db=owner_request.get("observer_replay_db"), codex_home=codex,
        )
        state.predecessor_closed_failure_receipt = receipt
        state.predecessor_closed_failure_receipt_sha256 = digest
        state.predecessor_closed_failure_receipt_path = path
        state.predecessor_recovery_binding = binding
    elif predecessor_pre_native_receipt is not None:
        recovery, recovery_sha256, recovery_path, recovery_binding = (
            _accept_predecessor_pre_native_recovery_receipt(
                predecessor_pre_native_receipt,
                observer_trust_store=owner_request.get(
                    "observer_trust_store"
                ),
                observer_replay_db=owner_request.get("observer_replay_db"),
            )
        )
        state.predecessor_pre_native_receipt = recovery
        state.predecessor_pre_native_receipt_sha256 = recovery_sha256
        state.predecessor_pre_native_receipt_path = recovery_path
        # One binding slot serves both recovery kinds: whichever receipt
        # bound the predecessor, the release assertion reads this and
        # _predecessor_binding_source reports which receipt filled it.
        state.predecessor_recovery_binding = recovery_binding
    elif not qualification_supplied:
        recovery, recovery_sha256, recovery_path, recovery_binding = (
            _accept_predecessor_recovery_receipt(
                predecessor_recovery_receipt,
                observer_trust_store=owner_request.get(
                    "observer_trust_store"
                ),
                observer_replay_db=owner_request.get("observer_replay_db"),
            )
        )
        state.predecessor_recovery_receipt = recovery
        state.predecessor_recovery_receipt_sha256 = recovery_sha256
        state.predecessor_recovery_receipt_path = recovery_path
        state.predecessor_recovery_binding = recovery_binding
    else:
        (
            qualification,
            qualification_sha256,
            qualification_path,
            evidence_sha256,
            evidence_path,
            identity,
        ) = _accept_predecessor_qualification(
            predecessor_qualification_receipt,
            predecessor_qualification_evidence,
            codex_home=codex,
        )
        state.predecessor_qualification_receipt = qualification
        state.predecessor_qualification_receipt_sha256 = qualification_sha256
        state.predecessor_qualification_receipt_path = qualification_path
        state.predecessor_qualification_evidence_sha256 = evidence_sha256
        state.predecessor_qualification_evidence_path = evidence_path
        state.predecessor_qualification_identity = identity
    try:
        predecessor = _FIXED_PREDECESSOR_PREFLIGHT(
            host,
            codex_home=codex,
            owner_request=owner_request,
        )
    except BaseException:
        state.phase = "TERMINAL_PREDECESSOR_FAILURE"
        raise
    if predecessor.get("status") != "READY":
        state.predecessor_preflight = rv.freeze(predecessor)
        state.phase = "TERMINAL_PREDECESSOR_FAILURE"
        _require(False, "stage_l_predecessor_not_ready")
    _assert_exact_predecessor(
        predecessor,
        "stage_l_predecessor_not_ready",
        recovery_binding=state.predecessor_recovery_binding,
    )
    state.predecessor_preflight = rv.freeze(predecessor)
    state.stage_l_action_authority = _STAGE_L_RELEASE_AUTHORITY
    release_result = _FIXED_RELEASE_ACTION(
        host,
        codex_executable=codex_executable,
        codex_home=codex_home,
        home_directory=home_directory,
    )
    if not (_state(host) is state and state.phase == "RELEASE_SUCCEEDED"
            and state.release_inputs is release_inputs
            and state.stage_l_action_authority is None):
        state.phase = "TERMINAL_RELEASE_FAILURE"
        _require(False, "stage_l_release_handoff")
    try:
        predecessor_after_release = _FIXED_PREDECESSOR_PREFLIGHT(
            host,
            codex_home=codex,
            owner_request=owner_request,
        )
    except BaseException:
        state.phase = "TERMINAL_PREDECESSOR_FAILURE_AFTER_RELEASE"
        raise
    state.predecessor_after_release = rv.freeze(predecessor_after_release)
    if (
        predecessor_after_release.get("status") != "READY"
        or predecessor_after_release.get("report_sha256")
        != predecessor.get("report_sha256")
    ):
        state.phase = "TERMINAL_PREDECESSOR_FAILURE_AFTER_RELEASE"
        _require(False, "stage_l_predecessor_changed_after_release")
    _assert_exact_predecessor(
        predecessor_after_release,
        "stage_l_predecessor_changed_after_release",
        recovery_binding=state.predecessor_recovery_binding,
    )
    state.stage_l_action_authority = _STAGE_L_LIVE_AUTHORITY
    live_result = _FIXED_LIVE_ACTION(host, owner_request)
    if not (
        _state(host) is state
        and state.release_inputs is release_inputs
        and state.stage_l_action_authority is None
    ):
        state.phase = "TERMINAL_LIVE_FAILURE"
        _require(False, "stage_l_action_inputs_drift")
    _require(state.phase == "LIVE_SUCCEEDED", "stage_l_live_not_succeeded")
    return StageLExecution(
        release_execution=release_result,
        live_execution=live_result,
        predecessor_preflight=state.predecessor_preflight,
        predecessor_after_release=state.predecessor_after_release,
    )


def action_host_report(host):
    """Read-only status; this projection grants no authority."""
    state = _state(host)
    return rv.freeze({
        "schema": SCHEMA,
        "phase": state.phase,
        "source_root": str(host.source_root),
        "candidate_root": str(host.candidate_root),
        "frozen_source_sha256": state.frozen_source.to_plain()["logical_sha256"],
        "profiles": {
            profile: (state.attestations[profile].report.to_plain()["invocation_id"]
                      if profile in state.attestations else None)
            for profile in PROFILES
        },
        "campaign_report_sha256": state.report.digest() if state.report else None,
        "candidate_transition_sha256": (
            state.transition.digest() if state.transition else None
        ),
        "candidate_readiness_sha256": state.candidate_readiness_sha256,
        "candidate_readiness_path": state.candidate_readiness_path,
        "candidate_readiness": (
            state.candidate_readiness.to_plain()
            if state.candidate_readiness is not None else None
        ),
        "candidate_readiness_validation": (
            state.candidate_readiness_validation.to_plain()
            if state.candidate_readiness_validation is not None else None
        ),
        "predecessor_recovery_receipt_sha256": (
            state.predecessor_recovery_receipt_sha256
        ),
        "predecessor_recovery_receipt_path": (
            state.predecessor_recovery_receipt_path
        ),
        "predecessor_recovery_binding": (
            state.predecessor_recovery_binding.to_plain()
            if state.predecessor_recovery_binding is not None else None
        ),
        "predecessor_pre_native_receipt_sha256": (
            state.predecessor_pre_native_receipt_sha256
        ),
        "predecessor_pre_native_receipt_path": (
            state.predecessor_pre_native_receipt_path
        ),
        "predecessor_closed_failure_receipt_sha256": state.predecessor_closed_failure_receipt_sha256,
        "predecessor_closed_failure_receipt_path": state.predecessor_closed_failure_receipt_path,
        "owner_ticket_id": state.owner_ticket_id,
        "owner_repair_branch": state.owner_repair_branch,
        "predecessor_binding_source": _predecessor_binding_source(state),
        "predecessor_qualification_receipt_sha256": (
            state.predecessor_qualification_receipt_sha256
        ),
        "predecessor_qualification_receipt_path": (
            state.predecessor_qualification_receipt_path
        ),
        "predecessor_qualification_evidence_sha256": (
            state.predecessor_qualification_evidence_sha256
        ),
        "predecessor_qualification_evidence_path": (
            state.predecessor_qualification_evidence_path
        ),
        "predecessor_qualification_identity": (
            state.predecessor_qualification_identity.to_plain()
            if state.predecessor_qualification_identity is not None
            else None
        ),
        "release_result_sha256": (
            state.release_report.digest()
            if state.release_report is not None else None
        ),
        "live_result_sha256": (
            state.live_report.digest() if state.live_report is not None else None
        ),
        "predecessor_preflight": (
            state.predecessor_preflight.to_plain()
            if state.predecessor_preflight is not None else None
        ),
        "predecessor_after_release": (
            state.predecessor_after_release.to_plain()
            if state.predecessor_after_release is not None else None
        ),
        "campaign_authority": False,
        "release_authority": False,
        "live_authority": False,
        "qualification_authority": False,
    })


__all__ = [
    "SCHEMA", "CANDIDATE_RECEIPT_SCHEMA", "PROFILES", "CAMPAIGN_TIMEOUT_SECONDS",
    "ActionHost", "StageLExecution", "create_action_host", "bind_candidate_readiness",
    "run_provider_free_campaign",
    "claim_and_build_candidate", "release_and_install_candidate",
    "begin_live_qualification", "release_install_and_qualify_candidate",
    "action_host_report",
]
