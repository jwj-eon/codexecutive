"""Owner-local, single-use bookkeeping; never campaign or action authority.

Root must independently validate the campaign and transport originals with
their fixed readers before acting. This module validates closed transport,
exact bindings and durable original receipts, not their execution assertions.
Root retains the store receipt and latest returned receipt outside this store:
they anchor its inode and chain against replacement/truncation. There is no
reset, recovery, retry, lease expiry, or alternate-store discovery API.
"""

from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat

import orch_dork_runtime_package as runtime_package
from lifecycle_conformance import candidate_identity, reference_values as rv
from lifecycle_conformance.values import LifecycleContractError, canonical_digest, canonical_json


RECEIPT_SCHEMA = "orch-dork/issue170-consumption-receipt/v1"
OUTCOME_SCHEMA = "orch-dork/issue170-consumption-outcome/v1"
TRANSPORT_SCHEMA = "orch-dork/issue170-consumption-transport/v1"
PHASES = ("candidate", "release_install", "live_attempt")
MAX_BYTES = 2_097_152
_PROCESS_TOKEN = secrets.token_hex(32)
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CAMPAIGN_FIELDS = frozenset({
    "schema", "status", "registry_sha256", "campaign_status", "consumption_status",
    "campaign_authorized", "candidate_authorized", "release_authorized",
    "live_attempt_authorized", "qualification_authorized", "promotion_authorized",
    "runtime_identity", "candidate_transition_contract", "validated_components",
    "missing_component_readers", "facts", "requirements", "remaining_requirements",
    "evidence_sha256", "source_inventory_hashes",
})
_STAGE_L_FIELDS = frozenset({
    "schema", "status", "source_inventory_hashes", "runtime_identity",
    "release_manifest", "profiles", "facts", "campaign_authorized",
    "candidate_authorized", "release_authorized", "live_attempt_authorized",
    "qualification_authorized", "promotion_authorized",
    "candidate_transition_sha256", "evidence_sha256",
})
# Kept local to avoid an action_authority -> consumption import cycle. A
# focused contract test pins this transport spelling to STAGE_L_REPORT_SCHEMA.
_STAGE_L_REPORT_SCHEMA = "orch-dork/stage-l-campaign/v1"
_FLAGS = {"campaign_authorized": False, "release_authorized": False,
          "live_attempt_authorized": False, "qualification_authorized": False,
          "external_evidence_validated": False}


def _reset_process_token():
    global _PROCESS_TOKEN
    # Invalidate first: an ignored fork-callback error must not retain the
    # parent's identity. A fresh exec gets its token at module import instead.
    _PROCESS_TOKEN = None
    _PROCESS_TOKEN = secrets.token_hex(32)


# Stable within one interpreter lifetime, distinct in every fork descendant;
# a recycled PID cannot let a sibling complete a dead claimant's success.
os.register_at_fork(after_in_child=_reset_process_token)


def _require(condition, reason):
    if not condition:
        raise LifecycleContractError("consumption:" + reason)


def _shape(value, fields, label):
    _require(type(value) is dict and set(value) == set(fields), label)


def _bytes(value):
    return canonical_json(value).encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _decode(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "transport_extent")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        _bytes(result)  # Reject non-finite/non-canonical values as well.
    except LifecycleContractError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise LifecycleContractError("consumption:invalid_transport") from error
    _require(type(result) is dict, "transport_object")
    return result


def _package(value):
    _shape(value, ("version", "inventory_hash", "descriptor_hash", "package_digest"), "package_shape")
    _require(type(value["version"]) is str and 0 < len(value["version"]) <= 128
             and not any(c in value["version"] for c in "/\\\x00")
             and all(ord(c) >= 32 for c in value["version"]), "package_version")
    for key in ("inventory_hash", "descriptor_hash", "package_digest"):
        _require(type(value[key]) is str and _SHA.fullmatch(value[key]), "package_digest")


def _campaign(raw, pre_runtime):
    """Check the fixed gate's wire shape/binding, without granting its facts."""
    report = _decode(raw)
    if report.get("schema") == _STAGE_L_REPORT_SCHEMA:
        _shape(report, _STAGE_L_FIELDS, "stage_l_campaign_shape")
        _package(pre_runtime)
        _require(
            report["status"] == "PASS"
            and report["campaign_authorized"] is True
            and report["candidate_authorized"] is True
            and report["release_authorized"] is False
            and report["live_attempt_authorized"] is False
            and report["qualification_authorized"] is False
            and report["promotion_authorized"] is False
            and report["candidate_transition_sha256"] is None,
            "stage_l_campaign_not_pass",
        )
        identity = report["runtime_identity"]
        _shape(identity, (
            "phase", "python_source_hashes", "runtime_entry_hashes",
            "runtime_inventory_sha256", "manifest_sha256",
            "package_digest_before_cachebuster", "version_before_cachebuster",
        ), "stage_l_campaign_runtime")
        entries = identity["runtime_entry_hashes"]
        _require(
            identity["phase"] == "pre_cachebuster"
            and identity["package_digest_before_cachebuster"] == pre_runtime["package_digest"]
            and identity["version_before_cachebuster"] == pre_runtime["version"]
            and identity["runtime_inventory_sha256"] == canonical_digest(entries)
            and identity["manifest_sha256"] == entries.get(runtime_package.MANIFEST_PATH)
            and identity["python_source_hashes"]
            == {path: digest for path, digest in entries.items() if path.endswith(".py")},
            "stage_l_campaign_runtime_binding",
        )
        sources = report["source_inventory_hashes"]
        _require(
            type(sources) is dict and bool(sources)
            and all(type(path) is str and path.endswith(".py")
                    and type(digest) is str and _SHA.fullmatch(digest)
                    for path, digest in sources.items())
            and all(sources.get(path) == digest
                    for path, digest in identity["python_source_hashes"].items()),
            "stage_l_source_inventory",
        )
        _require(
            type(report["release_manifest"]) is dict
            and type(report["profiles"]) is dict
            and set(report["profiles"]) == {
                "campaign", "focused", "rehearsal", "full_suite"
            }
            and type(report["facts"]) is list
            and "full_suite_same_runtime" in report["facts"]
            and type(report["evidence_sha256"]) is str
            and _SHA.fullmatch(report["evidence_sha256"]),
            "stage_l_campaign_evidence",
        )
        return report
    _shape(report, _CAMPAIGN_FIELDS, "campaign_shape")
    _package(pre_runtime)
    _require(report["schema"] == "orch-dork/lifecycle-campaign-completion/v1"
             and report["status"] == report["campaign_status"] == "PASS", "campaign_not_pass")
    for key in ("registry_sha256", "evidence_sha256"):
        _require(type(report[key]) is str and _SHA.fullmatch(report[key]), "campaign_digest")
    for key in ("campaign_authorized", "candidate_authorized", "release_authorized",
                "live_attempt_authorized", "qualification_authorized", "promotion_authorized"):
        _require(type(report[key]) is bool, "campaign_boolean")
    _require(report["campaign_authorized"] and report["candidate_authorized"], "campaign_not_pass")
    _require(report["consumption_status"] == "PENDING", "campaign_already_consumed")
    for key in ("candidate_transition_contract", "validated_components", "requirements"):
        _require(type(report[key]) is dict, "campaign_object")
    for key in ("missing_component_readers", "facts", "remaining_requirements"):
        _require(type(report[key]) is list, "campaign_list")
    identity = report["runtime_identity"]
    _shape(identity, ("phase", "python_source_hashes", "runtime_entry_hashes",
                     "runtime_inventory_sha256", "manifest_sha256",
                     "package_digest_before_cachebuster", "version_before_cachebuster"), "campaign_runtime")
    entries = identity["runtime_entry_hashes"]
    _require(type(entries) is dict and entries and all(
        type(k) is str and k and type(v) is str and _SHA.fullmatch(v)
        for k, v in entries.items()), "campaign_entries")
    _require(identity["phase"] == "pre_cachebuster"
             and identity["package_digest_before_cachebuster"] == pre_runtime["package_digest"]
             and identity["version_before_cachebuster"] == pre_runtime["version"]
             and identity["runtime_inventory_sha256"] == canonical_digest(entries)
             and identity["manifest_sha256"] == entries.get(runtime_package.MANIFEST_PATH)
             and identity["python_source_hashes"] == {k: v for k, v in entries.items() if k.endswith(".py")},
             "campaign_runtime_binding")
    # The complete source inventory is distinct from the projected package.
    # This checks the retained wire binding only; the fixed gate must re-read
    # source originals before any of their classification facts are trusted.
    sources = report["source_inventory_hashes"]
    _require(type(sources) is dict and sources and all(
        type(path) is str and path.endswith(".py")
        and type(digest) is str and _SHA.fullmatch(digest)
        for path, digest in sources.items()), "campaign_source_inventory")
    _require(all(sources.get(path) == digest
                 for path, digest in identity["python_source_hashes"].items()),
             "campaign_source_runtime_binding")
    return report


def _owned(info, mode, directory=False):
    _require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
             and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == mode
             and (directory or info.st_nlink == 1), "unsafe_owned_path")


@contextmanager
def _directory(root, create=False):
    name = str(root)
    parts = name.split("/")[1:]
    _require(name.startswith("/") and parts and all(p not in ("", ".", "..") for p in parts)
             and "\x00" not in name, "absolute_path_required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        directory = os.open("/", flags)
        stack.callback(os.close, directory)
        links = []
        for index, part in enumerate(parts):
            if create and index == len(parts) - 1:
                _owned(os.fstat(directory), 0o700, directory=True)
                os.mkdir(part, 0o700, dir_fd=directory)
                os.fsync(directory)
            child = os.open(part, flags, dir_fd=directory)
            stack.callback(os.close, child)
            links.append((directory, part, child))
            info = os.fstat(child)
            _require(info.st_uid in (0, os.getuid()) and (
                not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                "unsafe_ancestor")
            directory = child
        _owned(os.fstat(directory), 0o700, directory=True)
        try:
            yield directory
        finally:
            for parent, part, child in links:
                named = os.stat(part, dir_fd=parent, follow_symlinks=False)
                held = os.fstat(child)
                _require((named.st_dev, named.st_ino) == (held.st_dev, held.st_ino), "path_replaced")
                _require(held.st_uid in (0, os.getuid()) and (
                    not held.st_mode & 0o022 or held.st_uid == 0 and held.st_mode & stat.S_ISVTX),
                    "unsafe_ancestor")
            _owned(os.fstat(directory), 0o700, directory=True)


def _read(directory, name, mode=0o400):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(fd)
        _owned(before, mode)
        _require(0 < before.st_size <= MAX_BYTES, "file_extent")
        raw = os.pread(fd, before.st_size + 1, 0)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _require(len(raw) == before.st_size and
                 (before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                 and (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino), "file_changed")
        return raw
    finally:
        os.close(fd)


def _write(directory, name, raw, mode=0o400):
    _require(len(raw) <= MAX_BYTES, "file_extent")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode, dir_fd=directory)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            _require(count > 0, "short_write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)
    # Empty/partial files are intentionally never removed on any failure.


def _snapshot(store, binding, seq=0, tip=None, phase="candidate", status="READY", claim=None):
    return rv.freeze({"schema": RECEIPT_SCHEMA, "store": store, "binding": binding,
                      "sequence": seq, "tip_sha256": tip or store["anchor_sha256"],
                      "phase": phase, "status": status, "claim": claim, **_FLAGS})


def _outcome(raw, claim):
    data = _decode(raw)
    _shape(data, ("schema", "phase", "claim_sha256", "outcome", "transport"), "outcome_shape")
    _require(data["schema"] == OUTCOME_SCHEMA and data["phase"] == claim.to_plain()["phase"]
             and data["claim_sha256"] == claim.digest()
             and data["outcome"] in ("SUCCEEDED", "FAILED", "REFUSED", "CRASHED"), "outcome_binding")
    transport = data["transport"]
    _shape(transport, ("schema", "status", "original_receipt_json"), "transport_shape")
    _require(transport["schema"] == TRANSPORT_SCHEMA
             and transport["status"] in ("VALIDATED", "REFUSED")
             and type(transport["original_receipt_json"]) is str, "transport_shape")
    original = _decode(transport["original_receipt_json"].encode("utf-8"))
    _require(type(original.get("schema")) is str and original["schema"], "original_receipt_schema")
    _require(data["outcome"] != "SUCCEEDED" or transport["status"] == "VALIDATED", "transport_refused")
    return data


def _advance(previous, event, anchor):
    prior = previous.to_plain()
    _shape(event, ("previous_sha256", "operation", "phase", "claim", "outcome_json", "transition"), "event_shape")
    _require(event["previous_sha256"] == previous.digest() and event["phase"] in PHASES, "event_binding")
    binding = dict(prior["binding"])
    if event["operation"] == "claim":
        index = 0 if prior["status"] == "READY" else PHASES.index(prior["phase"]) + 1
        _require(prior["status"] in ("READY", "SUCCEEDED") and index < len(PHASES)
                 and event["phase"] == PHASES[index], "phase_consumed_or_out_of_order")
        _shape(event["claim"], ("nonce", "pid", "process_token"), "claim_shape")
        _require(type(event["claim"]["pid"]) is int and event["claim"]["pid"] > 0
                 and all(type(event["claim"][k]) is str and _SHA.fullmatch(event["claim"][k])
                         for k in ("nonce", "process_token")), "claim_owner")
        _require(event["outcome_json"] is None and event["transition"] is None, "claim_payload")
        status = "CLAIMED"
    else:
        _require(event["operation"] == "outcome" and prior["status"] == "CLAIMED"
                 and event["phase"] == prior["phase"] and event["claim"] == prior["claim"], "outcome_order")
        _require(type(event["outcome_json"]) is str, "outcome_transport")
        outcome = _outcome(event["outcome_json"].encode("utf-8"), previous)
        status = outcome["outcome"]
        if status == "SUCCEEDED" and event["phase"] == "candidate":
            transition = event["transition"]
            _require(type(transition) is dict and transition.get("schema") == candidate_identity.SCHEMA,
                     "candidate_transition_required")
            _require(transition["original"]["project_runtime_source_report"] == binding["pre_runtime"], "pre_runtime_binding")
            campaign = _decode(anchor["campaign_json"].encode("utf-8"))
            _require({row["path"]: row["sha256"] for row in transition["original"]["inventory"]}
                     == campaign["runtime_identity"]["runtime_entry_hashes"], "campaign_inventory_binding")
            binding["post_runtime"] = transition["candidate"]["project_runtime_source_report"]
            binding["transition_sha256"] = canonical_digest(transition)
        else:
            _require(event["transition"] is None, "unexpected_transition")
    return _snapshot(prior["store"], binding, prior["sequence"] + 1, canonical_digest(event),
                     event["phase"], status, event["claim"])


def create_store(root, *, campaign_receipt, pre_runtime):
    """Create once in a private parent; bind originals, never certify a gate."""
    _campaign(campaign_receipt, pre_runtime)
    with _directory(root, create=True) as directory:
        _write(directory, "lock", b"lock\n", 0o600)
        info = os.fstat(directory)
        anchor = {"schema": "orch-dork/issue170-consumption-anchor/v1", "key": secrets.token_hex(32),
                  "campaign_json": campaign_receipt.decode("utf-8"), "pre_runtime": pre_runtime}
        raw = _bytes(anchor)
        _write(directory, "anchor.json", raw)
        store = {"device": info.st_dev, "inode": info.st_ino,
                 "lock_inode": os.stat("lock", dir_fd=directory, follow_symlinks=False).st_ino,
                 "anchor_sha256": _sha(raw)}
        binding = {"campaign_receipt_sha256": _sha(campaign_receipt), "pre_runtime": pre_runtime,
                   "post_runtime": None, "transition_sha256": None}
        return _snapshot(store, binding)


@contextmanager
def _locked(root, reference, expected_binding):
    _require(type(reference) is rv.FrozenValue, "original_receipt_required")
    supplied = reference.to_plain()
    _shape(supplied, ("schema", "store", "binding", "sequence", "tip_sha256", "phase", "status", "claim", *_FLAGS), "receipt_shape")
    _shape(supplied["store"], ("device", "inode", "lock_inode", "anchor_sha256"), "store_shape")
    _require(type(expected_binding) is dict, "expected_binding_required")
    with _directory(root) as directory:
        info = os.fstat(directory)
        store = supplied["store"]
        _require((info.st_dev, info.st_ino) == (store["device"], store["inode"]), "store_replaced")
        fd = os.open("lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            _owned(os.fstat(fd), 0o600)
            _require(os.fstat(fd).st_ino == store["lock_inode"], "lock_replaced")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise LifecycleContractError("consumption:locked") from error
            _require(_read(directory, "lock", 0o600) == b"lock\n", "lock_changed")
            raw = _read(directory, "anchor.json")
            _require(_sha(raw) == store["anchor_sha256"], "anchor_changed")
            anchor = _decode(raw)
            binding = {"campaign_receipt_sha256": _sha(anchor["campaign_json"].encode("utf-8")),
                       "pre_runtime": anchor["pre_runtime"], "post_runtime": None, "transition_sha256": None}
            latest = _snapshot(store, binding)
            names = sorted(set(os.listdir(directory)) - {"lock", "anchor.json"})
            _require(len(names) <= 6 and names == [f"{i:04d}.json" for i in range(1, len(names) + 1)], "record_inventory")
            for name in names:
                row = _decode(_read(directory, name))
                _shape(row, ("event", "mac"), "record_shape")
                expected_mac = hmac.new(bytes.fromhex(anchor["key"]), _bytes(row["event"]), hashlib.sha256).hexdigest()
                _require(type(row["mac"]) is str and hmac.compare_digest(row["mac"], expected_mac), "record_mutated")
                latest = _advance(latest, row["event"], anchor)
            _require(reference == latest, "stale_or_mutated_receipt")
            _require(_bytes(expected_binding) == _bytes(latest.to_plain()["binding"]), "expected_identity_mismatch")
            yield directory, anchor, latest
            _require(_read(directory, "lock", 0o600) == b"lock\n", "lock_changed")
            _require(os.stat("lock", dir_fd=directory, follow_symlinks=False).st_ino == os.fstat(fd).st_ino,
                     "lock_replaced")
        finally:
            os.close(fd)


def _append(directory, anchor, previous, event):
    receipt = _advance(previous, event, anchor)
    mac = hmac.new(bytes.fromhex(anchor["key"]), _bytes(event), hashlib.sha256).hexdigest()
    raw = _bytes({"event": event, "mac": mac})
    name = f"{receipt.to_plain()['sequence']:04d}.json"
    _write(directory, name, raw)
    _require(_read(directory, name) == raw, "record_changed")
    return receipt


def claim_phase(root, previous, *, phase, expected_binding):
    """Persist consumption before an independently authorized effect starts."""
    with _locked(root, previous, expected_binding) as (directory, anchor, latest):
        event = {"previous_sha256": latest.digest(), "operation": "claim", "phase": phase,
                 "claim": {"nonce": secrets.token_hex(32), "pid": os.getpid(), "process_token": _PROCESS_TOKEN},
                 "outcome_json": None, "transition": None}
        return _append(directory, anchor, latest, event)


def record_outcome(root, claim, *, outcome_receipt, expected_binding,
                   transition=None, original_root=None, candidate_root=None):
    """Retain one outcome; success is bookkeeping, not transport attestation.

    Only the claimant process can record success. Another process may retain
    failure/refusal/crash evidence but cannot recover or reopen the claim.
    """
    _require(type(claim) is rv.FrozenValue, "original_receipt_required")
    data = _outcome(outcome_receipt, claim)
    plain = claim.to_plain()
    if data["outcome"] == "SUCCEEDED":
        _require(plain["claim"]["pid"] == os.getpid()
                 and plain["claim"]["process_token"] == _PROCESS_TOKEN, "claimant_process_required")
    if data["outcome"] == "SUCCEEDED" and plain["phase"] == "candidate":
        candidate_identity.validate_cachebuster_identity_transition(original_root, candidate_root, transition)
        transition_data = transition.to_plain()
    else:
        _require(transition is None and original_root is None and candidate_root is None, "unexpected_transition")
        transition_data = None
    with _locked(root, claim, expected_binding) as (directory, anchor, latest):
        event = {"previous_sha256": latest.digest(), "operation": "outcome", "phase": plain["phase"],
                 "claim": plain["claim"], "outcome_json": outcome_receipt.decode("utf-8"), "transition": transition_data}
        return _append(directory, anchor, latest, event)


def read_store(root, receipt, *, expected_binding):
    """Require the retained original receipt and exact current identity."""
    with _locked(root, receipt, expected_binding) as (_, _, latest):
        return latest
