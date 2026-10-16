#!/usr/bin/env python3
"""Append-only runtime receipt chain with independent terminal observation."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
from typing import Any
import unicodedata

try:
    from orch_dork_hostile_input import PROFILE, HostileInputError, canonicalize_bounded_json, parse_bounded_json
except ImportError:  # pragma: no cover - isolated runtime loader.
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
    parse_bounded_json = _hostile.parse_bounded_json


SOURCE_SCHEMA = "orch-dork/native-receipt-source/v1"
RECEIPT_SCHEMA = "orch-dork/runtime-receipt/v1"
APPEND_SCHEMA = "orch-dork/runtime-receipt-append/v1"
CHAIN_SCHEMA = "orch-dork/runtime-receipt-chain/v1"

STAGES = ("EVIDENCE", "PLAN", "ADMISSION", "SPAWN", "CUSTODY", "QUALIFICATION")
RECEIPT_TYPES = {
    "EVIDENCE": "EvidenceReceipt",
    "PLAN": "PlanReceipt",
    "ADMISSION": "AdmissionReceipt",
    "SPAWN": "SpawnReceipt",
    "CUSTODY": "CustodyReceipt",
    "QUALIFICATION": "QualificationReceipt",
}
SEALED = "SEALED"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
REFUSE = "REFUSE"

_SOURCE_KEYS = frozenset({"schema", "stage", "event_id", "observed_at", "evidence_tier", "observer", "identity", "claims"})
_OBSERVER_KEYS = frozenset({"id", "kind", "independent"})
_IDENTITY_KEYS = frozenset({"ticket_id", "attempt_id", "producer_run", "subject_run", "project_generation", "snapshot_digest", "plan_digest", "admission_digest"})
_RECEIPT_KEYS = frozenset({"schema", "receipt_type", "stage", "stage_index", "ticket_id", "attempt_id", "producer_run", "subject_run", "project_generation", "snapshot_digest", "plan_digest", "admission_digest", "prior_receipt_digest", "source_locator", "source_sha256", "source_event_id", "observer_id", "observer_kind", "observed_at", "evidence_tier", "claims", "claims_digest", "receipt_digest"})
_WORKER_KEYS = frozenset({"id", "parent_id", "host", "model", "effort", "selector", "lifecycle", "fresh", "creation_receipt_sha256"})
_TERMINAL_KEYS = frozenset({"id", "terminal", "handoff_complete", "terminal_receipt_sha256"})
_CLAIM_KEYS = {
    "EVIDENCE": frozenset({"snapshot_receipt", "source_installed_match", "canonical_input_sha256"}),
    "PLAN": frozenset({"semantic_decision", "lane_graph_closed", "integration_owned", "release_order_closed"}),
    "ADMISSION": frozenset({"admission_decision"}),
    "SPAWN": frozenset({"root_id", "workers", "terminal_worker_ids", "plan_digest", "creation_complete"}),
    "CUSTODY": frozenset({"status", "worker_ids", "fresh_inventory", "integrator_release_complete", "protected_resource_violation", "lease_match", "generation_match", "capability_expires_at"}),
    "QUALIFICATION": frozenset({"participant_ids", "evaluator_id", "terminal_records", "selectors_verified", "hashes_verified", "graph_match", "plan_match", "route_match", "lifecycle_match", "release_match", "submitted_conformance_verified", "timing", "usage", "cleanup"}),
}


def canonical_bytes(value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return canonicalize_bounded_json(raw, profile=PROFILE, batch=isinstance(value, list))


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value.encode("utf-8")) <= PROFILE.max_string_bytes


def _valid_selector(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > PROFILE.max_path_bytes:
        return False
    if value != unicodedata.normalize("NFC", value) or value.startswith(("/", "~/")) or "\\" in value:
        return False
    relative_text = value.split(":", 1)[1] if ":" in value else value
    relative = PurePosixPath(relative_text)
    return not relative.is_absolute() and bool(relative.parts) and all(part not in {"", ".", ".."} for part in relative.parts)


def _closed(value: Any, keys: frozenset[str], label: str, reasons: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        reasons.append(f"{label}:type_invalid")
        return {}
    reasons.extend(f"{label}:unknown_field:{field}" for field in sorted(set(value) - keys))
    return value


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        return None


class MemoryReceiptStore:
    """Create-only receipt adapter keyed by the module-produced receipt seal."""

    def __init__(self) -> None:
        self._receipts: dict[str, bytes] = {}

    def put(self, receipt: Mapping[str, Any]) -> str:
        digest = receipt.get("receipt_digest")
        if not _is_sha(digest):
            raise ValueError("receipt_digest_invalid")
        data = canonical_bytes(receipt)
        existing = self._receipts.get(str(digest))
        if existing is not None and existing != data:
            raise ValueError("receipt_digest_collision")
        self._receipts.setdefault(str(digest), data)
        return str(digest)

    def get(self, digest: str) -> dict[str, Any] | None:
        raw = self._receipts.get(digest)
        if raw is None:
            return None
        try:
            value = parse_bounded_json(raw, profile=PROFILE)
        except HostileInputError:
            return None
        if not isinstance(value, Mapping):
            return None
        expected = json_sha256({key: deepcopy(item) for key, item in value.items() if key != "receipt_digest"})
        return dict(value) if value.get("receipt_digest") == digest == expected else None

    def __len__(self) -> int:
        return len(self._receipts)


class DirectoryReceiptStore:
    """Create-only local receipt adapter; files are immutable and body-bounded."""

    def __init__(self, root: str | os.PathLike[str] | Path) -> None:
        raw_root = Path(root)
        if raw_root.is_symlink():
            raise ValueError("receipt_store_symlink")
        self.root = raw_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if not _is_sha(digest):
            raise ValueError("receipt_digest_invalid")
        return self.root / digest[:2] / (digest[2:] + ".json")

    def put(self, receipt: Mapping[str, Any]) -> str:
        digest = receipt.get("receipt_digest")
        if not _is_sha(digest):
            raise ValueError("receipt_digest_invalid")
        data = canonical_bytes(receipt)
        target = self._path(str(digest))
        if target.exists():
            if target.read_bytes() != data:
                raise ValueError("receipt_digest_collision")
            return str(digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".receipt-", dir=str(target.parent))
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o444)
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.read_bytes() != data:
                    raise ValueError("receipt_digest_collision")
            target.chmod(0o444)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return str(digest)

    def get(self, digest: str) -> dict[str, Any] | None:
        try:
            target = self._path(digest)
            info = target.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o222:
                return None
            raw = target.read_bytes()
            value = parse_bounded_json(raw, profile=PROFILE)
        except (OSError, ValueError, HostileInputError):
            return None
        if not isinstance(value, Mapping):
            return None
        expected = json_sha256({key: deepcopy(item) for key, item in value.items() if key != "receipt_digest"})
        return dict(value) if value.get("receipt_digest") == digest == expected else None


class MemoryNativeObserver:
    """Test adapter that returns exact canonical source bytes by selector."""

    def __init__(self, values: Mapping[str, bytes | bytearray | memoryview | str]) -> None:
        self.values = {str(key): value.encode("utf-8") if isinstance(value, str) else bytes(value) for key, value in values.items()}

    def read(self, selector: str) -> tuple[str, bytes | None]:
        value = self.values.get(selector)
        return ("UNAVAILABLE", None) if value is None else ("PASS", bytes(value))


class LocalNativeObserver:
    """Read native records beneath named roots without following links."""

    def __init__(self, roots: Mapping[str, str | os.PathLike[str] | Path]) -> None:
        self.roots = {str(name): Path(root).resolve() for name, root in roots.items()}

    def read(self, selector: str) -> tuple[str, bytes | None]:
        if not isinstance(selector, str) or ":" not in selector or len(selector.encode("utf-8")) > PROFILE.max_path_bytes:
            return "UNAVAILABLE", None
        root_name, relative_text = selector.split(":", 1)
        root = self.roots.get(root_name)
        relative = PurePosixPath(relative_text)
        if root is None or relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            return "UNAVAILABLE", None
        current = root
        try:
            for part in relative.parts:
                if part not in {entry.name for entry in current.iterdir()}:
                    return "UNAVAILABLE", None
                current = current / part
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode):
                    return "REFUSE", None
            resolved = current.resolve(strict=True)
            if os.path.commonpath((str(root), str(resolved))) != str(root):
                return "REFUSE", None
            info = resolved.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > PROFILE.canonical_json_bytes:
                return "REFUSE", None
            return "PASS", resolved.read_bytes()
        except (OSError, ValueError):
            return "UNAVAILABLE", None


class RuntimeReceiptChain:
    """Deep receipt module; ``append`` is its only mutation interface."""

    def __init__(
        self,
        store: MemoryReceiptStore | DirectoryReceiptStore,
        observer: MemoryNativeObserver | LocalNativeObserver,
        *,
        now: datetime | None = None,
    ) -> None:
        self.store = store
        self.observer = observer
        self.now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        self._attempt_heads: dict[str, str] = {}

    def append(self, prior_receipt: str | None, stage: Any, native_source: Any) -> dict[str, Any]:
        refuse: list[str] = []
        review: list[str] = []
        if stage not in STAGES:
            refuse.append("stage:invalid")
        if not _valid_selector(native_source):
            refuse.append("source:selector_invalid")
        chain = self._traverse(prior_receipt, refuse)
        expected_index = len(chain)
        expected_stage = STAGES[expected_index] if expected_index < len(STAGES) else None
        if stage != expected_stage:
            refuse.append("stage:out_of_order_or_duplicate")
        source: Mapping[str, Any] = {}
        source_raw: bytes | None = None
        if not refuse:
            source_status, source_raw = self.observer.read(str(native_source))
            if source_status == "UNAVAILABLE":
                review.append("source:unavailable")
            elif source_status != "PASS":
                refuse.append("source:unsafe")
            elif source_raw is None:
                refuse.append("source:missing_after_pass")
            else:
                try:
                    parsed = parse_bounded_json(source_raw, profile=PROFILE)
                    if canonical_bytes(parsed) != source_raw:
                        refuse.append("source:not_canonical")
                    source = _closed(parsed, _SOURCE_KEYS, "source", refuse)
                except HostileInputError:
                    refuse.append("source:malformed")
        if source:
            self._validate_source_common(source, str(stage), chain, refuse, review)
            self._validate_stage(str(stage), source, chain, refuse, review)
        if refuse or review:
            return self._result(
                REFUSE if refuse else REVIEW_REQUIRED,
                str(stage) if isinstance(stage, str) else None,
                prior_receipt,
                None,
                chain,
                refuse + review,
            )
        identity = source["identity"]
        observer = source["observer"]
        evidence_tier = "sealed-runtime" if stage == "QUALIFICATION" else "runtime-observed"
        receipt_core = {
            "schema": RECEIPT_SCHEMA,
            "receipt_type": RECEIPT_TYPES[str(stage)],
            "stage": stage,
            "stage_index": expected_index,
            "ticket_id": identity["ticket_id"],
            "attempt_id": identity["attempt_id"],
            "producer_run": identity["producer_run"],
            "subject_run": identity["subject_run"],
            "project_generation": identity["project_generation"],
            "snapshot_digest": identity["snapshot_digest"],
            "plan_digest": identity["plan_digest"],
            "admission_digest": identity["admission_digest"],
            "prior_receipt_digest": prior_receipt,
            "source_locator": native_source,
            "source_sha256": bytes_sha256(source_raw or b""),
            "source_event_id": source["event_id"],
            "observer_id": observer["id"],
            "observer_kind": observer["kind"],
            "observed_at": source["observed_at"],
            "evidence_tier": evidence_tier,
            "claims": deepcopy(source["claims"]),
            "claims_digest": json_sha256(source["claims"]),
        }
        receipt_core["receipt_digest"] = json_sha256(receipt_core)
        receipt = dict(receipt_core)
        receipt_digest = self.store.put(receipt)
        attempt_id = str(identity["attempt_id"])
        self._attempt_heads[attempt_id] = receipt_digest
        sealed_chain = chain + [receipt]
        return self._result(SEALED, str(stage), prior_receipt, receipt, sealed_chain, [])

    def _traverse(self, head: str | None, refuse: list[str]) -> list[dict[str, Any]]:
        if head is None:
            return []
        if not _is_sha(head):
            refuse.append("prior:identity_invalid")
            return []
        reversed_chain: list[dict[str, Any]] = []
        seen: set[str] = set()
        current: str | None = head
        while current is not None:
            if current in seen or len(reversed_chain) >= len(STAGES):
                refuse.append("prior:cycle_or_overlong")
                return []
            seen.add(current)
            receipt = self.store.get(current)
            if receipt is None:
                refuse.append("prior:missing_or_corrupt")
                return []
            local: list[str] = []
            _closed(receipt, _RECEIPT_KEYS, "prior_receipt", local)
            expected_stage_index = len(STAGES) - 1 - len(reversed_chain)
            if receipt.get("stage") not in STAGES or receipt.get("stage_index") != STAGES.index(str(receipt.get("stage"))):
                local.append("prior:stage_invalid")
            if local:
                refuse.extend(local)
                return []
            reversed_chain.append(receipt)
            current = receipt.get("prior_receipt_digest")
        chain = list(reversed(reversed_chain))
        if [receipt.get("stage") for receipt in chain] != list(STAGES[: len(chain)]):
            refuse.append("prior:stage_order_invalid")
            return []
        for index, receipt in enumerate(chain):
            expected_prior = None if index == 0 else chain[index - 1]["receipt_digest"]
            if receipt.get("prior_receipt_digest") != expected_prior:
                refuse.append("prior:chain_binding_invalid")
        return chain

    def _validate_source_common(
        self,
        source: Mapping[str, Any],
        stage: str,
        chain: list[Mapping[str, Any]],
        refuse: list[str],
        review: list[str],
    ) -> None:
        if source.get("schema") != SOURCE_SCHEMA or source.get("stage") != stage or not _text(source.get("event_id")):
            refuse.append("source:identity_invalid")
        observed_at = _time(source.get("observed_at"))
        if observed_at is None or observed_at > self.now:
            refuse.append("source:timestamp_invalid")
        if source.get("evidence_tier") != "runtime-observed":
            refuse.append("source:evidence_tier_invalid")
        observer = _closed(source.get("observer"), _OBSERVER_KEYS, "source.observer", refuse)
        if not _text(observer.get("id")) or observer.get("kind") not in {"native_reader", "independent_post_terminal"} or not isinstance(observer.get("independent"), bool):
            refuse.append("source:observer_invalid")
        identity = _closed(source.get("identity"), _IDENTITY_KEYS, "source.identity", refuse)
        if not all(_text(identity.get(field)) for field in ("ticket_id", "attempt_id", "producer_run", "subject_run", "project_generation")):
            refuse.append("source:attempt_identity_invalid")
        if not all(_is_sha(identity.get(field)) for field in ("snapshot_digest", "plan_digest", "admission_digest")):
            refuse.append("source:digest_identity_invalid")
        if not isinstance(source.get("claims"), Mapping):
            refuse.append("source:claims_invalid")
        if chain:
            first = chain[0]
            for field in ("ticket_id", "attempt_id", "producer_run", "subject_run", "project_generation", "snapshot_digest", "plan_digest", "admission_digest"):
                if identity.get(field) != first.get(field):
                    refuse.append(f"source:chain_identity_mismatch:{field}")
        else:
            attempt_id = str(identity.get("attempt_id"))
            if attempt_id in self._attempt_heads:
                refuse.append("source:attempt_chain_already_exists")
        event_id = str(source.get("event_id"))
        for receipt in chain:
            if receipt.get("source_event_id") == event_id:
                if receipt.get("source_sha256") != bytes_sha256(canonical_bytes(source)):
                    refuse.append("source:conflicting_duplicate")
                else:
                    refuse.append("source:duplicate_event")

    def _validate_stage(
        self,
        stage: str,
        source: Mapping[str, Any],
        chain: list[Mapping[str, Any]],
        refuse: list[str],
        review: list[str],
    ) -> None:
        claims = source.get("claims") if isinstance(source.get("claims"), Mapping) else {}
        identity = source.get("identity") if isinstance(source.get("identity"), Mapping) else {}
        claims = _closed(claims, _CLAIM_KEYS[stage], f"claims.{stage.lower()}", refuse)
        if stage == "EVIDENCE":
            receipt = claims.get("snapshot_receipt")
            if not self._sealed_mapping(receipt, "receipt_digest") or receipt.get("schema") != "orch-dork/evidence-snapshot-receipt/v1" or receipt.get("status") != "FRESH" or receipt.get("snapshot_digest") != identity.get("snapshot_digest") or receipt.get("mutation_permitted") is not False or receipt.get("authority_granted") is not False:
                refuse.append("evidence:snapshot_receipt_invalid")
            if claims.get("source_installed_match") is not True or not _is_sha(claims.get("canonical_input_sha256")):
                refuse.append("evidence:source_or_input_invalid")
        elif stage == "PLAN":
            decision = claims.get("semantic_decision")
            if not self._sealed_mapping(decision, "decision_digest") or decision.get("schema") != "orch-dork/semantic-plan-decision/v2" or decision.get("disposition") != "ADMIT" or decision.get("admitted") is not True or decision.get("decision_digest") != identity.get("plan_digest") or decision.get("snapshot_digest") != identity.get("snapshot_digest"):
                refuse.append("plan:semantic_decision_invalid")
            if claims.get("lane_graph_closed") is not True or claims.get("integration_owned") is not True or claims.get("release_order_closed") is not True:
                refuse.append("plan:closure_invalid")
        elif stage == "ADMISSION":
            decision = claims.get("admission_decision")
            if not self._sealed_mapping(decision, "admission_digest") or decision.get("schema") != "orch-dork/admission-decision/v1" or decision.get("decision") != "ADMIT" or decision.get("admitted") is not True or decision.get("admission_digest") != identity.get("admission_digest") or decision.get("plan_sha256") != identity.get("plan_digest"):
                refuse.append("admission:kernel_decision_invalid")
            if not isinstance(decision.get("component_seals"), Mapping) or set(decision.get("component_seals", {})) != {"inventory", "native_receipt", "spawn", "custody", "graph", "capability"}:
                refuse.append("admission:component_seals_invalid")
        elif stage == "SPAWN":
            root_id = claims.get("root_id")
            workers = claims.get("workers")
            if not _text(root_id) or not isinstance(workers, list) or len(workers) > PROFILE.max_queue:
                refuse.append("spawn:membership_invalid")
                return
            worker_ids: set[str] = set()
            terminal_prior = set(claims.get("terminal_worker_ids", [])) if isinstance(claims.get("terminal_worker_ids"), list) else set()
            for index, raw in enumerate(workers):
                row = _closed(raw, _WORKER_KEYS, f"spawn.workers[{index}]", refuse)
                worker_id = row.get("id")
                if not _text(worker_id) or worker_id in worker_ids or worker_id == root_id or row.get("parent_id") != root_id or not all(_text(row.get(field)) for field in ("host", "model", "effort", "selector", "lifecycle")) or row.get("fresh") is not True or not _is_sha(row.get("creation_receipt_sha256")):
                    refuse.append(f"spawn:worker_invalid:{index}")
                    continue
                if worker_id in terminal_prior:
                    refuse.append(f"spawn:terminal_worker_reuse:{worker_id}")
                worker_ids.add(str(worker_id))
            if claims.get("plan_digest") != identity.get("plan_digest") or claims.get("creation_complete") is not True:
                refuse.append("spawn:plan_or_creation_invalid")
        elif stage == "CUSTODY":
            spawn_claims = chain[3].get("claims", {}) if len(chain) >= 4 else {}
            expected_workers = sorted(row.get("id") for row in spawn_claims.get("workers", []) if isinstance(row, Mapping))
            if claims.get("status") != "PASS" or sorted(claims.get("worker_ids", [])) != expected_workers:
                refuse.append("custody:membership_invalid")
            if claims.get("fresh_inventory") is not True or claims.get("integrator_release_complete") is not True or claims.get("protected_resource_violation") is not False or claims.get("lease_match") is not True or claims.get("generation_match") is not True:
                refuse.append("custody:freshness_or_resource_invalid")
            capability_expires = _time(claims.get("capability_expires_at"))
            observed_at = _time(source.get("observed_at"))
            if capability_expires is None or observed_at is None or capability_expires <= observed_at or capability_expires < self.now:
                review.append("custody:capability_expired_or_unknown")
        elif stage == "QUALIFICATION":
            observer = source.get("observer") if isinstance(source.get("observer"), Mapping) else {}
            participant_ids = set(claims.get("participant_ids", [])) if isinstance(claims.get("participant_ids"), list) else set()
            evaluator_id = claims.get("evaluator_id")
            if observer.get("kind") != "independent_post_terminal" or observer.get("independent") is not True or observer.get("id") in participant_ids or observer.get("id") == evaluator_id or evaluator_id in participant_ids or not _text(evaluator_id):
                refuse.append("qualification:observer_not_independent")
            terminals = claims.get("terminal_records")
            if not isinstance(terminals, list) or {row.get("id") for row in terminals if isinstance(row, Mapping)} != participant_ids:
                refuse.append("qualification:terminal_membership_invalid")
            else:
                for index, raw in enumerate(terminals):
                    row = _closed(raw, _TERMINAL_KEYS, f"qualification.terminals[{index}]", refuse)
                    if row.get("terminal") is not True or row.get("handoff_complete") is not True or not _is_sha(row.get("terminal_receipt_sha256")):
                        refuse.append(f"qualification:terminal_invalid:{index}")
            for field in ("selectors_verified", "hashes_verified", "graph_match", "plan_match", "route_match", "lifecycle_match", "release_match", "submitted_conformance_verified"):
                if claims.get(field) is not True:
                    refuse.append(f"qualification:{field}_invalid")
            for field in ("timing", "usage"):
                row = claims.get(field)
                if not isinstance(row, Mapping) or row.get("status") != "PASS" or not _is_sha(row.get("digest")):
                    review.append(f"qualification:{field}_unknown")
            cleanup = claims.get("cleanup")
            if not isinstance(cleanup, Mapping) or cleanup.get("status") != "PASS" or cleanup.get("owned_resources_only") is not True or not _is_sha(cleanup.get("digest")):
                review.append("qualification:cleanup_unknown")

    @staticmethod
    def _sealed_mapping(value: Any, digest_field: str) -> bool:
        if not isinstance(value, Mapping) or not _is_sha(value.get(digest_field)):
            return False
        return value.get(digest_field) == json_sha256({key: deepcopy(item) for key, item in value.items() if key != digest_field})

    def _result(
        self,
        status: str,
        stage: str | None,
        prior: str | None,
        receipt: Mapping[str, Any] | None,
        chain: list[Mapping[str, Any]],
        reasons: list[str],
    ) -> dict[str, Any]:
        digests = [str(item.get("receipt_digest")) for item in chain if _is_sha(item.get("receipt_digest"))]
        chain_digest = json_sha256({"schema": CHAIN_SCHEMA, "receipt_digests": digests, "head": digests[-1] if digests else None})
        core = {
            "schema": APPEND_SCHEMA,
            "status": status,
            "sealed": status == SEALED,
            "stage": stage,
            "receipt": deepcopy(dict(receipt)) if isinstance(receipt, Mapping) else None,
            "receipt_digest": receipt.get("receipt_digest") if isinstance(receipt, Mapping) else None,
            "prior_receipt_digest": prior,
            "prior_preserved": status != SEALED,
            "chain_length": len(chain),
            "chain_digest": chain_digest,
            "evidence_tier": "sealed-runtime" if status == SEALED and stage == "QUALIFICATION" else "runtime-observed" if status == SEALED else "provider-free-deterministic",
            "qualified": status == SEALED and stage == "QUALIFICATION",
            "implementation_acceptance_implies_qualification": False,
            "reasons": sorted(set(reasons)),
            "retry_permitted": False,
            "fallback_permitted": False,
            "replacement_permitted": False,
            "authority_granted": False,
            "mutation_permitted": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        core["result_digest"] = json_sha256(core)
        return core


def chain_receipt(store: MemoryReceiptStore | DirectoryReceiptStore, head: Any) -> dict[str, Any]:
    """Return a body-free summary after verifying the complete chain."""

    chain = RuntimeReceiptChain(store, MemoryNativeObserver({}))
    issues: list[str] = []
    receipts = chain._traverse(head if isinstance(head, str) else None, issues)
    stages = [row.get("stage") for row in receipts]
    complete = not issues and stages == list(STAGES)
    core = {
        "schema": CHAIN_SCHEMA,
        "status": "SEALED_RUNTIME" if complete else "INCOMPLETE_OR_INVALID",
        "head_receipt_digest": head if _is_sha(head) else None,
        "receipt_digests": [row["receipt_digest"] for row in receipts],
        "stages": stages,
        "stage_receipts": [
            {
                "receipt_type": row.get("receipt_type"),
                "stage": row.get("stage"),
                "source_locator": row.get("source_locator"),
                "source_sha256": row.get("source_sha256"),
                "observer_id": row.get("observer_id"),
                "observed_at": row.get("observed_at"),
                "evidence_tier": row.get("evidence_tier"),
                "claims_digest": row.get("claims_digest"),
            }
            for row in receipts
        ],
        "ticket_id": receipts[0].get("ticket_id") if receipts else None,
        "attempt_id": receipts[0].get("attempt_id") if receipts else None,
        "observer_id": receipts[-1].get("observer_id") if complete else None,
        "terminal_evidence_tier": receipts[-1].get("evidence_tier") if complete else None,
        "unresolved": sorted(set(issues)),
        "implementation_acceptance_separate": True,
        "authority_granted": False,
        "mutation_permitted": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    core["chain_digest"] = json_sha256({"receipt_digests": core["receipt_digests"], "head": core["head_receipt_digest"]})
    core["receipt_digest"] = json_sha256(core)
    return core


__all__ = [
    "SOURCE_SCHEMA",
    "RECEIPT_SCHEMA",
    "APPEND_SCHEMA",
    "CHAIN_SCHEMA",
    "STAGES",
    "RECEIPT_TYPES",
    "SEALED",
    "REVIEW_REQUIRED",
    "REFUSE",
    "MemoryReceiptStore",
    "DirectoryReceiptStore",
    "MemoryNativeObserver",
    "LocalNativeObserver",
    "RuntimeReceiptChain",
    "chain_receipt",
    "canonical_bytes",
    "json_sha256",
]
