#!/usr/bin/env python3
"""Create-only Artifact Ledger adapter with content and lineage verification."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import threading
from typing import Any, Mapping


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault(name, module)
        spec.loader.exec_module(module)
        return module


contracts = _load_sibling("orch_dork_adaptive_contracts")


RECORD_SCHEMA = "orch-dork/artifact-ledger-record/v1"
PROVENANCE_FIELDS = frozenset(
    {
        "producer_run_id",
        "producer_node_id",
        "task_spec_sha256",
        "content_schema",
        "privacy_class",
        "custody_receipt_sha256",
        "source_lineage",
        "consumer_node_ids",
        "retention_state",
    }
)
RETENTION_STATES = frozenset({"consumed_by_join", "terminal_result", "retained_evidence"})
PRIVACY_CLASSES = frozenset({"local_only", "hosted_restricted", "hosted_standard"})
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
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


def _body_and_ref(
    body: bytes | str,
    *,
    media_type: str,
) -> tuple[bytes, dict[str, Any]]:
    if isinstance(body, str):
        data = body.encode("utf-8")
    elif isinstance(body, bytes):
        data = body
    else:
        raise ValueError("artifact_body_invalid")
    if not data or len(data) > 1_048_576:
        raise ValueError("artifact_body_invalid")
    digest = hashlib.sha256(data).hexdigest()
    ref = contracts.seal_artifact_ref(
        {
            "schema": contracts.ARTIFACT_REF_SCHEMA,
            "uri": "artifact://sha256/" + digest,
            "sha256": digest,
            "size_bytes": len(data),
            "media_type": media_type,
        }
    )
    return data, ref


def project_artifact_ref(
    body: bytes | str,
    *,
    media_type: str,
) -> dict[str, Any]:
    """Derive the exact ref a create-only publish must return, without writing."""

    _, ref = _body_and_ref(body, media_type=media_type)
    return deepcopy(ref)


def _validate_provenance(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != PROVENANCE_FIELDS:
        raise ValueError("artifact_provenance_invalid")
    producer_run_id = value.get("producer_run_id")
    producer_node_id = value.get("producer_node_id")
    if (
        not isinstance(producer_run_id, str)
        or _IDENTIFIER.fullmatch(producer_run_id) is None
        or not isinstance(producer_node_id, str)
        or _IDENTIFIER.fullmatch(producer_node_id) is None
    ):
        raise ValueError("artifact_producer_invalid")
    for field in ("task_spec_sha256", "custody_receipt_sha256"):
        digest = value.get(field)
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ValueError("artifact_" + field + "_invalid")
    content_schema = value.get("content_schema")
    if (
        not isinstance(content_schema, str)
        or _IDENTIFIER.fullmatch(content_schema) is None
    ):
        raise ValueError("artifact_content_schema_invalid")
    privacy = value.get("privacy_class")
    if privacy not in PRIVACY_CLASSES:
        raise ValueError("artifact_privacy_invalid")
    lineage = value.get("source_lineage")
    if not isinstance(lineage, list) or len(lineage) > 256:
        raise ValueError("artifact_lineage_invalid")
    normalized_lineage = []
    for ref in lineage:
        report = contracts.validate_artifact_ref(ref)
        if report.get("status") != "PASS":
            raise ValueError("artifact_lineage_ref_invalid")
        normalized_lineage.append(report["normalized"])
    normalized_lineage.sort(key=lambda ref: (ref["uri"], ref["sha256"]))
    consumers = value.get("consumer_node_ids")
    if (
        not isinstance(consumers, list)
        or len(consumers) > 64
        or any(
            not isinstance(consumer, str)
            or _IDENTIFIER.fullmatch(consumer) is None
            for consumer in consumers
        )
        or len(consumers) != len(set(consumers))
    ):
        raise ValueError("artifact_consumers_invalid")
    retention = value.get("retention_state")
    if retention not in RETENTION_STATES:
        raise ValueError("artifact_retention_invalid")
    return {
        "producer_run_id": producer_run_id,
        "producer_node_id": producer_node_id,
        "task_spec_sha256": value["task_spec_sha256"],
        "content_schema": content_schema,
        "privacy_class": privacy,
        "custody_receipt_sha256": value["custody_receipt_sha256"],
        "source_lineage": normalized_lineage,
        "consumer_node_ids": sorted(consumers),
        "retention_state": retention,
    }


class InMemoryArtifactLedger:
    """In-memory byte-store adapter; records remain create-only by digest."""

    durable = False

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._blobs: dict[str, bytes] = {}
        self._records: dict[str, dict[str, Any]] = {}

    def publish(
        self,
        body: bytes | str,
        *,
        media_type: str,
        provenance: Mapping[str, Any],
    ) -> dict[str, Any]:
        data, ref = _body_and_ref(body, media_type=media_type)
        normalized_provenance = _validate_provenance(provenance)
        digest = hashlib.sha256(data).hexdigest()
        record_core = {
            "schema": RECORD_SCHEMA,
            "artifact_ref": ref,
            **normalized_provenance,
        }
        record = {**record_core, "record_sha256": _sha256(record_core)}
        with self._lock:
            existing = self._blobs.get(digest)
            existing_record = self._records.get(digest)
            if existing is not None:
                if existing != data:
                    raise ValueError("artifact_digest_collision")
                if existing_record != record:
                    raise ValueError("artifact_provenance_conflict")
                return deepcopy(ref)
            self._blobs[digest] = data
            self._records[digest] = record
            return deepcopy(ref)

    def read(self, ref: Any) -> bytes:
        report = contracts.validate_artifact_ref(ref)
        if report.get("status") != "PASS":
            raise ValueError("artifact_ref_invalid")
        canonical = report["normalized"]
        with self._lock:
            data = self._blobs.get(canonical["sha256"])
            record = self._records.get(canonical["sha256"])
            if data is None or record is None:
                raise KeyError("artifact_not_found")
            if (
                len(data) != canonical["size_bytes"]
                or hashlib.sha256(data).hexdigest() != canonical["sha256"]
                or record["artifact_ref"] != canonical
            ):
                raise ValueError("artifact_bytes_invalid")
            return bytes(data)

    def record(self, ref: Any) -> dict[str, Any]:
        with self._lock:
            self.read(ref)
            canonical = contracts.validate_artifact_ref(ref)["normalized"]
            return deepcopy(self._records[canonical["sha256"]])

    def records(self, refs: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        records = [self.record(ref) for ref in refs]
        return sorted(
            records,
            key=lambda record: (
                record["producer_run_id"],
                record["producer_node_id"],
                record["artifact_ref"]["sha256"],
            ),
        )


def _record_for(
    ref: Mapping[str, Any], provenance: Mapping[str, Any]
) -> dict[str, Any]:
    record_core = {
        "schema": RECORD_SCHEMA,
        "artifact_ref": deepcopy(dict(ref)),
        **deepcopy(dict(provenance)),
    }
    return {**record_core, "record_sha256": _sha256(record_core)}


def _validate_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("artifact_record_invalid")
    expected_fields = {"schema", "artifact_ref", *PROVENANCE_FIELDS, "record_sha256"}
    if set(value) != expected_fields or value.get("schema") != RECORD_SCHEMA:
        raise ValueError("artifact_record_invalid")
    core = dict(value)
    digest = core.pop("record_sha256", None)
    if digest != _sha256(core):
        raise ValueError("artifact_record_seal_invalid")
    ref_report = contracts.validate_artifact_ref(value.get("artifact_ref"))
    if ref_report.get("status") != "PASS":
        raise ValueError("artifact_record_ref_invalid")
    provenance = _validate_provenance(
        {field: value.get(field) for field in PROVENANCE_FIELDS}
    )
    return _record_for(ref_report["normalized"], provenance)


class FilesystemArtifactLedger:
    """Create-only single-host byte store with portable sealed records."""

    durable = True

    def __init__(self, root: os.PathLike[str] | str) -> None:
        provided_root = Path(root).expanduser()
        self._ensure_directory(provided_root)
        self._root = provided_root.resolve()
        self._blob_root = self._root / "blobs"
        self._record_root = self._root / "records"
        self._ensure_directory(self._blob_root)
        self._ensure_directory(self._record_root)
        self._lock = threading.RLock()

    @staticmethod
    def _ensure_directory(path: Path) -> None:
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            path.mkdir(parents=True, mode=0o700, exist_ok=True)
            mode = path.lstat().st_mode
        if not stat.S_ISDIR(mode):
            raise ValueError("artifact_directory_invalid")

    def _paths(self, digest: str) -> tuple[Path, Path]:
        if _SHA256.fullmatch(digest) is None:
            raise ValueError("artifact_digest_invalid")
        return self._blob_root / digest, self._record_root / (digest + ".json")

    @staticmethod
    def _read_regular(path: Path) -> bytes:
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError as exc:
            raise KeyError("artifact_not_found") from exc
        except OSError as exc:
            raise ValueError("artifact_path_unreadable") from exc
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("artifact_path_not_regular")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                return handle.read(1_048_577)
        finally:
            os.close(descriptor)

    @staticmethod
    def _create(path: Path, data: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".artifact-create-",
            dir=str(path.parent),
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path, follow_symlinks=False)
            directory_descriptor = os.open(
                path.parent,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def publish(
        self,
        body: bytes | str,
        *,
        media_type: str,
        provenance: Mapping[str, Any],
    ) -> dict[str, Any]:
        data, ref = _body_and_ref(body, media_type=media_type)
        normalized_provenance = _validate_provenance(provenance)
        record = _record_for(ref, normalized_provenance)
        record_bytes = _canonical(record)
        blob_path, record_path = self._paths(ref["sha256"])
        with self._lock:
            if blob_path.exists():
                if self._read_regular(blob_path) != data:
                    raise ValueError("artifact_digest_collision")
            else:
                try:
                    self._create(blob_path, data)
                except FileExistsError:
                    if self._read_regular(blob_path) != data:
                        raise ValueError("artifact_digest_collision")
            if record_path.exists():
                existing = _validate_record(
                    json.loads(self._read_regular(record_path).decode("utf-8"))
                )
                if existing != record:
                    raise ValueError("artifact_provenance_conflict")
            else:
                try:
                    self._create(record_path, record_bytes)
                except FileExistsError:
                    existing = _validate_record(
                        json.loads(self._read_regular(record_path).decode("utf-8"))
                    )
                    if existing != record:
                        raise ValueError("artifact_provenance_conflict")
        return deepcopy(ref)

    def read(self, ref: Any) -> bytes:
        report = contracts.validate_artifact_ref(ref)
        if report.get("status") != "PASS":
            raise ValueError("artifact_ref_invalid")
        canonical = report["normalized"]
        blob_path, record_path = self._paths(canonical["sha256"])
        with self._lock:
            data = self._read_regular(blob_path)
            record = _validate_record(
                json.loads(self._read_regular(record_path).decode("utf-8"))
            )
            if (
                len(data) != canonical["size_bytes"]
                or hashlib.sha256(data).hexdigest() != canonical["sha256"]
                or record["artifact_ref"] != canonical
            ):
                raise ValueError("artifact_bytes_invalid")
            return data

    def record(self, ref: Any) -> dict[str, Any]:
        report = contracts.validate_artifact_ref(ref)
        if report.get("status") != "PASS":
            raise ValueError("artifact_ref_invalid")
        canonical = report["normalized"]
        _, record_path = self._paths(canonical["sha256"])
        with self._lock:
            self.read(canonical)
            return deepcopy(
                _validate_record(
                    json.loads(self._read_regular(record_path).decode("utf-8"))
                )
            )

    def records(self, refs: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        records = [self.record(ref) for ref in refs]
        return sorted(
            records,
            key=lambda record: (
                record["producer_run_id"],
                record["producer_node_id"],
                record["artifact_ref"]["sha256"],
            ),
        )


__all__ = [
    "RECORD_SCHEMA",
    "InMemoryArtifactLedger",
    "FilesystemArtifactLedger",
    "project_artifact_ref",
]
