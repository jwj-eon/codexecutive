#!/usr/bin/env python3
"""Append-only, host-local custody-exception ledger.

The read-custody evaluator normalizes one exception at a time.  This module
provides the deliberately separate persistence seam: canonical JSONL records,
one host identity, contiguous sequence numbers, and a SHA-256 hash chain.
Malformed or tampered history is rejected before an append can mutate it.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

import orch_dork_read_custody as read_custody


RECORD_SCHEMA = "orch-dork/custody-exception-ledger-record/v1"
SUMMARY_SCHEMA = "orch-dork/custody-exception-ledger-summary/v1"
GENESIS_SHA256 = "0" * 64
MAX_RECORD_BYTES = 262_144
MAX_LEDGER_BYTES = 64 * 1024 * 1024

RECORD_FIELDS = (
    "schema",
    "host",
    "seq",
    "prev_sha256",
    "exception",
    "record_sha256",
)
SUMMARY_FIELDS = (
    "schema",
    "host",
    "record_count",
    "disposition_counts",
    "head_sha256",
    "status",
    "issues",
    "summary_sha256",
)

_RAW_EXCEPTION_FIELDS = {
    "schema", "run_id", "lane_id", "paths", "recorded_at",
    "disposition", "evidence",
}
_NORMALIZED_EXCEPTION_FIELDS = _RAW_EXCEPTION_FIELDS | {
    "qualification_blocking", "exception_sha256",
}
_DISPOSITIONS = ("recorded", "cured", "superseded")


class CustodyExceptionLedgerError(ValueError):
    """The ledger or proposed exception is malformed; no append is safe."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _host(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\n" in value
        or "\r" in value
        or len(value.encode("utf-8")) > 255
    ):
        raise CustodyExceptionLedgerError(
            "host must be a non-empty single-line string of at most 255 bytes"
        )
    return value


def _digest(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise CustodyExceptionLedgerError(
            field + " must be a 64-character lowercase SHA-256 digest"
        )
    return value


def _normalize_exception(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CustodyExceptionLedgerError("exception must be a mapping")
    unknown = set(value) - _NORMALIZED_EXCEPTION_FIELDS
    missing = _RAW_EXCEPTION_FIELDS - set(value)
    if unknown:
        raise CustodyExceptionLedgerError(
            "exception has unknown fields: " + repr(sorted(unknown)))
    if missing:
        raise CustodyExceptionLedgerError(
            "exception is missing fields: " + repr(sorted(missing)))
    raw = {field: value[field] for field in _RAW_EXCEPTION_FIELDS}
    try:
        normalized = read_custody.validate_custody_exception(raw)
    except (TypeError, ValueError) as exc:
        raise CustodyExceptionLedgerError(
            "custody exception invalid: " + str(exc)) from exc
    for computed in ("qualification_blocking", "exception_sha256"):
        if computed in value and value[computed] != normalized[computed]:
            raise CustodyExceptionLedgerError(
                "exception computed field mismatch: " + computed)
    return normalized


def _parse_records(data: bytes, expected_host: str | None) -> list[dict[str, Any]]:
    if not data:
        return []
    if len(data) > MAX_LEDGER_BYTES:
        raise CustodyExceptionLedgerError("ledger exceeds maximum size")
    if not data.endswith(b"\n"):
        raise CustodyExceptionLedgerError(
            "ledger is missing its final newline (partial truncation)")
    expected = _host(expected_host) if expected_host is not None else None
    records: list[dict[str, Any]] = []
    previous = GENESIS_SHA256
    ledger_host = expected
    for index, raw in enumerate(data.splitlines(), start=1):
        if not raw:
            raise CustodyExceptionLedgerError(
                "blank ledger line at sequence " + str(index))
        if len(raw) > MAX_RECORD_BYTES:
            raise CustodyExceptionLedgerError(
                "ledger record exceeds maximum size at sequence " + str(index))
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CustodyExceptionLedgerError(
                "invalid JSON at sequence " + str(index)) from exc
        if not isinstance(value, Mapping) or set(value) != set(RECORD_FIELDS):
            raise CustodyExceptionLedgerError(
                "ledger record fields invalid at sequence " + str(index))
        if raw != _canonical_bytes(value):
            raise CustodyExceptionLedgerError(
                "ledger record is not canonical at sequence " + str(index))
        if value.get("schema") != RECORD_SCHEMA:
            raise CustodyExceptionLedgerError(
                "ledger record schema invalid at sequence " + str(index))
        host = _host(value.get("host"))
        if ledger_host is None:
            ledger_host = host
        if host != ledger_host:
            raise CustodyExceptionLedgerError(
                "ledger host mismatch at sequence " + str(index))
        seq = value.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq != index:
            raise CustodyExceptionLedgerError(
                "ledger sequence is not contiguous at record " + str(index))
        if _digest(value.get("prev_sha256"), "prev_sha256") != previous:
            raise CustodyExceptionLedgerError(
                "ledger chain mismatch at sequence " + str(index))
        normalized_exception = _normalize_exception(value.get("exception"))
        if normalized_exception != value.get("exception"):
            raise CustodyExceptionLedgerError(
                "exception is not canonical at sequence " + str(index))
        supplied = _digest(value.get("record_sha256"), "record_sha256")
        material = {
            field: value[field]
            for field in RECORD_FIELDS
            if field != "record_sha256"
        }
        if supplied != _sha256(material):
            raise CustodyExceptionLedgerError(
                "ledger record digest mismatch at sequence " + str(index))
        record = dict(value)
        records.append(record)
        previous = supplied
    return records


def load_records(
    path: str | os.PathLike[str], expected_host: str | None = None
) -> list[dict[str, Any]]:
    """Load and validate the complete canonical chain from ``path``."""

    target = Path(path)
    if target.is_symlink():
        raise CustodyExceptionLedgerError("ledger path may not be a symlink")
    try:
        data = target.read_bytes()
    except FileNotFoundError:
        data = b""
    except OSError as exc:
        raise CustodyExceptionLedgerError("ledger is unreadable: " + str(exc)) from exc
    return _parse_records(data, expected_host)


def append_record(
    path: str | os.PathLike[str], exception: Mapping[str, Any], host: str
) -> dict[str, Any]:
    """Validate and append one canonical record under an exclusive host lock."""

    normalized = _normalize_exception(exception)
    host_value = _host(host)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(target.name + ".lock")
    if target.is_symlink() or lock_path.is_symlink():
        raise CustodyExceptionLedgerError("ledger and lock paths may not be symlinks")
    try:
        with lock_path.open("a+b") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            records = load_records(target, expected_host=host_value)
            previous = (
                records[-1]["record_sha256"] if records else GENESIS_SHA256
            )
            record = {
                "schema": RECORD_SCHEMA,
                "host": host_value,
                "seq": len(records) + 1,
                "prev_sha256": previous,
                "exception": normalized,
            }
            record["record_sha256"] = _sha256(record)
            encoded = _canonical_bytes(record) + b"\n"
            if len(encoded) > MAX_RECORD_BYTES:
                raise CustodyExceptionLedgerError(
                    "ledger record exceeds maximum size")
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                written = os.write(descriptor, encoded)
                if written != len(encoded):
                    raise CustodyExceptionLedgerError(
                        "ledger append was incomplete")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return record
    except CustodyExceptionLedgerError:
        raise
    except OSError as exc:
        raise CustodyExceptionLedgerError("ledger append failed: " + str(exc)) from exc


def summarize(
    path: str | os.PathLike[str], expected_host: str | None = None
) -> dict[str, Any]:
    """Return a compact digest-bound summary of one validated ledger."""

    records = load_records(path, expected_host=expected_host)
    host = records[0]["host"] if records else expected_host
    if host is not None:
        host = _host(host)
    counts = {disposition: 0 for disposition in _DISPOSITIONS}
    for record in records:
        counts[record["exception"]["disposition"]] += 1
    report = {
        "schema": SUMMARY_SCHEMA,
        "host": host,
        "record_count": len(records),
        "disposition_counts": counts,
        "head_sha256": (
            records[-1]["record_sha256"] if records else GENESIS_SHA256
        ),
        "status": "PASS",
        "issues": [],
    }
    report["summary_sha256"] = _sha256(report)
    return report


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Append to or summarize a custody-exception ledger")
    parser.add_argument("path")
    parser.add_argument("--host", required=True)
    parser.add_argument("--append", metavar="RECORD_JSON")
    args = parser.parse_args(argv)
    try:
        if args.append is None:
            result = summarize(args.path, expected_host=args.host)
        else:
            value = json.loads(args.append)
            result = append_record(args.path, value, args.host)
    except (CustodyExceptionLedgerError, json.JSONDecodeError) as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2
    sys.stdout.buffer.write(_canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "CustodyExceptionLedgerError",
    "GENESIS_SHA256",
    "RECORD_FIELDS",
    "RECORD_SCHEMA",
    "SUMMARY_FIELDS",
    "SUMMARY_SCHEMA",
    "append_record",
    "load_records",
    "summarize",
]
