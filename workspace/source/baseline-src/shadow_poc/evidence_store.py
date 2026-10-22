"""Append-only JSONL evidence with schema, invariant, and hash-chain enforcement."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import fcntl
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from .errors import EvidenceIntegrityError
from .strict_json import loads_strict_json
from .validation import validate_event_invariants, validate_schema


def _canonical_bytes(event: dict[str, Any]) -> bytes:
    candidate = deepcopy(event)
    candidate["trusted_metadata"]["integrity"]["event_hash"] = ""
    if _contains_float(candidate):
        raise EvidenceIntegrityError("floating-point values are not permitted in hash-canonical events")
    return json.dumps(candidate, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _contains_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_contains_float(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_float(item) for item in value)
    return False


def calculate_event_hash(event: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(event)).hexdigest()


class AppendOnlyEvidenceStore:
    def __init__(self, path: Path, event_schema_path: Path, expected_schema_sha256: str) -> None:
        self._path = path
        self._anchor_path = path.with_suffix(path.suffix + ".anchor.json")
        actual_schema_hash = hashlib.sha256(event_schema_path.read_bytes()).hexdigest()
        if actual_schema_hash != expected_schema_sha256:
            raise EvidenceIntegrityError("event schema hash does not match the baseline lock")
        self._schema = loads_strict_json(event_schema_path.read_bytes())
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch(mode=0o600)
        self.verify_chain()
        records = self.read_all()
        self._count = len(records)
        self._head_hash = None if not records else records[-1]["trusted_metadata"]["integrity"]["event_hash"]
        self._last_event_id = None if not records else records[-1]["trusted_metadata"]["event_id"]
        self._run_id = None if not records else records[0]["trusted_metadata"]["run_id"]
        self._size = self._path.stat().st_size

    @property
    def path(self) -> Path:
        return self._path

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            record = deepcopy(event)
            metadata = record["trusted_metadata"]
            integrity = metadata["integrity"]
            if self._run_id is not None and metadata["run_id"] != self._run_id:
                raise EvidenceIntegrityError("one evidence chain cannot contain multiple run_id values")
            metadata["previous_event_id"] = self._last_event_id
            integrity["previous_event_hash"] = self._head_hash
            integrity["event_hash"] = calculate_event_hash(record)
            self._assert_valid(record)
            encoded = (json.dumps(record, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            descriptor = os.open(self._path, os.O_RDWR | os.O_APPEND)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                if os.fstat(descriptor).st_size != self._size:
                    raise EvidenceIntegrityError("evidence file changed by another writer")
                written = 0
                while written < len(encoded):
                    count = os.write(descriptor, encoded[written:])
                    if count <= 0:
                        raise EvidenceIntegrityError("partial evidence append")
                    written += count
                os.fsync(descriptor)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            self._count += 1
            self._head_hash = integrity["event_hash"]
            self._last_event_id = metadata["event_id"]
            self._run_id = metadata["run_id"] if self._run_id is None else self._run_id
            self._size += len(encoded)
            self._write_anchor()
            self._capture_for_current_test(encoded)
            return record

    def _capture_for_current_test(self, encoded: bytes) -> None:
        """Mirror committed events into the run-owned per-test evidence area.

        This is deliberately test-mode only.  It preserves the exact bytes that
        were committed before a TemporaryDirectory is removed; it does not
        manufacture an acceptance event or alter the production store.
        """
        root = os.environ.get("SHADOW_POC_EVIDENCE_CAPTURE_DIR")
        test_name = os.environ.get("SHADOW_POC_CURRENT_TEST")
        if not root or not test_name or os.environ.get("SHADOW_POC_TESTING") != "1":
            return
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", test_name)
        store_id = hashlib.sha256(str(self._path).encode("utf-8")).hexdigest()[:16]
        destination = Path(root) / safe / f"events-{store_id}.jsonl"
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def read_all(self) -> list[dict[str, Any]]:
        records = []
        try:
            raw = self._path.read_bytes()
        except OSError as exc:
            raise EvidenceIntegrityError(f"cannot read evidence: {exc}") from exc
        lines = raw.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        for index, line in enumerate(lines, start=1):
            if line == b"":
                raise EvidenceIntegrityError(f"blank evidence record at line {index}")
            try:
                value = loads_strict_json(line)
            except ValueError as exc:
                raise EvidenceIntegrityError(f"invalid evidence JSON at line {index}: {exc}") from exc
            if not isinstance(value, dict):
                raise EvidenceIntegrityError(f"evidence line {index} is not an object")
            records.append(value)
        return records

    def verify_chain(self) -> None:
        previous = None
        for index, record in enumerate(self.read_all(), start=1):
            self._assert_valid(record)
            metadata = record["trusted_metadata"]
            integrity = metadata["integrity"]
            if integrity["event_hash"] != calculate_event_hash(record):
                raise EvidenceIntegrityError(f"event hash mismatch at line {index}")
            expected_id = None if previous is None else previous["trusted_metadata"]["event_id"]
            expected_hash = None if previous is None else previous["trusted_metadata"]["integrity"]["event_hash"]
            if metadata.get("previous_event_id") != expected_id or integrity.get("previous_event_hash") != expected_hash:
                raise EvidenceIntegrityError(f"chain linkage mismatch at line {index}")
            previous = record
        if self._anchor_path.exists():
            anchor = loads_strict_json(self._anchor_path.read_bytes())
            records = self.read_all()
            expected_count = len(records)
            expected_head = None if not records else records[-1]["trusted_metadata"]["integrity"]["event_hash"]
            expected_run = None if not records else records[0]["trusted_metadata"]["run_id"]
            if anchor != {"event_count": expected_count, "head_hash": expected_head, "run_id": expected_run}:
                raise EvidenceIntegrityError("external evidence anchor mismatch")

    def _write_anchor(self) -> None:
        anchor = {"event_count": self._count, "head_hash": self._head_hash, "run_id": self._run_id}
        temporary = self._anchor_path.with_suffix(self._anchor_path.suffix + ".tmp")
        encoded = (json.dumps(anchor, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            written = 0
            while written < len(encoded):
                count = os.write(descriptor, encoded[written:])
                if count <= 0:
                    raise EvidenceIntegrityError("partial anchor write")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self._anchor_path)

    def _assert_valid(self, record: dict[str, Any]) -> None:
        issues = validate_schema(record, self._schema) + validate_event_invariants(record)
        if issues:
            raise EvidenceIntegrityError("; ".join(map(str, issues)))
