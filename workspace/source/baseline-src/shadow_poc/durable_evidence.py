"""Dual-store evidence, signed run seals, and deterministic crash reconciliation."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from .evidence_store import AppendOnlyEvidenceStore
from .errors import EvidenceIntegrityError
from .strict_json import loads_strict_json


class DurableEvidenceService:
    def __init__(
        self,
        enforcement: AppendOnlyEvidenceStore,
        trajectory_path: Path,
        seal_path: Path,
        seal_key: bytes,
        independent_anchor=None,
        trust_domain_id: str = "LOCAL_POC",
    ) -> None:
        if len(seal_key) < 16:
            raise ValueError("seal key must be at least 16 bytes")
        self.enforcement = enforcement
        self.trajectory_path = trajectory_path
        self.seal_path = seal_path
        self._key = bytes(seal_key)
        self._independent_anchor = independent_anchor
        self._trust_domain_id = trust_domain_id
        trajectory_path.parent.mkdir(parents=True, exist_ok=True)
        trajectory_path.touch(mode=0o600, exist_ok=True)
        seal_path.parent.mkdir(parents=True, exist_ok=True)
        self._refresh_heads()

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        recorded = self.enforcement.append(event)
        self._append_trajectory(recorded)
        self._enforcement_count += 1
        self._trajectory_count += 1
        self._enforcement_head = self._trajectory_head = self._event_hash(recorded)
        self._run_id = recorded["trusted_metadata"]["run_id"]
        self._write_seal()
        return recorded

    def verify(self) -> None:
        self.enforcement.verify_chain()
        enforcement = self.enforcement.read_all()
        trajectory = self.read_trajectory()
        if [self._event_hash(e) for e in enforcement] != [self._event_hash(e) for e in trajectory]:
            raise EvidenceIntegrityError("trajectory and enforcement stores diverge")
        if not self.seal_path.exists():
            raise EvidenceIntegrityError("signed run seal is missing")
        seal = loads_strict_json(self.seal_path.read_bytes())
        signature = seal.pop("signature", None)
        expected = self._sign(seal)
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
            raise EvidenceIntegrityError("signed run seal mismatch")
        if seal != self._seal_payload(enforcement, trajectory):
            raise EvidenceIntegrityError("signed run seal is stale")
        if self._independent_anchor is not None:
            self._independent_anchor.verify_latest(seal)

    def recover(self) -> int:
        """Repair only a missing trajectory tail from authoritative enforcement events."""
        enforcement = self.enforcement.read_all()
        trajectory = self.read_trajectory()
        if len(trajectory) > len(enforcement):
            raise EvidenceIntegrityError("trajectory store is ahead of enforcement store")
        for index, event in enumerate(trajectory):
            if self._event_hash(event) != self._event_hash(enforcement[index]):
                raise EvidenceIntegrityError("trajectory divergence cannot be auto-repaired")
        missing = enforcement[len(trajectory):]
        for event in missing:
            self._append_trajectory(event)
        self._refresh_heads()
        self._write_seal()
        return len(missing)

    def read_trajectory(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for index, line in enumerate(self.trajectory_path.read_bytes().split(b"\n"), start=1):
            if not line:
                continue
            try:
                value = loads_strict_json(line)
            except ValueError as exc:
                raise EvidenceIntegrityError(f"invalid trajectory JSON at line {index}: {exc}") from exc
            if not isinstance(value, dict):
                raise EvidenceIntegrityError(f"trajectory line {index} is not an object")
            records.append(value)
        return records

    def _append_trajectory(self, event: dict[str, Any]) -> None:
        encoded = (json.dumps(event, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        descriptor = os.open(self.trajectory_path, os.O_WRONLY | os.O_APPEND)
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise EvidenceIntegrityError("partial trajectory append")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_seal(self) -> None:
        payload = {
            "trust_domain_id": self._trust_domain_id,
            "run_id": self._run_id,
            "enforcement_count": self._enforcement_count,
            "enforcement_head": self._enforcement_head,
            "trajectory_count": self._trajectory_count,
            "trajectory_head": self._trajectory_head,
        }
        seal = dict(payload, signature=self._sign(payload))
        temporary = self.seal_path.with_suffix(self.seal_path.suffix + ".tmp")
        encoded = (json.dumps(seal, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise EvidenceIntegrityError("partial signed-seal write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.seal_path)
        if self._independent_anchor is not None:
            self._independent_anchor.publish(payload)

    def _refresh_heads(self) -> None:
        enforcement = self.enforcement.read_all()
        trajectory = self.read_trajectory()
        self._enforcement_count = len(enforcement)
        self._trajectory_count = len(trajectory)
        self._enforcement_head = None if not enforcement else self._event_hash(enforcement[-1])
        self._trajectory_head = None if not trajectory else self._event_hash(trajectory[-1])
        self._run_id = None if not enforcement else enforcement[0]["trusted_metadata"]["run_id"]

    def _seal_payload(self, enforcement: list[dict[str, Any]], trajectory: list[dict[str, Any]]) -> dict[str, Any]:
        run_id = None if not enforcement else enforcement[0]["trusted_metadata"]["run_id"]
        return {
            "trust_domain_id": self._trust_domain_id,
            "run_id": run_id,
            "enforcement_count": len(enforcement),
            "enforcement_head": None if not enforcement else self._event_hash(enforcement[-1]),
            "trajectory_count": len(trajectory),
            "trajectory_head": None if not trajectory else self._event_hash(trajectory[-1]),
        }

    def _sign(self, payload: dict[str, Any]) -> str:
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        return "hmac-sha256:" + hmac.new(self._key, encoded, hashlib.sha256).hexdigest()

    @staticmethod
    def _event_hash(event: dict[str, Any]) -> str:
        return event["trusted_metadata"]["integrity"]["event_hash"]
