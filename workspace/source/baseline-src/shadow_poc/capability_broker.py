"""Decision-bound, single-use execution tokens with explicit revocation states."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from time import monotonic_ns
from typing import Callable
from uuid import uuid4

from .contracts import ActionRequest
from .errors import ContractError

Clock = Callable[[], int]


@dataclass(frozen=True)
class ExecutionToken:
    token_id: str
    capability: str
    target: str
    parameters: tuple[tuple[str, object], ...]
    wrapper_id: str
    decision_epoch: int
    expires_at_ns: int


@dataclass
class _TokenRecord:
    token: ExecutionToken
    state: str = "ISSUED"
    effect_started: bool = False


class CapabilityBroker:
    def __init__(
        self,
        clock: Clock = monotonic_ns,
        ttl_ms: int = 2_000,
        max_terminal_records: int = 1_024,
        max_active_records: int = 1_024,
    ) -> None:
        if ttl_ms <= 0:
            raise ValueError("token TTL must be positive")
        self._clock = clock
        self._ttl_ns = ttl_ms * 1_000_000
        if max_terminal_records < 0:
            raise ValueError("max_terminal_records must be non-negative")
        if max_active_records <= 0:
            raise ValueError("max_active_records must be positive")
        self._max_terminal_records = max_terminal_records
        self._max_active_records = max_active_records
        self._records: dict[str, _TokenRecord] = {}
        self._revoked_epochs: set[int] = set()
        self._lock = RLock()

    def issue(self, action: ActionRequest, wrapper_id: str, decision_epoch: int) -> ExecutionToken:
        if not wrapper_id:
            raise ContractError("wrapper_id must be non-empty")
        token = ExecutionToken(
            token_id=f"tok-{uuid4()}", capability=action.capability, target=action.target,
            parameters=tuple(sorted(action.parameters.items())), wrapper_id=wrapper_id,
            decision_epoch=decision_epoch, expires_at_ns=self._clock() + self._ttl_ns,
        )
        with self._lock:
            if decision_epoch in self._revoked_epochs:
                raise ContractError("decision epoch has been revoked")
            active_count = sum(record.state in {"ISSUED", "ACTIVE"} for record in self._records.values())
            if active_count >= self._max_active_records:
                raise ContractError("active token capacity exhausted")
            self._records[token.token_id] = _TokenRecord(token)
            self._prune_excess_terminal_locked()
        return token

    def begin(self, token: ExecutionToken, action: ActionRequest, wrapper_id: str, decision_epoch: int) -> str:
        with self._lock:
            record = self._record(token)
            if record.state == "REVOKED":
                return "NOT_STARTED_REVOKED"
            if record.state != "ISSUED":
                raise ContractError("execution token is not available")
            if self._clock() > token.expires_at_ns:
                record.state = "REVOKED"
                return "NOT_STARTED_REVOKED"
            expected = (action.capability, action.target, tuple(sorted(action.parameters.items())), wrapper_id, decision_epoch)
            actual = (token.capability, token.target, token.parameters, token.wrapper_id, token.decision_epoch)
            if expected != actual:
                raise ContractError("execution token binding mismatch")
            record.state = "ACTIVE"
            return "ACTIVE"

    def authorize_effect(self, token: ExecutionToken) -> str:
        with self._lock:
            record = self._record(token)
            if record.state == "REVOKED":
                return "CANCELLED_PRE_EFFECT"
            if record.state != "ACTIVE":
                raise ContractError("execution token is not active")
            if self._clock() > token.expires_at_ns:
                record.state = "REVOKED"
                return "CANCELLED_PRE_EFFECT"
            record.effect_started = True
            return "ACTIVE"

    def complete(self, token: ExecutionToken) -> None:
        with self._lock:
            record = self._record(token)
            if record.state != "ACTIVE" or not record.effect_started:
                raise ContractError("cannot complete token before effect authorization")
            record.state = "USED"
            self._prune_excess_terminal_locked()

    def revoke(self, token_id: str) -> str:
        with self._lock:
            record = self._records.get(token_id)
            if record is None:
                raise ContractError("unknown execution token")
            result = self._revoke_locked(record)
            self._prune_excess_terminal_locked()
            return result

    def revoke_epoch(self, decision_epoch: int) -> list[tuple[str, str]]:
        """Atomically close an epoch and revoke every token already issued in it."""
        with self._lock:
            self._revoked_epochs.add(decision_epoch)
            results = []
            for token_id, record in tuple(self._records.items()):
                if record.token.decision_epoch == decision_epoch:
                    results.append((token_id, self._revoke_locked(record)))
            self._prune_excess_terminal_locked()
            return results

    def is_epoch_revoked(self, decision_epoch: int) -> bool:
        with self._lock:
            return decision_epoch in self._revoked_epochs

    def snapshot(self) -> dict[str, str]:
        """Return non-secret token identifiers and states for trusted diagnostics."""
        with self._lock:
            return {token_id: record.state for token_id, record in self._records.items()}

    def prune_terminal(self) -> int:
        """Remove used/revoked token records after their evidence has been retained."""
        with self._lock:
            terminal = [token_id for token_id, record in self._records.items() if record.state in {"USED", "REVOKED"}]
            for token_id in terminal:
                del self._records[token_id]
            return len(terminal)

    def _record(self, token: ExecutionToken) -> _TokenRecord:
        record = self._records.get(token.token_id)
        if record is None or record.token != token:
            raise ContractError("unknown or altered execution token")
        return record

    @staticmethod
    def _revoke_locked(record: _TokenRecord) -> str:
        if record.state == "ISSUED":
            record.state = "REVOKED"
            return "NOT_STARTED_REVOKED"
        if record.state == "ACTIVE" and not record.effect_started:
            record.state = "REVOKED"
            return "CANCELLED_PRE_EFFECT"
        if record.state == "USED":
            return "COMPLETED_BEFORE_REVOCATION"
        if record.effect_started:
            return "REVOCATION_TOO_LATE"
        return "NOT_STARTED_REVOKED"

    def _prune_excess_terminal_locked(self) -> None:
        terminal = [
            token_id for token_id, record in self._records.items()
            if record.state in {"USED", "REVOKED"}
        ]
        excess = len(terminal) - self._max_terminal_records
        for token_id in terminal[:max(0, excess)]:
            del self._records[token_id]
