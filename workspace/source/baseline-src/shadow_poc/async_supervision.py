"""Asynchronous Shadow supervision, escalation latch, and revocation broadcast."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from threading import Lock
from typing import Callable
from time import monotonic_ns
import multiprocessing

from .capability_broker import CapabilityBroker
from .errors import ContractError
from .shadow_adapter import ShadowAdapter, ShadowEvaluationEnvelope, ShadowResult


class EscalationLatch:
    def __init__(self) -> None:
        self._latched = False
        self._reason: str | None = None
        self._lock = Lock()

    @property
    def latched(self) -> bool:
        with self._lock:
            return self._latched

    @property
    def reason(self) -> str | None:
        with self._lock:
            return self._reason

    def set(self, reason: str) -> None:
        with self._lock:
            self._latched = True
            self._reason = reason

    def clear(self, actor: str) -> None:
        if actor not in {"HARNESS", "OPERATOR"}:
            raise ContractError("escalation latch may be cleared only by harness or operator")
        with self._lock:
            self._latched = False
            self._reason = None


class RevocationBus:
    def __init__(self) -> None:
        self._subscribers: list[Callable[[int], object]] = []
        self._lock = Lock()
        self._sequence = 0

    def subscribe(self, callback: Callable[[int], object]) -> None:
        with self._lock:
            self._subscribers.append(callback)

    def publish(self, decision_epoch: int) -> list[RevocationDelivery]:
        with self._lock:
            self._sequence += 1
            subscribers = tuple(self._subscribers)
        deliveries = []
        for index, callback in enumerate(subscribers):
            try:
                deliveries.append(RevocationDelivery(index, True, callback(decision_epoch)))
            except Exception as exc:
                deliveries.append(RevocationDelivery(index, False, error_type=type(exc).__name__))
        return deliveries

    @property
    def sequence(self) -> int:
        with self._lock:
            return self._sequence


@dataclass(frozen=True)
class AsyncDecision:
    outcome: str
    effective_outcome: str
    termination_reason: str
    reason_codes: tuple[str, ...]
    revoked: bool
    structural_block: bool
    measured_elapsed_ms: int = 0


@dataclass(frozen=True)
class RevocationDelivery:
    subscriber_index: int
    delivered: bool
    result: object | None = None
    error_type: str | None = None


def _adapter_worker(adapter, envelope, connection) -> None:
    try:
        connection.send(("RESULT", adapter.evaluate(envelope)))
    except BaseException as exc:
        connection.send(("ERROR", type(exc).__name__))
    finally:
        connection.close()


class AsyncShadowSupervisor:
    def __init__(
        self,
        adapter: ShadowAdapter,
        fail_safe: dict[str, str],
        bus: RevocationBus,
        latch: EscalationLatch,
        adapter_error_threshold: int = 3,
    ) -> None:
        self._adapter = adapter
        self._fail_safe = dict(fail_safe)
        self._bus = bus
        self._latch = latch
        self._threshold = adapter_error_threshold
        self._errors: dict[str, int] = {}
        self._process_start_method = "spawn"
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="shadow-supervisor")

    @property
    def process_start_method(self) -> str:
        return self._process_start_method

    def submit(self, envelope: ShadowEvaluationEnvelope, semantic_family: str) -> Future[AsyncDecision]:
        return self._executor.submit(self._evaluate, envelope, semantic_family)

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)

    def _evaluate(self, envelope: ShadowEvaluationEnvelope, family: str) -> AsyncDecision:
        result, measured_ms = self._bounded_evaluate(envelope)
        is_adapter_error = result.termination_reason in {"TIMEOUT", "TOKEN_BUDGET_EXHAUSTED", "SCHEMA_FAILURE", "SYSTEM_ERROR"}
        if is_adapter_error:
            self._errors[family] = self._errors.get(family, 0) + 1
        else:
            self._errors[family] = 0
        structural = self._errors.get(family, 0) >= self._threshold
        effective = result.outcome if result.outcome != "INDETERMINATE" and not is_adapter_error else self._fail_safe[envelope.risk_class]
        revoked = effective != "ALLOW" or structural
        if revoked:
            reason = "T1_SEQ" if structural else result.reason_codes[0]
            self._latch.set(reason)
            self._bus.publish(envelope.decision_epoch)
        return AsyncDecision(
            result.outcome, "BLOCK" if structural else effective, result.termination_reason,
            result.reason_codes, revoked, structural, measured_ms,
        )

    def _bounded_evaluate(self, envelope: ShadowEvaluationEnvelope) -> tuple[ShadowResult, int]:
        """Enforce the external wall-clock budget outside the untrusted adapter."""
        context = multiprocessing.get_context(self._process_start_method)
        parent, child = context.Pipe(duplex=False)
        process = context.Process(target=_adapter_worker, args=(self._adapter, envelope, child), daemon=True)
        started = monotonic_ns()
        process.start()
        child.close()
        process.join(envelope.time_budget_ms / 1000)
        measured_ms = max(0, (monotonic_ns() - started + 999_999) // 1_000_000)
        if process.is_alive():
            process.terminate()
            process.join(1)
            parent.close()
            return ShadowResult(
                "INDETERMINATE", "TIMEOUT", ("T2_SHD_TIMEOUT",), measured_ms, 0
            ), measured_ms
        try:
            kind, payload = parent.recv() if parent.poll() else ("ERROR", "NoResult")
        finally:
            parent.close()
        if kind != "RESULT":
            return ShadowResult(
                "INDETERMINATE", "SYSTEM_ERROR", ("T2_SHD_ADAPTER_FAILURE",), measured_ms, 0
            ), measured_ms
        if not isinstance(payload, ShadowResult):
            return ShadowResult(
                "INDETERMINATE", "SCHEMA_FAILURE", ("T2_SHD_SCHEMA_FAILURE",), measured_ms, 0
            ), measured_ms
        if payload.tokens_used > envelope.token_budget:
            return ShadowResult(
                "INDETERMINATE", "TOKEN_BUDGET_EXHAUSTED",
                ("T2_SHD_TOKEN_EXHAUSTED",), measured_ms, envelope.token_budget,
            ), measured_ms
        return ShadowResult(
            payload.outcome, payload.termination_reason, payload.reason_codes,
            measured_ms, payload.tokens_used, payload.provider_request_id,
            payload.provider_model, payload.response_sha256, payload.ignored_provider_fields,
        ), measured_ms


def broker_revocation_bus(broker: CapabilityBroker) -> RevocationBus:
    bus = RevocationBus()
    bus.subscribe(broker.revoke_epoch)
    return bus
