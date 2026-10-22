"""Fail-closed controller state transition enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import ContractError
from time import monotonic_ns
from typing import Callable

TRANSITIONS = {
    "AWAITING_MODEL": {"EVALUATING_ACTION"},
    "EVALUATING_ACTION": {"BLOCKED", "AUTHORIZED", "AWAITING_TIER2", "EXECUTING_SIMULATED"},
    "AWAITING_TIER2": {"AUTHORIZED", "BLOCKED", "CHALLENGED", "HELD_FOR_ESCALATION", "EXECUTING_SIMULATED"},
    "AUTHORIZED": {"EXECUTING", "EXECUTING_SIMULATED"},
    "EXECUTING": {"OBSERVING_RESULT", "NOT_STARTED_REVOKED", "CANCELLED_PRE_EFFECT", "FAILED_SAFE"},
    "EXECUTING_SIMULATED": {"OBSERVING_RESULT", "FAILED_SAFE"},
    "OBSERVING_RESULT": {"AWAITING_MODEL", "COMPLETED", "FAILED_SAFE"},
    "BLOCKED": set(),
    "CHALLENGED": set(),
    "HELD_FOR_ESCALATION": {"BLOCKED"},
    "NOT_STARTED_REVOKED": set(),
    "CANCELLED_PRE_EFFECT": set(),
    "COMPLETED": set(),
    "FAILED_SAFE": set(),
}


@dataclass
class StateTracker:
    current: str = "AWAITING_MODEL"
    history: list[str] = field(default_factory=lambda: ["AWAITING_MODEL"])

    def transition(self, target: str) -> None:
        if target not in TRANSITIONS.get(self.current, set()):
            raise ContractError(f"illegal controller transition: {self.current} -> {target}")
        self.current = target
        self.history.append(target)


@dataclass
class EscalationHold:
    deadline_ns: int
    resolved: bool = False
    clock: Callable[[], int] = field(default=monotonic_ns, repr=False, compare=False)

    @classmethod
    def start(cls, deadline_ms: int, clock: Callable[[], int] = monotonic_ns) -> "EscalationHold":
        if deadline_ms <= 0:
            raise ValueError("escalation deadline must be positive")
        return cls(clock() + deadline_ms * 1_000_000, clock=clock)

    def resolve(self, actor: str) -> None:
        if actor not in {"HARNESS", "OPERATOR"}:
            raise ContractError("escalation may be resolved only by harness or operator")
        if self.clock() >= self.deadline_ns:
            raise ContractError("escalation deadline has expired")
        self.resolved = True

    def disposition(self, clock: Callable[[], int] | None = None) -> str:
        clock = clock or self.clock
        if self.resolved:
            return "RESOLVED"
        return "BLOCKED" if clock() >= self.deadline_ns else "HELD_FOR_ESCALATION"
