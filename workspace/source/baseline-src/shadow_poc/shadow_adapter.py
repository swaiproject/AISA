"""Model-independent Tier 2 contract and deterministic test adapter."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from .contracts import ActionRequest
from .errors import ContractError

OUTCOMES = frozenset({"ALLOW", "CHALLENGE", "BLOCK", "ESCALATE", "INDETERMINATE"})
TERMINATIONS = frozenset({"COMPLETED", "TIMEOUT", "TOKEN_BUDGET_EXHAUSTED", "SCHEMA_FAILURE", "SYSTEM_ERROR"})


@dataclass(frozen=True)
class ShadowEvaluationEnvelope:
    action: ActionRequest
    risk_class: str
    tier1_reason_codes: tuple[str, ...]
    trace_id: str
    decision_epoch: int
    time_budget_ms: int
    token_budget: int
    data_classification: str = "PUBLIC"
    context_taint_state: str = "CLEAN"
    objective_summary: Mapping[str, Any] | None = None
    anchored_trajectory: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class ShadowResult:
    outcome: str
    termination_reason: str
    reason_codes: tuple[str, ...]
    elapsed_ms: int
    tokens_used: int
    provider_request_id: str | None = None
    provider_model: str | None = None
    response_sha256: str | None = None
    ignored_provider_fields: tuple[str, ...] = ()
    rationale: str | None = None

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ContractError(f"invalid Shadow outcome: {self.outcome}")
        if self.termination_reason not in TERMINATIONS:
            raise ContractError(f"invalid Shadow termination reason: {self.termination_reason}")
        if not self.reason_codes or any(not code.startswith("T2_") for code in self.reason_codes):
            raise ContractError("Shadow result requires at least one T2 reason code")
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (self.elapsed_ms, self.tokens_used)):
            raise ContractError("Shadow usage values must be non-negative integers")
        if self.rationale is not None and (not isinstance(self.rationale, str) or len(self.rationale) > 2048):
            raise ContractError("Shadow rationale must be bounded text")


class ShadowAdapter(Protocol):
    def evaluate(self, envelope: ShadowEvaluationEnvelope) -> ShadowResult: ...


class ScriptedShadowAdapter:
    """Deterministic integration adapter; it invokes no model or network."""

    def __init__(self, scripts: Mapping[str, ShadowResult], default: ShadowResult | None = None) -> None:
        self._scripts = MappingProxyType(dict(scripts))
        self._default = default or ShadowResult("INDETERMINATE", "COMPLETED", ("T2_EVD",), 1, 1)

    def evaluate(self, envelope: ShadowEvaluationEnvelope) -> ShadowResult:
        result = self._scripts.get(envelope.action.target, self._default)
        if result.elapsed_ms > envelope.time_budget_ms:
            return ShadowResult("INDETERMINATE", "TIMEOUT", ("T2_SHD_TIMEOUT",), envelope.time_budget_ms, min(result.tokens_used, envelope.token_budget))
        if result.tokens_used > envelope.token_budget:
            return ShadowResult("INDETERMINATE", "TOKEN_BUDGET_EXHAUSTED", ("T2_SHD_TOKEN_EXHAUSTED",), result.elapsed_ms, envelope.token_budget)
        return result

    def __reduce__(self):
        return (self.__class__, (dict(self._scripts), self._default))
