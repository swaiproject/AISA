"""Strict production contracts. Model-originated values remain untrusted data."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .errors import ContractError

ACTION_FIELDS = frozenset({"capability", "target", "parameters", "operation"})
OPERATIONS = frozenset({"USE", "DECLASSIFY"})
DISPOSITIONS = frozenset({"ALLOW", "DENY", "REVIEW"})
AUTHORIZATION_STATES = frozenset({"AUTHORIZED", "UNAUTHORIZED", "AMBIGUOUS"})
RISK_CLASSES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
TIER2_ROUTES = frozenset({"NONE", "ASYNCHRONOUS", "SYNCHRONOUS"})


def _nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{field_name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class ActionRequest:
    capability: str
    target: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    operation: str = "USE"

    @classmethod
    def from_untrusted(cls, value: Any) -> "ActionRequest":
        if not isinstance(value, dict):
            raise ContractError("ActionRequest must be an object")
        unknown = set(value) - ACTION_FIELDS
        if unknown:
            raise ContractError(f"ActionRequest contains unknown fields: {sorted(unknown)!r}")
        missing = {"capability", "target"} - set(value)
        if missing:
            raise ContractError(f"ActionRequest is missing fields: {sorted(missing)!r}")
        parameters = value.get("parameters", {})
        if not isinstance(parameters, dict):
            raise ContractError("parameters must be an object")
        for name in parameters:
            _nonempty_string(name, "parameter name")
        operation = value.get("operation", "USE")
        if operation not in OPERATIONS:
            raise ContractError(f"unsupported operation: {operation!r}")
        return cls(
            capability=_nonempty_string(value["capability"], "capability"),
            target=_nonempty_string(value["target"], "target"),
            parameters=MappingProxyType(dict(parameters)),
            operation=operation,
        )

    def as_untrusted_data(self) -> dict[str, Any]:
        return {
            "requested_action": self.capability,
            "target_resource": self.target,
            "input_parameters": dict(self.parameters),
        }

    def __reduce__(self):
        return (_restore_action_request, ({
            "capability": self.capability,
            "target": self.target,
            "parameters": dict(self.parameters),
            "operation": self.operation,
        },))


def _restore_action_request(value: dict[str, Any]) -> ActionRequest:
    return ActionRequest.from_untrusted(value)


@dataclass(frozen=True)
class PolicyDecision:
    disposition: str
    authorization_state: str
    risk_class: str
    tier2_route: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.disposition not in DISPOSITIONS:
            raise ContractError(f"invalid disposition: {self.disposition}")
        if self.authorization_state not in AUTHORIZATION_STATES:
            raise ContractError(f"invalid authorization state: {self.authorization_state}")
        if self.risk_class not in RISK_CLASSES:
            raise ContractError(f"invalid risk class: {self.risk_class}")
        if self.tier2_route not in TIER2_ROUTES:
            raise ContractError(f"invalid Tier 2 route: {self.tier2_route}")
        if not self.reason_codes or any(not code.startswith("T1_") for code in self.reason_codes):
            raise ContractError("Tier 1 decisions require at least one T1 reason code")

    def as_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition,
            "authorization_state": self.authorization_state,
            "risk_class": self.risk_class,
            "tier2_route": self.tier2_route,
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True)
class RunContext:
    run_id: str
    trace_id: str
    objective_id: str
    execution_mode: str = "ENFORCE"
    decision_epoch: int = 0
    supervision_state: str = "NORMAL"
    control_point_id: str = "CP-02"
    context_taint_state: str = "CLEAN"
    taint_source_resource_ids: tuple[str, ...] = ()
    action_origin: str = "MODEL_PROPOSAL"

    def __post_init__(self) -> None:
        for name in ("run_id", "trace_id", "objective_id", "control_point_id"):
            _nonempty_string(getattr(self, name), name)
        if self.execution_mode not in {"AUDIT", "ENFORCE"}:
            raise ContractError("execution_mode must be AUDIT or ENFORCE")
        if not isinstance(self.decision_epoch, int) or isinstance(self.decision_epoch, bool) or self.decision_epoch < 0:
            raise ContractError("decision_epoch must be a non-negative integer")
        if self.supervision_state not in {"NORMAL", "LATCHED", "HELD_FOR_ESCALATION", "OPERATOR_RESOLVED", "HARNESS_RESOLVED"}:
            raise ContractError("invalid supervision_state")
        if self.context_taint_state not in {"CLEAN", "TAINTED"}:
            raise ContractError("invalid context_taint_state")
        if any(not isinstance(item, str) or not item for item in self.taint_source_resource_ids):
            raise ContractError("taint_source_resource_ids must contain non-empty strings")
        if self.context_taint_state == "TAINTED" and not self.taint_source_resource_ids:
            raise ContractError("TAINTED context requires at least one taint source")
        if self.action_origin not in {"MODEL_PROPOSAL", "CONTROLLER_COMPACTION", "HARNESS", "OPERATOR", "TOOL_RESULT", "SYSTEM"}:
            raise ContractError("invalid action_origin")


@dataclass(frozen=True)
class ModelProvenance:
    provider_request_id: str
    model_id_and_version: str
    total_tokens: int
    response_sha256: str
    inference_time_ms: int
    finish_reason: str
    ignored_provider_fields: tuple[str, ...] = ()
    additional_result_provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value in (self.provider_request_id, self.model_id_and_version, self.response_sha256, self.finish_reason):
            _nonempty_string(value, "model provenance field")
        if not isinstance(self.total_tokens, int) or isinstance(self.total_tokens, bool) or self.total_tokens < 0:
            raise ContractError("total_tokens must be a non-negative integer")
        if not isinstance(self.inference_time_ms, int) or isinstance(self.inference_time_ms, bool) or self.inference_time_ms < 0:
            raise ContractError("inference_time_ms must be a non-negative integer")
        if any(not isinstance(item,str) or not item for item in self.additional_result_provenance):
            raise ContractError("additional result provenance must contain non-empty strings")
