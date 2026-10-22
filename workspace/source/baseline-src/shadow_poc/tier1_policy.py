"""Production deterministic Tier 1 policy engine. No model or oracle dependency."""

from __future__ import annotations

from .configuration import TrustedConfiguration
from .contracts import ActionRequest, PolicyDecision
from .errors import ConfigurationError

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _same_json_value(left: object, right: object) -> bool:
    """JSON booleans must not compare equal to integers (True == 1 in Python)."""
    return type(left) is type(right) and left == right


class Tier1PolicyEngine:
    def __init__(self, configuration: TrustedConfiguration) -> None:
        self._objective = configuration.objective
        self._policy = configuration.policy
        self._reason_codes = configuration.reason_codes

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        allowed = self._objective["allowed_capabilities"]
        risk = self._risk_for(request)
        if request.capability in self._objective["prohibited_capabilities"] or request.capability not in allowed:
            return self._decision("DENY", "UNAUTHORIZED", risk, "NONE", "T1_CAP")
        rule = allowed[request.capability]
        if request.target not in rule["targets"]:
            return self._decision("DENY", "UNAUTHORIZED", risk, "NONE", "T1_TGT")
        for name, value in request.parameters.items():
            permitted = rule["parameters"].get(name)
            if permitted is None or not any(_same_json_value(value, candidate) for candidate in permitted):
                return self._decision("DENY", "UNAUTHORIZED", risk, "NONE", "T1_PAR")
        resource = self._objective["resources"].get(request.target)
        if resource is None:
            return self._decision("DENY", "UNAUTHORIZED", risk, "NONE", "T1_TGT")
        if request.operation == "DECLASSIFY":
            return self._decision("REVIEW", "AMBIGUOUS", self._max_risk(risk, "HIGH"), "SYNCHRONOUS", "T1_DAT")
        if request.target in self._policy["tier1_rules"]["ambiguous_targets"]:
            return self._decision("REVIEW", "AMBIGUOUS", risk, "SYNCHRONOUS", "T1_TGT")
        route = self._policy["risk_routes"][risk]
        if route == "SYNCHRONOUS":
            capability_risk, data_risk = self._risk_components(request)
            reason = "T1_INT" if RISK_ORDER[capability_risk] > RISK_ORDER[data_risk] else "T1_DAT"
            return self._decision("REVIEW", "AMBIGUOUS", risk, route, reason)
        return self._decision("ALLOW", "AUTHORIZED", risk, route, "T1_OBJ")

    def _risk_for(self, request: ActionRequest) -> str:
        return self._max_risk(*self._risk_components(request))

    def _risk_components(self, request: ActionRequest) -> tuple[str, str]:
        capability_risk = self._policy["capability_risk"].get(
            request.capability, self._policy["unknown_capability_risk"]
        )
        resource = self._objective["resources"].get(request.target)
        data_risk = "LOW" if resource is None else self._policy["classification_risk"][resource["classification"]]
        return capability_risk, data_risk

    @staticmethod
    def _max_risk(*values: str) -> str:
        return max(values, key=RISK_ORDER.__getitem__)

    def _decision(self, disposition: str, authorization: str, risk: str, route: str, reason: str) -> PolicyDecision:
        if reason not in self._reason_codes:
            raise ConfigurationError(f"policy emitted unregistered reason code: {reason}")
        return PolicyDecision(disposition, authorization, risk, route, (reason,))
