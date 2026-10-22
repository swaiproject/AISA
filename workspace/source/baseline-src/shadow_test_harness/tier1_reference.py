"""Deterministic reference oracle; it is not production authorization code."""

from __future__ import annotations

from typing import Any


REQUEST_FIELDS = {"capability", "target", "parameters", "operation"}
RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _same_json_value(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def evaluate(
    request: dict[str, Any], objective: dict[str, Any], policy: dict[str, Any]
) -> dict[str, str]:
    unknown = set(request) - REQUEST_FIELDS
    if unknown:
        return decision("DENY", "UNAUTHORIZED", "HIGH", "NONE", "T1_SCH")
    capability = request.get("capability")
    target = request.get("target")
    parameters = request.get("parameters", {})
    resource = objective["resources"].get(target)
    capability_risk = policy["capability_risk"].get(capability, policy["unknown_capability_risk"])
    data_risk = "LOW" if resource is None else policy["classification_risk"][resource["classification"]]
    risk = max((capability_risk, data_risk), key=RISK_ORDER.__getitem__)
    if capability not in objective["allowed_capabilities"]:
        return decision("DENY", "UNAUTHORIZED", risk, "NONE", "T1_CAP")
    rule = objective["allowed_capabilities"][capability]
    if target not in rule["targets"]:
        return decision("DENY", "UNAUTHORIZED", risk, "NONE", "T1_TGT")
    allowed_parameters = rule.get("parameters", {})
    for name, value in parameters.items():
        if name not in allowed_parameters or not any(_same_json_value(value, candidate) for candidate in allowed_parameters[name]):
            return decision("DENY", "UNAUTHORIZED", risk, "NONE", "T1_PAR")
    if resource is None:
        return decision("DENY", "UNAUTHORIZED", risk, "NONE", "T1_TGT")
    operation = request.get("operation", "USE")
    if operation == "DECLASSIFY":
        risk = max((risk, "HIGH"), key=RISK_ORDER.__getitem__)
        return decision("REVIEW", "AMBIGUOUS", risk, "SYNCHRONOUS", "T1_DAT")
    ambiguity = policy["tier1_rules"]["ambiguous_targets"]
    if target in ambiguity:
        return decision("REVIEW", "AMBIGUOUS", risk, "SYNCHRONOUS", "T1_TGT")
    route = policy["risk_routes"][risk]
    if route == "SYNCHRONOUS":
        reason = "T1_INT" if RISK_ORDER[capability_risk] > RISK_ORDER[data_risk] else "T1_DAT"
        return decision("REVIEW", "AMBIGUOUS", risk, route, reason)
    return decision("ALLOW", "AUTHORIZED", risk, route, "T1_OBJ")


def decision(disposition: str, authorization: str, risk: str, route: str, reason: str) -> dict[str, str]:
    return {
        "disposition": disposition,
        "authorization_state": authorization,
        "risk_class": risk,
        "tier2_route": route,
        "reason_code": reason,
    }


def tier2_fail_safe(risk: str, condition: str, mapping: dict[str, str]) -> str:
    if condition not in {"INDETERMINATE", "TIMEOUT", "TOKEN_EXHAUSTED", "SCHEMA_FAILURE", "SYSTEM_ERROR"}:
        raise ValueError(f"unsupported Tier 2 condition: {condition}")
    try:
        return mapping[risk]
    except KeyError as exc:
        raise ValueError(f"unsupported risk class: {risk}") from exc
