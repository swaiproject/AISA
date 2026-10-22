"""Production event validation independent from the verification harness."""

from __future__ import annotations

from datetime import datetime
import re
from typing import Any


class ValidationFailure(ValueError):
    pass


OBSERVED = {"CONTROLLER_OBSERVED", "TOOL_OBSERVED", "ENVIRONMENT_OBSERVED", "HARNESS_OBSERVED"}
HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def validate_schema(instance: Any, schema: dict[str, Any]) -> list[str]:
    issues: list[str] = []

    def resolve(ref: str) -> dict[str, Any]:
        node: Any = schema
        for part in ref[2:].split("/"):
            node = node[part.replace("~1", "/").replace("~0", "~")]
        return node

    def is_type(value: Any, kind: str) -> bool:
        checks = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float), "boolean": bool, "null": type(None)}
        if kind not in checks:
            return True
        valid = isinstance(value, checks[kind])
        return valid and not (kind in {"integer", "number"} and isinstance(value, bool))

    def walk(value: Any, rule: dict[str, Any], path: str) -> None:
        if "$ref" in rule:
            walk(value, resolve(rule["$ref"]), path)
            return
        if "const" in rule and value != rule["const"]:
            issues.append(f"{path}: must equal {rule['const']!r}")
        if "enum" in rule and value not in rule["enum"]:
            issues.append(f"{path}: not in enum")
        kinds = rule.get("type")
        if kinds:
            kinds = kinds if isinstance(kinds, list) else [kinds]
            if not any(is_type(value, kind) for kind in kinds):
                issues.append(f"{path}: wrong type")
                return
        if isinstance(value, str):
            if len(value) < rule.get("minLength", 0):
                issues.append(f"{path}: string is too short")
            if "pattern" in rule and re.search(rule["pattern"], value) is None:
                issues.append(f"{path}: pattern mismatch")
            if rule.get("format") == "date-time":
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError
                except ValueError:
                    issues.append(f"{path}: invalid date-time")
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value < rule.get("minimum", value):
            issues.append(f"{path}: below minimum")
        if isinstance(value, list):
            if len(value) < rule.get("minItems", 0):
                issues.append(f"{path}: too few items")
            if rule.get("uniqueItems") and len({repr(item) for item in value}) != len(value):
                issues.append(f"{path}: duplicate items")
            for index, item in enumerate(value):
                if isinstance(rule.get("items"), dict):
                    walk(item, rule["items"], f"{path}[{index}]")
        if isinstance(value, dict):
            properties = rule.get("properties", {})
            for name in rule.get("required", []):
                if name not in value:
                    issues.append(f"{path}: missing {name}")
            if rule.get("additionalProperties") is False:
                for name in set(value) - set(properties):
                    issues.append(f"{path}.{name}: additional property")
            elif isinstance(rule.get("additionalProperties"), dict):
                for name in set(value) - set(properties):
                    walk(value[name], rule["additionalProperties"], f"{path}.{name}")
            for name, child in properties.items():
                if name in value:
                    walk(value[name], child, f"{path}.{name}")
        for child in rule.get("allOf", []):
            walk(value, child, path)
        if "if" in rule:
            before = len(issues)
            walk(value, rule["if"], path)
            matched = len(issues) == before
            del issues[before:]
            branch = rule.get("then" if matched else "else")
            if branch:
                walk(value, branch, path)

    walk(instance, schema, "$")
    return issues


def validate_event_invariants(event: dict[str, Any]) -> list[str]:
    m = event.get("trusted_metadata", {})
    status = m.get("execution_status")
    issues: list[str] = []
    if m.get("execution_mode") == "ENFORCE" and status == "EXECUTED_SIMULATED":
        issues.append("execution_status: simulated execution is AUDIT-only")
    provenance=set(m.get("result_provenance",[])); absent={"tier2_execution_mode:ABSENT_BY_ARM_DESIGN", "tier1_policy_route:SYNCHRONOUS", "counterfactual_arm:TIER1_ONLY", "counterfactual_resolution:PROCEED_WITHOUT_TIER2"}.issubset(provenance)
    if status == "AUTHORIZED" and m.get("evaluation_tier") != "TIER1_ONLY" and m.get("tier2_outcome") != "ALLOW" and not absent:
        issues.append("execution_status: AUTHORIZED requires Tier 1 only or Tier 2 ALLOW")
    if m.get("authorization_state") == "AMBIGUOUS" and status == "EXECUTED" and m.get("tier2_outcome") == "NOT_RUN" and not absent:
        issues.append("tier2_outcome: ambiguous execution requires Tier 2")
    if status in {"EXECUTED", "EXECUTED_SIMULATED"} and not set(m.get("evidence_provenance", [])) & OBSERVED:
        issues.append("evidence_provenance: execution requires observed evidence")
    if m.get("context_taint_state") == "TAINTED" and not m.get("taint_source_resource_ids"):
        issues.append("taint_source_resource_ids: taint sources are required")
    if status == "TIER2_TIMEOUT" and m.get("tier2_termination_reason") != "TIMEOUT":
        issues.append("tier2_termination_reason: timeout mismatch")
    if m.get("evaluation_tier") == "TIER2_SYNCHRONOUS" and (m.get("shadow_time_budget_ms") is None or m.get("shadow_token_budget") is None):
        issues.append("shadow_budget: synchronous Tier 2 requires budgets")
    integrity = m.get("integrity", {})
    if not HASH.fullmatch(integrity.get("event_hash", "")):
        issues.append("event_hash: invalid SHA-256 identifier")
    previous = integrity.get("previous_event_hash")
    if previous is not None and not HASH.fullmatch(previous):
        issues.append("previous_event_hash: invalid SHA-256 identifier")
    timing = m.get("timing", {})
    if timing.get("critical_path_latency_ms", 0) < timing.get("tier_1_policy_time_ms", 0):
        issues.append("critical_path_latency_ms: less than Tier 1 time")
    return issues
