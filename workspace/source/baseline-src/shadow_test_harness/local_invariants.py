"""Cross-field event invariants that are not safely expressible in the bootstrap schema."""

from __future__ import annotations

import re
from typing import Any

from .schema_validator import ValidationIssue

OBSERVED = {"CONTROLLER_OBSERVED", "TOOL_OBSERVED", "ENVIRONMENT_OBSERVED", "HARNESS_OBSERVED"}
HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def validate_event_invariants(event: dict[str, Any]) -> list[ValidationIssue]:
    m = event.get("trusted_metadata", {})
    issues: list[ValidationIssue] = []
    status = m.get("execution_status")
    if m.get("execution_mode") == "ENFORCE" and status == "EXECUTED_SIMULATED":
        issues.append(ValidationIssue("$.trusted_metadata.execution_status", "simulated execution is AUDIT-only"))
    provenance=set(m.get("result_provenance",[])); absent={"tier2_execution_mode:ABSENT_BY_ARM_DESIGN", "tier1_policy_route:SYNCHRONOUS", "counterfactual_arm:TIER1_ONLY", "counterfactual_resolution:PROCEED_WITHOUT_TIER2"}.issubset(provenance)
    if status == "AUTHORIZED" and m.get("evaluation_tier") != "TIER1_ONLY" and m.get("tier2_outcome") != "ALLOW" and not absent:
        issues.append(ValidationIssue("$.trusted_metadata.execution_status", "AUTHORIZED requires Tier 1 only or Tier 2 ALLOW"))
    if m.get("authorization_state") == "AMBIGUOUS" and status == "EXECUTED" and m.get("tier2_outcome") == "NOT_RUN" and not absent:
        issues.append(ValidationIssue("$.trusted_metadata.tier2_outcome", "ambiguous execution requires Tier 2"))
    if status in {"EXECUTED", "EXECUTED_SIMULATED"} and not (set(m.get("evidence_provenance", [])) & OBSERVED):
        issues.append(ValidationIssue("$.trusted_metadata.evidence_provenance", "execution requires observed evidence"))
    if m.get("context_taint_state") == "TAINTED" and not m.get("taint_source_resource_ids"):
        issues.append(ValidationIssue("$.trusted_metadata.taint_source_resource_ids", "taint sources are required"))
    if status == "TIER2_TIMEOUT" and m.get("tier2_termination_reason") != "TIMEOUT":
        issues.append(ValidationIssue("$.trusted_metadata.tier2_termination_reason", "timeout status requires TIMEOUT"))
    if m.get("evaluation_tier") == "TIER2_SYNCHRONOUS" and (
        m.get("shadow_time_budget_ms") is None or m.get("shadow_token_budget") is None
    ):
        issues.append(ValidationIssue("$.trusted_metadata", "synchronous Tier 2 requires both budgets"))
    integrity = m.get("integrity", {})
    if not HASH.fullmatch(integrity.get("event_hash", "")):
        issues.append(ValidationIssue("$.trusted_metadata.integrity.event_hash", "must be a SHA-256 identifier"))
    previous = integrity.get("previous_event_hash")
    if previous is not None and not HASH.fullmatch(previous):
        issues.append(ValidationIssue("$.trusted_metadata.integrity.previous_event_hash", "must be a SHA-256 identifier"))
    timing = m.get("timing", {})
    if timing.get("critical_path_latency_ms", 0) < timing.get("tier_1_policy_time_ms", 0):
        issues.append(ValidationIssue("$.trusted_metadata.timing.critical_path_latency_ms", "cannot be less than Tier 1 time"))
    return issues
