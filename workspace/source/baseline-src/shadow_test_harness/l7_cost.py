"""Pre-campaign L7 cost guidance derived from pilot telemetry.

This module estimates likely spend; it never chooses or mutates the campaign's
hard cap.  The cap remains an explicit operator decision.
"""
from __future__ import annotations

from statistics import mean
from typing import Any

from .l7_replay import ReplayContractError, canonical_sha256


def estimate_l7_campaign_cost(
    *,
    pilot_report: dict[str, Any],
    catalogue: dict[str, Any],
    pricing: dict[str, Any],
    primary_model: str,
    shadow_model: str,
    proposed_hard_cap_usd: float | None = None,
) -> dict[str, Any]:
    """Return conservative, pricing-bound guidance without selecting a cap."""
    claimed = pilot_report.get("report_sha256")
    unsigned = dict(pilot_report)
    unsigned.pop("report_sha256", None)
    if claimed != canonical_sha256(unsigned):
        raise ReplayContractError("COST_ESTIMATE_PILOT_HASH_MISMATCH")
    if pilot_report.get("status") != "PASS":
        raise ReplayContractError("COST_ESTIMATE_REQUIRES_PASSING_PILOT")

    pilot_gate = catalogue.get("calibration_pilot_gate")
    if not isinstance(pilot_gate, dict) or pilot_report.get("gate") != pilot_gate:
        raise ReplayContractError("COST_ESTIMATE_PILOT_GATE_CATALOGUE_MISMATCH")
    expected_pilot_calls = pilot_gate.get("expected_scenario_runs")
    if not isinstance(expected_pilot_calls, int) or expected_pilot_calls < 1:
        raise ReplayContractError("COST_ESTIMATE_PILOT_GATE_INVALID")

    rule = catalogue.get("cost_preflight")
    if not isinstance(rule, dict):
        raise ReplayContractError("COST_PREFLIGHT_RULE_MISSING")
    required = {
        "expected_primary_live_calls",
        "conservative_candidate_shadow_calls",
        "candidate_shadow_tokens_per_call",
        "recommendation_multiplier",
    }
    if not required.issubset(rule):
        raise ReplayContractError("COST_PREFLIGHT_RULE_INCOMPLETE")

    results = pilot_report.get("results")
    if not isinstance(results, list) or len(results) != expected_pilot_calls:
        raise ReplayContractError("COST_ESTIMATE_PILOT_TELEMETRY_INCOMPLETE")
    if catalogue.get("scenario_progression", {}).get("protocol") == "L7_STAGED_SCENARIOS_v1":
        from .l7_stage_protocol import validate_stage_calls
        # The estimator lacks the corpus; membership is checked by the operator CLI.
        if pilot_report.get("protocol") != "L7_STAGED_SCENARIOS_v1": raise ReplayContractError("COST_ESTIMATE_STAGE_PROTOCOL_REQUIRED")
        calls = [call for row in results for call in row.get("calls", [])]
        if not calls or len(calls) != pilot_report.get("provider_call_count") or len(calls)>40:
            raise ReplayContractError("COST_ESTIMATE_PILOT_TELEMETRY_INCOMPLETE")
        for row in results:
            if row.get("provider_total_tokens") != sum(c.get("provider_total_tokens", 0) for c in row.get("calls", [])):
                raise ReplayContractError("COST_ESTIMATE_PILOT_TELEMETRY_INCOMPLETE")
    else:
        calls = results
    tokens = [row.get("provider_total_tokens") for row in calls]
    if any(not isinstance(value, int) or value <= 0 for value in tokens):
        raise ReplayContractError("COST_ESTIMATE_PILOT_TELEMETRY_INCOMPLETE")
    reported_models = {row.get("model_snapshot") for row in calls}
    if reported_models != {primary_model}:
        raise ReplayContractError("COST_ESTIMATE_PRIMARY_MODEL_MISMATCH")

    models = pricing.get("models", {})
    if primary_model not in models or shadow_model not in models:
        raise ReplayContractError("COST_ESTIMATE_PRICING_MODEL_MISSING")
    try:
        primary_rate = float(models[primary_model]["usd_per_million_total_tokens_upper"])
        shadow_rate = float(models[shadow_model]["usd_per_million_total_tokens_upper"])
        primary_calls = int(rule["expected_primary_live_calls"])
        shadow_calls = int(rule["conservative_candidate_shadow_calls"])
        shadow_tokens = int(rule["candidate_shadow_tokens_per_call"])
        multiplier = float(rule["recommendation_multiplier"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReplayContractError("COST_PREFLIGHT_RULE_INVALID") from exc
    if min(primary_rate, shadow_rate, primary_calls, shadow_calls, shadow_tokens, multiplier) <= 0:
        raise ReplayContractError("COST_PREFLIGHT_RULE_INVALID")

    pilot_mean = mean(tokens)
    primary_estimate = pilot_mean * primary_calls * primary_rate / 1_000_000
    shadow_estimate = shadow_tokens * shadow_calls * shadow_rate / 1_000_000
    expected = primary_estimate + shadow_estimate
    recommended = expected * multiplier
    if proposed_hard_cap_usd is not None and proposed_hard_cap_usd <= 0:
        raise ReplayContractError("PROPOSED_HARD_CAP_INVALID")
    guidance = (
        "OPERATOR_CAP_NOT_PROVIDED"
        if proposed_hard_cap_usd is None
        else "CAP_AT_OR_ABOVE_RECOMMENDATION"
        if proposed_hard_cap_usd + 1e-12 >= recommended
        else "CAP_BELOW_RECOMMENDATION"
    )
    report = {
        "schema_version": "1.0",
        "status": "GUIDANCE_ONLY",
        "basis": rule.get("basis"),
        "pilot_report_sha256": claimed,
        "pricing_id": pricing.get("pricing_id"),
        "pricing_document_sha256": canonical_sha256(pricing),
        "catalogue_document_sha256": canonical_sha256(catalogue),
        "primary_model": primary_model,
        "shadow_model": shadow_model,
        "pilot_primary_calls_observed": len(tokens),
        "pilot_primary_total_tokens": sum(tokens),
        "pilot_primary_mean_tokens_per_call": pilot_mean,
        "expected_primary_live_calls": primary_calls,
        "conservative_candidate_shadow_calls": shadow_calls,
        "candidate_shadow_tokens_per_call": shadow_tokens,
        "estimated_primary_cost_usd": primary_estimate,
        "estimated_shadow_cost_usd": shadow_estimate,
        "estimated_campaign_cost_usd": expected,
        "recommendation_multiplier": multiplier,
        "recommended_hard_cap_usd": recommended,
        "recommended_cap_is_automatically_selected": False,
        "proposed_hard_cap_usd": proposed_hard_cap_usd,
        "cap_guidance": guidance,
        "no_resume": bool(rule.get("no_resume")),
        "cap_purpose": rule.get("cap_purpose"),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report
