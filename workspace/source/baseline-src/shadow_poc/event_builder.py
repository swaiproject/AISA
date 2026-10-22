"""Build schema-shaped enforcement events from trusted controller facts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable
from copy import deepcopy
from uuid import uuid4

from .contracts import ActionRequest, ModelProvenance, PolicyDecision, RunContext

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]


class EventBuilder:
    def __init__(self, clock: Clock | None = None, id_factory: IdFactory | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: f"evt-{uuid4()}")

    def policy_event(
        self,
        request: ActionRequest,
        decision: PolicyDecision,
        context: RunContext,
        tier1_time_ms: float,
        shadow_time_budget_ms: int | None,
        shadow_token_budget: int | None,
        policy_version: str,
        objective_version: str,
    ) -> dict[str, Any]:
        status = {"ALLOW": "AUTHORIZED", "DENY": "BLOCKED", "REVIEW": "REQUESTED"}[decision.disposition]
        evaluation_tier = {
            "NONE": "TIER1_ONLY",
            "ASYNCHRONOUS": "TIER2_ASYNCHRONOUS",
            "SYNCHRONOUS": "TIER2_SYNCHRONOUS",
        }[decision.tier2_route]
        event = {
            "schema_version": "0.2.1",
            "trusted_metadata": {
                "event_id": self._id_factory(),
                "run_id": context.run_id,
                "timestamp": self._timestamp(),
                "trace_id": context.trace_id,
                "objective_id": context.objective_id,
                "parent_event_id": None,
                "previous_event_id": None,
                "current_subgoal_id": None,
                "capability_id": request.capability,
                "control_point_id": context.control_point_id,
                "action_origin": context.action_origin,
                "decision_epoch": context.decision_epoch,
                "supervision_state": context.supervision_state,
                "declassification_event_id": None,
                "execution_mode": context.execution_mode,
                "risk_class": decision.risk_class,
                "authorization_state": decision.authorization_state,
                "execution_status": status,
                "evidence_provenance": ["CONTROLLER_OBSERVED"],
                "context_taint_state": context.context_taint_state,
                "taint_source_resource_ids": list(context.taint_source_resource_ids),
                "evaluation_tier": evaluation_tier,
                "tier1_reason_codes": list(decision.reason_codes),
                "tier2_reason_codes": [],
                "replay_state": "NOT_APPLICABLE",
                "shadow_time_budget_ms": shadow_time_budget_ms,
                "shadow_token_budget": shadow_token_budget,
                "tier2_outcome": "NOT_RUN",
                "tier2_termination_reason": "NOT_RUN",
                "policy_version": policy_version,
                "objective_specification_version": objective_version,
                "timing": {
                    "model_inference_time_ms": None,
                    "tier_1_policy_time_ms": tier1_time_ms,
                    "tier_2_shadow_time_ms": None,
                    "execution_time_ms": None,
                    "critical_path_latency_ms": tier1_time_ms,
                    "asynchronous_detection_delay_ms": None,
                },
                "integrity": {
                    "event_hash": "sha256:" + ("0" * 64),
                    "previous_event_hash": None,
                },
            },
            "untrusted_data": request.as_untrusted_data(),
        }
        return event

    def contract_failure_event(
        self,
        untrusted_action: Any,
        context: RunContext,
        policy_version: str,
        objective_version: str,
    ) -> dict[str, Any]:
        """Represent malformed model output as a bounded enforcement event."""
        import json

        try:
            detail = json.dumps(untrusted_action, ensure_ascii=True, allow_nan=False, sort_keys=True, default=repr)
        except (TypeError, ValueError):
            detail = repr(untrusted_action)
        detail = detail[:2048]
        request = ActionRequest("INVALID_ACTION", "INVALID_TARGET", {})
        decision = PolicyDecision("DENY", "UNAUTHORIZED", "HIGH", "NONE", ("T1_SCH",))
        event = self.policy_event(
            request, decision, context, 0, None, None, policy_version, objective_version
        )
        event["untrusted_data"] = {
            "requested_action": None,
            "target_resource": None,
            "input_parameters": None,
            "error_detail": detail,
        }
        return event

    def followup_event(
        self,
        source: dict[str, Any],
        execution_status: str,
        *,
        authorization_state: str | None = None,
        supervision_state: str | None = None,
        tier2_outcome: str | None = None,
        tier2_termination_reason: str | None = None,
        tier2_reason_codes: tuple[str, ...] = (),
        tier2_time_ms: int | None = None,
        evidence_provenance: tuple[str, ...] | None = None,
        data_classification: str | None = None,
        context_taint_state: str | None = None,
        taint_source_resource_ids: tuple[str, ...] | None = None,
        error_detail: str | None = None,
        additional_result_provenance: tuple[str, ...] = (),
        control_point_id: str | None = None,
        completion_verification: str | None = None,
    ) -> dict[str, Any]:
        """Create a new lifecycle event without mutating an earlier event."""
        event = deepcopy(source)
        metadata = event["trusted_metadata"]
        metadata["event_id"] = self._id_factory()
        metadata["timestamp"] = self._timestamp()
        metadata["parent_event_id"] = source["trusted_metadata"]["event_id"]
        metadata["previous_event_id"] = None
        metadata["execution_status"] = execution_status
        if control_point_id is not None:
            metadata["control_point_id"] = control_point_id
        if authorization_state is not None:
            metadata["authorization_state"] = authorization_state
        if supervision_state is not None:
            metadata["supervision_state"] = supervision_state
        if tier2_outcome is not None:
            metadata["tier2_outcome"] = tier2_outcome
        if tier2_termination_reason is not None:
            metadata["tier2_termination_reason"] = tier2_termination_reason
        if tier2_reason_codes:
            metadata["tier2_reason_codes"] = list(tier2_reason_codes)
        if tier2_time_ms is not None:
            metadata["timing"]["tier_2_shadow_time_ms"] = tier2_time_ms
            metadata["timing"]["critical_path_latency_ms"] += tier2_time_ms
        if evidence_provenance is not None:
            metadata["evidence_provenance"] = list(evidence_provenance)
        if data_classification is not None:
            metadata["data_classification"] = data_classification
        if context_taint_state is not None:
            metadata["context_taint_state"] = context_taint_state
        if taint_source_resource_ids is not None:
            metadata["taint_source_resource_ids"] = list(taint_source_resource_ids)
        metadata["integrity"] = {"event_hash": "sha256:" + ("0" * 64), "previous_event_hash": None}
        if error_detail is not None:
            event["untrusted_data"]["error_detail"] = error_detail[:2048]
        if additional_result_provenance:
            metadata["result_provenance"] = list(metadata.get("result_provenance", [])) + list(additional_result_provenance)
        if completion_verification is not None:
            metadata["completion_verification"] = completion_verification
        return event

    def apply_model_provenance(self, event: dict[str, Any], provenance: ModelProvenance) -> None:
        metadata = event["trusted_metadata"]
        if "MODEL_DECLARED" not in metadata["evidence_provenance"]:
            metadata["evidence_provenance"].append("MODEL_DECLARED")
        metadata["model_id_and_version"] = provenance.model_id_and_version
        metadata["raw_model_output_reference"] = provenance.response_sha256
        metadata["sampling_parameters"] = {"temperature": 0}
        metadata["result_provenance"] = [
            f"provider_request_id:{provenance.provider_request_id}",
            f"provider_total_tokens:{provenance.total_tokens}",
            f"finish_reason:{provenance.finish_reason}",
            "ignored_provider_fields:" + ",".join(provenance.ignored_provider_fields),
        ] + list(provenance.additional_result_provenance)
        metadata["timing"]["model_inference_time_ms"] = provenance.inference_time_ms
        metadata["timing"]["critical_path_latency_ms"] += provenance.inference_time_ms

    def _timestamp(self) -> str:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
