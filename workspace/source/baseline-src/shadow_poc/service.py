"""Increment 1 application service: assess and record, never execute."""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter_ns
from typing import Any, Callable

from .configuration import TrustedConfiguration
from .contracts import ActionRequest, ModelProvenance, PolicyDecision, RunContext
from .event_builder import EventBuilder
from .evidence_store import AppendOnlyEvidenceStore
from .tier1_policy import Tier1PolicyEngine
from .errors import ContractError
from .classification import effective_classification

Timer = Callable[[], int]


@dataclass(frozen=True)
class AssessmentResult:
    decision: PolicyDecision
    event: dict[str, Any]
    request: ActionRequest | None = None


class Tier1AssessmentService:
    """A closed vertical slice with intentionally no tool-execution interface."""

    def __init__(
        self,
        configuration: TrustedConfiguration,
        evidence_store: AppendOnlyEvidenceStore,
        event_builder: EventBuilder | None = None,
        timer: Timer = perf_counter_ns,
    ) -> None:
        self._configuration = configuration
        self._engine = Tier1PolicyEngine(configuration)
        self._store = evidence_store
        self._builder = event_builder or EventBuilder()
        self._timer = timer

    def assess(self, untrusted_action: Any, context: RunContext, model_provenance: ModelProvenance | None = None) -> AssessmentResult:
        try:
            request = ActionRequest.from_untrusted(untrusted_action)
        except ContractError:
            decision = PolicyDecision("DENY", "UNAUTHORIZED", "HIGH", "NONE", ("T1_SCH",))
            event = self._builder.contract_failure_event(
                untrusted_action,
                context,
                self._configuration.policy["version"],
                self._configuration.objective["version"],
            )
            if model_provenance is not None:
                self._builder.apply_model_provenance(event, model_provenance)
            return AssessmentResult(decision, self._store.append(event), None)
        started = self._timer()
        decision = self._engine.evaluate(request)
        elapsed_ms = max(0, (self._timer() - started + 999_999) // 1_000_000)
        budgets = self._configuration.policy["shadow_budgets"] if decision.tier2_route == "SYNCHRONOUS" else None
        event = self._builder.policy_event(
            request,
            decision,
            context,
            elapsed_ms,
            None if budgets is None else budgets["time_ms"],
            None if budgets is None else budgets["tokens"],
            self._configuration.policy["version"],
            self._configuration.objective["version"],
        )
        metadata = event["trusted_metadata"]
        resource = self._configuration.objective["resources"].get(request.target)
        if resource is not None:
            metadata["data_classification"] = effective_classification(
                self._configuration.objective, resource["classification"], context.taint_source_resource_ids
            )
        if model_provenance is not None:
            self._builder.apply_model_provenance(event, model_provenance)
        recorded = self._store.append(event)
        return AssessmentResult(decision, recorded, request)
