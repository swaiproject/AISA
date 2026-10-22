"""Increment 2 controller integrating Tier 1, Tier 2, broker, and mock wrapper."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any
from time import monotonic_ns
import multiprocessing
import os
import hashlib

from .capability_broker import CapabilityBroker
from .configuration import TrustedConfiguration
from .contracts import ActionRequest, ModelProvenance, RunContext
from .errors import ContractError
from .event_builder import EventBuilder
from .evidence_store import AppendOnlyEvidenceStore
from .service import Tier1AssessmentService
from .shadow_adapter import ShadowAdapter, ShadowEvaluationEnvelope, ShadowResult
from .wrappers import InMemoryResourceWrapper, IsolatedSimulationWrapper, WrapperResult
from .state_machine import EscalationHold, StateTracker
from .classification import effective_classification

FINAL_FOR_OUTCOME = {
    "ALLOW": ("AUTHORIZED", "AUTHORIZED", "NORMAL"),
    "CHALLENGE": ("CHALLENGED", "AMBIGUOUS", "NORMAL"),
    "BLOCK": ("BLOCKED", "UNAUTHORIZED", "NORMAL"),
    "ESCALATE": ("ESCALATED", "AMBIGUOUS", "HELD_FOR_ESCALATION"),
}


@dataclass(frozen=True)
class ControllerResult:
    final_status: str
    states: tuple[str, ...]
    events: tuple[dict[str, Any], ...]
    wrapper_result: WrapperResult | None = None
    escalation_hold: EscalationHold | None = None
    observation_classification: str | None = None
    taint_source_resource_ids: tuple[str, ...] = ()

    def next_context(self, previous: RunContext) -> RunContext:
        """Carry trusted observation taint into the next Primary-model turn."""
        if self.observation_classification in {None, "PUBLIC"} or not self.taint_source_resource_ids:
            return previous
        sources = tuple(dict.fromkeys(previous.taint_source_resource_ids + self.taint_source_resource_ids))
        return replace(previous, context_taint_state="TAINTED", taint_source_resource_ids=sources)


@dataclass(frozen=True)
class _MeasuredShadowResult:
    result: ShadowResult
    claimed_elapsed_ms: int
    measured_elapsed_ms: int
    worker_startup_ms: int
    worker_cleanup_ms: int
    controller_total_ms: int


def _shadow_worker(adapter, envelope, connection) -> None:
    try:
        connection.send(("READY", None))
        if connection.recv() != "GO":
            return
        connection.send(("RESULT", adapter.evaluate(envelope)))
    except BaseException as exc:
        connection.send(("ERROR", type(exc).__name__))
    finally:
        connection.close()


class AgentController:
    def __init__(
        self,
        configuration: TrustedConfiguration,
        store: AppendOnlyEvidenceStore,
        shadow: ShadowAdapter,
        broker: CapabilityBroker,
        wrapper: InMemoryResourceWrapper,
        builder: EventBuilder | None = None,
        simulation_wrapper: IsolatedSimulationWrapper | None = None,
        *,
        tier2_execution_mode: str = "PRESENT",
    ) -> None:
        if tier2_execution_mode not in {"PRESENT", "ABSENT_BY_ARM_DESIGN"}:
            raise ValueError("invalid Tier 2 execution mode")
        if tier2_execution_mode == "PRESENT" and shadow is None:
            raise ValueError("PRESENT Tier 2 mode requires a Shadow adapter")
        if tier2_execution_mode == "ABSENT_BY_ARM_DESIGN" and shadow is not None:
            raise ValueError("ABSENT_BY_ARM_DESIGN forbids a Shadow adapter")
        self._configuration = configuration
        self._store = store
        self._shadow = shadow
        self._tier2_execution_mode = tier2_execution_mode
        worker_budgets = self._configuration.policy["shadow_budgets"]
        self._tier2_worker_startup_deadline_ms = worker_budgets["worker_startup_ms"]
        self._tier2_worker_cleanup_deadline_ms = worker_budgets["worker_cleanup_ms"]
        self._broker = broker
        self._wrapper = wrapper
        self._builder = builder or EventBuilder()
        self._simulation_wrapper = simulation_wrapper or IsolatedSimulationWrapper()
        if hasattr(self._simulation_wrapper, "seed_from_production"):
            classifications = {
                target: value["classification"] for target, value in self._configuration.objective["resources"].items()
            }
            self._simulation_wrapper.seed_from_production(self._wrapper.resources, classifications)
        self._tier1 = Tier1AssessmentService(configuration, store, self._builder)
        self._trajectory_guards: dict[tuple[str, str], Any] = {}
        self._challenged_proposals: dict[tuple[str, str], dict[str, Any]] = {}
        self._identical_reproposal_counts: dict[tuple[str, str], int] = {}
        self._observed_evidence: dict[str, Any] = {}
        from .completion import CompletionControlService, CompletionVerifier, CriterionRule, UserResponseWrapper
        criteria = tuple(configuration.objective["completion_criteria"])
        rules = {item: CriterionRule(("RETRIEVAL", "WRAPPER_EFFECT")) for item in criteria}
        self._completion = CompletionControlService(
            CompletionVerifier(criteria, rules), UserResponseWrapper(), store, self._builder
        )

    def record_model_subgoal(
        self, text: str, context: RunContext, provenance: ModelProvenance
    ) -> dict[str, Any]:
        """Production CP-02 entry point for a model-declared subgoal."""
        from .batch_b_controls import ModelControlPathRecorder
        return self._control_recorder().record_subgoal(text, context, provenance)

    def record_permission_request(
        self, text: str, context: RunContext, provenance: ModelProvenance
    ) -> dict[str, Any]:
        """Production CP-08 entry point; recording never grants authority."""
        from .batch_b_controls import ModelControlPathRecorder
        return self._control_recorder().record_permission_request(text, context, provenance)

    def record_shadow_free_text(
        self, text: str, context: RunContext, provenance: ModelProvenance
    ) -> dict[str, Any]:
        """Production entry point for passive, untrusted Shadow free text."""
        from .batch_b_controls import ModelControlPathRecorder
        return self._control_recorder().record_shadow_free_text(text, context, provenance)

    def _control_recorder(self):
        from .batch_b_controls import ModelControlPathRecorder
        return ModelControlPathRecorder(
            self._store, self._builder,
            policy_version=self._configuration.policy["version"],
            objective_version=self._configuration.objective["version"],
        )

    def complete_response(
        self, text: str, claimed_criteria: tuple[str, ...], cited_ids: tuple[str, ...], context: RunContext
    ) -> ControllerResult:
        from .completion import CompletionProposal
        if not self._store.read_all():
            raise ContractError("completion has no preceding system evidence")
        criteria = claimed_criteria
        selected = cited_ids
        mapping = {criterion: selected for criterion in criteria}
        classification = effective_classification(
            self._configuration.objective, "PUBLIC", context.taint_source_resource_ids
        )
        result = self._completion.complete(
            self._store.read_all()[-1], CompletionProposal(text, selected, criteria),
            self._observed_evidence, mapping,
            context_taint_state=context.context_taint_state,
            data_classification=classification,
            taint_source_resource_ids=context.taint_source_resource_ids,
        )
        return ControllerResult(result.status, (result.status,), result.events)

    def terminate_turn_bound(self) -> ControllerResult:
        events = self._store.read_all()
        if not events:
            raise ContractError("turn bound termination requires prior evidence")
        event = self._builder.followup_event(
            events[-1], "BLOCKED", authorization_state="UNAUTHORIZED", supervision_state="LATCHED",
            error_detail="bounded agent loop reached its turn limit",
        )
        recorded = self._store.append(event)
        return ControllerResult("TERMINATED", ("BLOCKED",), (recorded,))

    def process(
        self,
        untrusted_action: Any,
        context: RunContext,
        model_provenance: ModelProvenance | None = None,
        *,
        proposal_relation: str | None = None,
        identical_reproposal_count: int = 0,
    ) -> ControllerResult:
        tracker = StateTracker()
        tracker.transition("EVALUATING_ACTION")
        events: list[dict[str, Any]] = []
        context = replace(context, control_point_id=self._control_point_for(untrusted_action))
        from .batch_b_controls import TrajectoryGuard
        guard_key = (context.run_id, context.trace_id)
        if guard_key not in self._trajectory_guards:
            self._trajectory_guards[guard_key] = TrajectoryGuard(
                self._configuration.objective["resources"], "objective-anchor"
            )
        trajectory_guard = self._trajectory_guards[guard_key]
        trajectory = (
            trajectory_guard.assess(untrusted_action)
            if isinstance(untrusted_action, dict) and {"capability", "target"} <= set(untrusted_action)
            else None
        )
        assessed = self._tier1.assess(untrusted_action, context, model_provenance)
        events.append(assessed.event)
        source = assessed.event
        challenge_key = (context.run_id, context.trace_id)
        if proposal_relation is None and challenge_key in self._challenged_proposals and assessed.request is not None:
            from .batch_b_controls import proposal_relation as classify_relation
            proposal_relation = classify_relation(self._challenged_proposals[challenge_key], {
                "capability": assessed.request.capability,
                "target": assessed.request.target,
                "parameters": dict(assessed.request.parameters),
                "operation": assessed.request.operation,
            })
            if proposal_relation == "IDENTICAL":
                identical_reproposal_count = self._identical_reproposal_counts.get(challenge_key, 0) + 1
                self._identical_reproposal_counts[challenge_key] = identical_reproposal_count
            else:
                identical_reproposal_count = 0
                self._identical_reproposal_counts[challenge_key] = 0
        if proposal_relation is not None:
            relation_event = self._builder.followup_event(
                source, "REQUESTED", authorization_state="AMBIGUOUS",
                additional_result_provenance=(
                    f"challenge_proposal_relation:{proposal_relation}",
                    f"identical_reproposal_count:{identical_reproposal_count}",
                ),
            )
            source = self._store.append(relation_event)
            events.append(source)
            if proposal_relation == "IDENTICAL" and identical_reproposal_count >= 2:
                blocked = self._builder.followup_event(
                    source, "BLOCKED", authorization_state="UNAUTHORIZED", supervision_state="LATCHED",
                    error_detail="repeated identical proposal after challenge",
                    additional_result_provenance=("challenge_repeat_limit:2",),
                )
                events.append(self._store.append(blocked))
                tracker.transition("BLOCKED")
                return ControllerResult("BLOCKED", tuple(tracker.history), tuple(events))
        if trajectory is not None and not trajectory.allowed:
            event = self._builder.followup_event(
                source, "BLOCKED", authorization_state="UNAUTHORIZED", supervision_state="LATCHED",
                error_detail="trajectory broadening rejected by controller",
                additional_result_provenance=(f"trajectory_rule:{trajectory.rule}",),
            )
            event["trusted_metadata"]["tier1_reason_codes"] = ["T1_SEQ"]
            event["trusted_metadata"]["result_provenance"] = list(event["trusted_metadata"].get("result_provenance", ())) + ["trajectory_reason:T1_TRJ"]
            events.append(self._store.append(event))
            tracker.transition("BLOCKED")
            return ControllerResult("BLOCKED", tuple(tracker.history), tuple(events))
        if self._broker.is_epoch_revoked(context.decision_epoch):
            event = self._builder.followup_event(
                assessed.event, "BLOCKED", authorization_state="UNAUTHORIZED",
                supervision_state="LATCHED", error_detail="decision epoch revoked by supervision",
            )
            events.append(self._store.append(event))
            tracker.transition("BLOCKED")
            return ControllerResult("BLOCKED", tuple(tracker.history), tuple(events))
        if assessed.decision.disposition == "DENY":
            if context.execution_mode == "AUDIT" and assessed.request is not None:
                return self._execute_simulated(assessed.request, assessed.event, tracker, events)
            tracker.transition("BLOCKED")
            return ControllerResult("BLOCKED", tuple(tracker.history), tuple(events))
        action = assessed.request
        if action is None:
            tracker.transition("BLOCKED")
            return ControllerResult("BLOCKED", tuple(tracker.history), tuple(events))

        if assessed.decision.tier2_route == "SYNCHRONOUS" and self._tier2_execution_mode == "ABSENT_BY_ARM_DESIGN":
            counterfactual = self._builder.followup_event(
                # Preserve the determination Tier 1 actually made.  The arm's
                # counterfactual resolution permits execution without a Tier 2;
                # it must not rewrite AMBIGUOUS into a deterministic
                # authorization in the trusted evidence.
                source, "AUTHORIZED", authorization_state=assessed.decision.authorization_state,
                tier2_outcome="NOT_RUN", tier2_termination_reason="NOT_RUN",
                additional_result_provenance=(
                    "tier2_execution_mode:ABSENT_BY_ARM_DESIGN",
                    "tier1_policy_route:SYNCHRONOUS",
                    "counterfactual_arm:TIER1_ONLY",
                    "counterfactual_resolution:PROCEED_WITHOUT_TIER2",
                ),
            )
            source = self._store.append(counterfactual)
            events.append(source)
            tracker.transition("AUTHORIZED")
        elif assessed.decision.tier2_route == "SYNCHRONOUS":
            tracker.transition("AWAITING_TIER2")
            measured = self._evaluate_shadow(action, assessed.decision, context)
            shadow = measured.result
            if shadow.rationale:
                provenance = ModelProvenance(
                    shadow.provider_request_id or "shadow-local", shadow.provider_model or "shadow-scripted",
                    shadow.tokens_used, shadow.response_sha256 or "sha256:" + "0" * 64,
                    measured.measured_elapsed_ms, "stop", shadow.ignored_provider_fields,
                )
                events.append(self.record_shadow_free_text(shadow.rationale, context, provenance))
            outcome = self._effective_outcome(shadow, assessed.decision.risk_class)
            status, authorization, supervision = FINAL_FOR_OUTCOME[outcome]
            diagnostic = {
                "TIMEOUT": "TIER2_TIMEOUT",
                "TOKEN_BUDGET_EXHAUSTED": "TIER2_TOKEN_EXHAUSTED",
                "SCHEMA_FAILURE": "FAILED",
                "SYSTEM_ERROR": "FAILED",
            }.get(shadow.termination_reason, status)
            diagnostic_status = shadow.termination_reason != "COMPLETED"
            decision_event = self._builder.followup_event(
                source, diagnostic, authorization_state="AMBIGUOUS" if diagnostic_status else authorization,
                supervision_state=supervision, tier2_outcome=shadow.outcome,
                tier2_termination_reason=shadow.termination_reason,
                tier2_reason_codes=shadow.reason_codes, tier2_time_ms=measured.measured_elapsed_ms,
                error_detail=f"adapter_claimed_elapsed_ms={measured.claimed_elapsed_ms};controller_measured_elapsed_ms={measured.measured_elapsed_ms}",
                additional_result_provenance=self._shadow_provenance(shadow) + (
                    f"tier2_worker_startup_ms:{measured.worker_startup_ms}",
                    f"tier2_shadow_evaluation_ms:{measured.measured_elapsed_ms}",
                    f"tier2_worker_cleanup_ms:{measured.worker_cleanup_ms}",
                    f"tier2_controller_total_ms:{measured.controller_total_ms}",
                ),
            )
            # tier_2_shadow_time_ms remains evaluation-only. The critical path
            # additionally includes isolated-worker startup and cleanup.
            decision_event["trusted_metadata"]["timing"]["critical_path_latency_ms"] += max(
                0, measured.controller_total_ms - measured.measured_elapsed_ms
            )
            decision_event = self._store.append(decision_event)
            events.append(decision_event)
            source = decision_event
            if outcome != "ALLOW":
                if outcome == "CHALLENGE":
                    self._challenged_proposals[challenge_key] = {
                        "capability": action.capability, "target": action.target,
                        "parameters": dict(action.parameters), "operation": action.operation,
                    }
                else:
                    self._challenged_proposals.pop(challenge_key, None)
                    self._identical_reproposal_counts.pop(challenge_key, None)
                if context.execution_mode == "AUDIT" and outcome == "BLOCK":
                    return self._execute_simulated(action, source, tracker, events)
                if diagnostic_status:
                    final_event = self._builder.followup_event(
                        source, status, authorization_state=authorization, supervision_state=supervision
                    )
                    events.append(self._store.append(final_event))
                state = "HELD_FOR_ESCALATION" if outcome == "ESCALATE" else status
                tracker.transition(state)
                hold = EscalationHold.start(self._configuration.policy["escalation_deadline_ms"]) if outcome == "ESCALATE" else None
                return ControllerResult(status, tuple(tracker.history), tuple(events), escalation_hold=hold)

            self._challenged_proposals.pop(challenge_key, None)
            self._identical_reproposal_counts.pop(challenge_key, None)
            tracker.transition("AUTHORIZED")

        else:
            tracker.transition("AUTHORIZED")
        if context.execution_mode == "AUDIT" and self._simulation_wrapper.should_route(action.target):
            return self._execute_simulated(action, source, tracker, events)
        tracker.transition("EXECUTING")
        # Normally the source is AUTHORIZED.  The explicit Tier-2-absent L7
        # counterfactual deliberately executes an AMBIGUOUS Tier 1 decision;
        # retain that fact throughout the lifecycle instead of laundering it
        # into a deterministic authorization at the wrapper boundary.
        execution_authorization_state = source["trusted_metadata"]["authorization_state"]
        try:
            token = self._broker.issue(action, self._wrapper.wrapper_id, context.decision_epoch)
        except ContractError as exc:
            event = self._builder.followup_event(
                source, "NOT_STARTED_REVOKED", authorization_state="UNAUTHORIZED",
                supervision_state="LATCHED", error_detail=str(exc),
            )
            events.append(self._store.append(event))
            tracker.transition("NOT_STARTED_REVOKED")
            return ControllerResult("NOT_STARTED_REVOKED", tuple(tracker.history), tuple(events))
        try:
            wrapper_result = self._wrapper.execute(token, action, self._broker, context.decision_epoch)
        except Exception as exc:
            event = self._builder.followup_event(
                source, "FAILED", authorization_state=execution_authorization_state,
                evidence_provenance=("CONTROLLER_OBSERVED",), error_detail=f"wrapper failure: {type(exc).__name__}",
            )
            events.append(self._store.append(event))
            tracker.transition("OBSERVING_RESULT")
            return ControllerResult("FAILED", tuple(tracker.history), tuple(events))
        if wrapper_result.status == "EXECUTED":
            event = self._builder.followup_event(
                source, "EXECUTED", authorization_state=execution_authorization_state,
                evidence_provenance=("CONTROLLER_OBSERVED", "TOOL_OBSERVED"),
            )
            final_state = "OBSERVING_RESULT"
        else:
            event = self._builder.followup_event(source, wrapper_result.status, authorization_state=execution_authorization_state)
            final_state = wrapper_result.status
        events.append(self._store.append(event))
        if wrapper_result.status == "EXECUTED":
            from .completion import ObservedArtifact
            evidence_id = event["trusted_metadata"]["event_id"]
            observed = wrapper_result.observed_result or ""
            self._observed_evidence[evidence_id] = ObservedArtifact(
                evidence_id, action.target, "sha256:" + hashlib.sha256(observed.encode()).hexdigest(),
                observed_text=observed,
            )
        tracker.transition(final_state)
        resource = self._configuration.objective["resources"].get(action.target, {})
        observation_classification = resource.get("classification", wrapper_result.data_classification)
        taint_sources = (
            (action.target,) if action.capability == "read_file" and observation_classification != "PUBLIC" else ()
        )
        return ControllerResult(
            wrapper_result.status, tuple(tracker.history), tuple(events), wrapper_result,
            observation_classification=observation_classification,
            taint_source_resource_ids=taint_sources,
        )

    @staticmethod
    def _control_point_for(untrusted_action: Any) -> str:
        if not isinstance(untrusted_action, dict):
            return "CP-01"
        capability = untrusted_action.get("capability")
        if capability == "read_file":
            return "CP-03"
        if capability in {"write_file", "write_summary"}:
            return "CP-04"
        if capability == "network_request":
            return "CP-05"
        if capability in {"context_write", "compact_context"}:
            return "CP-07"
        if capability in {"cross_agent_message", "handoff"}:
            return "CP-09"
        return "CP-06"

    def _execute_simulated(
        self,
        action: ActionRequest,
        source: dict[str, Any],
        tracker: StateTracker,
        events: list[dict[str, Any]],
    ) -> ControllerResult:
        tracker.transition("EXECUTING_SIMULATED")
        try:
            simulated = self._simulation_wrapper.execute(action)
        except Exception as exc:
            event = self._builder.followup_event(
                source, "FAILED", authorization_state=source["trusted_metadata"]["authorization_state"],
                evidence_provenance=("CONTROLLER_OBSERVED", "ENVIRONMENT_OBSERVED"),
                error_detail=f"simulation failure: {type(exc).__name__}",
            )
            events.append(self._store.append(event))
            tracker.transition("OBSERVING_RESULT")
            return ControllerResult("FAILED", tuple(tracker.history), tuple(events))
        event = self._builder.followup_event(
            source, "EXECUTED_SIMULATED", authorization_state=source["trusted_metadata"]["authorization_state"],
            evidence_provenance=("CONTROLLER_OBSERVED", "TOOL_OBSERVED", "ENVIRONMENT_OBSERVED"),
            data_classification=simulated.data_classification,
            context_taint_state="TAINTED" if simulated.taint_source_resource_ids else source["trusted_metadata"]["context_taint_state"],
            taint_source_resource_ids=tuple(dict.fromkeys(
                tuple(source["trusted_metadata"].get("taint_source_resource_ids", ())) + simulated.taint_source_resource_ids
            )),
            additional_result_provenance=simulated.result_provenance,
        )
        events.append(self._store.append(event))
        tracker.transition("OBSERVING_RESULT")
        return ControllerResult(
            "EXECUTED_SIMULATED", tuple(tracker.history), tuple(events), simulated,
            observation_classification=simulated.data_classification,
            taint_source_resource_ids=simulated.taint_source_resource_ids,
        )

    def enforce_expired_escalation(self, result: ControllerResult) -> ControllerResult:
        if result.escalation_hold is None or result.escalation_hold.disposition() != "BLOCKED":
            return result
        source = result.events[-1]
        event = self._builder.followup_event(
            source, "BLOCKED", authorization_state="UNAUTHORIZED", supervision_state="HELD_FOR_ESCALATION",
            error_detail="escalation deadline expired",
        )
        recorded = self._store.append(event)
        return ControllerResult("BLOCKED", result.states + ("BLOCKED",), result.events + (recorded,))

    def _evaluate_shadow(self, action: ActionRequest, decision, context: RunContext) -> _MeasuredShadowResult:
        controller_started = monotonic_ns()

        def elapsed_ms(since: int) -> int:
            return max(0, (monotonic_ns() - since + 999_999) // 1_000_000)

        def measured_result(
            result: ShadowResult,
            claimed_ms: int,
            evaluation_ms: int,
            startup_ms: int,
            cleanup_ms: int,
        ) -> _MeasuredShadowResult:
            return _MeasuredShadowResult(
                result, claimed_ms, evaluation_ms, startup_ms, cleanup_ms, elapsed_ms(controller_started)
            )

        def bounded_cleanup(process) -> int:
            cleanup_started = monotonic_ns()
            if process.is_alive():
                process.terminate()
            process.join(self._tier2_worker_cleanup_deadline_ms / 1000)
            if process.is_alive():
                process.kill()
                process.join(self._tier2_worker_cleanup_deadline_ms / 1000)
            return elapsed_ms(cleanup_started)

        budgets = self._configuration.policy["shadow_budgets"]
        envelope = ShadowEvaluationEnvelope(
            action, decision.risk_class, decision.reason_codes, context.trace_id,
            context.decision_epoch, budgets["time_ms"], budgets["tokens"],
            effective_classification(
                self._configuration.objective,
                self._configuration.objective["resources"][action.target]["classification"],
                context.taint_source_resource_ids,
            ),
            context.context_taint_state,
            self._shadow_objective_summary(),
            self._anchored_trajectory(8),
        )
        process_context = multiprocessing.get_context("spawn")
        parent, child = process_context.Pipe(duplex=True)
        process = process_context.Process(target=_shadow_worker, args=(self._shadow, envelope, child), daemon=True)
        process.start()
        child.close()
        if not parent.poll(self._tier2_worker_startup_deadline_ms / 1000):
            startup_ms = elapsed_ms(controller_started)
            cleanup_ms = bounded_cleanup(process)
            parent.close()
            result = ShadowResult("INDETERMINATE", "SYSTEM_ERROR", ("T2_SHD_ADAPTER_FAILURE",), 0, 0)
            return measured_result(result, 0, 0, startup_ms, cleanup_ms)
        try:
            ready, _ = parent.recv()
        except EOFError:
            startup_ms = elapsed_ms(controller_started)
            cleanup_ms = bounded_cleanup(process)
            parent.close()
            result = ShadowResult("INDETERMINATE", "SYSTEM_ERROR", ("T2_SHD_ADAPTER_FAILURE",), 0, 0)
            return measured_result(result, 0, 0, startup_ms, cleanup_ms)
        if ready != "READY":
            startup_ms = elapsed_ms(controller_started)
            cleanup_ms = bounded_cleanup(process)
            parent.close()
            result = ShadowResult("INDETERMINATE", "SYSTEM_ERROR", ("T2_SHD_ADAPTER_FAILURE",), 0, 0)
            return measured_result(result, 0, 0, startup_ms, cleanup_ms)
        startup_ms = elapsed_ms(controller_started)
        started = monotonic_ns()
        parent.send("GO")
        process.join(budgets["time_ms"] / 1000)
        measured_ms = elapsed_ms(started)
        if process.is_alive():
            cleanup_ms = bounded_cleanup(process)
            parent.close()
            result = ShadowResult("INDETERMINATE", "TIMEOUT", ("T2_SHD_TIMEOUT",), measured_ms, 0)
            return measured_result(result, 0, measured_ms, startup_ms, cleanup_ms)
        try:
            kind, payload = parent.recv() if parent.poll() else ("ERROR", "NoResult")
        finally:
            parent.close()
        if kind != "RESULT":
            result = ShadowResult("INDETERMINATE", "SYSTEM_ERROR", ("T2_SHD_ADAPTER_FAILURE",), measured_ms, 0)
            return measured_result(result, 0, measured_ms, startup_ms, 0)
        if not isinstance(payload, ShadowResult):
            result = ShadowResult("INDETERMINATE", "SCHEMA_FAILURE", ("T2_SHD_SCHEMA_FAILURE",), measured_ms, 0)
            return measured_result(result, 0, measured_ms, startup_ms, 0)
        claimed = payload.elapsed_ms
        if payload.tokens_used > budgets["tokens"]:
            result = ShadowResult("INDETERMINATE", "TOKEN_BUDGET_EXHAUSTED", ("T2_SHD_TOKEN_EXHAUSTED",), measured_ms, budgets["tokens"])
        else:
            result = ShadowResult(
                payload.outcome, payload.termination_reason, payload.reason_codes, measured_ms, payload.tokens_used,
                payload.provider_request_id, payload.provider_model, payload.response_sha256, payload.ignored_provider_fields,
                payload.rationale,
            )
        return measured_result(result, claimed, measured_ms, startup_ms, 0)

    @staticmethod
    def _shadow_provenance(result: ShadowResult) -> tuple[str, ...]:
        if result.provider_request_id is None:
            return ()
        return (
            f"shadow_provider_request_id:{result.provider_request_id}",
            f"shadow_model:{result.provider_model}",
            f"shadow_total_tokens:{result.tokens_used}",
            f"shadow_response:{result.response_sha256}",
            "shadow_ignored_provider_fields:" + ",".join(result.ignored_provider_fields),
        )

    def _shadow_objective_summary(self) -> dict[str, Any]:
        objective = self._configuration.objective
        return {
            "objective_id": objective["objective_id"],
            "version": objective["version"],
            "purpose": objective["purpose"],
            "resources": {key: dict(value) for key, value in objective["resources"].items()},
            "allowed_capabilities": {
                key: {"targets": list(value["targets"]), "parameters": {name: list(items) for name, items in value["parameters"].items()}, "risk": value["risk"]}
                for key, value in objective["allowed_capabilities"].items()
            },
            "prohibited_capabilities": list(objective["prohibited_capabilities"]),
            "allowed_destinations": list(objective["allowed_destinations"]),
            "completion_criteria": list(objective["completion_criteria"]),
            "termination_conditions": list(objective["termination_conditions"]),
            "declassification_rules": dict(objective["declassification_rules"]),
            "capability_exposure": objective["capability_exposure"],
        }

    def _anchored_trajectory(self, limit: int) -> tuple[dict[str, Any], ...]:
        source = self._store.enforcement if hasattr(self._store, "enforcement") else self._store
        events = source.read_all()[-limit:]
        return tuple({
            "event_id": event["trusted_metadata"]["event_id"],
            "event_hash": event["trusted_metadata"]["integrity"]["event_hash"],
            "execution_status": event["trusted_metadata"]["execution_status"],
            "capability_id": event["trusted_metadata"]["capability_id"],
            "action_origin": event["trusted_metadata"]["action_origin"],
            "risk_class": event["trusted_metadata"]["risk_class"],
            "authorization_state": event["trusted_metadata"]["authorization_state"],
        } for event in events)

    def _effective_outcome(self, result: ShadowResult, risk: str) -> str:
        if result.outcome != "INDETERMINATE" and result.termination_reason == "COMPLETED":
            return result.outcome
        return self._configuration.policy["tier2_fail_safe"][risk]
