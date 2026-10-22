"""Production-shaped recording of independently observed control outcomes."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import ActionRequest, PolicyDecision, RunContext
from .event_builder import EventBuilder
from .evidence_store import AppendOnlyEvidenceStore


@dataclass
class RuntimeControlEvidence:
    store: AppendOnlyEvidenceStore
    policy_version: str = "poc-policy-v0.1"
    objective_version: str = "0.1"

    def record(
        self,
        *,
        run_id: str,
        trace_id: str,
        capability: str,
        target: str,
        status: str,
        control_point_id: str,
        reason_code: str = "T1_SCH",
        detail: str | None = None,
    ) -> tuple[dict, dict]:
        builder = EventBuilder()
        request = ActionRequest.from_untrusted({"capability": capability, "target": target, "parameters": {}})
        context = RunContext(
            run_id, trace_id, "OBJ-DEMO-001", control_point_id=control_point_id,
            action_origin="HARNESS",
        )
        requested = builder.policy_event(
            request,
            PolicyDecision("REVIEW", "AMBIGUOUS", "HIGH", "SYNCHRONOUS", (reason_code,)),
            context, 0, 100, 100, self.policy_version, self.objective_version,
        )
        requested["trusted_metadata"]["evidence_provenance"] = ["HARNESS_OBSERVED"]
        requested = self.store.append(requested)
        observed = builder.followup_event(
            requested, status,
            authorization_state="AUTHORIZED" if status in {"EXECUTED", "EXECUTED_SIMULATED"} else None,
            tier2_outcome="ALLOW" if status in {"EXECUTED", "EXECUTED_SIMULATED"} else None,
            tier2_termination_reason="COMPLETED" if status in {"EXECUTED", "EXECUTED_SIMULATED"} else None,
            control_point_id=control_point_id,
            evidence_provenance=("HARNESS_OBSERVED",), error_detail=detail,
        )
        if status == "EXECUTED_SIMULATED":
            observed["trusted_metadata"]["execution_mode"] = "AUDIT"
        return requested, self.store.append(observed)
