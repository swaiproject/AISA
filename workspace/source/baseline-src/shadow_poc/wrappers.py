"""Isolated in-memory wrappers for Increment 2 integration tests."""

from __future__ import annotations

from dataclasses import dataclass

from .capability_broker import CapabilityBroker, ExecutionToken
from .contracts import ActionRequest
from .errors import ContractError
from .simulation import StatefulAuditEnvironment


@dataclass(frozen=True)
class WrapperResult:
    status: str
    observed_result: str | None
    result_provenance: tuple[str, ...] = ()
    data_classification: str = "PUBLIC"
    taint_source_resource_ids: tuple[str, ...] = ()


class InMemoryResourceWrapper:
    wrapper_id = "mock-resource-wrapper-v1"

    def __init__(self, resources: dict[str, str] | None = None) -> None:
        self.resources = dict(resources or {})

    def execute(
        self,
        token: ExecutionToken,
        action: ActionRequest,
        broker: CapabilityBroker,
        decision_epoch: int,
    ) -> WrapperResult:
        status = broker.begin(token, action, self.wrapper_id, decision_epoch)
        if status != "ACTIVE":
            return WrapperResult(status, None)
        status = broker.authorize_effect(token)
        if status != "ACTIVE":
            return WrapperResult(status, None)
        if action.capability == "read_file":
            observed = self.resources.get(action.target, "synthetic-content")
        elif action.capability == "bounded_search":
            import json
            limit = action.parameters.get("limit")
            dry_run = action.parameters.get("dry_run")
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20 or dry_run is not True:
                raise ContractError("fixture search requires a bounded limit and dry_run true")
            entries = self.resources.get(action.target, "PUBLIC synthetic search fixture entry").splitlines()
            observed = json.dumps({"fixture_only": True, "target": action.target,
                                   "limit": limit, "dry_run": True,
                                   "results": entries[:limit]}, sort_keys=True)
        elif action.capability == "write_summary":
            observed = "synthetic-summary-written"
            self.resources[action.target] = observed
        elif action.capability == "context_write":
            observed = "context-write-authorized"
        elif action.capability == "network_request":
            observed = "synthetic-network-response"
        elif action.capability == "create_account":
            observed = "synthetic-account-created"
            self.resources[action.target] = observed
        elif action.capability == "cross_agent_message":
            observed = "synthetic-cross-agent-message-recorded"
            self.resources[action.target] = observed
        else:
            raise ContractError(f"mock wrapper does not implement {action.capability!r}")
        broker.complete(token)
        return WrapperResult("EXECUTED", observed)



class StatefulSimulationWrapper:
    """AUDIT-only adapter over a network-inert stateful environment."""

    wrapper_id = "stateful-simulation-wrapper-v2"

    def __init__(self, environment: StatefulAuditEnvironment | None = None) -> None:
        self.environment = environment or StatefulAuditEnvironment()

    def execute(self, action: ActionRequest) -> WrapperResult:
        effect = self.environment.execute(action)
        return WrapperResult(
            effect.status, effect.observed_result, effect.provenance(self.environment.environment_id),
            effect.data_classification, effect.taint_source_ids,
        )

    def seed_from_production(self, resources: dict[str, str], classifications: dict[str, str]) -> None:
        self.environment.seed_from_production(resources, classifications)

    def should_route(self, target: str) -> bool:
        return self.environment.is_touched(target)

    @property
    def simulated_effects(self) -> list[tuple[str, str]]:
        return [(item.capability, item.target) for item in self.environment.history]


class IsolatedSimulationWrapper(StatefulSimulationWrapper):
    """Compatibility name retained for earlier controller integrations."""
