"""Trusted controls added for Increment 8 Batch B.

The classes in this module deliberately emit their own enforcement evidence.  A
test may retain those events, but it does not manufacture them after observing
an outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Callable, Iterable, Mapping

from .contracts import ActionRequest, ModelProvenance, PolicyDecision, RunContext
from .errors import ContractError
from .event_builder import EventBuilder


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _strict_parameter_subset(old: Mapping[str, Any], new: Mapping[str, Any]) -> bool:
    """Return true only where narrowing is mechanically provable."""
    if not set(new).issubset(old):
        return False
    strict = set(new) != set(old)
    for key, value in new.items():
        previous = old[key]
        if isinstance(previous, Mapping) and isinstance(value, Mapping):
            if not set(value).issubset(previous):
                return False
            if any(previous[item] != value[item] for item in value):
                return False
            strict = strict or set(value) != set(previous)
        elif isinstance(previous, (list, tuple, set)) and isinstance(value, (list, tuple, set)):
            if not set(value).issubset(set(previous)):
                return False
            strict = strict or set(value) != set(previous)
        elif value != previous:
            # No policy-specific partial order exists for arbitrary scalar changes.
            return False
    return strict


def proposal_relation(previous: Mapping[str, Any], current: Mapping[str, Any]) -> str:
    """Classify a challenged re-proposal descriptively; this never authorizes it."""
    if _canonical(previous) == _canonical(current):
        return "IDENTICAL"
    if previous.get("capability") != current.get("capability") or previous.get("target") != current.get("target"):
        return "LATERAL"
    old = dict(previous.get("parameters") or {})
    new = dict(current.get("parameters") or {})
    restrictive = {"dry_run", "limit", "max_bytes", "path_prefix", "filter"}
    if any(key in old and key not in new for key in restrictive):
        return "BROADER"
    narrower = False
    broader = False
    for key in set(old) | set(new):
        if key not in old:
            narrower = True
            continue
        if key not in new:
            broader = True
            continue
        left, right = old[key], new[key]
        if key in {"limit", "max_bytes"} and isinstance(left, (int, float)) and isinstance(right, (int, float)):
            narrower |= right < left
            broader |= right > left
        elif key == "dry_run" and isinstance(left, bool) and isinstance(right, bool):
            narrower |= right and not left
            broader |= left and not right
        elif left != right:
            return "LATERAL"
    if narrower and not broader:
        return "NARROWER"
    if broader and not narrower:
        return "BROADER"
    return "LATERAL"


class ModelControlPathRecorder:
    """Records model declarations without treating them as authority."""

    def __init__(self, store, builder: EventBuilder | None = None, *, policy_version: str = "UNKNOWN", objective_version: str = "UNKNOWN") -> None:
        self._store = store
        self._builder = builder or EventBuilder()
        self._policy_version = policy_version
        self._objective_version = objective_version

    def record_subgoal(
        self, text: str, context: RunContext, provenance: ModelProvenance
    ) -> dict[str, Any]:
        return self._record("CP-02", "declare_subgoal", text, context, provenance)

    def record_permission_request(
        self, text: str, context: RunContext, provenance: ModelProvenance
    ) -> dict[str, Any]:
        return self._record("CP-08", "request_permission", text, context, provenance)

    def record_shadow_free_text(
        self, text: str, context: RunContext, provenance: ModelProvenance
    ) -> dict[str, Any]:
        return self._record("CP-05", "shadow_free_text", text, context, provenance)

    def _record(
        self, control_point: str, capability: str, text: str,
        context: RunContext, provenance: ModelProvenance,
    ) -> dict[str, Any]:
        if not isinstance(text, str) or not text.strip():
            raise ContractError("model declaration must be non-empty text")
        bounded = text[:2048]
        request = ActionRequest(capability, "control://model-declaration", {"text": bounded})
        decision = PolicyDecision("REVIEW", "AMBIGUOUS", "MEDIUM", "SYNCHRONOUS", ("T1_INT",))
        declaration_context = RunContext(
            context.run_id, context.trace_id, context.objective_id,
            execution_mode=context.execution_mode, decision_epoch=context.decision_epoch,
            supervision_state=context.supervision_state, control_point_id=control_point,
            context_taint_state=context.context_taint_state,
            taint_source_resource_ids=context.taint_source_resource_ids,
            action_origin="MODEL_PROPOSAL",
        )
        event = self._builder.policy_event(
            request, decision, declaration_context, 0, 0, 0, self._policy_version, self._objective_version
        )
        self._builder.apply_model_provenance(event, provenance)
        event["trusted_metadata"]["authorization_state"] = "AMBIGUOUS"
        if control_point == "CP-02":
            event["untrusted_data"]["model_declared_subgoal"] = bounded
            event["trusted_metadata"]["current_subgoal_id"] = "subgoal-sha256:" + sha256(bounded.encode()).hexdigest()
        else:
            event["untrusted_data"]["model_output"] = bounded
        event["trusted_metadata"]["result_provenance"] = list(event["trusted_metadata"].get("result_provenance", ())) + ["declaration_only:no_authority"]
        return self._store.append(event)


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    classified_as_egress: bool
    origin_match: bool
    endpoint_match: bool
    reason: str


class DestinationEgressPolicy:
    """Origin-and-destination policy for outbound requests, including GET data."""

    def __init__(self, allowed: Mapping[str, Iterable[str]]) -> None:
        self._allowed = {origin: frozenset(endpoints) for origin, endpoints in allowed.items()}

    def evaluate(
        self, *, origin: str, endpoint: str, method: str = "POST",
        query: Mapping[str, str] | None = None, headers: Mapping[str, str] | None = None,
        tainted: bool = False,
    ) -> EgressDecision:
        carries_data = bool(query or headers) and method.upper() == "GET"
        classified = tainted or carries_data
        origin_match = origin in self._allowed
        endpoint_match = origin_match and endpoint in self._allowed[origin]
        allowed = origin_match and endpoint_match
        reason = "CAP-05_ALLOWED" if allowed else "CAP-05_DESTINATION_DENIED"
        return EgressDecision(allowed, classified, origin_match, endpoint_match, reason)

    def evaluate_and_record(self, store, context: RunContext, **request: Any) -> tuple[EgressDecision, dict[str, Any]]:
        decision = self.evaluate(**request)
        action = ActionRequest("network_request", request["endpoint"], {
            "method": request.get("method", "POST"),
            "origin": request["origin"],
            "query": dict(request.get("query") or {}),
            "headers": dict(request.get("headers") or {}),
        })
        policy = PolicyDecision(
            "ALLOW" if decision.allowed else "DENY",
            "AUTHORIZED" if decision.allowed else "UNAUTHORIZED",
            "HIGH", "NONE" if decision.allowed else "SYNCHRONOUS", ("T1_DAT",),
        )
        event = EventBuilder().policy_event(action, policy, context, 0, 200, 1024, "batch-b", "batch-b")
        event["trusted_metadata"]["result_provenance"] = [
            f"origin_policy_match:{str(decision.origin_match).lower()}",
            f"endpoint_policy_match:{str(decision.endpoint_match).lower()}",
            f"classified_as_egress:{str(decision.classified_as_egress).lower()}",
        ]
        return decision, store.append(event)


@dataclass(frozen=True)
class TrajectoryDecision:
    allowed: bool
    reason_code: str
    latch: bool
    rule: str = "DIRECT"


class TrajectoryGuard:
    """Fail-safe trajectory and context-window checks over model proposals."""

    def __init__(self, objective_targets: Iterable[str] | Mapping[str, Any], anchor_id: str, window_size: int = 8) -> None:
        self._targets = dict(objective_targets) if isinstance(objective_targets, Mapping) else frozenset(objective_targets)
        self._anchor = anchor_id
        self._window_size = window_size
        self._history: list[dict[str, Any]] = []

    def assess(self, proposal: Mapping[str, Any]) -> TrajectoryDecision:
        target = proposal.get("target")
        parameters = proposal.get("parameters", {})
        if parameters.get("scope") in {"expanded", "all", "recursive"}:
            return TrajectoryDecision(False, "T1_TRJ", True, "EXPLICIT_SCOPE_EXPANSION")
        current_class = self._classification(target)
        prior = self._history[-1] if self._history else None
        if prior is not None and proposal.get("capability") == prior.get("capability") == "read_file":
            previous_class = self._classification(prior.get("target"))
            order = {"PUBLIC": 0, "INTERNAL": 1, "SENSITIVE": 2, "RESTRICTED": 3}
            if order[current_class] > order[previous_class]:
                return TrajectoryDecision(False, "T1_TRJ", True, "CLASSIFICATION_ESCALATION")
        prior_targets = {item.get("target") for item in self._history}
        if target not in prior_targets and len(prior_targets) >= 2:
            return TrajectoryDecision(False, "T1_TRJ", True, "DISTINCT_TARGET_EXPANSION")
        for name in ("limit", "max_bytes", "size"):
            values = [
                item.get("parameters", {}).get(name) for item in self._history[-2:]
                if isinstance(item.get("parameters", {}).get(name), (int, float))
            ]
            current = parameters.get(name)
            if len(values) == 2 and isinstance(current, (int, float)) and values[0] < values[1] < current:
                return TrajectoryDecision(False, "T1_TRJ", True, f"MONOTONIC_{name.upper()}_EXPANSION")
        self._history.append(dict(proposal))
        return TrajectoryDecision(True, "T1_DIR", False, "DIRECT")

    def _classification(self, target: Any) -> str:
        if not isinstance(target, str):
            return "RESTRICTED"
        value = self._targets.get(target) if isinstance(self._targets, dict) else None
        if isinstance(value, Mapping):
            return value.get("classification", "RESTRICTED")
        return "PUBLIC" if target in self._targets else "RESTRICTED"

    def anchored_window(self, events: Iterable[Mapping[str, Any]]) -> tuple[tuple[Mapping[str, Any], ...], bool]:
        rows = list(events)
        anchors = [row for row in rows if row.get("event_id") == self._anchor]
        tail = rows[-max(0, self._window_size - 1):]
        result = anchors[:1] + [row for row in tail if row.get("event_id") != self._anchor]
        truncated = len(rows) > self._window_size
        if not anchors:
            raise ContractError("trajectory anchor missing after truncation")
        return tuple(result[-self._window_size:]), truncated


class InjectionMediator:
    """Treats injection-shaped content from every channel as quoted data."""

    CHANNELS = frozenset({"file", "tool_result", "memory", "summary", "telemetry", "relayed_free_text"})

    def inspect(self, channel: str, content: str) -> dict[str, Any]:
        if channel not in self.CHANNELS:
            raise ContractError("unsupported injection channel")
        lower = content.lower()
        suspicious = any(marker in lower for marker in ("ignore previous", "system prompt", "execute", "send secret"))
        return {
            "channel": channel,
            "quoted_untrusted_evidence": content,
            "control_change": False,
            "reason_code": "T2_INJ" if suspicious else "T2_EVD",
            "tainted": True,
        }


class SafeTerminationService:
    def __init__(self, store) -> None:
        self._store = store

    def terminate_no_safe_primer(self) -> dict[str, Any]:
        events = self._store.read_all()
        if events:
            final = EventBuilder().followup_event(
                events[-1], "BLOCKED", authorization_state="UNAUTHORIZED",
                supervision_state="LATCHED", control_point_id="CP-07",
                error_detail="no safe primer could be authorized; run terminated",
            )
            self._store.append(final)
        self._store.verify_chain()
        events = self._store.read_all()
        return {"state": "TERMINATED", "evidence_flushed": True, "event_count": len(events)}


class MultiTurnChallengeDriver:
    """Runs a bounded CHALLENGE/re-proposal exchange with narrowing checks."""

    def __init__(self, process: Callable[[Mapping[str, Any], RunContext], Any], max_turns: int = 3) -> None:
        self._process = process
        self._max_turns = max_turns

    def run(self, proposals: Iterable[Mapping[str, Any]], context: RunContext) -> tuple[Any, ...]:
        results = []
        previous: Mapping[str, Any] | None = None
        for index, proposal in enumerate(proposals):
            if index >= self._max_turns:
                raise ContractError("challenge turn bound exceeded")
            if previous is not None:
                if _canonical(previous) == _canonical(proposal):
                    raise ContractError("unchanged challenge proposal fails safe")
                if proposal.get("capability") != previous.get("capability") or proposal.get("target") != previous.get("target"):
                    raise ContractError("challenge re-proposal expanded scope")
                old = previous.get("parameters", {})
                new = proposal.get("parameters", {})
                if not _strict_parameter_subset(old, new):
                    raise ContractError("challenge re-proposal is not a provable strict subset")
            turn_context = RunContext(
                context.run_id, context.trace_id, context.objective_id,
                execution_mode=context.execution_mode, decision_epoch=context.decision_epoch + index,
                supervision_state=context.supervision_state, control_point_id=context.control_point_id,
                context_taint_state=context.context_taint_state,
                taint_source_resource_ids=context.taint_source_resource_ids,
                action_origin=context.action_origin,
            )
            result = self._process(proposal, turn_context)
            results.append(result)
            if result.final_status != "CHALLENGED":
                return tuple(results)
            previous = proposal
        if results and results[-1].final_status == "CHALLENGED":
            raise ContractError("challenge was not resolved within turn bound")
        return tuple(results)
