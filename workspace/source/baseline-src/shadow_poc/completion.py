"""Completion, result-provenance, and user-response release controls."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping
from uuid import uuid4
import hashlib
from datetime import datetime, timezone
import re

from .errors import ContractError
from .event_builder import EventBuilder


@dataclass(frozen=True)
class ObservedRetrieval:
    retrieval_id: str
    source_uri: str
    content_hash: str
    status: str = "SUCCEEDED"
    observed_text: str | None = None

    @property
    def evidence_id(self) -> str:
        return self.retrieval_id

    @property
    def evidence_type(self) -> str:
        return "RETRIEVAL"


@dataclass(frozen=True)
class ObservedArtifact:
    evidence_id: str
    resource_uri: str
    content_hash: str
    status: str = "SUCCEEDED"
    observed_text: str | None = None
    evidence_type: str = "WRAPPER_EFFECT"


@dataclass(frozen=True)
class CriterionRule:
    evidence_types: tuple[str, ...]
    require_response_grounding: bool = False


@dataclass(frozen=True)
class EgressAuthorization:
    actor: str
    authorization_event_id: str

    def __post_init__(self) -> None:
        if self.actor not in {"HARNESS", "OPERATOR", "DECLASSIFICATION_EVENT"}:
            raise ContractError("egress authority must be harness, operator, or declassification event")
        if not self.authorization_event_id:
            raise ContractError("egress authorization requires an event identifier")


@dataclass(frozen=True)
class CompletionProposal:
    model_text: str
    cited_retrieval_ids: tuple[str, ...]
    claimed_criteria: tuple[str, ...]


@dataclass(frozen=True)
class CompletionDecision:
    status: str
    reason: str
    release_token: str | None
    response_hash: str | None


@dataclass(frozen=True)
class EgressEvent:
    control_point_id: str
    timestamp: str
    response_hash: str
    context_taint_state: str
    risk_class: str
    data_classification: str


@dataclass(frozen=True)
class CompletionReleaseResult:
    status: str
    delivered_text: str | None
    events: tuple[dict[str, Any], ...]


class CompletionVerifier:
    def __init__(
        self,
        required_criteria: tuple[str, ...],
        criterion_rules: Mapping[str, CriterionRule] | None = None,
    ) -> None:
        self._required = frozenset(required_criteria)
        supplied = dict(criterion_rules or {})
        unknown = set(supplied) - self._required
        if unknown:
            raise ContractError(f"criterion rules contain unknown criteria: {sorted(unknown)!r}")
        self._rules = {
            criterion: supplied.get(criterion, CriterionRule(("RETRIEVAL",)))
            for criterion in self._required
        }

    def verify(
        self,
        proposal: CompletionProposal,
        retrievals: Mapping[str, ObservedRetrieval | ObservedArtifact],
        criterion_evidence: Mapping[str, tuple[str, ...]],
    ) -> CompletionDecision:
        if not proposal.model_text.strip():
            return CompletionDecision("COMPLETION_REJECTED", "empty model response", None, None)
        if not proposal.cited_retrieval_ids:
            return CompletionDecision("COMPLETION_INDETERMINATE", "completion cites no independent evidence", None, None)
        missing_sources = set(proposal.cited_retrieval_ids) - set(retrievals)
        if missing_sources:
            return CompletionDecision("COMPLETION_REJECTED", "cited source was not controller-observed", None, None)
        if any(retrievals[item].status != "SUCCEEDED" for item in proposal.cited_retrieval_ids):
            return CompletionDecision("COMPLETION_REJECTED", "cited retrieval did not succeed", None, None)
        for criterion in self._required:
            evidence_ids = criterion_evidence.get(criterion, ())
            if not evidence_ids:
                return CompletionDecision("COMPLETION_INDETERMINATE", f"criterion {criterion!r} lacks independent evidence", None, None)
            if set(evidence_ids) - set(retrievals):
                return CompletionDecision("COMPLETION_REJECTED", f"criterion {criterion!r} cites unobserved evidence", None, None)
            evidence = [retrievals[item] for item in evidence_ids]
            if any(item.status != "SUCCEEDED" for item in evidence):
                return CompletionDecision("COMPLETION_REJECTED", f"criterion {criterion!r} evidence did not succeed", None, None)
            allowed_types = set(self._rules[criterion].evidence_types)
            if any(item.evidence_type not in allowed_types for item in evidence):
                return CompletionDecision("COMPLETION_REJECTED", f"criterion {criterion!r} has the wrong evidence type", None, None)
            if self._rules[criterion].require_response_grounding:
                observed = "\n".join(item.observed_text or "" for item in evidence)
                facts = set(re.findall(r"(?<![A-Za-z])[-+]?\d[\d,]*(?:\.\d+)?%?", proposal.model_text))
                if not observed or any(fact not in observed for fact in facts):
                    return CompletionDecision("COMPLETION_REJECTED", f"criterion {criterion!r} response facts lack observed support", None, None)
        response_hash = _response_hash(proposal.model_text)
        return CompletionDecision("COMPLETION_VERIFIED", "completion and provenance independently verified", f"release-{uuid4()}", response_hash)


class UserResponseWrapper:
    """The sole release path for model text in the Increment 3 system boundary."""

    wrapper_id = "user-response-wrapper-v1"

    def __init__(self) -> None:
        self._unused_tokens: dict[str, tuple[str, str, str]] = {}
        self._delivered: list[str] = []
        self._egress_events: list[EgressEvent] = []

    def authorize(self, decision: CompletionDecision, context_taint_state: str, data_classification: str) -> None:
        if decision.status != "COMPLETION_VERIFIED" or decision.release_token is None or decision.response_hash is None:
            raise ContractError("only verified completion decisions can authorize a user response")
        if context_taint_state not in {"CLEAN", "TAINTED"}:
            raise ContractError("invalid response taint state")
        self._unused_tokens[decision.release_token] = (decision.response_hash, context_taint_state, data_classification)

    def deliver(self, model_text: str, release_token: str) -> str:
        if release_token not in self._unused_tokens:
            raise ContractError("invalid or already-used response release token")
        expected_hash, taint, classification = self._unused_tokens[release_token]
        actual_hash = _response_hash(model_text)
        if not hmac_compare(actual_hash, expected_hash):
            raise ContractError("response text does not match the verified completion")
        del self._unused_tokens[release_token]
        self._delivered.append(model_text)
        risk = "HIGH" if taint == "TAINTED" else "LOW"
        self._egress_events.append(EgressEvent(
            "CP-10", datetime.now(timezone.utc).isoformat(), actual_hash, taint, risk, classification
        ))
        return model_text

    @property
    def delivered(self) -> tuple[str, ...]:
        return tuple(self._delivered)

    @property
    def egress_events(self) -> tuple[EgressEvent, ...]:
        return tuple(self._egress_events)


class CompletionControlService:
    """Controller-owned CP-10 verification, authorization, release, and evidence."""

    def __init__(self, verifier: CompletionVerifier, wrapper: UserResponseWrapper, store, builder: EventBuilder | None = None) -> None:
        self._verifier = verifier
        self._wrapper = wrapper
        self._store = store
        self._builder = builder or EventBuilder()

    def complete(
        self,
        source_event: dict[str, Any],
        proposal: CompletionProposal,
        retrievals: Mapping[str, ObservedRetrieval | ObservedArtifact],
        criterion_evidence: Mapping[str, tuple[str, ...]],
        *,
        context_taint_state: str,
        data_classification: str,
        taint_source_resource_ids: tuple[str, ...] = (),
        egress_authorization: EgressAuthorization | None = None,
    ) -> CompletionReleaseResult:
        decision = self._verifier.verify(proposal, retrievals, criterion_evidence)
        high_egress = context_taint_state == "TAINTED" or data_classification in {"SENSITIVE", "RESTRICTED"}
        if decision.status == "COMPLETION_VERIFIED" and high_egress and egress_authorization is None:
            decision = CompletionDecision(
                "COMPLETION_REJECTED", "high-risk CP-10 egress lacks authorization", None, decision.response_hash
            )
        verification = {
            "COMPLETION_VERIFIED": "VERIFIED",
            "COMPLETION_REJECTED": "REJECTED",
            "COMPLETION_INDETERMINATE": "INDETERMINATE",
        }[decision.status]
        authority_provenance = () if egress_authorization is None else (
            f"egress_authority:{egress_authorization.actor}",
            f"egress_authorization_event:{egress_authorization.authorization_event_id}",
        )
        verification_event = self._builder.followup_event(
            source_event, decision.status,
            authorization_state="AUTHORIZED" if decision.status == "COMPLETION_VERIFIED" else "NOT_APPLICABLE",
            control_point_id="CP-10", completion_verification=verification,
            evidence_provenance=("CONTROLLER_OBSERVED",),
            data_classification=data_classification,
            context_taint_state=context_taint_state,
            taint_source_resource_ids=taint_source_resource_ids,
            error_detail=decision.reason,
            additional_result_provenance=((decision.response_hash,) if decision.response_hash else ()) + authority_provenance,
        )
        recorded_verification = self._store.append(verification_event)
        if decision.status != "COMPLETION_VERIFIED":
            return CompletionReleaseResult(decision.status, None, (recorded_verification,))

        self._wrapper.authorize(decision, context_taint_state, data_classification)
        delivered = self._wrapper.deliver(proposal.model_text, decision.release_token)
        delivery_event = self._builder.followup_event(
            recorded_verification, "EXECUTED", authorization_state="AUTHORIZED",
            control_point_id="CP-10", completion_verification="VERIFIED",
            evidence_provenance=("CONTROLLER_OBSERVED",),
            data_classification=data_classification,
            context_taint_state=context_taint_state,
            taint_source_resource_ids=taint_source_resource_ids,
            additional_result_provenance=(decision.response_hash,),
        )
        recorded_delivery = self._store.append(delivery_event)
        return CompletionReleaseResult("EXECUTED", delivered, (recorded_verification, recorded_delivery))


def retrieval_registry(items: tuple[ObservedRetrieval, ...]) -> Mapping[str, ObservedRetrieval]:
    return MappingProxyType({item.retrieval_id: item for item in items})


def evidence_registry(
    items: tuple[ObservedRetrieval | ObservedArtifact, ...],
) -> Mapping[str, ObservedRetrieval | ObservedArtifact]:
    result = {item.evidence_id: item for item in items}
    if len(result) != len(items):
        raise ContractError("evidence identifiers must be unique")
    return MappingProxyType(result)


def _response_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def hmac_compare(left: str, right: str) -> bool:
    import hmac
    return hmac.compare_digest(left, right)
