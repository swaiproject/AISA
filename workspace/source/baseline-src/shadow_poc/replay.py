"""Offline structural replay and originating-event reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Reconstruction:
    enforcement_event_id: str
    originating_event_id: str
    confidence: str


class ReplayAnalyzer:
    REPLAY_FIELDS = (
        "risk_class", "evaluation_tier", "authorization_state",
        "execution_status", "tier1_reason_codes", "tier2_reason_codes",
    )

    def compare_decision_sequence(
        self, recorded: list[dict[str, Any]], replayed: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Compare every policy-significant field and stop behavior at divergence."""
        limit = min(len(recorded), len(replayed))
        divergence = None
        differences: list[str] = []
        for index in range(limit):
            left = recorded[index]["trusted_metadata"]
            right = replayed[index]["trusted_metadata"]
            changed = [field for field in self.REPLAY_FIELDS if left.get(field) != right.get(field)]
            if changed:
                divergence = index
                differences = changed
                break
        if divergence is None and len(recorded) != len(replayed):
            divergence = limit
            differences = ["sequence_length"]
        return {
            "exact_match": divergence is None,
            "divergence_index": divergence,
            "different_fields": differences,
            "behavioral_checked": limit if divergence is None else divergence,
            "structural_checked": len(replayed),
        }

    def analyze(self, events: list[dict[str, Any]], candidate_statuses: list[str]) -> dict[str, Any]:
        divergence_index = None
        for index, event in enumerate(events):
            if index < len(candidate_statuses) and candidate_statuses[index] != event["trusted_metadata"]["execution_status"]:
                divergence_index = index
                break
        # Structural checks always continue through physical EOF.
        structural_checked = len(events)
        passive_taint_issues = sum(
            1 for event in events
            if event["trusted_metadata"].get("context_taint_state") == "TAINTED"
            and not event["trusted_metadata"].get("taint_source_resource_ids")
        )
        return {
            "divergence_index": divergence_index,
            "behavioral_checked": len(events) if divergence_index is None else divergence_index,
            "structural_checked": structural_checked,
            "passive_taint_issues": passive_taint_issues,
        }

    def reconstruct_origin(self, events: list[dict[str, Any]], event_id: str) -> Reconstruction:
        by_id = {event["trusted_metadata"]["event_id"]: event for event in events}
        current = by_id[event_id]
        visited: set[str] = set()
        while current["trusted_metadata"].get("parent_event_id"):
            parent_id = current["trusted_metadata"]["parent_event_id"]
            if parent_id in visited or parent_id not in by_id:
                return Reconstruction(event_id, current["trusted_metadata"]["event_id"], "LOW")
            visited.add(parent_id)
            current = by_id[parent_id]
        provenance = set(current["trusted_metadata"].get("evidence_provenance", []))
        if provenance & {"TOOL_OBSERVED", "ENVIRONMENT_OBSERVED", "HARNESS_OBSERVED"}:
            confidence = "HIGH"
        elif "MODEL_DECLARED" in provenance:
            confidence = "LOW"
        elif "CONTROLLER_OBSERVED" in provenance:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        return Reconstruction(event_id, current["trusted_metadata"]["event_id"], confidence)
