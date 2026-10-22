"""Mediated compaction, emergency checkpoint, and fresh-context resume controls."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .contracts import RunContext
from .controller import AgentController, ControllerResult
from .errors import EvidenceIntegrityError
from .event_builder import EventBuilder
from .evidence_store import AppendOnlyEvidenceStore


@dataclass(frozen=True)
class CompactionResult:
    state: str
    controller_result: ControllerResult
    checkpoint_path: Path | None = None


@dataclass(frozen=True)
class Primer:
    text: str
    signature: str


class HarnessOracle:
    def __init__(self, key: bytes) -> None:
        if len(key) < 16:
            raise ValueError("oracle key must be at least 16 bytes")
        self._key = bytes(key)

    def issue_primer(self, text: str) -> Primer:
        return Primer(text, self._sign(text))

    def verify(self, primer: Primer) -> bool:
        return hmac.compare_digest(primer.signature, self._sign(primer.text))

    def _sign(self, text: str) -> str:
        return "hmac-sha256:" + hmac.new(self._key, text.encode("utf-8"), hashlib.sha256).hexdigest()


class ContextManager:
    def __init__(
        self,
        controller: AgentController,
        store: AppendOnlyEvidenceStore,
        checkpoint_path: Path,
        capacity_tokens: int,
        builder: EventBuilder | None = None,
        checkpoint_writer: Callable[[Path, bytes], None] | None = None,
    ) -> None:
        if capacity_tokens < 100:
            raise ValueError("context capacity must be at least 100 tokens")
        self._controller = controller
        self._store = store
        self._checkpoint_path = checkpoint_path
        self._capacity = capacity_tokens
        self._builder = builder or EventBuilder()
        self._writer = checkpoint_writer or self._atomic_write

    def compact(self, model_summary: str, context: RunContext, selected_evidence_ids: tuple[str, ...]) -> CompactionResult:
        if not isinstance(model_summary, str):
            raise EvidenceIntegrityError("compaction summary must be text")
        if len(model_summary) > self._capacity:
            raise EvidenceIntegrityError("compaction summary exceeds the configured size bound")
        if context.context_taint_state == "TAINTED" and not selected_evidence_ids:
            raise EvidenceIntegrityError("tainted compaction requires explicit source-evidence identifiers")
        compact_context = RunContext(
            context.run_id, context.trace_id, context.objective_id,
            execution_mode=context.execution_mode, decision_epoch=context.decision_epoch,
            supervision_state=context.supervision_state, control_point_id="CP-07",
            context_taint_state=context.context_taint_state,
            taint_source_resource_ids=context.taint_source_resource_ids,
            action_origin="CONTROLLER_COMPACTION",
        )
        action = {"capability": "context_write", "target": "context://persistent"}
        result = self._controller.process(action, compact_context)
        if result.final_status == "EXECUTED":
            event = self._builder.followup_event(
                result.events[-1], "EXECUTED", authorization_state="AUTHORIZED",
                evidence_provenance=("CONTROLLER_OBSERVED",),
            )
            event["untrusted_data"]["summary_content"] = model_summary
            event["untrusted_data"]["input_parameters"] = {"selected_evidence_ids": list(selected_evidence_ids)}
            self._store.append(event)
            return CompactionResult("AWAITING_MODEL", result)
        try:
            checkpoint = {
                "run_id": context.run_id,
                "trace_id": context.trace_id,
                "decision_epoch": context.decision_epoch,
                "taint_state": context.context_taint_state,
                "taint_source_resource_ids": list(context.taint_source_resource_ids),
                "selected_evidence_ids": list(selected_evidence_ids),
                "model_summary_included": False,
            }
            encoded = (json.dumps(checkpoint, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            self._writer(self._checkpoint_path, encoded)
        except OSError as exc:
            failure = self._builder.followup_event(
                result.events[-1], "FAILED", authorization_state="AMBIGUOUS",
                supervision_state="LATCHED", error_detail=f"emergency checkpoint write failed: {type(exc).__name__}",
            )
            failure["trusted_metadata"]["tier1_reason_codes"] = ["T1_CMP"]
            failure = self._store.append(failure)
            final_block = self._builder.followup_event(
                failure, "BLOCKED", authorization_state="UNAUTHORIZED", supervision_state="LATCHED"
            )
            final_block["trusted_metadata"]["tier1_reason_codes"] = ["T1_CMP"]
            self._store.append(final_block)
            raise EvidenceIntegrityError(f"emergency checkpoint write failed: {exc}") from exc
        return CompactionResult("SUSPENDED_CONTEXT_EXHAUSTED", result, self._checkpoint_path)

    def resume(self, primer: Primer, oracle: HarnessOracle, context: RunContext) -> ControllerResult:
        if not oracle.verify(primer):
            raise EvidenceIntegrityError("resume primer signature is invalid")
        # Conservative four-characters-per-token bound; strictly below five percent.
        if len(primer.text) >= int(self._capacity * 0.05) * 4:
            raise EvidenceIntegrityError("resume primer exceeds five-percent context reserve")
        resume_context = RunContext(
            context.run_id, context.trace_id, context.objective_id,
            execution_mode=context.execution_mode, decision_epoch=context.decision_epoch + 1,
            supervision_state="HARNESS_RESOLVED", control_point_id="CP-07",
            context_taint_state=context.context_taint_state,
            taint_source_resource_ids=context.taint_source_resource_ids,
            action_origin="HARNESS",
        )
        result = self._controller.process({"capability": "context_write", "target": "context://persistent"}, resume_context)
        if result.final_status != "EXECUTED":
            raise EvidenceIntegrityError("resume primer failed context-write mediation")
        event = self._builder.followup_event(
            result.events[-1], "EXECUTED", authorization_state="AUTHORIZED",
            evidence_provenance=("HARNESS_OBSERVED",),
        )
        event["untrusted_data"]["summary_content"] = primer.text
        self._store.append(event)
        return result

    @staticmethod
    def _atomic_write(path: Path, encoded: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("partial checkpoint write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
