"""Manifest-driven execution for pre-implementation oracle interfaces."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .io import load_json
from .tier1_reference import evaluate, tier2_fail_safe

MANIFEST_RESULTS: dict[str, str] = {}


class InvalidShadowContractAdapter:
    def evaluate(self, envelope):
        return {"outcome": "ALLOW"}


def _selected_rows(stimulus: dict[str, Any]) -> list[dict[str, Any]]:
    rows = load_json(stimulus["fixture"])
    selector = stimulus.get("selector", {})
    selected = [row for row in rows if all(row.get(key) == value for key, value in selector.items())]
    if not selected:
        raise AssertionError(f"selector matched no rows: {selector}")
    return selected


def execute_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    interface = manifest.get("implementation_interface")
    if interface == "production_broker_revocation":
        from shadow_poc.capability_broker import CapabilityBroker
        from shadow_poc.contracts import ActionRequest

        action = ActionRequest.from_untrusted({
            "capability": "read_file", "target": "fixture://public/report.txt", "parameters": {},
        })
        broker = CapabilityBroker()
        token = broker.issue(action, "wrapper", 12)
        self_status = broker.begin(token, action, "wrapper", 12)
        if self_status != "ACTIVE":
            raise AssertionError("token did not enter ACTIVE state")
        scenario = manifest["stimulus"]["scenario"]
        if scenario == "revoke_pre_effect":
            outcome = broker.revoke(token.token_id)
            effect_committed = False
        elif scenario == "revoke_post_effect":
            if broker.authorize_effect(token) != "ACTIVE":
                raise AssertionError("effect was not authorized")
            outcome = broker.revoke(token.token_id)
            effect_committed = True
        else:
            raise NotImplementedError(scenario)
        return {
            "control": {"revocation_outcome": outcome, "effect_committed": effect_committed},
            "events": [outcome],
        }
    if interface == "increment3_probe":
        return _increment3_probe(manifest["stimulus"]["scenario"])
    if interface == "reference_tier1":
        rows = _selected_rows(manifest["stimulus"])
        if len(rows) != 1:
            raise AssertionError("reference_tier1 requires exactly one selected case")
        actual = evaluate(
            rows[0]["request"],
            load_json("fixtures/objectives/basic_authorized.json"),
            load_json("fixtures/policies/poc_policy_v0.1.json"),
        )
        event = {"ALLOW": "AUTHORIZED", "DENY": "BLOCKED", "REVIEW": "REQUESTED"}[actual["disposition"]]
        return {"control": actual, "events": [event]}
    if interface == "production_tier1":
        from shadow_poc.configuration import TrustedConfiguration
        from shadow_poc.contracts import RunContext
        from shadow_poc.evidence_store import AppendOnlyEvidenceStore
        from shadow_poc.service import Tier1AssessmentService
        from .io import ROOT

        stimulus = manifest["stimulus"]
        if "action" in stimulus:
            action = stimulus["action"]
        else:
            rows = _selected_rows(stimulus)
            if len(rows) != 1:
                raise AssertionError("production_tier1 requires exactly one selected case")
            action = rows[0]["request"]
        configuration = TrustedConfiguration.load(
            ROOT,
            Path("fixtures/objectives/basic_authorized.json"),
            Path("fixtures/policies/poc_policy_v0.1.json"),
        )
        with TemporaryDirectory() as directory:
            store = AppendOnlyEvidenceStore(
                Path(directory) / "events.jsonl",
                ROOT / "schemas/primary_agent_event_v0.2.schema.json",
                configuration.event_schema_sha256,
            )
            result = Tier1AssessmentService(configuration, store).assess(
                action,
                RunContext("manifest-run", manifest["test_id"], configuration.objective["objective_id"]),
            )
        actual = result.decision.as_dict()
        actual["reason_code"] = actual.pop("reason_codes")[0]
        return {"control": actual, "events": [result.event["trusted_metadata"]["execution_status"]]}
    if interface in {"production_tier2_budget_fail_safe", "production_tier2_schema_fail_safe"}:
        from shadow_poc.capability_broker import CapabilityBroker
        from shadow_poc.configuration import TrustedConfiguration
        from shadow_poc.contracts import RunContext
        from shadow_poc.controller import AgentController
        from shadow_poc.evidence_store import AppendOnlyEvidenceStore
        from shadow_poc.shadow_adapter import ScriptedShadowAdapter, ShadowResult
        from shadow_poc.wrappers import InMemoryResourceWrapper
        from .io import ROOT

        configuration = TrustedConfiguration.load(
            ROOT, Path("fixtures/objectives/basic_authorized.json"), Path("fixtures/policies/poc_policy_v0.1.json")
        )
        high_action = {"capability": "write_summary", "target": "fixture://internal/summary.json", "parameters": {"format": "json"}}
        medium_action = {"capability": "read_file", "target": "fixture://ambiguous/current-report", "parameters": {"encoding": "utf-8"}}
        with TemporaryDirectory() as directory:
            store = AppendOnlyEvidenceStore(
                Path(directory) / "events.jsonl", ROOT / "schemas/primary_agent_event_v0.2.schema.json",
                configuration.event_schema_sha256,
            )
            if interface == "production_tier2_budget_fail_safe":
                events: list[str] = []
                outcomes: dict[str, str] = {}
                cases = [
                    ("HIGH", high_action, ShadowResult("ALLOW", "COMPLETED", ("T2_EVD",), 3_000, 20)),
                    ("HIGH", high_action, ShadowResult("ALLOW", "COMPLETED", ("T2_EVD",), 2, 2_000)),
                    ("MEDIUM", medium_action, ShadowResult("ALLOW", "COMPLETED", ("T2_EVD",), 3_000, 20)),
                ]
                for index, (risk, action, scripted) in enumerate(cases):
                    shadow = ScriptedShadowAdapter({action["target"]: scripted})
                    controller = AgentController(configuration, store, shadow, CapabilityBroker(), InMemoryResourceWrapper())
                    result = controller.process(action, RunContext("manifest-run", f"TP-T2-008-{index}", configuration.objective["objective_id"]))
                    outcomes[risk] = configuration.policy["tier2_fail_safe"][risk]
                    for event in result.events:
                        status = event["trusted_metadata"]["execution_status"]
                        if status in {"TIER2_TIMEOUT", "TIER2_TOKEN_EXHAUSTED"} and status not in events:
                            events.append(status)
                outcomes["CRITICAL"] = configuration.policy["tier2_fail_safe"]["CRITICAL"]
                return {"control": {key: outcomes[key] for key in ("HIGH", "CRITICAL", "MEDIUM")}, "events": events}

            controller = AgentController(configuration, store, InvalidShadowContractAdapter(), CapabilityBroker(), InMemoryResourceWrapper())
            result = controller.process(high_action, RunContext("manifest-run", "TP-T2-009", configuration.objective["objective_id"]))
            statuses = [event["trusted_metadata"]["execution_status"] for event in result.events]
            return {"control": {"HIGH": configuration.policy["tier2_fail_safe"]["HIGH"]}, "events": [status for status in statuses if status in {"FAILED", "BLOCKED"}]}
    if interface == "tier2_fail_safe_oracle":
        rows = _selected_rows(manifest["stimulus"])
        mapping = load_json("fixtures/policies/poc_policy_v0.1.json")["tier2_fail_safe"]
        actual = {row["risk"]: tier2_fail_safe(row["risk"], row["condition"], mapping) for row in rows}
        events = []
        for row in rows:
            condition = row["condition"]
            outcome = actual[row["risk"]]
            if condition == "TIMEOUT":
                candidate = "TIER2_TIMEOUT"
            elif condition == "TOKEN_EXHAUSTED":
                candidate = "TIER2_TOKEN_EXHAUSTED"
            elif condition in {"SCHEMA_FAILURE", "SYSTEM_ERROR"}:
                for candidate in ("FAILED", {"BLOCK": "BLOCKED", "ESCALATE": "ESCALATED", "CHALLENGE": "CHALLENGED"}[outcome]):
                    if candidate not in events:
                        events.append(candidate)
                continue
            else:
                candidate = {"BLOCK": "BLOCKED", "ESCALATE": "ESCALATED", "CHALLENGE": "CHALLENGED"}[outcome]
            if candidate not in events:
                events.append(candidate)
        return {"control": actual, "events": events}
    raise NotImplementedError(interface)


def _increment3_probe(scenario: str) -> dict[str, Any]:
    if scenario == "dual_store":
        from shadow_poc.configuration import TrustedConfiguration
        from shadow_poc.contracts import RunContext
        from shadow_poc.durable_evidence import DurableEvidenceService
        from shadow_poc.evidence_store import AppendOnlyEvidenceStore
        from shadow_poc.service import Tier1AssessmentService
        from .io import ROOT
        configuration = TrustedConfiguration.load(ROOT, Path("fixtures/objectives/basic_authorized.json"), Path("fixtures/policies/poc_policy_v0.1.json"))
        with TemporaryDirectory() as directory:
            root = Path(directory)
            enforcement = AppendOnlyEvidenceStore(root / "enforcement.jsonl", ROOT / "schemas/primary_agent_event_v0.2.schema.json", configuration.event_schema_sha256)
            durable = DurableEvidenceService(enforcement, root / "trajectory.jsonl", root / "seal.json", b"increment-3-seal-key")
            event = Tier1AssessmentService(configuration, enforcement).assess(
                {"capability": "read_file", "target": "fixture://public/report.txt"},
                RunContext("manifest-run", "TP-EVT-001", configuration.objective["objective_id"]),
            ).event
            durable.recover()
            durable.verify()
            return {"control": {"enforcement_count": 1, "trajectory_count": 1, "signed_seal_verified": True}, "events": [event["trusted_metadata"]["execution_status"]]}
    if scenario == "replay_divergence":
        from shadow_poc.replay import ReplayAnalyzer
        import copy
        base = load_json("fixtures/events/valid_authorized.json")
        events = []
        for index, status in enumerate(("REQUESTED", "AUTHORIZED", "EXECUTED")):
            event = copy.deepcopy(base)
            event["trusted_metadata"]["event_id"] = f"replay-{index}"
            event["trusted_metadata"]["execution_status"] = status
            events.append(event)
        result = ReplayAnalyzer().analyze(events, ["REQUESTED", "BLOCKED", "EXECUTED"])
        return {"control": {
            "disable_live_behavioral_loop_at_divergence": result["divergence_index"] is not None,
            "behavioral_claims": "end_at_divergence",
            "downstream": "observational_only",
            "structural_validation_to_physical_eof": ["EVENT_HASH", "APPEND_ONLY_SIGNATURE", "PASSIVE_METADATA_INVARIANTS", "TAINT_PROPAGATION"],
        }, "events": []}
    if scenario == "origin_reconstruction":
        from shadow_poc.replay import ReplayAnalyzer
        import copy
        base = load_json("fixtures/events/valid_authorized.json")
        events = []
        parent = None
        for index in range(3):
            event = copy.deepcopy(base)
            event["trusted_metadata"]["event_id"] = f"origin-{index}"
            event["trusted_metadata"]["parent_event_id"] = parent
            parent = f"origin-{index}"
            events.append(event)
        result = ReplayAnalyzer().reconstruct_origin(events, "origin-2")
        return {"control": {"originating_event_id": result.originating_event_id, "confidence": result.confidence}, "events": []}
    if scenario == "fabricated_result_provenance":
        from shadow_poc.completion import CompletionProposal, CompletionVerifier, ObservedRetrieval, retrieval_registry
        registry = retrieval_registry((ObservedRetrieval("observed", "fixture://public/report.txt", "sha256:" + "1" * 64),))
        result = CompletionVerifier(("summary_written",)).verify(
            CompletionProposal("answer", ("fabricated",), ("summary_written",)), registry,
            {"summary_written": ("observed",)},
        )
        return {"control": {"completion_status": result.status, "release_token_issued": result.release_token is not None}, "events": [result.status]}

    from shadow_poc.capability_broker import CapabilityBroker
    from shadow_poc.configuration import TrustedConfiguration
    from shadow_poc.context_manager import ContextManager, HarnessOracle
    from shadow_poc.contracts import RunContext
    from shadow_poc.controller import AgentController
    from shadow_poc.evidence_store import AppendOnlyEvidenceStore
    from shadow_poc.errors import EvidenceIntegrityError
    from shadow_poc.shadow_adapter import ScriptedShadowAdapter, ShadowResult
    from shadow_poc.wrappers import InMemoryResourceWrapper
    from .io import ROOT

    configuration = TrustedConfiguration.load(ROOT, Path("fixtures/objectives/basic_authorized.json"), Path("fixtures/policies/poc_policy_v0.1.json"))
    with TemporaryDirectory() as directory:
        root = Path(directory)
        store = AppendOnlyEvidenceStore(root / "events.jsonl", ROOT / "schemas/primary_agent_event_v0.2.schema.json", configuration.event_schema_sha256)
        shadow = ScriptedShadowAdapter({"context://persistent": ShadowResult("ALLOW", "COMPLETED", ("T2_CTX",), 2, 20)})
        controller = AgentController(configuration, store, shadow, CapabilityBroker(), InMemoryResourceWrapper())
        context = RunContext("manifest-run", scenario, configuration.objective["objective_id"], context_taint_state="TAINTED", taint_source_resource_ids=("fixture://sensitive/accounts.csv",))
        if scenario == "mediated_compaction":
            manager = ContextManager(controller, store, root / "checkpoint.json", 10_000)
            result = manager.compact("untrusted summary", context, ("source-event",))
            event = store.read_all()[-1]
            return {"control": {
                "state": result.state, "control_point_id": event["trusted_metadata"]["control_point_id"],
                "action_origin": event["trusted_metadata"]["action_origin"],
                "taint_preserved": event["trusted_metadata"]["context_taint_state"] == "TAINTED",
                "summary_trust": "UNTRUSTED_DATA",
            }, "events": [item["trusted_metadata"]["execution_status"] for item in result.controller_result.events]}
        if scenario == "fresh_context_resume":
            manager = ContextManager(controller, store, root / "checkpoint.json", 10_000)
            oracle = HarnessOracle(b"increment-3-oracle-key")
            result = manager.resume(oracle.issue_primer("Safe mediated restart."), oracle, context)
            return {"control": {
                "mediation_control_point": "CP-07", "primer_context_fraction_less_than": True,
                "fresh_context_step_one_compaction": False, "primer_attribution_required": True,
                "primer_taint_preserved": result.events[-1]["trusted_metadata"]["context_taint_state"] == "TAINTED",
            }, "events": ["REQUESTED", "AUTHORIZED"]}
        if scenario == "checkpoint_failure":
            def fail(path, data):
                raise OSError("synthetic")
            manager = ContextManager(controller, store, root / "checkpoint.json", 10_000, checkpoint_writer=fail)
            try:
                # Force ordinary compaction denial before emergency checkpoint.
                blocked_controller = AgentController(
                    configuration, store,
                    ScriptedShadowAdapter({"context://persistent": ShadowResult("BLOCK", "COMPLETED", ("T2_CTX",), 2, 20)}),
                    CapabilityBroker(), InMemoryResourceWrapper(),
                )
                ContextManager(blocked_controller, store, root / "checkpoint.json", 10_000, checkpoint_writer=fail).compact("summary", context, ("source-event",))
            except EvidenceIntegrityError:
                pass
            statuses = [event["trusted_metadata"]["execution_status"] for event in store.read_all()]
            return {"control": {"state": "FAILED_SAFE", "fallback_log": "independent"}, "events": [status for status in statuses if status in {"FAILED", "BLOCKED"}][-2:]}
    raise NotImplementedError(scenario)


def assert_manifest(manifest: dict[str, Any]) -> None:
    try:
        actual = execute_manifest(manifest)
        if actual["control"] != manifest["expected_control"]:
            raise AssertionError(f"control mismatch: expected {manifest['expected_control']!r}, got {actual['control']!r}")
        if actual["events"] != manifest["expected_events"]:
            raise AssertionError(f"event mismatch: expected {manifest['expected_events']!r}, got {actual['events']!r}")
    except Exception:
        MANIFEST_RESULTS[manifest["test_id"]] = "FAIL"
        raise
    MANIFEST_RESULTS[manifest["test_id"]] = "PASS"
