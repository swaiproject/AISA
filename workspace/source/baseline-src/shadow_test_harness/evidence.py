from __future__ import annotations

from pathlib import Path
from typing import Any

from .io import loads_json


def verify_findings(findings: list[dict[str, Any]], run_results: dict[str, str]) -> dict[str, int]:
    counts = {"OPEN": 0, "FIXED_VERIFIED": 0, "FIXED_UNVERIFIED": 0, "DEFERRED": 0, "REJECTED": 0}
    for item in findings:
        status = item["status"]
        if status == "FIXED":
            closures = item.get("closure_tests", [])
            key = "FIXED_VERIFIED" if closures and all(run_results.get(name) == "PASS" for name in closures) else "FIXED_UNVERIFIED"
            counts[key] += 1
        else:
            counts[status] += 1
    return counts


def _evidence_class(manifest: dict[str, Any] | None) -> str:
    if manifest is None:
        return "no_manifest"
    if manifest.get("status") == "ORACLE_SELF_TEST":
        return "oracle_self_test"
    interface = manifest.get("implementation_interface", "")
    if interface == "external_host_observation":
        return "external_host"
    if interface == "external_live_model_observation":
        return "external_live"
    if interface == "production_system_e2e":
        return "production_system"
    if interface.startswith("production_"):
        return "production_component"
    if interface == "increment3_probe" and manifest.get("stimulus", {}).get("scenario") in {"replay_divergence", "origin_reconstruction"}:
        return "offline_analyzer"
    return "integration_probe"


def traceability_evidence(
    root: Path,
    traceability: dict[str, list[str]],
    run_results: dict[str, str],
    manifest_overrides: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    manifests = {}
    for path in (root / "manifests").glob("*.json"):
        record = loads_json(path.read_text(encoding="utf-8"))
        manifests[record["test_id"]] = record
    manifests.update(manifest_overrides or {})
    core_path = root / "config/criterion_core_cases.json"
    core_cases = loads_json(core_path.read_text(encoding="utf-8")) if core_path.exists() else {}
    result = {}
    for criterion, ids in traceability.items():
        counts = {"linked": len(ids), "no_manifest": 0, "not_run": 0, "skipped": 0, "production_passed": 0, "production_system_passed": 0, "production_component_passed": 0, "external_host_passed": 0, "external_live_passed": 0, "integration_probe_passed": 0, "offline_analyzer_passed": 0, "oracle_self_test_passed": 0, "failed": 0}
        for test_id in ids:
            manifest = manifests.get(test_id)
            if manifest is None:
                counts["no_manifest"] += 1
            elif run_results.get(test_id) == "FAIL":
                counts["failed"] += 1
            elif manifest["status"] == "SKIP_NOT_IMPLEMENTED" or run_results.get(test_id) == "SKIP":
                counts["skipped"] += 1
            elif run_results.get(test_id) != "PASS":
                counts["not_run"] += 1
            elif manifest["status"] == "ORACLE_SELF_TEST":
                counts["oracle_self_test_passed"] += 1
            elif (evidence_class := _evidence_class(manifest)) in {"external_host", "external_live"}:
                counts["production_passed"] += 1
                counts[f"{evidence_class}_passed"] += 1
            elif (interface := manifest.get("implementation_interface", "")) == "production_system_e2e":
                counts["production_passed"] += 1
                counts["production_system_passed"] += 1
            elif interface.startswith("production_"):
                counts["production_passed"] += 1
                counts["production_component_passed"] += 1
            elif interface in {"increment3_probe", "integration_probe_runtime_observation"}:
                scenario = manifest.get("stimulus", {}).get("scenario")
                if interface == "increment3_probe" and scenario in {"replay_divergence", "origin_reconstruction"}:
                    counts["offline_analyzer_passed"] += 1
                else:
                    counts["integration_probe_passed"] += 1
            else:
                raise ValueError(f"unclassified passing evidence interface for {test_id}: {interface!r}")
        requirements_path = root / "config/criterion_evidence_requirements.json"
        requirements = loads_json(requirements_path.read_text(encoding="utf-8")) if requirements_path.exists() else {}
        minimum = requirements.get(criterion)
        class_key = None if minimum is None else f"{minimum}_passed"
        counts["minimum_evidence_class"] = minimum
        required_core = core_cases.get(criterion, [])
        override_path = root / "config/criterion_core_evidence_requirements.json"
        overrides = loads_json(override_path.read_text(encoding="utf-8")) if override_path.exists() else {}
        core_results = {}
        for test_id in required_core:
            manifest = manifests.get(test_id)
            evidence_class = _evidence_class(manifest)
            required_class = overrides.get(criterion, {}).get(test_id, minimum)
            class_met = (
                evidence_class == required_class
                or required_class == "production" and evidence_class in {"production_system", "production_component", "external_host", "external_live"}
            )
            core_results[test_id] = {
                "result": run_results.get(test_id, "NOT_RUN"),
                "evidence_class": evidence_class,
                "required_evidence_class": required_class,
                "meets_minimum": run_results.get(test_id) == "PASS" and class_met,
            }
        counts["core_cases"] = core_results
        counts["minimum_evidence_class_met"] = (
            minimum is None or (
                bool(required_core)
                and all(item["meets_minimum"] for item in core_results.values())
            )
        )
        result[criterion] = counts
    return result
