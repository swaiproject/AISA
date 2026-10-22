"""Increment 7 evidence anchoring, bundle ingestion, metrics, and acceptance reporting."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Iterable, Mapping

from .errors import EvidenceIntegrityError
from .evidence_store import calculate_event_hash
from .strict_json import loads_strict_json
from .validation import validate_event_invariants, validate_schema


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _verify_findings(findings: list[dict[str, Any]], run_results: Mapping[str, str]) -> dict[str, int]:
    """Verify closure tests without introducing a production-to-harness dependency."""
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


class IndependentAnchorStore:
    """Append-only signed head receipts in a separately identified trust domain."""

    def __init__(self, path: Path, key: bytes, trust_domain_id: str) -> None:
        if len(key) < 16 or not trust_domain_id:
            raise ValueError("independent anchor requires a key and trust-domain identifier")
        self.path = path
        self._key = bytes(key)
        self.trust_domain_id = trust_domain_id
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(mode=0o600, exist_ok=True)

    def publish(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        records = self.read_all()
        receipt = {
            "sequence": len(records) + 1,
            "trust_domain_id": self.trust_domain_id,
            "previous_receipt_hash": None if not records else _sha256(_canonical(records[-1])),
            "payload": dict(payload),
        }
        receipt["signature"] = "hmac-sha256:" + hmac.new(self._key, _canonical(receipt), hashlib.sha256).hexdigest()
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND)
        try:
            encoded = _canonical(receipt) + b"\n"
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise EvidenceIntegrityError("partial independent-anchor write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return receipt

    def read_all(self) -> list[dict[str, Any]]:
        records = []
        for index, line in enumerate(self.path.read_bytes().splitlines(), start=1):
            try:
                record = loads_strict_json(line)
            except ValueError as exc:
                raise EvidenceIntegrityError(f"invalid anchor receipt at line {index}") from exc
            unsigned = dict(record)
            signature = unsigned.pop("signature", None)
            expected = "hmac-sha256:" + hmac.new(self._key, _canonical(unsigned), hashlib.sha256).hexdigest()
            if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
                raise EvidenceIntegrityError("independent anchor signature mismatch")
            expected_previous = None if not records else _sha256(_canonical(records[-1]))
            if unsigned.get("sequence") != index or unsigned.get("previous_receipt_hash") != expected_previous:
                raise EvidenceIntegrityError("independent anchor chain mismatch")
            records.append(record)
        return records

    def verify_latest(self, payload: Mapping[str, Any]) -> None:
        records = self.read_all()
        if not records or records[-1]["payload"] != dict(payload):
            raise EvidenceIntegrityError("independent anchor head mismatch")


@dataclass(frozen=True)
class BundleInspection:
    run_id: str
    event_count: int
    head_hash: str | None
    files_verified: int
    credential_findings: int


class EvidenceBundleExporter:
    FILES = ("enforcement.jsonl", "trajectory.jsonl", "seal.json", "anchor.jsonl")

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 16:
            raise ValueError("bundle signing key must be at least 16 bytes")
        self._key = bytes(signing_key)

    def export(self, output: Path, sources: Mapping[str, Path], metadata: Mapping[str, Any]) -> Path:
        if output.exists():
            raise EvidenceIntegrityError("evidence bundle destination already exists")
        output.mkdir(parents=True, mode=0o700)
        hashes = {}
        if not set(self.FILES) <= set(sources):
            raise EvidenceIntegrityError("required evidence bundle sources are missing")
        for name, source in sources.items():
            member = Path(name)
            if member.is_absolute() or ".." in member.parts:
                raise EvidenceIntegrityError(f"unsafe evidence member name: {name}")
            if source.is_symlink() or not source.is_file():
                raise EvidenceIntegrityError(f"unsafe evidence source: {name}")
            destination = output / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            hashes[name] = _sha256(destination.read_bytes())
        manifest = {"bundle_version": "1.0", "metadata": dict(metadata), "files": hashes}
        manifest["signature"] = "hmac-sha256:" + hmac.new(self._key, _canonical(manifest), hashlib.sha256).hexdigest()
        (output / "bundle-manifest.json").write_bytes(_canonical(manifest) + b"\n")
        return output


class EvidenceBundleImporter:
    def __init__(self, bundle_key: bytes, seal_key: bytes, anchor_key: bytes, event_schema_path: Path, max_file_bytes: int = 16_000_000) -> None:
        self._bundle_key = bytes(bundle_key)
        self._seal_key = bytes(seal_key)
        self._anchor_key = bytes(anchor_key)
        self._schema = loads_strict_json(event_schema_path.read_bytes())
        self._max = max_file_bytes

    def inspect(self, bundle: Path, decoy_hashes: frozenset[str] = frozenset()) -> BundleInspection:
        if bundle.is_symlink() or not bundle.is_dir():
            raise EvidenceIntegrityError("bundle path is unsafe")
        manifest_path = bundle / "bundle-manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > self._max:
            raise EvidenceIntegrityError("bundle manifest is unsafe")
        manifest = loads_strict_json(manifest_path.read_bytes())
        unsigned = dict(manifest)
        signature = unsigned.pop("signature", None)
        expected = "hmac-sha256:" + hmac.new(self._bundle_key, _canonical(unsigned), hashlib.sha256).hexdigest()
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
            raise EvidenceIntegrityError("bundle manifest signature mismatch")
        if not set(EvidenceBundleExporter.FILES) <= set(manifest.get("files", {})):
            raise EvidenceIntegrityError("bundle is missing required members")
        for name, digest in manifest["files"].items():
            member = Path(name)
            if member.is_absolute() or ".." in member.parts:
                raise EvidenceIntegrityError(f"unsafe bundle member name: {name}")
            path = bundle / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size > self._max:
                raise EvidenceIntegrityError(f"unsafe bundle member: {name}")
            if _sha256(path.read_bytes()) != digest:
                raise EvidenceIntegrityError(f"bundle member hash mismatch: {name}")
        enforcement = self._events(bundle / "enforcement.jsonl")
        trajectory = self._events(bundle / "trajectory.jsonl")
        self._verify_chain(enforcement)
        if [self._event_hash(item) for item in enforcement] != [self._event_hash(item) for item in trajectory]:
            raise EvidenceIntegrityError("bundle dual stores diverge")
        seal = loads_strict_json((bundle / "seal.json").read_bytes())
        seal_unsigned = dict(seal)
        seal_signature = seal_unsigned.pop("signature", None)
        expected_seal = "hmac-sha256:" + hmac.new(self._seal_key, _canonical(seal_unsigned), hashlib.sha256).hexdigest()
        if not isinstance(seal_signature, str) or not hmac.compare_digest(seal_signature, expected_seal):
            raise EvidenceIntegrityError("bundle run seal mismatch")
        anchor = IndependentAnchorStore(bundle / "anchor.jsonl", self._anchor_key, seal_unsigned["trust_domain_id"])
        anchor.verify_latest(seal_unsigned)
        findings = SecretScanner(decoy_hashes).scan_paths(bundle / name for name in manifest["files"])
        return BundleInspection(
            seal_unsigned["run_id"], len(enforcement),
            None if not enforcement else self._event_hash(enforcement[-1]),
            len(manifest["files"]), len(findings),
        )

    def _events(self, path: Path) -> list[dict[str, Any]]:
        result = []
        for line in path.read_bytes().splitlines():
            value = loads_strict_json(line)
            if not isinstance(value, dict):
                raise EvidenceIntegrityError("event record is not an object")
            result.append(value)
        return result

    @staticmethod
    def _event_hash(event: dict[str, Any]) -> str:
        return event["trusted_metadata"]["integrity"]["event_hash"]

    def _verify_chain(self, events: list[dict[str, Any]]) -> None:
        previous = None
        for index, event in enumerate(events, start=1):
            metadata = event["trusted_metadata"]
            issues = validate_schema(event, self._schema) + validate_event_invariants(event)
            if issues:
                raise EvidenceIntegrityError(f"event structural validation failed at line {index}: {'; '.join(issues)}")
            if metadata["integrity"]["event_hash"] != calculate_event_hash(event):
                raise EvidenceIntegrityError(f"event hash mismatch at line {index}")
            expected_id = None if previous is None else previous["trusted_metadata"]["event_id"]
            expected_hash = None if previous is None else self._event_hash(previous)
            if metadata.get("previous_event_id") != expected_id or metadata["integrity"].get("previous_event_hash") != expected_hash:
                raise EvidenceIntegrityError(f"event linkage mismatch at line {index}")
            previous = event


class SecretScanner:
    PATTERNS = (
        re.compile(rb"sk-[A-Za-z0-9_-]{12,}"),
        re.compile(rb"AKIA[0-9A-Z]{16}"),
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(rb"Bearer\s+[A-Za-z0-9._~-]{12,}", re.I),
    )

    def __init__(self, allowlisted_value_hashes: frozenset[str] = frozenset(), exact_values: Iterable[bytes] = ()) -> None:
        self._allowlisted = allowlisted_value_hashes
        self._exact = tuple(value for value in exact_values if value)

    def scan_paths(self, paths: Iterable[Path]) -> tuple[dict[str, Any], ...]:
        findings = []
        for path in paths:
            data = path.read_bytes()
            for value in self._exact:
                if value in data:
                    findings.append({"file": str(path), "value_sha256": hashlib.sha256(value).hexdigest(), "pattern": "EXACT_CONFIGURED_CREDENTIAL"})
            for pattern in self.PATTERNS:
                for match in pattern.finditer(data):
                    digest = hashlib.sha256(match.group()).hexdigest()
                    if digest not in self._allowlisted:
                        findings.append({"file": path.name, "value_sha256": digest, "pattern": pattern.pattern.decode("ascii")})
        return tuple(findings)

    def scan_tree(self, root: Path) -> tuple[dict[str, Any], ...]:
        return self.scan_paths(path for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink())


@dataclass(frozen=True)
class TraceMetrics:
    metric_scope: str
    event_count: int
    authorized: int
    executed: int
    blocked: int
    simulated: int
    tier2_failures: int
    tainted_events: int
    completion_verified: int
    mean_critical_path_ms: float
    maximum_critical_path_ms: float
    origin_reconstruction_rate: float
    origin_confidence: Mapping[str, int]
    tier1_only_latency_ms: Mapping[str, float]
    synchronous_tier2_latency_ms: Mapping[str, float]


class TraceMetricsAnalyzer:
    def analyze(self, events: list[dict[str, Any]], reconstructions: Iterable[Any] = ()) -> TraceMetrics:
        statuses = [item["trusted_metadata"]["execution_status"] for item in events]
        timing = [float(item["trusted_metadata"].get("timing", {}).get("critical_path_latency_ms") or 0) for item in events]
        recon = list(reconstructions)
        confidence = {name: sum(item.confidence == name for item in recon) for name in ("HIGH", "MEDIUM", "LOW")}
        def distribution(values: list[float]) -> dict[str, float]:
            if not values:
                return {"count": 0, "p50": 0.0, "p95": 0.0, "maximum": 0.0}
            ordered = sorted(values)
            percentile = lambda value: ordered[max(0, min(len(ordered) - 1, (len(ordered) * value + 99) // 100 - 1))]
            return {"count": len(ordered), "p50": percentile(50), "p95": percentile(95), "maximum": ordered[-1]}
        tier1 = [value for value, item in zip(timing, events) if item["trusted_metadata"].get("evaluation_tier") == "TIER1_ONLY"]
        tier2 = [value for value, item in zip(timing, events) if item["trusted_metadata"].get("evaluation_tier") == "TIER2_SYNCHRONOUS"]
        return TraceMetrics(
            "TEST_CORPUS_STATISTICS_NOT_FIELD_RELIABILITY",
            len(events), statuses.count("AUTHORIZED"), statuses.count("EXECUTED"), statuses.count("BLOCKED"),
            statuses.count("EXECUTED_SIMULATED"),
            sum(item["trusted_metadata"].get("tier2_termination_reason") in {"TIMEOUT", "TOKEN_BUDGET_EXHAUSTED", "SCHEMA_FAILURE", "SYSTEM_ERROR"} for item in events),
            sum(item["trusted_metadata"].get("context_taint_state") == "TAINTED" for item in events),
            statuses.count("COMPLETION_VERIFIED"),
            0.0 if not timing else round(sum(timing) / len(timing), 3),
            0.0 if not timing else max(timing),
            0.0 if not events else round(len(recon) / len(events), 3), confidence,
            distribution(tier1), distribution(tier2),
        )


class AcceptanceReportBuilder:
    def build(
        self,
        *,
        baseline_status: str,
        traceability: Mapping[str, Mapping[str, int]],
        findings: Iterable[Mapping[str, Any]],
        bundle: BundleInspection,
        metrics: TraceMetrics,
        test_run: Mapping[str, Any] | None = None,
        bundle_manifest_hash: str | None = None,
        traceability_changes: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        findings = list(findings)
        failed = sum(item.get("failed", 0) for item in traceability.values())
        incomplete = sum(item.get("no_manifest", 0) + item.get("skipped", 0) + item.get("not_run", 0) for item in traceability.values())
        evidence_class_gaps = sum(not item.get("minimum_evidence_class_met", True) for item in traceability.values())
        open_findings = sum(item["status"] == "OPEN" for item in findings)
        if test_run is None or not test_run.get("case_results") or not bundle_manifest_hash:
            raise EvidenceIntegrityError("acceptance report requires the bound current test run and bundle manifest hash")
        finding_verification = _verify_findings(findings, dict(test_run["case_results"]))
        if not baseline_status.startswith("L0_BASELINE_PASS"):
            verdict = "PROVISIONAL_NON_EVIDENCE"
        elif failed or open_findings or finding_verification["FIXED_UNVERIFIED"] or bundle.credential_findings:
            verdict = "FAIL"
        elif incomplete or evidence_class_gaps:
            verdict = "INCOMPLETE"
        else:
            verdict = "PASS"
        return {
            "report_version": "1.0",
            "verdict": verdict,
            "baseline_status": baseline_status,
            "test_run_hash": test_run.get("content_sha256"),
            "bundle_manifest_hash": bundle_manifest_hash,
            "criteria": dict(traceability),
            "traceability_changes": dict(traceability_changes or {}),
            "minimum_evidence_class_gaps": evidence_class_gaps,
            "findings": {
                status: sum(item["status"] == status for item in findings)
                for status in ("OPEN", "FIXED", "DEFERRED", "REJECTED")
            },
            "finding_verification": finding_verification,
            "bundle": {
                "run_id": bundle.run_id,
                "anchor_chain_event_count": bundle.event_count,
                "retained_corpus_event_count": metrics.event_count,
                "head_hash": bundle.head_hash,
                "files_verified": bundle.files_verified,
                "credential_findings": bundle.credential_findings,
            },
            "metrics": asdict(metrics),
            "evidence_classes": {
                "production": "system behavior through production interfaces",
                "integration_probe": "component integration with synthetic inputs",
                "offline_analyzer": "analysis of retained event data",
                "oracle_self_test": "harness consistency only; never acceptance evidence",
            },
        }
