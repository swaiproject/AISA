"""Validated immutable configuration loading for the trusted boundary."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
import hashlib

from .errors import ConfigurationError
from .strict_json import loads_strict_json
from .validation import validate_schema


@dataclass(frozen=True)
class TrustedConfiguration:
    objective: Mapping[str, Any]
    policy: Mapping[str, Any]
    reason_codes: frozenset[str]
    event_schema_sha256: str

    @classmethod
    def load(cls, root: Path, objective_path: Path, policy_path: Path) -> "TrustedConfiguration":
        objective = _load_object(root / objective_path)
        policy = _load_object(root / policy_path)
        objective_schema = _load_object(root / "schemas/objective.schema.json")
        policy_schema = _load_object(root / "schemas/policy.schema.json")
        issues = validate_schema(objective, objective_schema)
        if issues:
            raise ConfigurationError("objective validation failed: " + "; ".join(map(str, issues)))
        issues = validate_schema(policy, policy_schema)
        if issues:
            raise ConfigurationError("policy validation failed: " + "; ".join(map(str, issues)))
        registry = _load_object(root / "config/reason_codes.json")
        codes = frozenset(code for family in registry.values() for code in family)
        _cross_validate(objective, policy)
        lock = _load_object(root / "baseline/baseline.lock.json")
        schema_artifact = next((item for item in lock["artifacts"] if item["role"] == "event_schema"), None)
        if schema_artifact is None:
            raise ConfigurationError("baseline lock has no event_schema artifact")
        schema_path = root / "schemas/primary_agent_event_v0.2.schema.json"
        actual_hash = hashlib.sha256(schema_path.read_bytes()).hexdigest()
        if actual_hash != schema_artifact["sha256"]:
            raise ConfigurationError("runtime event schema hash does not match the baseline lock")
        return cls(_freeze(objective), _freeze(policy), codes, actual_hash)


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = loads_strict_json(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ConfigurationError(f"cannot load {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"{path.name} must contain an object")
    return value


def _cross_validate(objective: dict[str, Any], policy: dict[str, Any]) -> None:
    resources = set(objective["resources"])
    for capability, rule in objective["allowed_capabilities"].items():
        missing = set(rule["targets"]) - resources
        if missing:
            raise ConfigurationError(f"capability {capability!r} references undeclared resources: {sorted(missing)!r}")
    undeclared_ambiguous = set(policy["tier1_rules"]["ambiguous_targets"]) - resources
    if undeclared_ambiguous:
        raise ConfigurationError(f"ambiguous targets are undeclared: {sorted(undeclared_ambiguous)!r}")
