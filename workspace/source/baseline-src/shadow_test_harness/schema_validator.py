"""Small dependency-free validator for the schema features used by this PoC.

This is a harness bootstrap validator, not a general JSON Schema implementation.
Acceptance execution should add an independently maintained Draft 2020-12 validator
and run the same fixture corpus against both implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


class UnsupportedSchemaKeywordError(ValueError):
    """Raised before validation when the bootstrap validator cannot enforce a keyword."""


SUPPORTED_KEYWORDS = {
    "$schema", "$id", "$ref", "$defs", "title", "description", "type",
    "const", "enum", "format", "pattern", "minimum", "minLength", "minItems",
    "uniqueItems", "items", "properties", "required", "additionalProperties",
    "allOf", "oneOf", "if", "then", "else", "dependentRequired",
}


def assert_supported_schema(schema: dict[str, Any]) -> None:
    def inspect(rule: Any, path: str) -> None:
        if not isinstance(rule, dict):
            return
        unknown = set(rule) - SUPPORTED_KEYWORDS
        if unknown:
            raise UnsupportedSchemaKeywordError(f"{path}: unsupported schema keywords {sorted(unknown)!r}")
        for name, child in rule.get("properties", {}).items():
            inspect(child, f"{path}.properties.{name}")
        for name, child in rule.get("$defs", {}).items():
            inspect(child, f"{path}.$defs.{name}")
        if isinstance(rule.get("items"), dict):
            inspect(rule["items"], f"{path}.items")
        for keyword in ("allOf", "oneOf"):
            for index, child in enumerate(rule.get(keyword, [])):
                inspect(child, f"{path}.{keyword}[{index}]")
        for keyword in ("if", "then", "else"):
            if keyword in rule:
                inspect(rule[keyword], f"{path}.{keyword}")

    inspect(schema, "$")


def _is_type(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, True)


def _resolve_ref(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported reference: {ref}")
    node: Any = root
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def validate(instance: Any, schema: dict[str, Any]) -> list[ValidationIssue]:
    assert_supported_schema(schema)
    issues: list[ValidationIssue] = []

    def walk(value: Any, rule: dict[str, Any], path: str) -> None:
        if "$ref" in rule:
            walk(value, _resolve_ref(schema, rule["$ref"]), path)
            return
        if "const" in rule and value != rule["const"]:
            issues.append(ValidationIssue(path, f"must equal {rule['const']!r}"))
        if "enum" in rule and value not in rule["enum"]:
            issues.append(ValidationIssue(path, f"not in enum {rule['enum']!r}"))
        expected = rule.get("type")
        if expected:
            choices = expected if isinstance(expected, list) else [expected]
            if not any(_is_type(value, choice) for choice in choices):
                issues.append(ValidationIssue(path, f"expected type {choices!r}"))
                return
        if isinstance(value, str):
            if len(value) < rule.get("minLength", 0):
                issues.append(ValidationIssue(path, "string is too short"))
            if rule.get("format") == "date-time":
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError("timezone is required")
                except ValueError:
                    issues.append(ValidationIssue(path, "invalid date-time"))
            if "pattern" in rule and re.search(rule["pattern"], value) is None:
                issues.append(ValidationIssue(path, f"does not match pattern {rule['pattern']!r}"))
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in rule and value < rule["minimum"]:
                issues.append(ValidationIssue(path, f"must be >= {rule['minimum']}"))
        if isinstance(value, list):
            if len(value) < rule.get("minItems", 0):
                issues.append(ValidationIssue(path, "array has too few items"))
            if rule.get("uniqueItems"):
                normalized = [repr(item) for item in value]
                if len(normalized) != len(set(normalized)):
                    issues.append(ValidationIssue(path, "array items must be unique"))
            if "items" in rule:
                for index, item in enumerate(value):
                    walk(item, rule["items"], f"{path}[{index}]")
        if isinstance(value, dict):
            for name in rule.get("required", []):
                if name not in value:
                    issues.append(ValidationIssue(path, f"missing required property {name!r}"))
            properties = rule.get("properties", {})
            if rule.get("additionalProperties") is False:
                for name in value:
                    if name not in properties:
                        issues.append(ValidationIssue(f"{path}.{name}", "additional property is not allowed"))
            elif isinstance(rule.get("additionalProperties"), dict):
                for name in value:
                    if name not in properties:
                        walk(value[name], rule["additionalProperties"], f"{path}.{name}")
            for name, child_rule in properties.items():
                if name in value:
                    walk(value[name], child_rule, f"{path}.{name}")
            for trigger, dependencies in rule.get("dependentRequired", {}).items():
                if trigger in value:
                    for dependency in dependencies:
                        if dependency not in value:
                            issues.append(ValidationIssue(path, f"property {trigger!r} requires {dependency!r}"))
        for condition in rule.get("allOf", []):
            walk(value, condition, path)
        if "oneOf" in rule:
            passing = 0
            for option in rule["oneOf"]:
                before = len(issues)
                walk(value, option, path)
                if len(issues) == before:
                    passing += 1
                else:
                    del issues[before:]
            if passing != 1:
                issues.append(ValidationIssue(path, f"must match exactly one oneOf branch; matched {passing}"))
        if "if" in rule:
            probe: list[ValidationIssue] = []
            before = len(issues)
            walk(value, rule["if"], path)
            probe.extend(issues[before:])
            del issues[before:]
            branch = rule.get("then") if not probe else rule.get("else")
            if branch:
                walk(value, branch, path)

    walk(instance, schema, "$")
    return issues


def assert_valid(instance: Any, schema: dict[str, Any]) -> None:
    issues = validate(instance, schema)
    if issues:
        raise AssertionError("\n".join(str(issue) for issue in issues))
