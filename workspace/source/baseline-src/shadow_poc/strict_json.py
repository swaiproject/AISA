"""Strict JSON parsing for the production trust boundary."""

from __future__ import annotations

import json
from typing import Any


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def loads_strict_json(text: str | bytes) -> Any:
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
