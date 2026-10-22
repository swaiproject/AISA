from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def loads_json(text: str) -> Any:
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_constant,
    )
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON number is not permitted")
    return value


def load_json(relative_path: str | Path) -> Any:
    with (ROOT / relative_path).open("r", encoding="utf-8") as handle:
        return loads_json(handle.read())
