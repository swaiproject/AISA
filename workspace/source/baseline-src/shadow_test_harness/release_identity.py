"""Deterministic identity for the exact formal-acceptance controlled tree."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def controlled_file_hashes(root: Path) -> dict[str, str]:
    configuration = json.loads((root / "config/formal_acceptance_inputs.json").read_text(encoding="utf-8"))
    files: dict[str, str] = {}
    for name in configuration["controlled_paths"]:
        path = root / name
        candidates = sorted(
            item for item in ([path] if path.is_file() else path.rglob("*"))
            if item.is_file() and "__pycache__" not in item.parts
        )
        if not candidates:
            raise ValueError(f"CONTROLLED_PATH_EMPTY:{name}")
        for item in candidates:
            files[item.relative_to(root).as_posix()] = "sha256:" + hashlib.sha256(item.read_bytes()).hexdigest()
    return files


def release_identity(root: Path) -> str:
    return "sha256:" + hashlib.sha256(canonical(controlled_file_hashes(root))).hexdigest()
