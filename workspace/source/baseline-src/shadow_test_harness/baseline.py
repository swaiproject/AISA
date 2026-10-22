from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _cell_text(cell: ET.Element) -> str:
    return "".join(node.text or "" for node in cell.iter(f"{W}t")).strip()


def docx_document_control(path: Path) -> dict[str, str]:
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read("word/document.xml"))
    first_table = root.find(f".//{W}tbl")
    if first_table is None:
        return {}
    result: dict[str, str] = {}
    for row in first_table.findall(f"{W}tr"):
        cells = row.findall(f"{W}tc")
        if len(cells) >= 2:
            result[_cell_text(cells[0])] = _cell_text(cells[1])
    return result


def docx_text(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read("word/document.xml"))
    return " ".join((node.text or "") for node in root.iter(f"{W}t"))


def json_document_control(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    version = data.get("properties", {}).get("schema_version", {}).get("const")
    return {"schema_version": version, "title": data.get("title")}


def consistency_issues(lock: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    declared = lock["test_plan_declared_inputs"]
    for artifact in lock["artifacts"]:
        role = artifact["role"]
        if role in declared and artifact["content_identity"] != declared[role]:
            issues.append(
                f"{role}: embedded identity {artifact['content_identity']!r} does not match Test Plan declaration {declared[role]!r}"
            )
    return issues


def byte_issues(lock: dict[str, Any], documents_dir: Path) -> list[str]:
    issues: list[str] = []
    for artifact in lock["artifacts"]:
        path = documents_dir / artifact["file_name"]
        if not path.exists():
            issues.append(f"missing: {artifact['file_name']}")
            continue
        if sha256(path) != artifact["sha256"]:
            issues.append(f"hash mismatch: {artifact['file_name']}")
            continue
        actual = json_document_control(path) if path.suffix.lower() == ".json" else docx_document_control(path)
        for field, expected in artifact["document_control"].items():
            if actual.get(field) != expected:
                issues.append(
                    f"content identity mismatch: {artifact['file_name']} field {field!r} expected {expected!r}, found {actual.get(field)!r}"
                )
    plan = next((item for item in lock["artifacts"] if item["role"] == "test_plan"), None)
    if plan is not None:
        plan_path = documents_dir / plan["file_name"]
        if plan_path.exists() and sha256(plan_path) == plan["sha256"]:
            text = docx_text(plan_path)
            for role, identity in lock["test_plan_declared_inputs"].items():
                if identity not in text:
                    issues.append(f"test plan declaration missing or mismatched for {role}: {identity!r}")
    return issues
