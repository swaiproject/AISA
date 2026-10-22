from __future__ import annotations

from typing import Any


def expand_catalogue(catalogue: dict[str, Any], external_passes: set[str] | None = None) -> dict[str, str]:
    external_passes = external_passes or set()
    cases: dict[str, str] = {}
    for family, definition in catalogue["families"].items():
        executable = set(definition["executable"])
        for number in range(definition["first"], definition["last"] + 1):
            test_id = f"TP-{family}-{number:03d}"
            cases[test_id] = "EXTERNAL_EVIDENCE" if test_id in external_passes else ("EXECUTABLE" if number in executable else "SKIP_NOT_IMPLEMENTED")
    return cases


def reconcile(catalogue: dict[str, Any], discovered_ids: set[str], external_passes: set[str] | None = None) -> dict[str, Any]:
    cases = expand_catalogue(catalogue, external_passes)
    expected = set(cases)
    return {
        "catalogue_ids": len(expected),
        "discovered": len(expected & discovered_ids),
        "executable": sum(value == "EXECUTABLE" for value in cases.values()),
        "external_evidence": sum(value == "EXTERNAL_EVIDENCE" for value in cases.values()),
        "skipped_not_implemented": sum(value == "SKIP_NOT_IMPLEMENTED" for value in cases.values()),
        "not_registered": sorted(expected - discovered_ids),
        "unexpected": sorted(discovered_ids - expected),
    }
