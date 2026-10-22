"""Trusted data-classification aggregation."""

from __future__ import annotations
from typing import Any, Mapping

CLASSIFICATION_ORDER = {"PUBLIC": 0, "INTERNAL": 1, "SENSITIVE": 2, "RESTRICTED": 3}


def maximum_classification(*values: str) -> str:
    if not values:
        return "PUBLIC"
    if any(value not in CLASSIFICATION_ORDER for value in values):
        return "RESTRICTED"
    return max(values, key=CLASSIFICATION_ORDER.__getitem__)


def effective_classification(
    objective: Mapping[str, Any], target_classification: str, taint_source_resource_ids: tuple[str, ...]
) -> str:
    source_classes = []
    resources = objective["resources"]
    for resource_id in taint_source_resource_ids:
        resource = resources.get(resource_id)
        source_classes.append("RESTRICTED" if resource is None else resource["classification"])
    return maximum_classification(target_classification, *source_classes)
