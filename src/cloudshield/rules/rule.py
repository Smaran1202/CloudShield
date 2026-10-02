from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Hit:
    resource: dict
    details: dict
    variant: str = ""  # tells apart several findings on one resource
    severity: str | None = None  # overrides the rule severity for this finding


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    description: str
    fix: str
    check: Callable[[list[dict]], list[Hit]]
    counts_toward_risk: bool = True  # False for INFO rules


def of_type(resources: list[dict], resource_type: str) -> list[dict]:
    return [r for r in resources if r["resource_type"] == resource_type]
