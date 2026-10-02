import hashlib
from dataclasses import dataclass, field
from typing import Literal, get_args

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
FindingStatus = Literal["OPEN", "RESOLVED"]
Certainty = Literal["verified", "heuristic", "unknown"]
SEVERITIES = get_args(Severity)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    resource_id: str
    resource_type: str
    title: str
    severity: Severity
    category: str
    status: FindingStatus
    details: dict
    evidence: dict = field(default_factory=dict)
    risk_score: int | None = None  # None for rules that do not count toward risk
    risk_factors: list = field(default_factory=list)


def make_finding_id(rule_id: str, resource_id: str, variant: str = "") -> str:
    digest = hashlib.sha256((resource_id + variant).encode("utf-8")).hexdigest()
    return f"F-{rule_id}-{digest[:8]}"
