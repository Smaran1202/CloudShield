import hashlib
from dataclasses import dataclass
from typing import Literal, get_args

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
FindingStatus = Literal["OPEN", "RESOLVED"]
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


def make_finding_id(rule_id: str, resource_id: str, variant: str = "") -> str:
    digest = hashlib.sha256((resource_id + variant).encode("utf-8")).hexdigest()
    return f"F-{rule_id}-{digest[:8]}"
