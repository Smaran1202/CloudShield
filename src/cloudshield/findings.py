import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    resource_id: str
    resource_type: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW or INFO
    category: str
    status: str  # OPEN or RESOLVED
    details: dict


def make_finding_id(rule_id: str, resource_id: str, variant: str = "") -> str:
    digest = hashlib.sha256((resource_id + variant).encode("utf-8")).hexdigest()
    return f"F-{rule_id}-{digest[:8]}"
