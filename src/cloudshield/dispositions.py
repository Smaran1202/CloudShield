from datetime import datetime

from cloudshield.db.models import FindingRow


def is_dismissed(row: FindingRow, now: datetime) -> bool:
    """Dismissed while the disposition has not expired. An expired one is open again."""
    if row.disposition == "none":
        return False
    return row.disposition_until is None or row.disposition_until > now


def counts_toward_open(row: FindingRow, now: datetime) -> bool:
    """Open, not merged into another finding, and not dismissed."""
    return row.status == "OPEN" and row.merged_into is None and not is_dismissed(row, now)


def own_identities(setting: str) -> set[str]:
    return {name.strip() for name in setting.split(",") if name.strip()}


def suggested_not_applicable(row: FindingRow, identities: set[str]) -> str | None:
    """A reason to consider marking the finding not applicable, or None. It is only a
    suggestion: nothing is ever dismissed automatically."""
    resource = row.resource_id
    parts = resource.split(":")
    if resource.startswith("arn:") and len(parts) > 4 and parts[4] == "aws":
        return "This is an AWS-managed policy. AWS owns it and you cannot change it."
    if "/aws-service-role/" in resource:
        return "This is an AWS service-linked role. AWS manages it."
    if resource in identities or resource.split("/")[-1] in identities:
        return "This identity is listed in CLOUDSHIELD_OWN_IDENTITIES as belonging to CloudShield."
    return None
