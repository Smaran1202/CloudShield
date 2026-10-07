from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cloudshield.db.models import FindingRow, ImportRow, ResourceRow, ScanRow

# The scanner service that has to have run without errors before we can say a resource is gone.
# IAM roles are left out: roles are only found through instances, so a missing role is not proof.
SERVICE_OF = {"S3": "s3", "Security Group": "ec2", "EC2": "ec2", "IAM Policy": "iam"}
REGIONAL_TYPES = ("Security Group", "EC2")
GONE_REASON = "resource no longer exists"


def latest_import_id(session: Session, account_id: str) -> int | None:
    query = select(func.max(ImportRow.id)).where(ImportRow.account_id == account_id)
    return session.scalar(query)


def resolve_gone_resources(session: Session, scan: ScanRow, account_id: str, now: datetime) -> int:
    """Resolves open imported findings that the newest import did not recheck, when our own scan
    shows their resource gone. Returns how many were resolved."""
    newest = latest_import_id(session, account_id)
    error_services = {error["service"] for error in scan.errors}
    query = select(FindingRow).where(
        FindingRow.account_id == account_id,
        FindingRow.source == "prowler",
        FindingRow.status == "OPEN",
        FindingRow.import_id != newest,
    )
    resolved = 0
    for finding in session.scalars(query).all():
        service = SERVICE_OF.get(finding.resource_type)
        if service is None or service in error_services:
            continue
        # A policy owned by AWS itself is never in our scan, so its absence says nothing.
        if finding.resource_type == "IAM Policy" and finding.resource_id.split(":")[4] == "aws":
            continue
        resource = session.get(ResourceRow, (account_id, finding.resource_id))
        # A resource we never saw cannot be called gone.
        if resource is None or resource.last_seen_scan_id >= scan.id:
            continue
        if finding.resource_type in REGIONAL_TYPES and resource.region not in scan.regions:
            continue
        finding.status = "RESOLVED"
        finding.resolved_at = now
        finding.resolution_reason = GONE_REASON
        resolved += 1
    return resolved
