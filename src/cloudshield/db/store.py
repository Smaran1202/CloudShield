from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.db.models import ACCOUNT_ID, FindingRow, ResourceRow, ScanRow
from cloudshield.findings import Finding
from cloudshield.dispositions import counts_toward_open
from cloudshield.imports.merge import reconcile
from cloudshield.imports.recheck import resolve_gone_resources
from cloudshield.risk.environment import environment_score, severity_counts

# The scanner service that has to run without errors before a finding of this type can be
# called fixed.
SERVICE_OF = {
    "S3": "s3",
    "EC2": "ec2",
    "Security Group": "ec2",
    "IAM Policy": "iam",
    "IAM Role": "iam",
}
REGIONAL_TYPES = ("EC2", "Security Group")


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def active_scan(session: Session) -> ScanRow | None:
    query = select(ScanRow).where(
        ScanRow.account_id == ACCOUNT_ID, ScanRow.status.in_(("queued", "running"))
    )
    return session.scalars(query).first()


def create_scan(session: Session, regions: list[str]) -> ScanRow:
    scan = ScanRow(account_id=ACCOUNT_ID, status="queued", progress="Queued", regions=regions)
    session.add(scan)
    session.commit()
    return scan


def mark_running(session: Session, scan_id: int) -> None:
    scan = session.get(ScanRow, scan_id)
    scan.status = "running"
    scan.progress = "Scanning AWS"
    scan.started_at = utcnow()
    session.commit()


def set_progress(session: Session, scan_id: int, progress: str) -> None:
    session.get(ScanRow, scan_id).progress = progress
    session.commit()


def mark_failed(session: Session, scan_id: int, message: str) -> None:
    scan = session.get(ScanRow, scan_id)
    scan.status = "failed"
    scan.progress = "Failed"
    scan.failure_message = message
    scan.finished_at = utcnow()
    session.commit()


def fail_unfinished(session: Session) -> None:
    # A scan left queued or running after a restart can never finish and would block new scans.
    query = select(ScanRow).where(ScanRow.status.in_(("queued", "running")))
    for scan in session.scalars(query).all():
        scan.status = "failed"
        scan.progress = "Failed"
        scan.failure_message = "The server restarted before the scan finished."
        scan.finished_at = utcnow()
    session.commit()


def save_result(session: Session, scan_id: int, result: dict, findings: list[Finding]) -> None:
    scan = session.get(ScanRow, scan_id)
    now = utcnow()
    save_resources(session, scan_id, result["resources"])
    save_findings(session, scan_id, findings, now)
    resolve_fixed(session, scan, result, {f.finding_id for f in findings}, now)
    scan.errors = result["errors"]
    scan.status = "completed"
    resolve_gone_resources(session, scan, ACCOUNT_ID, now)
    session.flush()
    reconcile(session, ACCOUNT_ID)
    save_environment_score(session, scan)
    scan.progress = "Done"
    scan.finished_at = now
    scan.resource_count = len(result["resources"])
    scan.finding_count = len(findings)
    scan.error_count = len(result["errors"])
    session.commit()


def save_resources(session: Session, scan_id: int, resources: list[dict]) -> None:
    for resource in resources:
        row = session.get(ResourceRow, (ACCOUNT_ID, resource["resource_id"]))
        if row is None:
            row = ResourceRow(account_id=ACCOUNT_ID, resource_id=resource["resource_id"])
            session.add(row)
        row.resource_type = resource["resource_type"]
        row.region = resource["region"]
        row.name = resource["name"]
        row.attributes = resource["attributes"]
        row.last_seen_scan_id = scan_id


def save_findings(session: Session, scan_id: int, findings: list[Finding], now: datetime) -> None:
    for finding in findings:
        row = session.get(FindingRow, (ACCOUNT_ID, finding.finding_id))
        if row is None:
            row = FindingRow(
                account_id=ACCOUNT_ID, finding_id=finding.finding_id, first_seen_at=now
            )
            session.add(row)
        row.rule_id = finding.rule_id
        row.resource_id = finding.resource_id
        row.resource_type = finding.resource_type
        row.title = finding.title
        row.severity = finding.severity
        row.category = finding.category
        row.details = finding.details
        row.evidence = finding.evidence
        row.risk_score = finding.risk_score
        row.risk_factors = finding.risk_factors
        row.score_basis = "context adjusted" if finding.risk_factors else "severity only"
        row.status = "OPEN"
        row.resolved_at = None
        row.resolution_reason = None
        row.last_seen_at = now
        row.last_scan_id = scan_id


def save_environment_score(session: Session, scan: ScanRow) -> None:
    query = select(FindingRow).where(
        FindingRow.account_id == ACCOUNT_ID, FindingRow.status == "OPEN"
    )
    now = utcnow()
    open_rows = [r for r in session.scalars(query).all() if counts_toward_open(r, now)]
    scores = [row.risk_score for row in open_rows if row.risk_score is not None]
    scan.environment_score = environment_score(scores)
    scan.severity_counts = severity_counts([row.severity for row in open_rows])


def resolve_fixed(
    session: Session, scan: ScanRow, result: dict, current_ids: set[str], now: datetime
) -> None:
    # Unknown is not fixed: a finding is only resolved when the service for its resource type
    # ran without errors, and (for regional resources) its region was part of this scan.
    error_services = {error["service"] for error in result["errors"]}
    seen_ids = {resource["resource_id"] for resource in result["resources"]}
    query = select(FindingRow).where(
        FindingRow.account_id == ACCOUNT_ID,
        FindingRow.status == "OPEN",
        FindingRow.source == "cloudshield",
        FindingRow.finding_id.not_in(list(current_ids)),
    )
    for row in session.scalars(query).all():
        service = SERVICE_OF.get(row.resource_type)
        if service is None or service in error_services:
            continue
        resource = session.get(ResourceRow, (ACCOUNT_ID, row.resource_id))
        if row.resource_type in REGIONAL_TYPES:
            if resource is None or resource.region not in scan.regions:
                continue
        if row.resource_id in seen_ids:
            reason = "no longer detected"
        elif row.resource_type == "IAM Role":
            # Roles are only found through instances, so a role missing from the scan is not
            # proof that it was deleted.
            continue
        else:
            reason = "resource not found"
        row.status = "RESOLVED"
        row.resolved_at = now
        row.resolution_reason = reason
        row.last_scan_id = scan.id
