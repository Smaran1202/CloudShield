from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.db.models import FindingRow, ResourceRow, ScanRow
from cloudshield.fixes.service import resource_dict
from cloudshield.imports.mapping import SOURCE, rule_id_of
from cloudshield.imports.parser import Record
from cloudshield.risk.scoring import BASE_SCORES, context_factors, factor

NO_CONTEXT = "context not available for imported findings"
SEVERITY_ONLY = "severity only"
CONTEXT_ADJUSTED = "context adjusted"


def title_for(record: Record) -> str:
    # The check's own title describes the passing state, so it can never be the title of a
    # failure. The failing statement is used, or the check title with "Failed:" in front.
    return record.status_detail.strip() or f"Failed: {record.check_title}"


def item(fact: str, value) -> dict:
    # Everything here is the tool's own output. CloudShield did not collect it, so it is
    # "reported".
    return {"fact": fact, "value": value, "source": SOURCE, "certainty": "reported"}


def evidence_for(record: Record) -> dict:
    items = []
    if record.status_detail:
        items.append(item("Failing statement", record.status_detail))
    resource = {
        "uid": record.resource_uid or None,
        "type": record.resource_type,
        "region": record.region,
    }
    items.append(item("Resource", resource))
    items.append(
        item("Check and severity", {"check_id": record.check_id, "severity": record.tool_severity})
    )
    if record.risk:
        items.append(item("Risk described by the scanner", record.risk))
    if record.description:
        items.append(item("Check description", record.description))
    return {"items": items}


def details_for(record: Record) -> dict:
    return {
        "check_id": record.check_id,
        "check_title": record.check_title,
        "description": record.description,
        "risk": record.risk,
        "remediation": record.remediation,
        "references": record.references,
        "categories": record.categories,
        "region": record.region,
        "prowler_uid": record.prowler_uid,
    }


def score_record(
    session: Session, account_id: str, record: Record
) -> tuple[int | None, list, str]:
    """The base score comes from the severity only. Our own context is added only when the same
    resource id is in our own scanned resources."""
    if record.severity == "INFO":
        return None, [], SEVERITY_ONLY
    base = BASE_SCORES[record.severity]
    row = None
    if record.resource_type != "Account":
        row = session.get(ResourceRow, (account_id, record.resource_id))
    if row is None:
        return base, [factor("context", 0, NO_CONTEXT, "unknown")], SEVERITY_ONLY

    scan = session.get(ScanRow, row.last_seen_scan_id)
    instances = session.scalars(
        select(ResourceRow).where(
            ResourceRow.account_id == account_id,
            ResourceRow.resource_type == "EC2",
            ResourceRow.last_seen_scan_id == row.last_seen_scan_id,
        )
    ).all()
    ec2_has_errors = any(error["service"] == "ec2" for error in scan.errors)
    ec2_known = not ec2_has_errors and row.region in scan.regions
    factors = context_factors(resource_dict(row), [resource_dict(i) for i in instances], ec2_known)
    return min(100, base + sum(f["adjustment"] for f in factors)), factors, CONTEXT_ADJUSTED


def fill_finding(session: Session, row: FindingRow, account_id: str, record: Record) -> None:
    score, factors, basis = score_record(session, account_id, record)
    row.rule_id = rule_id_of(record.check_id)
    row.resource_id = record.resource_id
    row.resource_type = record.resource_type
    row.title = title_for(record)
    row.severity = record.severity
    row.category = record.service or "imported"
    row.details = details_for(record)
    row.evidence = evidence_for(record)
    row.risk_score = score
    row.risk_factors = factors
    row.score_basis = basis
    row.source = "prowler"


def refresh_text(row: FindingRow, record: Record) -> None:
    """Re-applies the parsing to a finding that already exists. Status, dates and the
    resolution are not touched, and neither is the score."""
    row.title = title_for(record)
    row.details = details_for(record)
    row.evidence = evidence_for(record)
