import logging
from collections import Counter
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.db.models import FindingRow, ImportRow, PassedCheckRow, ScanRow
from cloudshield.db.store import utcnow
from cloudshield.findings import make_finding_id
from cloudshield.imports.build import fill_finding, refresh_text
from cloudshield.imports.mapping import rule_id_of
from cloudshield.imports.merge import PASSED_REASON, latest_completed_scan, reconcile
from cloudshield.imports.parser import AlreadyImported, ParsedFile, Record
from cloudshield.imports.recheck import resolve_gone_resources

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RunInfo:
    """How an import came about: from a file you gave, or from a run started in the dashboard."""

    origin: str = "file"
    duration_seconds: float | None = None
    services: list[str] | None = None
    regions: list[str] | None = None
    scan_id: int | None = None


def check_not_imported(session: Session, parsed: ParsedFile, account_id: str) -> None:
    query = select(ImportRow).where(
        ImportRow.account_id == account_id, ImportRow.file_sha256 == parsed.sha256
    )
    earlier = session.scalars(query).first()
    if earlier is not None:
        when = earlier.imported_at.strftime("%Y-%m-%d %H:%M")
        raise AlreadyImported(f"This file was already imported (import {earlier.id}, {when} UTC).")


def account_warning(session: Session, parsed: ParsedFile, account_id: str) -> str | None:
    query = (
        select(ImportRow).where(ImportRow.account_id == account_id).order_by(ImportRow.id.desc())
    )
    previous = session.scalars(query).first()
    if previous is None or previous.external_account_id == parsed.external_account_id:
        return None
    return (
        f"The AWS account in this file differs from the one in import {previous.id}. "
        f"Both are stored under '{account_id}'."
    )


def save_pass(
    session: Session, record: Record, account_id: str, import_row: ImportRow, now, counts: Counter
) -> None:
    key = (account_id, record.check_id, record.resource_id)
    passed = session.get(PassedCheckRow, key)
    if passed is None:
        passed = PassedCheckRow(
            account_id=account_id, check_id=record.check_id, resource_id=record.resource_id
        )
        session.add(passed)
    passed.region = record.region
    passed.last_import_id = import_row.id
    counts["passed"] += 1

    rule_id = rule_id_of(record.check_id)
    finding = session.get(FindingRow, (account_id, make_finding_id(rule_id, record.resource_id)))
    if finding is not None and finding.status == "OPEN":
        finding.status = "RESOLVED"
        finding.resolved_at = now
        finding.resolution_reason = PASSED_REASON
        finding.import_id = import_row.id
        finding.last_imported_at = now
        counts["resolved"] += 1


def save_failure(
    session: Session, record: Record, account_id: str, import_row: ImportRow, now, counts: Counter
) -> None:
    finding_id = make_finding_id(rule_id_of(record.check_id), record.resource_id)
    row = session.get(FindingRow, (account_id, finding_id))
    new = row is None
    if new:
        row = FindingRow(account_id=account_id, finding_id=finding_id, first_seen_at=now)
    # Filled before it is added, so the queries made while scoring never see a half-built row.
    fill_finding(session, row, account_id, record)
    if new:
        session.add(row)
    counts["imported" if new else "already_seen"] += 1
    row.status = "OPEN"
    row.resolved_at = None
    row.resolution_reason = None
    row.last_seen_at = now
    row.import_id = import_row.id
    row.last_imported_at = now


def import_parsed(
    session: Session,
    parsed: ParsedFile,
    account_id: str,
    file_name: str | None = None,
    run: RunInfo | None = None,
    scan: ScanRow | None = None,
) -> dict:
    """Stores the records of one file. Returns the counts and an optional warning.

    `scan` is the scan being saved right now, when the import is part of one."""
    run = run or RunInfo()
    check_not_imported(session, parsed, account_id)
    warning = account_warning(session, parsed, account_id)
    now = utcnow()
    import_row = ImportRow(
        account_id=account_id,
        source="prowler",
        file_sha256=parsed.sha256,
        imported_at=now,
        external_account_id=parsed.external_account_id,
        counts={},
        regions_covered=sorted({r.region for r in parsed.records if r.region}),
        checks_covered=sorted({r.check_id for r in parsed.records}),
        file_name=file_name,
        tool_name=parsed.tool_name,
        tool_version=parsed.tool_version,
        pass_count=sum(r.status == "PASS" for r in parsed.records),
        fail_count=sum(r.status == "FAIL" for r in parsed.records),
        origin=run.origin,
        duration_seconds=run.duration_seconds,
        services_used=run.services,
        regions_used=run.regions,
        scan_id=run.scan_id,
    )
    session.add(import_row)
    session.flush()

    counts: Counter = Counter()
    for record in parsed.records:
        if record.status == "PASS":
            save_pass(session, record, account_id, import_row, now, counts)
        else:
            save_failure(session, record, account_id, import_row, now, counts)
        session.flush()

    scan = scan or latest_completed_scan(session, account_id)
    if scan is not None:
        counts["resolved"] += resolve_gone_resources(session, scan, account_id, now)

    reconcile(session, account_id, scan)
    import_row.counts = {
        "imported": counts["imported"],
        "passed": counts["passed"],
        "ignored": parsed.ignored,
        "already_seen": counts["already_seen"],
        "resolved": counts["resolved"],
        "rejected": parsed.rejected,
        "unknown_severity": parsed.unknown_severity,
    }
    session.commit()
    logger.info("Import %d stored: %s", import_row.id, import_row.counts)
    if warning:
        logger.warning(warning)
    return {"import_id": import_row.id, "counts": import_row.counts, "warning": warning}


def refresh_parsed(
    session: Session, parsed: ParsedFile, account_id: str, file_name: str | None = None
) -> dict:
    """Re-applies the parsing to findings that already exist, even for a file that was imported
    before. Title, evidence and details change. Status, first_seen_at and the resolution do not."""
    refreshed = 0
    for record in parsed.records:
        if record.status != "FAIL":
            continue
        finding_id = make_finding_id(rule_id_of(record.check_id), record.resource_id)
        row = session.get(FindingRow, (account_id, finding_id))
        if row is not None:
            refresh_text(row, record)
            refreshed += 1
    # The import row of this file may have been made before the history fields existed.
    query = select(ImportRow).where(
        ImportRow.account_id == account_id, ImportRow.file_sha256 == parsed.sha256
    )
    earlier = session.scalars(query).first()
    if earlier is not None:
        earlier.file_name = earlier.file_name or file_name
        earlier.tool_name = earlier.tool_name or parsed.tool_name
        earlier.tool_version = earlier.tool_version or parsed.tool_version
        if earlier.pass_count is None:
            earlier.pass_count = sum(r.status == "PASS" for r in parsed.records)
            earlier.fail_count = sum(r.status == "FAIL" for r in parsed.records)
    reconcile(session, account_id)
    session.commit()
    logger.info("Refreshed %d findings", refreshed)
    failures = sum(r.status == "FAIL" for r in parsed.records)
    return {"refreshed": refreshed, "not_found": failures - refreshed}
