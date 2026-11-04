"""The baseline for the unknown-handling experiment (E1).

A naive resolver treats missing data and scanner errors as passing: a finding that the latest scan
or import does not report again is called fixed. CloudShield deliberately does not do this. This
code is used only by the experiments. It is not imported by the product, and nothing in the API
or the dashboard can select it.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.db.models import ACCOUNT_ID, FindingRow, ScanRow
from cloudshield.findings import make_finding_id
from cloudshield.imports.mapping import rule_id_of
from cloudshield.imports.parser import ParsedFile


def naive_resolve_fixed(
    session: Session, scan: ScanRow, result: dict, current_ids: set[str], now: datetime
) -> None:
    """Same arguments as cloudshield.db.store.resolve_fixed, so the experiment can swap it in.
    No check of the scan errors, the regions, or whether the resource was seen."""
    query = select(FindingRow).where(
        FindingRow.account_id == ACCOUNT_ID,
        FindingRow.status == "OPEN",
        FindingRow.source == "cloudshield",
        FindingRow.finding_id.not_in(list(current_ids)),
    )
    for row in session.scalars(query).all():
        row.status = "RESOLVED"
        row.resolved_at = now
        row.resolution_reason = "naive: not reported by the scan"
        row.last_scan_id = scan.id


def naive_resolve_imports(session: Session, parsed: ParsedFile, now: datetime) -> int:
    """Resolves every open imported finding that the newer import does not report as failing again,
    whether the check passed, was left out, or could not run. Returns how many it resolved."""
    failing = {
        make_finding_id(rule_id_of(record.check_id), record.resource_id)
        for record in parsed.records
        if record.status == "FAIL"
    }
    query = select(FindingRow).where(
        FindingRow.account_id == ACCOUNT_ID,
        FindingRow.source == "prowler",
        FindingRow.status == "OPEN",
    )
    resolved = 0
    for row in session.scalars(query).all():
        if row.finding_id not in failing:
            row.status = "RESOLVED"
            row.resolved_at = now
            row.resolution_reason = "naive: not reported by the import"
            resolved += 1
    return resolved
