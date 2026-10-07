from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.db.models import (
    FindingRow,
    ImportRow,
    PassedCheckRow,
    ResourceRow,
    ScanRow,
)
from cloudshield.imports.mapping import NEEDS, SAME_CHECK, SOURCE, rule_id_of
from cloudshield.imports.recheck import SERVICE_OF

PASSED_REASON = "passed in a newer import"
ALSO_REPORTED = "Also reported by an imported scan"
NOT_COMPARED = "CloudShield could not read this setting, so the two results are not compared."


def without_corroboration(evidence: dict) -> dict:
    items = [i for i in evidence.get("items", []) if i["fact"] not in (ALSO_REPORTED, NOT_COMPARED)]
    return {**evidence, "items": items}


def with_item(evidence: dict, item: dict) -> dict:
    return {**evidence, "items": [*evidence["items"], item]}


def no_data(session: Session, account_id: str, our_rule: str, resource_id: str, scan) -> bool:
    """True when our side cannot say anything about this rule and resource: the attribute the
    rule needs is missing (unknown), or our latest scan had an error for that service."""
    resource = session.get(ResourceRow, (account_id, resource_id))
    if resource is None:
        return False
    errors = {error["service"] for error in scan.errors} if scan is not None else set()
    if SERVICE_OF.get(resource.resource_type) in errors:
        return True
    return NEEDS[our_rule] not in resource.attributes


def current_status(imported: FindingRow | None, passed) -> str | None:
    """What the imported scan says now: FAIL, PASS, or None when it has said nothing."""
    if imported is not None and imported.status == "OPEN":
        return "FAIL"
    if passed is not None and (imported is None or imported.resolution_reason == PASSED_REASON):
        return "PASS"
    return None


def when_imported(session: Session, imported: FindingRow | None, passed) -> str:
    if imported is not None and imported.status == "OPEN":
        moment = imported.last_imported_at
    else:
        moment = session.get(ImportRow, passed.last_import_id).imported_at
    return moment.isoformat()


def reconcile(session: Session, account_id: str) -> None:
    """Works out, for every pair in SAME_CHECK, how our finding and the imported one relate.

    Both fail: ours stays primary, and the imported one is merged into it and hidden.
    They disagree: both stay visible and are flagged. The result is rebuilt each time, so it is
    always in step with the latest scan and the latest import. When our side has no data
    for a resource, the two are never compared: nothing is merged or flagged."""
    scan = session.scalars(
        select(ScanRow)
        .where(ScanRow.account_id == account_id, ScanRow.status == "completed")
        .order_by(ScanRow.id.desc())
    ).first()
    for check_id, our_rule in SAME_CHECK.items():
        imported_rows = session.scalars(
            select(FindingRow).where(
                FindingRow.account_id == account_id,
                FindingRow.source == "prowler",
                FindingRow.rule_id == rule_id_of(check_id),
            )
        ).all()
        our_rows = session.scalars(
            select(FindingRow).where(
                FindingRow.account_id == account_id,
                FindingRow.source == "cloudshield",
                FindingRow.rule_id == our_rule,
            )
        ).all()
        for row in imported_rows:
            row.merged_into = None
            row.tools_disagree = False
            row.evidence = without_corroboration(row.evidence)
        for row in our_rows:
            row.corroborated_by = []
            row.tools_disagree = False
            row.evidence = without_corroboration(row.evidence)

        imported_by_resource = {r.resource_id: r for r in imported_rows}
        ours_by_resource = {r.resource_id: r for r in our_rows}
        passes = session.scalars(
            select(PassedCheckRow).where(
                PassedCheckRow.account_id == account_id, PassedCheckRow.check_id == check_id
            )
        ).all()
        passed_by_resource = {p.resource_id: p for p in passes}

        for resource_id in set(imported_by_resource) | set(passed_by_resource):
            imported = imported_by_resource.get(resource_id)
            passed = passed_by_resource.get(resource_id)
            theirs = current_status(imported, passed)
            ours = ours_by_resource.get(resource_id)
            ours_open = ours is not None and ours.status == "OPEN"
            if theirs is None:
                continue
            if no_data(session, account_id, our_rule, resource_id, scan):
                not_compared = {
                    "fact": NOT_COMPARED,
                    "value": None,
                    "source": SOURCE,
                    "certainty": "unknown",
                }
                for row in (ours, imported if theirs == "FAIL" else None):
                    if row is not None:
                        row.evidence = with_item(row.evidence, not_compared)
                continue
            entry = {
                "source": "prowler",
                "check_id": check_id,
                "status": theirs,
                "last_imported_at": when_imported(session, imported, passed),
            }
            if theirs == "FAIL" and ours_open:
                imported.merged_into = ours.finding_id
                ours.corroborated_by = [*ours.corroborated_by, entry]
                ours.evidence = {
                    **ours.evidence,
                    "items": [
                        *ours.evidence["items"],
                        {
                            "fact": ALSO_REPORTED,
                            "value": {"check_id": check_id},
                            "source": SOURCE,
                            "certainty": "reported",
                        },
                    ],
                }
            elif theirs == "PASS" and ours_open:
                ours.tools_disagree = True
                ours.corroborated_by = [*ours.corroborated_by, entry]
            elif theirs == "FAIL" and session.get(ResourceRow, (account_id, resource_id)):
                # Our scan holds this resource and has no open finding for it.
                imported.tools_disagree = True
                if ours is not None:
                    ours.tools_disagree = True
