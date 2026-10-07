import threading
from dataclasses import dataclass
from datetime import datetime, time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.api.jobs import run_scan_job
from cloudshield.api.schemas import (
    FindingDetailOut,
    DispositionIn,
    FindingOut,
    FindingSource,
    FixOut,
    ImportedResourceOut,
    ImportOut,
    ResourceOut,
    RiskSummaryOut,
    ScanOut,
    ScanRequest,
    SuggestedNotApplicable,
    TrendPoint,
)
from cloudshield.db import store
from cloudshield.db.models import (
    ACCOUNT_ID,
    FindingRow,
    FixRow,
    ImportRow,
    ResourceRow,
    ScanRow,
)
from cloudshield.dispositions import (
    counts_toward_open,
    is_dismissed,
    own_identities,
    suggested_not_applicable,
)
from cloudshield.findings import SEVERITIES, FindingStatus, Severity
from cloudshield.fixes.service import make_fix
from cloudshield.imports.recheck import latest_import_id
from cloudshield.risk.environment import environment_score, severity_counts

router = APIRouter(prefix="/api")


def get_session(request: Request):
    with request.app.state.session_factory() as session:
        yield session


@dataclass
class View:
    """What is needed, besides the row itself, to describe a finding to the client."""

    newest_import: int | None
    identities: set[str]
    now: datetime


def make_view(request: Request, session: Session) -> View:
    identities = own_identities(request.app.state.settings.cloudshield_own_identities)
    return View(latest_import_id(session, ACCOUNT_ID), identities, store.utcnow())


def finding_out(row: FindingRow, view: View) -> FindingOut:
    out = FindingOut.model_validate(row)
    out.not_rechecked = (
        row.source == "prowler" and row.status == "OPEN" and row.import_id != view.newest_import
    )
    out.dismissed = is_dismissed(row, view.now)
    if row.disposition != "none" and not out.dismissed:
        # The disposition has expired, so the finding is open again.
        out.disposition = "none"
        out.disposition_reason = out.disposition_until = out.disposition_at = None
    if row.status == "OPEN" and not out.dismissed:
        reason = suggested_not_applicable(row, view.identities)
        out.suggested_not_applicable = SuggestedNotApplicable(reason=reason) if reason else None
    return out


@router.post("/scans", status_code=202, response_model=ScanOut)
def start_scan(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    body: ScanRequest | None = None,
) -> ScanRow:
    state = request.app.state
    regions = body.regions if body and body.regions else None
    if regions is None and state.settings.aws_region:
        regions = [state.settings.aws_region]
    if not regions:
        raise HTTPException(
            status_code=422,
            detail='No regions. Send {"regions": [...]} or set AWS_REGION on the server.',
        )

    with state.scan_lock:
        if store.active_scan(session) is not None:
            raise HTTPException(status_code=409, detail="A scan is already running.")
        scan = store.create_scan(session, regions)

    args = (state.session_factory, scan.id, regions, state.scan_function)
    threading.Thread(target=run_scan_job, args=args, daemon=True).start()
    return scan


@router.get("/scans", response_model=list[ScanOut])
def list_scans(session: Annotated[Session, Depends(get_session)]) -> list[ScanRow]:
    query = select(ScanRow).where(ScanRow.account_id == ACCOUNT_ID).order_by(ScanRow.id.desc())
    return list(session.scalars(query))


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, session: Annotated[Session, Depends(get_session)]) -> ScanRow:
    scan = session.get(ScanRow, scan_id)
    if scan is None or scan.account_id != ACCOUNT_ID:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@router.get("/resources", response_model=list[ResourceOut])
def list_resources(
    session: Annotated[Session, Depends(get_session)], resource_type: str | None = None
) -> list[ResourceRow]:
    query = select(ResourceRow).where(ResourceRow.account_id == ACCOUNT_ID)
    if resource_type:
        query = query.where(ResourceRow.resource_type == resource_type)
    return list(session.scalars(query.order_by(ResourceRow.resource_type, ResourceRow.name)))


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    severity: Severity | None = None,
    source: FindingSource | None = None,
    status: FindingStatus | None = None,
    rule_id: str | None = None,
    resource_type: str | None = None,
) -> list[FindingOut]:
    # An imported finding that repeats one of ours is merged into it and never listed.
    query = select(FindingRow).where(
        FindingRow.account_id == ACCOUNT_ID, FindingRow.merged_into.is_(None)
    )
    filters = {
        "severity": severity,
        "source": source,
        "status": status,
        "rule_id": rule_id,
        "resource_type": resource_type,
    }
    for column, value in filters.items():
        if value:
            query = query.where(getattr(FindingRow, column) == value)
    rows = session.scalars(query).all()
    rows = sorted(rows, key=lambda r: (SEVERITIES.index(r.severity), r.rule_id, r.resource_id))
    view = make_view(request, session)
    return [finding_out(row, view) for row in rows]


@router.get("/risk/summary", response_model=RiskSummaryOut)
def risk_summary(
    request: Request, session: Annotated[Session, Depends(get_session)]
) -> RiskSummaryOut:
    query = select(FindingRow).where(
        FindingRow.account_id == ACCOUNT_ID, FindingRow.status == "OPEN"
    )
    view = make_view(request, session)
    # Merged and dismissed findings are left out of the counts and the scores.
    open_rows = [r for r in session.scalars(query).all() if counts_toward_open(r, view.now)]
    scored = [row for row in open_rows if row.risk_score is not None]
    top = sorted(scored, key=lambda r: (-r.risk_score, SEVERITIES.index(r.severity), r.resource_id))
    return RiskSummaryOut(
        environment_score=environment_score([row.risk_score for row in scored]),
        counts_by_severity=severity_counts([row.severity for row in open_rows]),
        top_findings=[finding_out(row, view) for row in top[:5]],
    )


@router.get("/risk/trend", response_model=list[TrendPoint])
def risk_trend(session: Annotated[Session, Depends(get_session)]) -> list[TrendPoint]:
    query = (
        select(ScanRow)
        .where(
            ScanRow.account_id == ACCOUNT_ID,
            ScanRow.status == "completed",
            ScanRow.environment_score.is_not(None),
        )
        .order_by(ScanRow.id)
    )
    return [
        TrendPoint(
            scan_id=scan.id,
            finished_at=scan.finished_at,
            environment_score=scan.environment_score,
            severity_counts=scan.severity_counts,
        )
        for scan in session.scalars(query)
    ]


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding(
    finding_id: str, request: Request, session: Annotated[Session, Depends(get_session)]
) -> FindingDetailOut:
    row = session.get(FindingRow, (ACCOUNT_ID, finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    finding = FindingDetailOut.model_validate(row)
    for name, value in finding_out(row, make_view(request, session)):
        setattr(finding, name, value)
    resource = session.get(ResourceRow, (ACCOUNT_ID, row.resource_id))
    if resource is not None:
        finding.resource = ResourceOut.model_validate(resource)
    return finding


@router.post("/findings/{finding_id}/fix", response_model=FixOut)
def create_fix(
    finding_id: str,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    refresh: bool = False,
) -> FixRow:
    finding = session.get(FindingRow, (ACCOUNT_ID, finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if finding.status == "RESOLVED":
        stored = session.get(FixRow, (ACCOUNT_ID, finding_id))
        if stored is None:
            raise HTTPException(status_code=409, detail="This finding is resolved and has no fix.")
        return stored
    state = request.app.state
    try:
        return make_fix(
            session, finding, state.settings, state.ai_limit, state.gemini_transport, refresh
        )
    except LookupError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/findings/{finding_id}/fix", response_model=FixOut)
def get_stored_fix(finding_id: str, session: Annotated[Session, Depends(get_session)]) -> FixRow:
    fix = session.get(FixRow, (ACCOUNT_ID, finding_id))
    if fix is None:
        raise HTTPException(status_code=404, detail="No stored fix for this finding.")
    return fix


@router.patch("/findings/{finding_id}/disposition", response_model=FindingOut)
def set_disposition(
    finding_id: str,
    body: DispositionIn,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> FindingOut:
    row = session.get(FindingRow, (ACCOUNT_ID, finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if row.status != "OPEN":
        raise HTTPException(status_code=409, detail="Only an open finding can be dismissed.")
    row.disposition = body.disposition
    row.disposition_reason = body.disposition_reason
    # A date stands for the whole day: the finding stays dismissed until that day ends.
    until = body.disposition_until
    row.disposition_until = datetime.combine(until, time(23, 59, 59)) if until else None
    row.disposition_at = store.utcnow()
    session.commit()
    return finding_out(row, make_view(request, session))


@router.delete("/findings/{finding_id}/disposition", response_model=FindingOut)
def clear_disposition(
    finding_id: str, request: Request, session: Annotated[Session, Depends(get_session)]
) -> FindingOut:
    row = session.get(FindingRow, (ACCOUNT_ID, finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    row.disposition = "none"
    row.disposition_reason = row.disposition_until = row.disposition_at = None
    session.commit()
    return finding_out(row, make_view(request, session))


@router.get("/imports", response_model=list[ImportOut])
def list_imports(session: Annotated[Session, Depends(get_session)]) -> list[ImportOut]:
    query = select(ImportRow).where(ImportRow.account_id == ACCOUNT_ID)
    return [
        ImportOut(
            id=row.id,
            file_name=row.file_name,
            tool_name=row.tool_name,
            tool_version=row.tool_version,
            imported_at=row.imported_at,
            pass_count=row.pass_count,
            fail_count=row.fail_count,
            findings_added=row.counts["imported"],
            already_seen=row.counts["already_seen"],
            resolved=row.counts["resolved"],
            rejected=row.counts["rejected"],
            ignored=row.counts["ignored"],
            regions_covered=row.regions_covered,
        )
        for row in session.scalars(query.order_by(ImportRow.id.desc()))
    ]


@router.get("/resources/imported", response_model=list[ImportedResourceOut])
def list_imported_resources(
    session: Annotated[Session, Depends(get_session)],
) -> list[ImportedResourceOut]:
    """Resources that only an imported scan has told us about."""
    own_ids = select(ResourceRow.resource_id).where(ResourceRow.account_id == ACCOUNT_ID)
    ours = set(session.scalars(own_ids))
    query = select(FindingRow).where(
        FindingRow.account_id == ACCOUNT_ID, FindingRow.source == "prowler"
    )
    now = store.utcnow()
    groups: dict[str, list[FindingRow]] = {}
    for row in session.scalars(query):
        if row.resource_id not in ours:
            groups.setdefault(row.resource_id, []).append(row)
    result = []
    for resource_id, rows in groups.items():
        open_rows = [r for r in rows if counts_toward_open(r, now)]
        scores = [r.risk_score for r in open_rows if r.risk_score is not None]
        result.append(
            ImportedResourceOut(
                resource_id=resource_id,
                resource_type=rows[0].resource_type,
                region=rows[0].details.get("region"),
                open_count=len(open_rows),
                highest_risk=max(scores, default=None),
            )
        )
    return sorted(result, key=lambda r: (-(r.highest_risk or 0), r.resource_id))
