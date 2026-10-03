import threading
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.api.jobs import run_scan_job
from cloudshield.api.schemas import (
    FindingDetailOut,
    FindingOut,
    FixOut,
    ResourceOut,
    RiskSummaryOut,
    ScanOut,
    ScanRequest,
    TrendPoint,
)
from cloudshield.db import store
from cloudshield.db.models import ACCOUNT_ID, FindingRow, FixRow, ResourceRow, ScanRow
from cloudshield.findings import SEVERITIES, FindingStatus, Severity
from cloudshield.fixes.service import make_fix
from cloudshield.risk.environment import environment_score, severity_counts

router = APIRouter(prefix="/api")


def get_session(request: Request):
    with request.app.state.session_factory() as session:
        yield session


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
    session: Annotated[Session, Depends(get_session)],
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    rule_id: str | None = None,
    resource_type: str | None = None,
) -> list[FindingRow]:
    query = select(FindingRow).where(FindingRow.account_id == ACCOUNT_ID)
    filters = {
        "severity": severity,
        "status": status,
        "rule_id": rule_id,
        "resource_type": resource_type,
    }
    for column, value in filters.items():
        if value:
            query = query.where(getattr(FindingRow, column) == value)
    rows = session.scalars(query).all()
    return sorted(rows, key=lambda r: (SEVERITIES.index(r.severity), r.rule_id, r.resource_id))


@router.get("/risk/summary", response_model=RiskSummaryOut)
def risk_summary(session: Annotated[Session, Depends(get_session)]) -> RiskSummaryOut:
    query = select(FindingRow).where(
        FindingRow.account_id == ACCOUNT_ID, FindingRow.status == "OPEN"
    )
    open_rows = session.scalars(query).all()
    scored = [row for row in open_rows if row.risk_score is not None]
    top = sorted(scored, key=lambda r: (-r.risk_score, SEVERITIES.index(r.severity), r.resource_id))
    return RiskSummaryOut(
        environment_score=environment_score([row.risk_score for row in scored]),
        counts_by_severity=severity_counts([row.severity for row in open_rows]),
        top_findings=[FindingOut.model_validate(row) for row in top[:5]],
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
    finding_id: str, session: Annotated[Session, Depends(get_session)]
) -> FindingDetailOut:
    row = session.get(FindingRow, (ACCOUNT_ID, finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    finding = FindingDetailOut.model_validate(row)
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
