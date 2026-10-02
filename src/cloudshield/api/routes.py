import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.api.jobs import run_scan_job
from cloudshield.api.schemas import (
    FindingDetailOut,
    FindingOut,
    ResourceOut,
    ScanOut,
    ScanRequest,
)
from cloudshield.db import store
from cloudshield.db.models import ACCOUNT_ID, FindingRow, ResourceRow, ScanRow
from cloudshield.findings import SEVERITIES, FindingStatus, Severity

router = APIRouter(prefix="/api")


def get_session(request: Request):
    with request.app.state.session_factory() as session:
        yield session


@router.post("/scans", status_code=202, response_model=ScanOut)
def start_scan(
    request: Request, body: ScanRequest | None = None, session: Session = Depends(get_session)
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
def list_scans(session: Session = Depends(get_session)) -> list[ScanRow]:
    query = select(ScanRow).where(ScanRow.account_id == ACCOUNT_ID).order_by(ScanRow.id.desc())
    return list(session.scalars(query))


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, session: Session = Depends(get_session)) -> ScanRow:
    scan = session.get(ScanRow, scan_id)
    if scan is None or scan.account_id != ACCOUNT_ID:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@router.get("/resources", response_model=list[ResourceOut])
def list_resources(
    resource_type: str | None = None, session: Session = Depends(get_session)
) -> list[ResourceRow]:
    query = select(ResourceRow).where(ResourceRow.account_id == ACCOUNT_ID)
    if resource_type:
        query = query.where(ResourceRow.resource_type == resource_type)
    return list(session.scalars(query.order_by(ResourceRow.resource_type, ResourceRow.name)))


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    rule_id: str | None = None,
    resource_type: str | None = None,
    session: Session = Depends(get_session),
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


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding(finding_id: str, session: Session = Depends(get_session)) -> FindingDetailOut:
    row = session.get(FindingRow, (ACCOUNT_ID, finding_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    finding = FindingDetailOut.model_validate(row)
    resource = session.get(ResourceRow, (ACCOUNT_ID, row.resource_id))
    if resource is not None:
        finding.resource = ResourceOut.model_validate(resource)
    return finding
