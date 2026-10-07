import hashlib
import json
import time

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from cloudshield.config import Settings
from cloudshield.db.models import ACCOUNT_ID, FindingRow, FixRow, ResourceRow
from cloudshield.db.store import utcnow
from cloudshield.fixes.blast import blast_radius
from cloudshield.fixes.explain import HourlyLimit, explain_fix, load_knowledge
from cloudshield.fixes.imported import make_imported_fix
from cloudshield.fixes.templates import build_fix


def finding_dict(row: FindingRow) -> dict:
    return {
        "finding_id": row.finding_id,
        "rule_id": row.rule_id,
        "resource_id": row.resource_id,
        "resource_type": row.resource_type,
        "title": row.title,
        "severity": row.severity,
        "details": row.details,
        "evidence": row.evidence,
    }


def resource_dict(row: ResourceRow) -> dict:
    return {
        "resource_id": row.resource_id,
        "resource_type": row.resource_type,
        "region": row.region,
        "name": row.name,
        "attributes": row.attributes,
    }


def instances_seen_with(session: Session, finding: FindingRow) -> list[dict]:
    # Only instances from the scan that last saw the finding: stored rows are never deleted, so
    # an older instance may be gone.
    query = select(ResourceRow).where(
        ResourceRow.account_id == ACCOUNT_ID,
        ResourceRow.resource_type == "EC2",
        ResourceRow.last_seen_scan_id == finding.last_scan_id,
    )
    return [resource_dict(row) for row in session.scalars(query)]


def ai_now_possible(row: FixRow, settings: Settings) -> bool:
    # A template made only because Gemini was not configured is replaced once it is configured.
    skipped = row.explanation.get("skipped_reason") or ""
    models = settings.gemini_model or settings.gemini_fallback_model
    waiting_for_config = skipped.startswith("no GEMINI_")
    configured = bool(settings.gemini_api_key and models)
    return row.generated_by == "template" and waiting_for_config and configured


def make_fix(
    session: Session,
    finding_row: FindingRow,
    settings: Settings,
    limit: HourlyLimit,
    transport: httpx.BaseTransport | None = None,
    refresh: bool = False,
) -> FixRow:
    if finding_row.source == "prowler":
        return make_imported_fix(session, finding_row)
    resource_row = session.get(ResourceRow, (ACCOUNT_ID, finding_row.resource_id))
    if resource_row is None:
        raise LookupError("The resource for this finding is not stored, so no fix can be built.")
    finding = finding_dict(finding_row)
    resource = resource_dict(resource_row)
    instances = instances_seen_with(session, finding_row) if resource["region"] else []

    parts = build_fix(finding, resource)
    blast = blast_radius(finding, resource, instances)
    # The hash covers the evidence and everything built from it, so a stored fix is reused only
    # while all of its inputs are unchanged.
    inputs = {"evidence": finding["evidence"], "blast_radius": blast, "fix": parts}
    digest = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode("utf-8")).hexdigest()

    row = session.get(FixRow, (ACCOUNT_ID, finding_row.finding_id))
    unchanged = row is not None and row.evidence_hash == digest
    if unchanged and not refresh and not ai_now_possible(row, settings):
        return row

    started = time.perf_counter()
    context = {
        "finding": finding,
        "knowledge": load_knowledge(finding["rule_id"]),
        "blast_radius": blast,
        "patches": parts["patches"],
        "guidance": parts["guidance"],
    }
    explained = explain_fix(context, settings, limit, transport)
    milliseconds = int((time.perf_counter() - started) * 1000)

    if row is None:
        row = FixRow(account_id=ACCOUNT_ID, finding_id=finding_row.finding_id)
        session.add(row)
    row.evidence_hash = digest
    row.blast_radius = blast
    row.patches = parts["patches"]
    row.guidance = parts["guidance"]
    row.pre_checks = parts["pre_checks"]
    row.rollback = parts["rollback"]
    row.verify = parts["verify"]
    row.explanation = explained["explanation"]
    row.generated_by = explained["generated_by"]
    row.model = explained["model"]
    row.generation_ms = milliseconds
    row.created_at = utcnow()
    session.commit()
    return row
