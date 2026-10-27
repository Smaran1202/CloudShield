import hashlib
import json

from sqlalchemy.orm import Session

from cloudshield.db.models import FindingRow, FixRow
from cloudshield.db.store import utcnow
from cloudshield.imports.guidance import guidance_for

# Imported findings have no patch templates and no AI text: CloudShield did not collect the
# evidence, so it only passes on what the external scanner reported, and says so once.
NOT_COLLECTED = "CloudShield did not collect this evidence."
GENERIC_PRE_CHECK = "Find out what depends on this resource before you change it."
VERIFY = (
    "Run the full scan to verify, or import a newer results file with "
    "python -m cloudshield.imports prowler <file>. The finding resolves only when the check "
    "passes."
)


def imported_parts(finding: FindingRow) -> dict:
    details = finding.details
    entry = guidance_for(details.get("check_id"))
    guidance = [details["remediation"]] if details.get("remediation") else []
    guidance += [f"Reference: {url}" for url in details.get("references", [])]
    if not guidance:
        guidance = ["The external scanner gave no remediation text for this check."]
    evidence_ids = [f"e{number}" for number in range(1, len(finding.evidence["items"]) + 1)]
    return {
        "patches": [],
        "guidance": guidance,
        "pre_checks": entry["before_you_apply"] if entry else [GENERIC_PRE_CHECK],
        "rollback": "No rollback steps are generated for an imported finding.",
        "verify": VERIFY,
        # The scanner's own description of the risk is passed on as it was written. CloudShield
        # adds no explanation of its own.
        "explanation": {
            "why_it_matters": details.get("risk") or "",
            "what_changes": "",
            "what_could_break": "",
            "cited": evidence_ids,
            "skipped_reason": NOT_COLLECTED,
        },
    }


def make_imported_fix(session: Session, finding: FindingRow) -> FixRow:
    parts = imported_parts(finding)
    digest = hashlib.sha256(json.dumps(parts, sort_keys=True).encode("utf-8")).hexdigest()
    row = session.get(FixRow, (finding.account_id, finding.finding_id))
    if row is not None and row.evidence_hash == digest:
        return row
    if row is None:
        row = FixRow(account_id=finding.account_id, finding_id=finding.finding_id)
        session.add(row)
    row.evidence_hash = digest
    row.blast_radius = {}
    row.patches = parts["patches"]
    row.guidance = parts["guidance"]
    row.pre_checks = parts["pre_checks"]
    row.rollback = parts["rollback"]
    row.verify = parts["verify"]
    row.explanation = parts["explanation"]
    row.generated_by = "template"
    row.model = None
    row.generation_ms = 0
    row.created_at = utcnow()
    session.commit()
    return row
