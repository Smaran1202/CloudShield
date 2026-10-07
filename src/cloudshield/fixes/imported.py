import hashlib
import json

from sqlalchemy.orm import Session

from cloudshield.db.models import FindingRow, FixRow
from cloudshield.db.store import utcnow

# Imported findings have no patch templates and no AI explanation: CloudShield did not collect
# the evidence, so it only passes on what the external tool reported.
SKIPPED = "imported from an external tool: no AI explanation is generated"
BLAST_NOTE = (
    "The tool that reported this finding does not say what depends on the resource, and "
    "CloudShield did not collect it. The blast radius is unknown."
)


def imported_parts(finding: FindingRow) -> dict:
    details = finding.details
    guidance = [details["remediation"]] if details.get("remediation") else []
    guidance += [f"Reference: {url}" for url in details.get("references", [])]
    if not guidance:
        guidance = ["The external tool gave no remediation text for this check."]
    evidence_ids = [f"e{number}" for number in range(1, len(finding.evidence["items"]) + 1)]
    return {
        "blast_radius": {"level": "unknown", "factors": [], "notes": [BLAST_NOTE]},
        "patches": [],
        "guidance": guidance,
        "pre_checks": ["Find out what depends on this resource before you change it."],
        "rollback": "No rollback steps are generated for an imported finding.",
        "verify": "Run the tool again and import its new output. The finding resolves when the "
        "check passes.",
        "explanation": {
            "why_it_matters": details.get("risk") or finding.title,
            "what_changes": "No patch is generated. Follow the guidance from the external tool.",
            "what_could_break": f"Blast radius: unknown. {BLAST_NOTE}",
            "cited": evidence_ids,
            "skipped_reason": SKIPPED,
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
    row.blast_radius = parts["blast_radius"]
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
