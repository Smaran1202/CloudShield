from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints

from cloudshield.findings import Certainty, FindingStatus, Severity

ScanStatus = Literal["queued", "running", "completed", "failed"]
BlastLevel = Literal["low", "medium", "high", "unknown"]
PatchFormat = Literal["terraform", "cloudformation", "cli"]
Region = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]+$")]
# The database stores UTC without a timezone; the API always says it is UTC.
UtcDateTime = Annotated[datetime, AfterValidator(lambda value: value.replace(tzinfo=UTC))]


class ScanRequest(BaseModel):
    # No profile or credentials here: the AWS profile comes from the server's environment.
    model_config = ConfigDict(extra="forbid")

    regions: list[Region] | None = None


class ScanError(BaseModel):
    service: str
    region: str | None
    resource: str | None
    message: str


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    account_id: str
    status: ScanStatus
    progress: str | None
    started_at: UtcDateTime | None
    finished_at: UtcDateTime | None
    regions: list[str]
    resource_count: int
    finding_count: int
    error_count: int
    environment_score: float | None
    severity_counts: dict[str, int]
    errors: list[ScanError]
    failure_message: str | None


class ResourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    resource_id: str
    resource_type: str
    region: str | None
    name: str
    attributes: dict
    last_seen_scan_id: int


class RiskFactor(BaseModel):
    factor: str
    adjustment: int
    reason: str
    certainty: Certainty


class EvidenceItem(BaseModel):
    fact: str
    value: Any
    source: str
    certainty: Certainty


class Evidence(BaseModel):
    items: list[EvidenceItem] = []


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    rule_id: str
    resource_id: str
    resource_type: str
    title: str
    severity: Severity
    category: str
    status: FindingStatus
    details: dict
    evidence: Evidence
    risk_score: int | None
    risk_factors: list[RiskFactor]
    first_seen_at: UtcDateTime
    last_seen_at: UtcDateTime
    resolved_at: UtcDateTime | None
    resolution_reason: str | None
    last_scan_id: int


class RiskSummaryOut(BaseModel):
    environment_score: float
    counts_by_severity: dict[str, int]
    top_findings: list[FindingOut]


class TrendPoint(BaseModel):
    scan_id: int
    finished_at: UtcDateTime
    environment_score: float
    severity_counts: dict[str, int]


class PatchFile(BaseModel):
    name: str
    content: str


class PatchOut(BaseModel):
    format: PatchFormat
    title: str
    content: str
    files: list[PatchFile]
    needs_input: bool
    inputs_needed: list[str]
    instructions_only: bool


class BlastRadiusOut(BaseModel):
    level: BlastLevel
    factors: list[EvidenceItem]
    notes: list[str]


class ExplanationOut(BaseModel):
    why_it_matters: str
    what_changes: str
    what_could_break: str
    cited: list[str]
    skipped_reason: str | None = None


class FixOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    evidence_hash: str
    blast_radius: BlastRadiusOut
    patches: list[PatchOut]
    guidance: list[str]
    pre_checks: list[str]
    rollback: str
    verify: str
    explanation: ExplanationOut
    generated_by: Literal["gemini", "template"]
    model: str | None
    generation_ms: int
    created_at: UtcDateTime


class FindingDetailOut(FindingOut):
    # The stored state of the resource the finding is about.
    resource: ResourceOut | None = None
