from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints

from cloudshield.findings import FindingStatus, Severity

ScanStatus = Literal["queued", "running", "completed", "failed"]
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
    first_seen_at: UtcDateTime
    last_seen_at: UtcDateTime
    resolved_at: UtcDateTime | None
    resolution_reason: str | None
    last_scan_id: int


class FindingDetailOut(FindingOut):
    # The related resource's attributes are the evidence for the finding.
    resource: ResourceOut | None = None
