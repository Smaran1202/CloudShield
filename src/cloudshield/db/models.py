from datetime import datetime

from sqlalchemy import JSON, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# There are no accounts or logins yet, so every row belongs to this one account.
ACCOUNT_ID = "local"


class Base(DeclarativeBase):
    pass


# All datetimes are stored as UTC without a timezone.
class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[str] = mapped_column(default=ACCOUNT_ID, server_default=ACCOUNT_ID)
    status: Mapped[str]  # queued, running, completed or failed
    progress: Mapped[str | None]
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    regions: Mapped[list] = mapped_column(JSON)
    resource_count: Mapped[int] = mapped_column(default=0)
    finding_count: Mapped[int] = mapped_column(default=0)  # findings this scan detected
    error_count: Mapped[int] = mapped_column(default=0)
    environment_score: Mapped[float | None]  # from the open findings when the scan finished
    severity_counts: Mapped[dict] = mapped_column(JSON, default=dict, server_default="{}")
    errors: Mapped[list] = mapped_column(JSON, default=list)
    failure_message: Mapped[str | None]


class ResourceRow(Base):
    __tablename__ = "resources"

    account_id: Mapped[str] = mapped_column(
        primary_key=True, default=ACCOUNT_ID, server_default=ACCOUNT_ID
    )
    resource_id: Mapped[str] = mapped_column(primary_key=True)
    resource_type: Mapped[str]
    region: Mapped[str | None]
    name: Mapped[str]
    attributes: Mapped[dict] = mapped_column(JSON)
    last_seen_scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))


class FindingRow(Base):
    __tablename__ = "findings"

    account_id: Mapped[str] = mapped_column(
        primary_key=True, default=ACCOUNT_ID, server_default=ACCOUNT_ID
    )
    finding_id: Mapped[str] = mapped_column(primary_key=True)
    rule_id: Mapped[str]
    resource_id: Mapped[str]
    resource_type: Mapped[str]
    title: Mapped[str]
    severity: Mapped[str]
    category: Mapped[str]
    status: Mapped[str]  # OPEN or RESOLVED
    details: Mapped[dict] = mapped_column(JSON)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict, server_default="{}")
    risk_score: Mapped[int | None]  # None for findings that do not count toward risk
    risk_factors: Mapped[list] = mapped_column(JSON, default=list, server_default="[]")
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    resolved_at: Mapped[datetime | None]
    resolution_reason: Mapped[str | None]
    last_scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
