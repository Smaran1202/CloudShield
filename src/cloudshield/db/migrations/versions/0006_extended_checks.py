"""add extended check results to scans and run details to imports

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("extended_status", sa.String(), nullable=False, server_default="skipped"),
    )
    op.add_column("scans", sa.Column("extended_message", sa.String(), nullable=True))
    op.add_column("scans", sa.Column("extended_hint", sa.String(), nullable=True))

    op.add_column(
        "imports", sa.Column("origin", sa.String(), nullable=False, server_default="file")
    )
    op.add_column("imports", sa.Column("duration_seconds", sa.Double(), nullable=True))
    op.add_column("imports", sa.Column("services_used", sa.JSON(), nullable=True))
    op.add_column("imports", sa.Column("regions_used", sa.JSON(), nullable=True))
    op.add_column("imports", sa.Column("scan_id", sa.Integer(), nullable=True))


def downgrade() -> None:
    for name in ("scan_id", "regions_used", "services_used", "duration_seconds", "origin"):
        op.drop_column("imports", name)
    for name in ("extended_hint", "extended_message", "extended_status"):
        op.drop_column("scans", name)
