"""create scans, resources and findings tables

Revision ID: 0001
Revises:
Create Date: 2026-10-02
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("account_id", sa.String(), nullable=False, server_default="local"),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("progress", sa.String(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("regions", sa.JSON(), nullable=False),
        sa.Column("resource_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.Column("errors", sa.JSON(), nullable=False),
        sa.Column("failure_message", sa.String(), nullable=True),
    )
    op.create_table(
        "resources",
        sa.Column("account_id", sa.String(), nullable=False, server_default="local"),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("resource_type", sa.String(), nullable=False),
        sa.Column("region", sa.String(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("last_seen_scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.PrimaryKeyConstraint("account_id", "resource_id"),
    )
    op.create_table(
        "findings",
        sa.Column("account_id", sa.String(), nullable=False, server_default="local"),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("resource_type", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolution_reason", sa.String(), nullable=True),
        sa.Column("last_scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.PrimaryKeyConstraint("account_id", "finding_id"),
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("resources")
    op.drop_table("scans")
