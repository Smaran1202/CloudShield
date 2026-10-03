"""create the fixes table

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-03
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fixes",
        sa.Column("account_id", sa.String(), nullable=False, server_default="local"),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("evidence_hash", sa.String(), nullable=False),
        sa.Column("blast_radius", sa.JSON(), nullable=False),
        sa.Column("patches", sa.JSON(), nullable=False),
        sa.Column("guidance", sa.JSON(), nullable=False),
        sa.Column("pre_checks", sa.JSON(), nullable=False),
        sa.Column("rollback", sa.String(), nullable=False),
        sa.Column("verify", sa.String(), nullable=False),
        sa.Column("explanation", sa.JSON(), nullable=False),
        sa.Column("generated_by", sa.String(), nullable=False),
        sa.Column("model", sa.String(), nullable=True),
        sa.Column("generation_ms", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("account_id", "finding_id"),
    )


def downgrade() -> None:
    op.drop_table("fixes")
