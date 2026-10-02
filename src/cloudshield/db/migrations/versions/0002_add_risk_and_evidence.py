"""add risk scores, risk factors and evidence

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-03
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing rows get empty values until their next scan fills them in.
    op.add_column("scans", sa.Column("environment_score", sa.Double(), nullable=True))
    op.add_column(
        "scans", sa.Column("severity_counts", sa.JSON(), nullable=False, server_default="{}")
    )
    op.add_column("findings", sa.Column("evidence", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column("findings", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column(
        "findings", sa.Column("risk_factors", sa.JSON(), nullable=False, server_default="[]")
    )


def downgrade() -> None:
    op.drop_column("findings", "risk_factors")
    op.drop_column("findings", "risk_score")
    op.drop_column("findings", "evidence")
    op.drop_column("scans", "severity_counts")
    op.drop_column("scans", "environment_score")
