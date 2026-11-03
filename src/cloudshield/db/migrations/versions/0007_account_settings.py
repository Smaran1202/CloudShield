"""add the account-wide settings a scan could read

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-02
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans", sa.Column("account_settings", sa.JSON(), nullable=False, server_default="{}")
    )


def downgrade() -> None:
    op.drop_column("scans", "account_settings")
