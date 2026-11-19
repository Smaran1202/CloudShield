"""label a scan whose data is not from a real account (demo data)

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-17
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("data_label", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "data_label")
