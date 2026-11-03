"""record how a dashboard run was made: local or docker, and the image

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-03
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("imports", sa.Column("run_mode", sa.String(), nullable=True))
    op.add_column("imports", sa.Column("run_image", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("imports", "run_image")
    op.drop_column("imports", "run_mode")
