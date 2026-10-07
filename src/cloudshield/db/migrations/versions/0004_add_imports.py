"""add imports, passed checks and finding source

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-07
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "imports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("account_id", sa.String(), nullable=False, server_default="local"),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("file_sha256", sa.String(), nullable=False),
        sa.Column("imported_at", sa.DateTime(), nullable=False),
        sa.Column("external_account_id", sa.String(), nullable=True),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("regions_covered", sa.JSON(), nullable=False),
        sa.Column("checks_covered", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_id", "file_sha256", name="uq_imports_file"),
    )
    op.create_table(
        "passed_checks",
        sa.Column("account_id", sa.String(), nullable=False, server_default="local"),
        sa.Column("check_id", sa.String(), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("region", sa.String(), nullable=True),
        sa.Column("last_import_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["last_import_id"], ["imports.id"]),
        sa.PrimaryKeyConstraint("account_id", "check_id", "resource_id"),
    )
    op.add_column(
        "findings",
        sa.Column("source", sa.String(), nullable=False, server_default="cloudshield"),
    )
    op.add_column("findings", sa.Column("import_id", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("last_imported_at", sa.DateTime(), nullable=True))
    # An imported finding was not found by one of our scans.
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("last_scan_id", existing_type=sa.Integer(), nullable=True)


def downgrade() -> None:
    op.execute("delete from findings where last_scan_id is null")
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("last_scan_id", existing_type=sa.Integer(), nullable=False)
    op.drop_column("findings", "last_imported_at")
    op.drop_column("findings", "import_id")
    op.drop_column("findings", "source")
    op.drop_table("passed_checks")
    op.drop_table("imports")
