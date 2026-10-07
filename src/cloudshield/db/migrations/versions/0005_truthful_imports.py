"""add merging, dispositions, score basis and import history

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("score_basis", sa.String(), nullable=False, server_default="severity only"),
    )
    op.add_column("findings", sa.Column("merged_into", sa.String(), nullable=True))
    op.add_column(
        "findings",
        sa.Column("tools_disagree", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.add_column(
        "findings", sa.Column("corroborated_by", sa.JSON(), nullable=False, server_default="[]")
    )
    op.add_column(
        "findings",
        sa.Column("disposition", sa.String(), nullable=False, server_default="none"),
    )
    op.add_column("findings", sa.Column("disposition_reason", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("disposition_until", sa.DateTime(), nullable=True))
    op.add_column("findings", sa.Column("disposition_at", sa.DateTime(), nullable=True))
    # Earlier findings: ours were always scored with context. An imported one was scored with
    # context only when it has no "context not available" factor.
    op.execute("update findings set score_basis = 'context adjusted' where source = 'cloudshield'")
    op.execute(
        "update findings set score_basis = 'context adjusted' where source = 'prowler' "
        'and risk_score is not null and risk_factors not like \'%"factor": "context"%\''
    )

    op.add_column("imports", sa.Column("file_name", sa.String(), nullable=True))
    op.add_column("imports", sa.Column("tool_name", sa.String(), nullable=True))
    op.add_column("imports", sa.Column("tool_version", sa.String(), nullable=True))
    op.add_column("imports", sa.Column("pass_count", sa.Integer(), nullable=True))
    op.add_column("imports", sa.Column("fail_count", sa.Integer(), nullable=True))


def downgrade() -> None:
    for name in ("fail_count", "pass_count", "tool_version", "tool_name", "file_name"):
        op.drop_column("imports", name)
    for name in (
        "disposition_at",
        "disposition_until",
        "disposition_reason",
        "disposition",
        "corroborated_by",
        "tools_disagree",
        "merged_into",
        "score_basis",
    ):
        op.drop_column("findings", name)
