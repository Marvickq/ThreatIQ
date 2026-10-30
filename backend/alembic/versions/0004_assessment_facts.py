"""assessment observed facts and interpretation

Separates observed facts, interpretation and uncertainty on each assessment.
Existing assessments keep NULL/empty values; nothing is rewritten.

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.add_column(sa.Column("observed_facts", sa.JSON(), server_default="[]", nullable=False))
        batch_op.add_column(sa.Column("interpretation", sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.drop_column("interpretation")
        batch_op.drop_column("observed_facts")
