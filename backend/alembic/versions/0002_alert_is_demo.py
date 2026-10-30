"""mark demo alerts

Adds security_alerts.is_demo so synthetic demo data is explicit in the database.
Alerts created by the original demo seed (their descriptions start with "[SYNTHETIC]")
are backfilled as demo; nothing is deleted or reset.

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "security_alerts",
        sa.Column("is_demo", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.get_bind().execute(
        sa.text("UPDATE security_alerts SET is_demo = :yes WHERE description LIKE :prefix").bindparams(
            sa.bindparam("yes", True, type_=sa.Boolean()),
            sa.bindparam("prefix", "[SYNTHETIC]%"),
        )
    )


def downgrade() -> None:
    with op.batch_alter_table("security_alerts") as batch_op:
        batch_op.drop_column("is_demo")
