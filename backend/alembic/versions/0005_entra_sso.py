"""entra sso

Adds organizations.entra_tenant_id (operator-set tenant binding) and the external_identities table.
Existing data and password sign-in are untouched.

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
import sqlmodel
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.add_column(sa.Column("entra_tenant_id", sa.String(), nullable=True))
        batch_op.create_index("ix_organizations_entra_tenant_id", ["entra_tenant_id"], unique=True)

    op.create_table(
        "external_identities",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("user_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("provider", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("tenant_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("subject", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_at", sqlmodel.sql.sqltypes.UTCDateTime(), nullable=False),
        sa.Column("last_login_at", sqlmodel.sql.sqltypes.UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider", "tenant_id", "subject", name="uq_external_identity"),
    )
    op.create_index("ix_external_identities_user_id", "external_identities", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_external_identities_user_id", table_name="external_identities")
    op.drop_table("external_identities")
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.drop_index("ix_organizations_entra_tenant_id")
        batch_op.drop_column("entra_tenant_id")
