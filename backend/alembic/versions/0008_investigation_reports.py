"""investigation reports

Adds investigation_reports: metadata, generation history and the generated PDF for each alert report.
Existing tables and data are untouched.

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa
import sqlmodel
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigation_reports",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("organization_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("alert_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("report_number", sa.String(), nullable=False),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("classification", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("generated_by", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("assessment_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("decision_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("evidence_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_code", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("pdf", sa.LargeBinary(), nullable=True),
        sa.Column("created_at", sqlmodel.sql.sqltypes.UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.id"]),
        sa.ForeignKeyConstraint(["generated_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_number"),
    )
    op.create_index("ix_reports_org_alert_created", "investigation_reports", ["organization_id", "alert_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_reports_org_alert_created", table_name="investigation_reports")
    op.drop_table("investigation_reports")
