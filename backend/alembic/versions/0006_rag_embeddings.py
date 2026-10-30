"""rag embeddings

Adds alert_embeddings (portable JSON vectors, all databases). On PostgreSQL it also enables pgvector when the
server offers it, adds an HNSW-indexed vector column, and adds a full-text index on alert text. Existing data
is untouched. Without pgvector the application falls back to keyword + exact retrieval (and, for small corpora,
an in-process cosine scan).

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa
import sqlmodel
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

DIMENSIONS = 1024  # must equal EMBEDDING_DIMENSIONS
FTS_EXPR = "to_tsvector('english', coalesce(title, '') || ' ' || coalesce(description, ''))"


def upgrade() -> None:
    op.create_table(
        "alert_embeddings",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("organization_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("alert_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("model", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("dimensions", sa.Integer(), nullable=False),
        sa.Column("text_hash", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("embedding", sa.JSON(), nullable=False),
        sa.Column("created_at", sqlmodel.sql.sqltypes.UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["alert_id"], ["security_alerts.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id", "model", name="uq_alert_embedding_alert_model"),
    )
    op.create_index("ix_alert_embeddings_org_model", "alert_embeddings", ["organization_id", "model"])

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    # Full-text search needs no extension.
    op.execute(f"CREATE INDEX IF NOT EXISTS ix_security_alerts_fts ON security_alerts USING gin (({FTS_EXPR}))")
    available = bind.execute(sa.text("SELECT 1 FROM pg_available_extensions WHERE name = 'vector'")).first()
    if not available:
        return  # no pgvector on this server: semantic search stays disabled, everything else works
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute(f"ALTER TABLE alert_embeddings ADD COLUMN IF NOT EXISTS embedding_vec vector({DIMENSIONS})")
    op.execute("CREATE INDEX IF NOT EXISTS ix_alert_embeddings_vec ON alert_embeddings USING hnsw (embedding_vec vector_cosine_ops)")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS ix_security_alerts_fts")
        # The vector extension is left installed: other objects may depend on it.
    op.drop_index("ix_alert_embeddings_org_model", table_name="alert_embeddings")
    op.drop_table("alert_embeddings")
