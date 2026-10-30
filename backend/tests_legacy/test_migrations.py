"""Migration tests use their own throwaway databases, separate from the shared app DB."""
import tempfile
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlmodel import SQLModel

from app import models  # noqa: F401
from app.migrations import _config, run_migrations


@pytest.fixture
def engine():
    path = Path(tempfile.mkdtemp(prefix="threatiq-mig-")) / "m.db"
    eng = create_engine(f"sqlite:///{path.as_posix()}")
    yield eng
    eng.dispose()


def _version(engine):
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()


def _upgrade_to(engine, revision):
    config = _config()
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.upgrade(config, revision)


def test_fresh_database_is_created_empty_at_head(engine):
    run_migrations(engine)
    assert {"security_alerts", "assessments", "review_decisions", "audit_events"} <= set(inspect(engine).get_table_names())
    assert _version(engine) == "0002"
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM security_alerts")).scalar_one() == 0


def test_running_migrations_twice_is_safe(engine):
    run_migrations(engine)
    run_migrations(engine)
    assert _version(engine) == "0002"


def test_legacy_database_is_upgraded_without_losing_data(engine):
    # Build a database exactly as the pre-migration app did, then strip the version table so it
    # looks like one created by SQLModel.metadata.create_all.
    _upgrade_to(engine, "0001")
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO security_alerts (id, title, description, severity, source, status, created_at, updated_at) VALUES "
            "('A-DEMO', 't1', '[SYNTHETIC] demo row', 'low', 's', 'resolved', '2026-10-01 00:00:00', '2026-10-01 00:00:00'),"
            "('A-REAL', 't2', 'a genuine alert', 'high', 's', 'new', '2026-10-02 00:00:00', '2026-10-02 00:00:00')"
        ))
        conn.execute(text(
            "INSERT INTO review_decisions (id, alert_id, decision, created_at) "
            "VALUES ('D1', 'A-DEMO', 'false_positive', '2026-10-01 01:00:00')"
        ))
        conn.execute(text("DROP TABLE alembic_version"))

    run_migrations(engine)

    assert _version(engine) == "0002"
    with engine.connect() as conn:
        rows = dict(conn.execute(text("SELECT id, is_demo FROM security_alerts")).all())
        assert rows == {"A-DEMO": 1, "A-REAL": 0}  # only the synthetic row is flagged demo
        assert conn.execute(text("SELECT status FROM security_alerts WHERE id='A-DEMO'")).scalar_one() == "resolved"
        assert conn.execute(text("SELECT decision FROM review_decisions WHERE id='D1'")).scalar_one() == "false_positive"


def test_migrated_schema_matches_models(engine):
    """Guards against changing models.py without writing a migration."""
    run_migrations(engine)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), SQLModel.metadata)
    assert diff == []
