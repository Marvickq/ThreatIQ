from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.engine import Engine

BACKEND_DIR = Path(__file__).resolve().parent.parent

# Revision that matches databases created by SQLModel.metadata.create_all before
# migrations existed. Such databases are stamped, never reset.
LEGACY_BASELINE = "0001"


def _config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return config


def run_migrations(engine: Engine) -> None:
    """Bring the database to the latest schema without losing data.

    On SQLite, table rebuilds (batch operations) need foreign-key enforcement off while they run;
    it is switched back on afterwards and integrity is verified.
    """
    config = _config()
    is_sqlite = engine.dialect.name == "sqlite"

    with engine.connect() as connection:
        if is_sqlite:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()  # PRAGMA foreign_keys is a no-op inside a transaction
        try:
            config.attributes["connection"] = connection
            with connection.begin():
                tables = set(inspect(connection).get_table_names())
                if "alembic_version" not in tables and "security_alerts" in tables:
                    command.stamp(config, LEGACY_BASELINE)
                command.upgrade(config, "head")
        finally:
            if is_sqlite:
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
                connection.commit()

        if is_sqlite:
            violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise RuntimeError(f"Foreign key violations after migration: {violations[:5]}")


def schema_status(connection) -> dict:
    """Read-only: the revision the database is at, versus the newest one this code ships."""
    from alembic.script import ScriptDirectory
    from sqlalchemy import text

    head = ScriptDirectory.from_config(_config()).get_current_head()
    try:
        current = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:
        connection.rollback()
        current = None
    return {"revision": current, "head": head, "up_to_date": current == head}
