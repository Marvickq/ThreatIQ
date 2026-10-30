import os
import tempfile
from pathlib import Path

# Must be set before the app is imported so the engine binds to a throwaway database, never the dev or production one.
_tmp = Path(tempfile.mkdtemp(prefix="threatiq-test-")) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.as_posix()}"
os.environ["SCHEDULER_ENABLED"] = "false"
# Tests create many accounts from one address; the production limiter (10/min) is a real control and stays default.
os.environ["RATE_LIMIT_LOGIN_PER_MINUTE"] = "100000"
os.environ["NVIDIA_API_KEY"] = ""  # retrieval tests must never call the embedding API

import pytest  # noqa: E402
from sqlmodel import Session  # noqa: E402

from app.database import engine  # noqa: E402
from app.migrations import run_migrations  # noqa: E402
from app.models import Organization  # noqa: E402
from app.services.seed_service import seed_demo_alerts  # noqa: E402


@pytest.fixture(scope="session")
def db():
    run_migrations(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(scope="session")
def demo_org(db):
    """The first organization to load demo data, so the synthetic alerts keep their ALT-nnn ids."""
    org = Organization(name="Demo Org", slug="demo-org")
    db.add(org)
    db.commit()
    assert seed_demo_alerts(db, org.id) == 12
    return org
