import os
import tempfile
from pathlib import Path

# Must be set before the app is imported so the engine binds to a throwaway DB.
_tmp = Path(tempfile.mkdtemp(prefix="threatiq-test-")) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.as_posix()}"
# Tests rely on the labelled demo fixtures; the app default is off.
os.environ["SEED_DEMO_DATA"] = "true"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    # The context manager runs the lifespan (table creation + seeding).
    with TestClient(app) as test_client:
        yield test_client
