import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import func
from sqlmodel import Session, select

from app.models import Organization, SecurityAlert
from app.services import indicators
from app.services.audit_service import record_event

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load_demo_incidents() -> list[dict]:
    """Synthetic past incidents that belong to the demo data set only."""
    return json.loads((DATA_DIR / "incidents.json").read_text(encoding="utf-8"))


def seed_demo_alerts(session: Session, organization_id: str) -> int:
    """Insert clearly labelled demo alerts into one organization, only if it has no alerts yet.

    Every row is flagged `is_demo`. Returns the number inserted.
    """
    org = session.get(Organization, organization_id)
    if org is None:
        return 0
    existing = session.exec(
        select(func.count()).select_from(SecurityAlert).where(SecurityAlert.organization_id == organization_id)
    ).one()
    if existing > 0:
        return 0

    rows = json.loads((DATA_DIR / "alerts.json").read_text(encoding="utf-8"))
    for row in rows:
        created_at = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
        alert_id = row["id"]
        if session.get(SecurityAlert, alert_id) is not None:  # IDs are global; avoid clashing with another org's demo set
            alert_id = f"{org.slug[:16]}-{row['id']}"
        alert = SecurityAlert(
            id=alert_id,
            organization_id=organization_id,
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            source=row["source"],
            is_demo=True,
            affected_entity=row.get("affected_entity"),
            created_at=created_at,
            updated_at=created_at,
            first_seen_at=created_at,
            last_seen_at=created_at,
        )
        session.add(alert)
        session.flush()
        indicators.store(session, alert)
        record_event(session, organization_id, alert.id, "alert_created", "system", details={"demo": True}, created_at=created_at)
    session.commit()
    return len(rows)
