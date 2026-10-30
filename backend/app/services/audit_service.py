from datetime import datetime

from sqlmodel import Session

from app.models import AuditEvent


def record_event(
    session: Session,
    organization_id: str,
    alert_id: str | None,
    event_type: str,
    actor_type: str,
    actor_id: str | None = None,
    details: dict | None = None,
    created_at: datetime | None = None,
) -> AuditEvent:
    """Append an audit event. The caller owns the commit so related writes stay atomic.

    Audit events are append-only: nothing in the application updates or deletes them.
    Never put credentials, tokens or alert content in `details`.
    """
    event = AuditEvent(
        organization_id=organization_id,
        alert_id=alert_id,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        details=details or {},
    )
    if created_at is not None:
        event.created_at = created_at
    session.add(event)
    return event
