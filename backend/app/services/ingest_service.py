"""Normalized alert ingestion with idempotency and deduplication.

Rules, in order:
1. Exact replay (same source, external ID and event time, or same idempotency key) -> "duplicate", nothing changes.
2. Same source + external ID, different time -> the provider is updating/re-sending an alert. Occurrences are
   counted; fields are only overwritten by an event that is *newer* than anything seen. An older event arriving
   late is recorded and widens first_seen_at but never overwrites newer data ("out_of_order").
3. Different external ID but the same fingerprint (source + title + entity) within 24h on an unresolved alert ->
   a repeat firing of the same detection: attached to the existing alert ("updated").
4. Otherwise a new alert is created.
"""
import hashlib
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app import storage
from app.events import bus
from app.models import SecurityAlert, SourceEvent, utcnow
from app.observability import INGESTED
from app.schemas_saas import IngestEvent, IngestResult
from app.services import indicators
from app.services import triage_service
from app.services.audit_service import record_event

logger = logging.getLogger(__name__)

REPEAT_WINDOW = timedelta(hours=24)
MAX_FUTURE_SKEW = timedelta(minutes=10)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def fingerprint(source: str, title: str, entity: str | None) -> str:
    key = "\x1f".join([source.lower(), " ".join(title.lower().split()), (entity or "").lower()])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _raw_for_storage(organization_id: str, raw: dict | None, event: IngestEvent) -> tuple[dict, str | None]:
    body = raw if raw is not None else event.model_dump(mode="json", exclude={"raw"})
    uri = storage.put_if_large(organization_id, "source_event", body)
    return ({"_stored_externally": True, "sha256": storage.sha256_json(body)} if uri else body), uri


def ingest_event(
    session: Session,
    organization_id: str,
    event: IngestEvent,
    actor_type: str = "system",
    actor_id: str | None = None,
    integration_id: str | None = None,
    idempotency_key: str | None = None,
    commit: bool = True,
) -> IngestResult:
    now = utcnow()
    event_time = event.event_time or now
    if event_time - now > MAX_FUTURE_SKEW:
        event_time = now  # a clock far in the future must not pin an alert to the top forever
    fp = fingerprint(event.source, event.title, event.affected_entity)

    # 1. exact replay
    existing_event = session.exec(
        select(SourceEvent).where(
            SourceEvent.organization_id == organization_id, SourceEvent.source == event.source, SourceEvent.external_id == event.external_id,
            SourceEvent.event_time == event_time,
        )
    ).first()
    if existing_event is None and idempotency_key:
        existing_event = session.exec(
            select(SourceEvent).where(SourceEvent.organization_id == organization_id, SourceEvent.idempotency_key == idempotency_key)
        ).first()
    if existing_event is not None and existing_event.alert_id:
        alert = session.get(SecurityAlert, existing_event.alert_id)
        INGESTED.labels("duplicate").inc()
        return IngestResult(outcome="duplicate", alert_id=alert.id, occurrence_count=alert.occurrence_count)

    # 2. same alert from the same source, seen before at another time
    alert = session.exec(
        select(SecurityAlert).where(
            SecurityAlert.organization_id == organization_id, SecurityAlert.source == event.source,
            SecurityAlert.external_id == event.external_id,
        )
    ).first()
    outcome = "updated"
    same_alert_update = alert is not None
    # 3. repeat firing of the same detection
    if alert is None:
        cutoff = now - REPEAT_WINDOW
        alert = session.exec(
            select(SecurityAlert).where(
                SecurityAlert.organization_id == organization_id, SecurityAlert.fingerprint == fp,
                SecurityAlert.status != "resolved", SecurityAlert.last_seen_at >= cutoff,
            ).order_by(SecurityAlert.last_seen_at.desc())
        ).first()

    created = False
    if alert is None:
        alert = SecurityAlert(
            organization_id=organization_id, title=event.title, description=event.description or event.title,
            severity=event.severity, source=event.source, affected_entity=event.affected_entity, integration_id=integration_id,
            external_id=event.external_id, fingerprint=fp, created_at=event_time, updated_at=now,
            first_seen_at=event_time, last_seen_at=event_time,
        )
        session.add(alert)
        session.flush()
        created, outcome = True, "created"
        record_event(session, organization_id, alert.id, "alert_created", actor_type, actor_id,
                     {"source": event.source, "external_id": event.external_id, "integration_id": integration_id}, created_at=event_time)
    else:
        last_seen = _aware(alert.last_seen_at) or _aware(alert.created_at)
        first_seen = _aware(alert.first_seen_at) or _aware(alert.created_at)
        alert.occurrence_count += 1
        if event_time >= last_seen:
            alert.last_seen_at = event_time
            alert.updated_at = now
            # An update to the same provider alert carries its current severity (latest wins). A repeat
            # firing from a different event ID can only escalate: a calmer duplicate must not hide it.
            rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            new_severity = event.severity if same_alert_update else max(alert.severity, event.severity, key=lambda s: rank[s])
            if new_severity != alert.severity:
                record_event(session, organization_id, alert.id, "severity_changed", actor_type, actor_id,
                             {"from": alert.severity, "to": new_severity})
                alert.severity = new_severity
            if alert.status == "resolved":
                record_event(session, organization_id, alert.id, "status_changed", "system", None,
                             {"from": "resolved", "to": "new", "reason": "new occurrence after resolution"})
                alert.status = "new"
        else:
            outcome = "out_of_order"
            if event_time < first_seen:
                alert.first_seen_at = event_time
        session.add(alert)
        record_event(session, organization_id, alert.id, "alert_occurrence_recorded", actor_type, actor_id,
                     {"external_id": event.external_id, "outcome": outcome, "occurrence_count": alert.occurrence_count})

    raw, raw_uri = _raw_for_storage(organization_id, event.raw, event)
    session.add(SourceEvent(
        organization_id=organization_id, alert_id=alert.id, integration_id=integration_id, source=event.source,
        external_id=event.external_id, event_time=event_time, idempotency_key=idempotency_key, raw=raw, raw_storage_uri=raw_uri,
    ))
    indicators.store(session, alert, [(i.type, i.value) for i in event.indicators])

    try:
        session.flush()
        if commit:
            session.commit()
    except IntegrityError:
        # A concurrent request inserted the same source event first: treat as a duplicate.
        session.rollback()
        existing = session.exec(
            select(SecurityAlert).where(
                SecurityAlert.organization_id == organization_id, SecurityAlert.source == event.source, SecurityAlert.external_id == event.external_id
            )
        ).first()
        INGESTED.labels("duplicate").inc()
        if existing is None:
            raise
        return IngestResult(outcome="duplicate", alert_id=existing.id, occurrence_count=existing.occurrence_count)

    INGESTED.labels(outcome).inc()
    bus.publish(organization_id, "alert.created" if created else "alert.updated", {"id": alert.id, "severity": alert.severity, "title": alert.title})
    if created and commit:
        # After the alert is committed, so a triage problem can never lose it. Queues only; no model call here.
        triage_service.maybe_enqueue(session, organization_id, alert.id)
    return IngestResult(outcome=outcome, alert_id=alert.id, occurrence_count=alert.occurrence_count)
